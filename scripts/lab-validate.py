#!/usr/bin/env python3
"""
CCO Live Lab Validation — embedded veya docker lab'a karşı hunter + validator e2e.

Varsayılan davranış:
1. Loopback-only VulnLab'i process içinde başlatır.
2. Hunter ve validator MCP server dosyalarını doğrudan import eder.
3. RAG hazırsa enrich akışını, değilse ingest-plan davranışını doğrular.
4. Hunter zinciri ve deterministik validator'ları gerçek HTTP üzerinden koşturur.

Docker kullanımı:
    docker compose -f scripts/lab/docker-compose.yml up --build -d vuln-lab
    python3 scripts/lab-validate.py --base-url http://127.0.0.1:8899 --skip-rag
"""

import argparse
import importlib.util
import json
import os
import sqlite3
import sys
import tempfile
import threading
import time
from typing import Dict, List

import requests


REPO = os.path.dirname(os.path.dirname(os.path.abspath(__file__)))
_SURFACE = os.path.join(REPO, "mcp-servers", "mcp-memory-server")
if _SURFACE not in sys.path:
    sys.path.insert(0, _SURFACE)
LLM_ENV_KEYS = ("OPENROUTER_API_KEY", "ANTHROPIC_AUTH_TOKEN", "DEEPSEEK_API_KEY")


def _load(name: str, path: str):
    spec = importlib.util.spec_from_file_location(name, path)
    module = importlib.util.module_from_spec(spec)
    sys.modules[name] = module
    spec.loader.exec_module(module)
    return module


def _hdr(title: str, quiet: bool):
    if quiet:
        return
    print("\n" + "═" * 68 + f"\n  {title}\n" + "═" * 68)


def _seed_endpoints(mem_db: str, target: str, base: str):
    with sqlite3.connect(mem_db) as conn:
        conn.execute(
            "CREATE TABLE IF NOT EXISTS endpoints ("
            "id INTEGER PRIMARY KEY, target TEXT, url_or_port TEXT, protocol TEXT, "
            "state TEXT, technologies TEXT, timestamp TEXT)"
        )
        conn.execute(
            "CREATE TABLE IF NOT EXISTS findings ("
            "id INTEGER PRIMARY KEY, target TEXT, type TEXT, severity TEXT, "
            "description TEXT, payload TEXT, timestamp TEXT)"
        )
        for url, tech in [
            (f"{base}/search?q=1", "php apache"),
            (f"{base}/item?id=1", "php mysql"),
            (f"{base}/api/orders/1001", "rest api jwt"),
            (f"{base}/admin/export", "admin"),
            (f"{base}/checkout?price=10&quantity=1", "checkout payment"),
            (f"{base}/go?next=/home", "oauth redirect"),
        ]:
            conn.execute(
                "INSERT INTO endpoints (target,url_or_port,protocol,state,technologies) "
                "VALUES (?,?,?,?,?)",
                (target, url, "http", "open", tech),
            )


def _seed_rag(quiet: bool) -> bool:
    _hdr("ADIM 2 — RAG tohumlama", quiet)
    try:
        rag = _load("rag_lab_seed", os.path.join(REPO, "mcp-servers", "mcp-rag-engine", "server.py"))
        if not getattr(rag, "HAS_CHROMADB", False):
            if not quiet:
                print("  ⚠ chromadb yok → enrich plan modu doğrulanacak")
            return False
        rag.rag_ingest_writeup(
            title="Apache 2.4.49 Path Traversal RCE (CVE-2021-41773)",
            content=(
                "Apache HTTP Server 2.4.49 path traversal via encoded ../ in URL leads to "
                "source disclosure and, with mod_cgi enabled, remote code execution."
            ),
            category="web", tags="apache,rce,cve-2021-41773", source="manual",
        )
        rag.rag_ingest_writeup(
            title="MySQL error-based SQL injection cheatsheet",
            content=(
                "Error-based SQLi: inject a single quote to trigger SQL syntax errors; "
                "confirm with boolean and time-based payloads."
            ),
            category="web", tags="sqli,mysql,error-based", source="manual",
        )
        rag.rag_ingest_writeup(
            title="BOLA / IDOR exploitation guide",
            content=(
                "Swap the object id with another user's id and compare owner vs attacker "
                "responses to confirm BOLA."
            ),
            category="web", tags="bola,idor,api", source="manual",
        )
        count = rag._get_collection("writeups").count()
        if not quiet:
            print(f"  ✓ RAG writeups seeded ({count} kayıt)")
        return count > 0
    except Exception as exc:
        if not quiet:
            print(f"  ⚠ RAG seed atlandı: {exc}")
        return False


def run_validation(base_url: str = "", skip_rag: bool = False, skip_zap: bool = False, quiet: bool = False) -> Dict[str, object]:
    env_backup = {key: os.environ.get(key) for key in
                  ("CCO_HOME", "CCO_GRAPH_BACKEND", "CCO_SCOPE_FILE", "CCO_PROGRAM_POLICY_FILE",
                   "CCO_STUCK_THRESHOLD")}
    llm_backup = {key: os.environ.get(key) for key in LLM_ENV_KEYS}
    os.environ["CCO_HOME"] = tempfile.mkdtemp(prefix="cco_lab_")
    os.environ["CCO_GRAPH_BACKEND"] = "networkx"
    # Lab koşusu repo kapsam/politikasını miras almaz: gerçek programın hız
    # profili (örn. conservative 20/dk) döngüyü fuzz öncesi keser. İzole
    # loopback kapsamı + lab profili temp CCO_HOME içine yazılır.
    lab_home = os.environ["CCO_HOME"]
    with open(os.path.join(lab_home, "lab-scope.json"), "w", encoding="utf-8") as fh:
        json.dump({"allow_loopback": True, "allow_public_labs": True, "rules": {}}, fh)
    try:
        with open(os.path.join(REPO, "config", "program-profiles", "lab.json"),
                  encoding="utf-8") as fh:
            lab_policy = json.load(fh)
    except (OSError, ValueError):
        lab_policy = {}
    lab_policy["rate_limits"] = {
        "default": {"window_seconds": 60, "max_calls": 600},
        "conservative": {"window_seconds": 60, "max_calls": 600},
    }
    with open(os.path.join(lab_home, "lab-policy.json"), "w", encoding="utf-8") as fh:
        json.dump(lab_policy, fh)
    os.environ["CCO_SCOPE_FILE"] = os.path.join(lab_home, "lab-scope.json")
    os.environ["CCO_PROGRAM_POLICY_FILE"] = os.path.join(lab_home, "lab-policy.json")
    # Takılma dedektörü LLM döngüsü içindir; tek koşu içi deterministik fuzz
    # aynı uca çok sonda basar ve sahte "stuck" üretir. Labda eşik yükseltilir
    # (dedektörün kendi testleri ayrıca koşar).
    os.environ["CCO_STUCK_THRESHOLD"] = "10000"
    for key in LLM_ENV_KEYS:
        os.environ.pop(key, None)

    lab_server = None
    try:
        hunter = _load("hunter_lab", os.path.join(REPO, "mcp-servers", "mcp-hunter", "server.py"))
        validator = _load("validator_lab", os.path.join(REPO, "mcp-servers", "mcp-validator", "server.py"))
        kali = _load("kali_lab", os.path.join(REPO, "mcp-servers", "mcp-kali-tools", "server.py"))

        if base_url:
            base = base_url.rstrip("/")
        else:
            lab = _load("vuln_lab_embedded", os.path.join(REPO, "scripts", "lab", "vuln_lab.py"))
            lab_server = lab.serve(0)
            threading.Thread(target=lab_server.serve_forever, daemon=True).start()
            time.sleep(0.3)
            base = f"http://127.0.0.1:{lab_server.server_address[1]}"

        target = base
        if not quiet:
            print(f"VulnLab hedefi → {base}")

        _seed_endpoints(hunter.MEM_DB, target, base)
        rag_seeded = False if skip_rag else _seed_rag(quiet)

        checks: List[Dict[str, object]] = []

        def record(name: str, passed: bool, detail: str = ""):
            checks.append({"name": name, "passed": bool(passed), "detail": detail})
            if not quiet:
                prefix = "✓ PASS" if passed else "✗ FAIL"
                suffix = f" — {detail}" if detail else ""
                print(f"  {prefix}  {name}{suffix}")

        _hdr("ADIM 2b — discover_web_surface", quiet)
        discovered = json.loads(kali.discover_web_surface(
            base, mode="active", include_historic=False, probe_limit=16, timeout=5
        ))
        queue_urls = " ".join(item.get("url", "") for item in discovered.get("work_queue") or [])
        probe = discovered.get("probe") or {}
        wordlist_blob = " ".join(discovered.get("wordlist_sample") or [])
        sources = json.dumps(discovered.get("sources") or {})
        record("discover ingest", int(discovered.get("ingested") or 0) >= 8, str(discovered.get("ingested")))
        record(
            "discover queue includes search/item",
            ("/search" in queue_urls) or ("/item" in queue_urls),
            queue_urls[:180],
        )
        record(
            "discover probe title/hash",
            bool(probe.get("title") and probe.get("body_hash")),
            str(probe.get("title") or ""),
        )
        record(
            "discover wordlist from js/openapi",
            int(discovered.get("wordlist_size") or 0) >= 6
            and any(token in wordlist_blob or token in queue_urls or token in sources
                    for token in ("sort", "debug", "notes", "csrf", "openapi")),
            f"size={discovered.get('wordlist_size')} sample={wordlist_blob[:80]}",
        )
        compiled = json.loads(kali.compile_target_wordlist(target))
        record("compile_target_wordlist", int(compiled.get("size") or 0) >= 6, str(compiled.get("size")))

        from cco_surface_core.parsers import parse_zap
        zap_fixture = parse_zap({
            "urls": [f"{base}/search?q=1", f"{base}/item?id=1"],
            "alerts": [{
                "url": f"{base}/item?id=1",
                "method": "GET",
                "param": "id",
                "alert": "SQL Injection",
                "risk": "High",
                "pluginId": "40018",
            }],
        }, target=target)
        record(
            "parse_zap fixture",
            any("/item" in (item.get("url") or "") for item in zap_fixture)
            and any("sql_injection" in (item.get("tech") or []) for item in zap_fixture),
            str(len(zap_fixture)),
        )
        discover_blob = json.dumps(discovered)
        record(
            "discover misses depth-2 secret",
            "/portal/secret" not in discover_blob,
            "secret absent" if "/portal/secret" not in discover_blob else "leaked into discover",
        )

        has_pw = bool(getattr(kali, "HAS_PLAYWRIGHT", False))
        if has_pw:
            crawled = json.loads(kali.crawl_web_surface(
                base, max_pages=20, cookie="session=userA", timeout=60
            ))
            crawl_blob = json.dumps(crawled)
            record("crawl ok", crawled.get("ok") is True, crawled.get("error") or "")
            record(
                "crawl depth-2 secret",
                "/portal/secret" in crawl_blob,
                crawl_blob[:220],
            )
            record(
                "crawl cookie account",
                "/account" in crawl_blob,
                "account" if "/account" in crawl_blob else "missing",
            )
            xhr_blob = json.dumps(crawled.get("xhr") or [])
            record(
                "crawl xhr notes",
                "/api/notes" in xhr_blob or "/api/notes" in crawl_blob,
                xhr_blob[:180],
            )
        else:
            skipped = json.loads(kali.crawl_web_surface(base, max_pages=2))
            record(
                "crawl skipped without playwright",
                skipped.get("ok") is False and "playwright" in str(skipped.get("error") or "").lower(),
                str(skipped.get("error") or "")[:120],
            )

        if skip_zap:
            record("zap live skipped", True, "--skip-zap")
        else:
            zapped = json.loads(kali.zap_map_surface(base, ajax=False, allow_ascan=False, timeout=20))
            if zapped.get("ok"):
                record("zap map ingest", int(zapped.get("ingested") or 0) >= 1, str(zapped.get("ingested")))
                ascan = zapped.get("ascan") or {}
                record("zap ascan skipped by default", ascan.get("ran") is not True and ascan.get("skipped") is not False)
            else:
                record(
                    "zap live skipped",
                    True,
                    str(zapped.get("error") or "api unreachable")[:160],
                )

        _hdr("ADIM 3 — enrich_with_rag", quiet)
        enrich = json.loads(hunter.enrich_with_rag(fingerprint="Apache 2.4.49 PHP MySQL REST API"))
        has_inline_hits = any(item.get("rag_hits") for item in enrich["enriched_predictions"])
        record(
            "enrich_with_rag behaviour",
            has_inline_hits if rag_seeded else bool(enrich["ingest_plan"]),
            "inline hit" if rag_seeded else "ingest plan",
        )
        record(
            "enrich CVE extraction",
            "CVE-2021-41773" in enrich["cve_ids_found"],
        )

        _hdr("ADIM 4 — predict_vulnerabilities", quiet)
        prediction = json.loads(hunter.predict_vulnerabilities(
            target=target, fingerprint="Apache 2.4.49 PHP MySQL REST API"
        ))
        classes = [item["vuln_class"] for item in prediction["predictions"]]
        record("predict includes traversal/sqli", any(c in classes for c in ("path_traversal", "sql_injection", "rce")))

        _hdr("ADIM 5 — coverage_report", quiet)
        coverage = json.loads(hunter.coverage_report(target=target))
        record("coverage blind spot detection", len(coverage["blind_spots"]) > 0)
        coverage_before = int(coverage.get("coverage_percent") or 0)

        _hdr("ADIM 5b — run_web_loop", quiet)
        looped = json.loads(hunter.run_web_loop(
            target, live=True, crawl=False, zap=False,
            cookie="session=userA", fuzz_limit=12, max_validations=5, sleep_s=0.05,
        ))
        fuzzed = looped.get("fuzz") or {}
        likely_classes = {item.get("vuln_class") for item in fuzzed.get("likely_hits") or []}
        likely_urls = " ".join(item.get("url") or "" for item in fuzzed.get("likely_hits") or [])
        record("web loop ok", looped.get("ok") is True, str(looped.get("errors") or "")[:160])
        record(
            "fuzz XSS likely",
            "xss_reflected" in likely_classes or "/search" in likely_urls,
            ",".join(sorted(c for c in likely_classes if c)),
        )
        record(
            "fuzz SQLi candidate routed",
            any(item.get("vuln_class") == "sql_injection"
                for item in looped.get("validation_candidates") or []),
            "Observed canary candidate reaches validation selection; confirmation is checked separately.",
        )
        record(
            "fuzz params probed",
            int(fuzzed.get("probes") or 0) >= 4 or int(fuzzed.get("executed_live") or 0) >= 4,
            f"probes={fuzzed.get('probes')} executed={fuzzed.get('executed_live')}",
        )
        record(
            "web loop confirmed",
            len(looped.get("confirmed") or []) >= 1,
            json.dumps(looped.get("confirmed") or [])[:180],
        )
        record(
            "web loop no dump",
            looped.get("allow_deepen") is False and looped.get("ascan") is False,
        )
        coverage_after = json.loads(hunter.coverage_report(target=target))
        record(
            "coverage increased after fuzz",
            int(coverage_after.get("coverage_percent") or 0) >= coverage_before
            and (bool(fuzzed.get("marked_tested")) or bool(looped.get("confirmed"))),
            f"{coverage_before} -> {coverage_after.get('coverage_percent')}",
        )

        _hdr("ADIM 6 — authz differential", quiet)
        matrix = json.loads(hunter.build_authz_matrix(
            target=target,
            identities="anon,userA,userB,admin",
            resources=f"{base}/api/orders/1001,{base}/admin/export",
            object_ids="1001,1002",
        ))
        record("build_authz_matrix generated cases", matrix["tests_generated"] >= 2)

        owner = requests.get(f"{base}/api/orders/1001", headers={"Authorization": "Bearer userA"}, timeout=5)
        attacker = requests.get(f"{base}/api/orders/1001", headers={"Authorization": "Bearer userB"}, timeout=5)
        bola = json.loads(hunter.analyze_authz_result(json.dumps({
            "target": target,
            "test_type": "bola",
            "authorized": {"identity": "userA", "status": owner.status_code, "body": owner.text, "markers": ["alice@lab.local"]},
            "attacker": {"identity": "userB", "status": attacker.status_code, "body": attacker.text, "markers": ["alice@lab.local"]},
        })))
        record("BOLA confirmed", bola["verdict"] == "CONFIRMED")

        unauth = requests.get(f"{base}/admin/export", timeout=5)
        bfla = json.loads(hunter.analyze_authz_result(json.dumps({
            "target": target,
            "test_type": "unauth",
            "protected_markers": ["all-customer-pii"],
            "attacker": {"identity": "anon", "status": unauth.status_code, "body": unauth.text,
                         "markers": ["all-customer-pii"]},
        })))
        record("unauth admin confirmed", bfla["verdict"] == "CONFIRMED")

        _hdr("ADIM 7 — business logic", quiet)
        abuse = json.loads(hunter.generate_abuse_cases(endpoint=f"{base}/checkout", params="price,quantity"))
        negative = requests.get(f"{base}/checkout?price=-100&quantity=2", timeout=5).json()
        record("abuse cases include price manipulation", any(item["vuln_class"] == "price_manipulation" for item in abuse["abuse_cases"]))
        record("negative checkout accepted", negative["charged"] < 0)

        _hdr("ADIM 8 — auto_fanout live", quiet)
        fanout_xss = json.loads(hunter.auto_fanout_variants(
            finding_type="xss_reflected",
            target=f"{base}/search?q=1",
            param="q",
            endpoint=f"{base}/search?q=1",
            live=True,
            max_requests=6,
        ))
        record("auto_fanout XSS likely", len(fanout_xss["likely_hits"]) >= 1)
        record(
            "fanout siblings",
            int(fanout_xss.get("variants") or 0) >= 2,
            str(fanout_xss.get("variants")),
        )

        fanout_sqli = json.loads(hunter.auto_fanout_variants(
            finding_type="sql_injection",
            target=f"{base}/item?id=1",
            param="id",
            endpoint=f"{base}/item?id=1",
            live=True,
            max_requests=6,
        ))
        record("auto_fanout SQLi likely", len(fanout_sqli["likely_hits"]) >= 1)

        _hdr("ADIM 9 — validator e2e", quiet)
        xss = json.loads(validator.validate_xss_reflection(f"{base}/search?q=1", param="q"))
        record(
            "validator XSS reflection-only candidate",
            xss["verdict"] == "INCONCLUSIVE" and xss["evidence"]["reflection"]["verdict"] == "CONFIRMED",
        )

        sqli = json.loads(validator.validate_sqli(f"{base}/item?id=1", param="id"))
        record("validator SQLi confirmed", sqli["verdict"] == "CONFIRMED")

        exploited = json.loads(hunter.exploit_confirmed(sqli.get("validation_id") or "", live=True))
        deepen_blob = json.dumps(exploited.get("deepen") or {})
        record(
            "exploit_confirmed SQLi pack",
            exploited.get("ok") is True and bool(exploited.get("evidence_pack")),
            exploited.get("error") or exploited.get("vuln_class") or "",
        )
        record(
            "exploit_confirmed min-proof no dump",
            exploited.get("ok") is True and "dump — request_approval" not in deepen_blob,
        )
        sqlmap_blocked = json.loads(kali.sqlmap_test_structured(f"{base}/item?id=1"))
        record("sqlmap without validation blocked", sqlmap_blocked.get("ok") is False)

        safe_sqli = json.loads(validator.validate_sqli(f"{base}/safe/item?id=1", param="id"))
        record("validator safe SQLi unconfirmed", safe_sqli["verdict"] == "UNCONFIRMED")

        waf_blocked = requests.get(f"{base}/waf/item", params={"id": "1 AND 1=1"}, timeout=5)
        record(
            "lab WAF blocks canonical SQLi",
            waf_blocked.status_code == 403 and "Mod_Security" in (waf_blocked.text or ""),
            str(waf_blocked.status_code),
        )
        waf_bypass = requests.get(f"{base}/waf/item", params={"id": "1/**/AND/**/1=1"}, timeout=5)
        record(
            "lab WAF allows comment mutation",
            waf_bypass.status_code == 200 and "Widget" in (waf_bypass.text or ""),
            str(waf_bypass.status_code),
        )
        waf_sqli = json.loads(validator.validate_sqli(f"{base}/waf/item?id=1", param="id"))
        waf_evidence = waf_sqli.get("evidence") or {}
        record(
            "validator WAF SQLi retry confirmed",
            waf_sqli["verdict"] == "CONFIRMED",
            waf_sqli.get("verdict"),
        )
        record(
            "validator WAF SQLi used mutation",
            bool(waf_evidence.get("waf_retry"))
            or "/**/" in str(waf_evidence.get("true_payload") or "")
            or "%0" in str(waf_evidence.get("true_payload") or ""),
            str(waf_evidence.get("true_payload") or "")[:80],
        )

        open_redirect = json.loads(validator.validate_open_redirect(f"{base}/go?next=/home", param="next"))
        record("validator open redirect confirmed", open_redirect["verdict"] == "CONFIRMED")

        safe_redirect = json.loads(validator.validate_open_redirect(f"{base}/safe/go?next=/home", param="next"))
        record("validator safe open redirect unconfirmed", safe_redirect["verdict"] == "UNCONFIRMED")

        idor = json.loads(validator.validate_idor(
            f"{base}/api/orders/1001",
            owner_headers_json=json.dumps({"Authorization": "Bearer userA"}),
            attacker_headers_json=json.dumps({"Authorization": "Bearer userB"}),
            owner_marker="alice@lab.local",
        ))
        record("validator IDOR confirmed", idor["verdict"] == "CONFIRMED")

        safe_idor = json.loads(validator.validate_idor(
            f"{base}/safe/api/orders/1001",
            owner_headers_json=json.dumps({"Authorization": "Bearer userA"}),
            attacker_headers_json=json.dumps({"Authorization": "Bearer userB"}),
            owner_marker="alice@lab.local",
        ))
        record("validator safe IDOR unconfirmed", safe_idor["verdict"] == "UNCONFIRMED")

        auth = json.loads(validator.validate_auth_bypass(
            f"{base}/admin/export",
            authorized_headers_json=json.dumps({"Authorization": "Bearer admin"}),
            protected_marker="all-customer-pii",
        ))
        record("validator auth bypass confirmed", auth["verdict"] == "CONFIRMED")

        safe_auth = json.loads(validator.validate_auth_bypass(
            f"{base}/safe/admin/export",
            authorized_headers_json=json.dumps({"Authorization": "Bearer admin"}),
            protected_marker="all-customer-pii",
        ))
        record("validator safe auth bypass unconfirmed", safe_auth["verdict"] == "UNCONFIRMED")

        confirmed = sum(
            1 for item in checks
            if item["passed"] and "confirmed" in item["name"].lower()
            and "unconfirmed" not in item["name"].lower()
        )
        record("confirmed count", confirmed >= 3, str(confirmed))

        passed = sum(1 for item in checks if item["passed"])
        result = {
            "base_url": base,
            "checks": checks,
            "passed": passed,
            "total": len(checks),
            "all_passed": passed == len(checks),
        }

        if not quiet:
            _hdr("SONUÇ", quiet)
            print(f"  {passed}/{len(checks)} kontrol geçti.")
        return result
    finally:
        if lab_server is not None:
            lab_server.shutdown()
        for key, value in env_backup.items():
            if value is None:
                os.environ.pop(key, None)
            else:
                os.environ[key] = value
        for key, value in llm_backup.items():
            if value is None:
                os.environ.pop(key, None)
            else:
                os.environ[key] = value


def main(argv=None) -> int:
    parser = argparse.ArgumentParser(description="CCO loopback lab validation")
    parser.add_argument("--base-url", help="Existing VulnLab URL (skip embedded server startup)")
    parser.add_argument("--skip-rag", action="store_true", help="Skip RAG seed/enrich checks")
    parser.add_argument("--skip-zap", action="store_true", help="Skip live ZAP daemon mapping")
    parser.add_argument("--json", action="store_true", help="Print structured JSON summary")
    parser.add_argument("--quiet", action="store_true", help="Suppress step-by-step output")
    args = parser.parse_args(argv)

    result = run_validation(
        base_url=args.base_url or "",
        skip_rag=args.skip_rag,
        skip_zap=args.skip_zap,
        quiet=args.quiet,
    )
    if args.json:
        print(json.dumps(result, indent=2, ensure_ascii=False))
    return 0 if result["all_passed"] else 1


if __name__ == "__main__":
    sys.exit(main())
