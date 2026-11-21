#!/usr/bin/env python3
"""Launch a bounded PythonSolver session against an external owned loopback target."""
from __future__ import annotations

import argparse
from contextlib import redirect_stderr, redirect_stdout
import json
import os
from pathlib import Path
import shutil
import sys
import tempfile
import time
from typing import Any, Sequence
from urllib.parse import urljoin, urlsplit
import uuid

import requests

SCRIPTS = Path(__file__).resolve().parent
if str(SCRIPTS) not in sys.path:
    sys.path.insert(0, str(SCRIPTS))

import full_agent_launcher as launcher  # noqa: E402
import full_agent_preflight as preflight  # noqa: E402
import llm_config  # noqa: E402
import qa_expectation_policy  # noqa: E402
import write_isolation  # noqa: E402
from campaign_worker import LocalMCPExecutor  # noqa: E402
from evidence_trust import prepare as prepare_trust  # noqa: E402
from full_agent_budget import SharedBudget  # noqa: E402
from full_agent_executor import CATALOG  # noqa: E402
from full_agent_provider import dump  # noqa: E402
from full_agent_python_broker import PythonBroker, PythonRuntimePolicy  # noqa: E402
from full_agent_python_solver import PythonSolver  # noqa: E402
from full_agent_tasks import TaskRegistry  # noqa: E402
from orchestration_spec import dump_specs  # noqa: E402
from policy_engine import PolicyEngine  # noqa: E402
from provider_auth import authorize_provider  # noqa: E402

SCHEMA = "external-target-run/1"
_ALL_MUTATING_METHODS = ("POST", "PUT", "PATCH", "DELETE", "CONNECT", "TRACE")
_ADMIN_ROLES = frozenset({"platform_admin", "tenant_admin", "admin", "superadmin"})


def normalize_loopback_origin(raw_url: str) -> str:
    """Validate and normalize an explicit owned loopback origin URL."""
    raw = str(raw_url or "").strip()
    if not raw:
        raise ValueError("target URL is required")
    parsed = urlsplit(raw)
    if parsed.scheme != "http" or parsed.hostname != "127.0.0.1" or not parsed.port:
        raise ValueError("external target must be an explicit http://127.0.0.1:<port>/ origin")
    if parsed.path not in {"", "/"} or parsed.username or parsed.password or parsed.query or parsed.fragment:
        raise ValueError("external target must be a clean origin without path, credentials, query, or fragment")
    return f"http://127.0.0.1:{parsed.port}/"


def load_credentials_bundle(path: Path | None) -> dict[str, Any]:
    """Load public target metadata and synthetic test accounts from an operator bundle."""
    if path is None:
        return {}
    data = json.loads(Path(path).expanduser().resolve(strict=True).read_text(encoding="utf-8"))
    if not isinstance(data, dict):
        raise ValueError("credentials file must be a JSON object")
    return data


def select_representative_accounts(
    accounts: Sequence[dict[str, Any]],
    *,
    max_members: int = 4,
    max_admins: int = 1,
) -> list[dict[str, Any]]:
    """Select bounded synthetic accounts spanning tenants, roles, and peer comparisons."""
    cleaned = [dict(row) for row in accounts if isinstance(row, dict) and row.get("alias") and row.get("password")]
    if max_members < 0 or max_admins < 0:
        raise ValueError("account limits must be non-negative")
    admins = [row for row in cleaned if str(row.get("role") or "").lower() in _ADMIN_ROLES]
    members = [row for row in cleaned if str(row.get("role") or "").lower() not in _ADMIN_ROLES]

    selected_members: list[dict[str, Any]] = []
    seen_tenants: set[str] = set()
    seen_roles: set[str] = set()
    # First pass: maximize role and tenant diversity; second pass: keep same-tenant peers for BOLA.
    for row in members:
        if len(selected_members) >= max_members:
            break
        tenant = str(row.get("tenant") or "")
        role = str(row.get("role") or "")
        if tenant not in seen_tenants or role not in seen_roles:
            selected_members.append(row)
            seen_tenants.add(tenant)
            seen_roles.add(role)
    for row in members:
        if len(selected_members) >= max_members:
            break
        if row not in selected_members:
            selected_members.append(row)

    selected_admins = admins[:max_admins]
    return [*selected_members, *selected_admins]


def external_policy_config(
    base: str,
    *,
    allowed_methods: Sequence[str] = ("GET",),
    max_seconds: int = 900,
    max_requests: int = 550,
) -> tuple[dict[str, Any], dict[str, Any]]:
    """Build strict loopback scope and policy aligned with operator-declared allowed HTTP methods."""
    origin = normalize_loopback_origin(base)
    allowed = {str(m or "").strip().upper() for m in allowed_methods if str(m or "").strip()}
    blocked = [m for m in _ALL_MUTATING_METHODS if m not in allowed]
    scope = {
        "in_scope": [{"asset": origin}],
        "scope_policy": "explicit_only",
        "blind_mode": True,
        "allow_loopback": False,
        "allow_osint": False,
        "allow_public_labs": False,
    }
    policy = {
        "blind_mode": True,
        "blocked_http_methods": blocked,
        "background_network_jobs": "deny",
        "fuzz_max_requests_per_call": max(1, min(int(max_requests), 600)),
        "time_budget_max_seconds": int(max_seconds),
        "rate_limits": {
            "default": {"window_seconds": 60, "max_calls": max(300, int(max_requests))},
            "conservative": {"window_seconds": 60, "max_calls": max(300, int(max_requests))},
            "aggressive": {"window_seconds": 60, "max_calls": max(600, int(max_requests))},
            "overrides": {},
        },
        "blind_discovery": {
            "synthetic_accounts_only": True,
            "owned_objects_private": True,
            "differential_ownership": True,
        },
        "xss_execution": {"enabled": True, "max_browser_requests": 8, "wait_ms": 0},
    }
    return scope, policy


def _pick_session_marker(session_text: str, account: dict[str, Any]) -> str:
    candidates: list[str] = []
    for key in ("alias", "work_email", "email", "username"):
        val = account.get(key)
        if isinstance(val, str) and val.strip():
            clean = val.strip()
            candidates.append(clean)
            if key == "username" and ("." in clean or "_" in clean):
                spaced = " ".join(part for part in clean.replace(".", " ").replace("_", " ").split() if part)
                if spaced:
                    candidates.extend([spaced, spaced.title()])
    try:
        parsed = json.loads(session_text)
    except ValueError:
        parsed = None
    if isinstance(parsed, dict):
        for key in ("alias", "work_email", "email", "username", "tenant", "role", "user_id", "id"):
            val = parsed.get(key)
            if isinstance(val, str) and len(val.strip()) >= 3:
                candidates.append(val.strip())
        user_obj = parsed.get("user")
        if isinstance(user_obj, dict):
            for key in ("alias", "work_email", "email", "username", "tenant", "role"):
                val = user_obj.get(key)
                if isinstance(val, str) and len(val.strip()) >= 3:
                    candidates.append(val.strip())
    for cand in candidates:
        if cand in session_text:
            return cand
    raise ValueError(f"could not determine verifiable session marker for account {account.get('alias')}")


def sign_in_accounts(
    base: str,
    accounts: Sequence[dict[str, Any]],
    *,
    login_path: str = "/api/v1/access/sign-in",
    session_check_path: str = "/api/v1/access/session",
    timeout_s: int = 10,
) -> dict[str, dict[str, Any]]:
    """Sign in synthetic accounts over loopback HTTP and build non-persistent session descriptors."""
    login_url = urljoin(base, login_path.lstrip("/"))
    check_url = urljoin(base, session_check_path.lstrip("/"))
    signed_in: dict[str, dict[str, Any]] = {}
    session = requests.Session()
    session.trust_env = False
    for acc in accounts:
        alias = str(acc["alias"]).strip()
        headers: dict[str, str] = {}
        if isinstance(acc.get("headers"), dict):
            headers.update({str(k): str(v) for k, v in acc["headers"].items() if k and v is not None})
        if isinstance(acc.get("auth_header"), str) and acc["auth_header"].strip():
            headers.setdefault("Authorization", acc["auth_header"].strip())
        elif isinstance(acc.get("session_token"), str) and acc["session_token"].strip():
            headers.setdefault("Authorization", f"Bearer {acc['session_token'].strip()}")
        if isinstance(acc.get("cookie"), str) and acc["cookie"].strip():
            headers.setdefault("Cookie", acc["cookie"].strip())

        if not headers:
            payload: dict[str, Any] = {"password": str(acc["password"])}
            if acc.get("work_email"):
                payload["work_email"] = str(acc["work_email"])
            elif acc.get("email"):
                payload["email"] = str(acc["email"])
            elif acc.get("username"):
                payload["username"] = str(acc["username"])
            else:
                raise ValueError(f"account {alias} is missing login identifier")
            resp = session.post(login_url, json=payload, timeout=timeout_s, allow_redirects=False)
            if resp.status_code in {400, 415}:
                resp = session.post(login_url, data=payload, timeout=timeout_s, allow_redirects=False)
            if resp.status_code not in {200, 201, 302, 303}:
                raise RuntimeError(f"sign-in failed for {alias} with HTTP {resp.status_code}")
            try:
                data = resp.json()
            except ValueError:
                data = {}
            if not isinstance(data, dict):
                data = {}
            token = str(data.get("access_token") or data.get("token") or "").strip()
            if token:
                headers = {"Authorization": f"Bearer {token}"}
                csrf = str(data.get("csrf_token") or "").strip()
                if csrf:
                    headers["X-CSRF-Token"] = csrf
            elif resp.cookies or session.cookies:
                jar = resp.cookies if len(resp.cookies) else session.cookies
                cookie_pairs = [f"{c.name}={c.value}" for c in jar]
                if cookie_pairs:
                    headers = {"Cookie": "; ".join(cookie_pairs)}
                    csrf = str(data.get("csrf_token") or "").strip()
                    if csrf:
                        headers["X-CSRF-Token"] = csrf
            if not headers:
                raise RuntimeError(f"sign-in response for {alias} omitted access_token and session cookie")
        check_resp = session.get(check_url, headers=headers, timeout=timeout_s, allow_redirects=False)
        if not (200 <= check_resp.status_code < 400):
            raise RuntimeError(f"session check failed for {alias} with HTTP {check_resp.status_code}")
        marker = _pick_session_marker(check_resp.text, acc)
        app_role = str(acc.get("role") or "member").strip() or "member"
        tenant = str(acc.get("tenant") or "").strip()
        identifiers: list[str] = []
        for candidate in (alias, acc.get("work_email"), acc.get("email"), acc.get("username")):
            if isinstance(candidate, str) and candidate.strip() and candidate.strip() not in identifiers:
                identifiers.append(candidate.strip())
        try:
            chk_json = check_resp.json()
        except ValueError:
            chk_json = None
        if isinstance(chk_json, dict):
            nodes = [chk_json]
            if isinstance(chk_json.get("user"), dict):
                nodes.append(chk_json["user"])
            for node in nodes:
                for key in ("id", "user_id", "alias", "work_email", "email", "username"):
                    val = node.get(key)
                    if isinstance(val, (str, int)) and not isinstance(val, bool):
                        sval = str(val).strip()
                        if sval and sval not in identifiers:
                            identifiers.append(sval)
        signed_in[alias] = {
            "headers": headers,
            "check_url": check_url,
            "marker": marker,
            "role": "admin" if app_role.lower() in _ADMIN_ROLES else "member",
            "app_role": app_role,
            "tenant": tenant,
            "identifiers": identifiers,
        }
    return signed_in


def provision_external_sessions(
    broker: PythonBroker,
    signed_in: dict[str, dict[str, Any]],
    base: str,
    home: Path,
    *,
    verify_checks: str = "crawl_only",
) -> dict[str, Any]:
    """Store signed-in headers in host session vault and return non-secret task bindings."""
    if not signed_in:
        return {}
    from cco_surface_core import session_store

    ordered = sorted(signed_in)
    if verify_checks == "all":
        verify_identities = set(ordered)
    elif verify_checks == "crawl_only":
        members = [name for name in ordered if signed_in[name]["role"] == "member"]
        verify_identities = {(members or ordered)[0]}
    else:
        verify_identities = set()

    bindings: dict[str, Any] = {}
    for alias in ordered:
        info = signed_in[alias]
        facts: list[dict[str, str]] = []
        if info["tenant"]:
            facts.append({
                "field": "tenant",
                "value": info["tenant"],
                "source": "response_metadata",
                "evidence": info["check_url"],
                "confidence": "observed",
            })
        if info["app_role"]:
            facts.append({
                "field": "role",
                "value": info["app_role"],
                "source": "response_metadata",
                "evidence": info["check_url"],
                "confidence": "observed",
            })
        session_store.put_session(
            base,
            alias,
            headers=info["headers"],
            check_url=info["check_url"],
            marker=info["marker"],
            home=str(home),
        )
        resource_spec: dict[str, Any] = {"role": info["role"]}
        if facts:
            resource_spec["identity_facts"] = facts
        session_store.bind_resources(
            base,
            alias,
            resource_spec,
            permits=lambda url, origin=base: url.startswith(origin),
            home=str(home),
        )
        if alias in verify_identities:
            result = broker.call_tool("validator", "session_vault_check", {"target": base, "identity": alias}, origin="setup")
            checked = json.loads(result["content"][0]["text"])
            if result.get("isError") or checked.get("status") != "fresh":
                raise RuntimeError(f"session_vault_check failed for {alias}: {checked}")
        bindings[alias] = {
            "target": base,
            "role": info["role"],
            "test_data_only": True,
            "owned_objects_private": True,
        }
    return bindings


def _collect_external_findings(private: Path, workdir: Path) -> list[dict[str, Any]]:
    """Collect confirmed signed validator artifacts without leaking secrets."""
    findings: list[dict[str, Any]] = []
    validations_dir = private / "state/validations"
    if validations_dir.is_dir():
        for path in sorted(validations_dir.glob("*.json")):
            try:
                data = json.loads(path.read_text(encoding="utf-8"))
            except (OSError, ValueError):
                continue
            if not isinstance(data, dict) or data.get("verdict") != "CONFIRMED" or data.get("reportable") is not True:
                continue
            findings.append({
                "validation_id": data.get("validation_id", ""),
                "vuln_class": data.get("vuln_class") or data.get("vuln_type") or "",
                "oracle": data.get("oracle", ""),
                "target": data.get("target") or data.get("resource") or "",
                "verdict": "CONFIRMED",
                "reportable": True,
                "artifact": str(path),
            })
    summary_path = workdir / "summaries/access-3.json"
    if not findings and summary_path.is_file():
        try:
            summary = json.loads(summary_path.read_text(encoding="utf-8"))
            if isinstance(summary.get("findings"), list):
                findings.extend(row for row in summary["findings"] if isinstance(row, dict))
        except (OSError, ValueError):
            pass
    return findings


def _collect_probable_findings(private: Path, workdir: Path) -> list[dict[str, Any]]:
    """Collect signed operator-review PROBABLE artifacts, strictly separate from CONFIRMED."""
    probable: list[dict[str, Any]] = []
    validations_dir = private / "state/validations"
    if validations_dir.is_dir():
        for path in sorted(validations_dir.glob("*.json")):
            try:
                data = json.loads(path.read_text(encoding="utf-8"))
            except (OSError, ValueError):
                continue
            if not isinstance(data, dict) or data.get("verdict") != "PROBABLE" or data.get("reportable") is True:
                continue
            probable.append({
                "validation_id": data.get("validation_id", ""),
                "vuln_class": data.get("vuln_class") or data.get("vuln_type") or "",
                "oracle": data.get("oracle", ""),
                "target": data.get("target") or data.get("resource") or "",
                "verdict": "PROBABLE",
                "review_tier": "operator-review",
                "reportable": False,
                "details": data.get("evidence") if isinstance(data.get("evidence"), dict) else (
                    data.get("details") if isinstance(data.get("details"), dict) else {}
                ),
                "repro": data.get("reproduction") or data.get("repro"),
                "artifact": str(path),
            })
    return probable


def run_external_target(
    *,
    target: str = "",
    credentials_file: Path | None = None,
    provider_config: Path = llm_config.default_config(),
    model: str = "",
    worker_model: str = "",
    api_key_env: str | None = None,
    output_dir: Path,
    http_budget: int = 550,
    token_budget: int = 180_000,
    seconds_budget: int = 900,
    login_path: str = "/api/v1/access/sign-in",
    session_check_path: str = "/api/v1/access/session",
    max_member_accounts: int = 6,
    max_admin_accounts: int = 2,
    qa_policy: Path | dict[str, Any] | None = None,
    write_isolation_attestation: Path | dict[str, Any] | str | None = None,
    auto_issue_write_isolation: bool = True,
    run_id: str = "",
    execute: bool = False,
    authorize_live_provider: bool = False,
    live_authorization_reason: str = "",
) -> tuple[Path, dict[str, Any]]:
    """Run (or plan when execute=False) PythonSolver against an external owned loopback target."""
    bundle = load_credentials_bundle(credentials_file)
    base = normalize_loopback_origin(target or str(bundle.get("target_url") or ""))
    qa_policy_doc = qa_expectation_policy.load_qa_policy(qa_policy) if qa_policy is not None else None
    qa_mode = "policy" if qa_policy_doc is not None else "blind"
    eff_run_id = str(run_id or "").strip() or uuid.uuid4().hex
    raw_scope_rules = bundle.get("scope_rules")
    scope_rules: dict[str, Any] = raw_scope_rules if isinstance(raw_scope_rules, dict) else {}
    raw_methods = scope_rules.get("allowed_methods")
    allowed_methods: list[str] = (
        [str(m) for m in raw_methods if isinstance(m, str) and m.strip()]
        if isinstance(raw_methods, list) and raw_methods
        else ["GET"]
    )
    discovery_hints = [str(item) for item in (bundle.get("discovery") or []) if isinstance(item, str) and item.strip()]
    accounts = select_representative_accounts(
        bundle.get("test_accounts") or [],
        max_members=max_member_accounts,
        max_admins=max_admin_accounts,
    )

    auth = authorize_provider(
        provider_config,
        model=model,
        worker_model=worker_model,
        execute=execute,
        authorize_live_provider=authorize_live_provider,
        live_authorization_reason=live_authorization_reason,
        api_key_env=api_key_env,
    )
    models = auth["models"]
    provider = llm_config.provider_settings(provider_config, models)
    limits = {
        "http_requests_per_seed": int(http_budget),
        "llm_tokens_per_seed": int(token_budget),
        "seconds_per_seed": int(seconds_budget),
    }

    output = Path(output_dir).expanduser().resolve()
    output.mkdir(parents=True, exist_ok=True)
    if not execute:
        plan_path = output / "external-plan.json"
        plan = {
            "schema": SCHEMA,
            "mode": "plan_only",
            "target": base,
            "models": models,
            "provider_kind": auth["provider_kind"],
            "provider_host": auth["provider_host"],
            "allowed_methods": allowed_methods,
            "discovery_hints": discovery_hints,
            "selected_accounts": [
                {"alias": row["alias"], "tenant": row.get("tenant", ""), "role": row.get("role", "")}
                for row in accounts
            ],
            "limits": limits,
            "llm_calls": 0,
            "target_requests": 0,
        }
        dump(plan_path, plan)
        return plan_path, plan

    env_name = api_key_env or provider.get("api_key_env", "")
    api_key = os.environ.get(env_name, "")
    if not api_key and auth["provider_kind"] == "remote":
        raise PermissionError("provider credentials are missing in environment")

    started = time.monotonic()
    directory = Path(tempfile.mkdtemp(prefix="external-python-", dir=output))
    private, workdir = directory / "private", directory / "solver"
    private.mkdir(mode=0o700)
    workdir.mkdir(mode=0o700)
    home = private / "state"
    home.mkdir(mode=0o700)
    (home / "validations").mkdir(mode=0o700)

    budget = SharedBudget(
        http=limits["http_requests_per_seed"],
        tokens=limits["llm_tokens_per_seed"],
        seconds=limits["seconds_per_seed"],
    )
    runtime_policy = PythonRuntimePolicy(budget, phase_call_limits={"enum": 36, "access": 120})

    stage_root = directory / "_staging"
    stage_root.mkdir(mode=0o700)
    snapshot = preflight.prepare_python_runtime(stage_root, models, Path(provider_config))
    prepared = {
        "manifest": {"runtime_snapshot": {"index_sha256": snapshot["index_sha256"]}},
        "manifest_path": str(directory / "external-contract.json"),
        "contract": {"solver_mode": "python_loop", "models": models, "limits": limits},
        "runtime": Path(snapshot["path"]),
    }
    runtime, index = launcher.stage_python_runtime(prepared, directory, base)
    scope, policy = external_policy_config(
        base,
        allowed_methods=allowed_methods,
        max_seconds=limits["seconds_per_seed"],
        max_requests=limits["http_requests_per_seed"],
    )
    runtime.chmod(0o700)
    codex_dir = runtime / ".codex"
    codex_dir.chmod(0o700)
    for fname, payload in (("scope.json", scope), ("program-policy.json", policy)):
        p = codex_dir / fname
        if p.exists():
            p.chmod(0o600)
        dump(p, payload)
        p.chmod(0o444)
    codex_dir.chmod(0o555)
    runtime.chmod(0o555)
    policy_path = home / "holdout-program-policy.json"
    dump(policy_path, policy)
    policy_path.chmod(0o600)

    signed_in = sign_in_accounts(
        base,
        accounts,
        login_path=login_path,
        session_check_path=session_check_path,
    )
    specs = launcher.bootstrap_plan(base, workdir, solver_mode="python_loop")
    for spec in specs:
        if spec.phase == "enum":
            spec.max_calls = max(spec.max_calls, 30)
            if discovery_hints and spec.steps:
                hint_text = ", ".join(discovery_hints)
                spec.steps[0].command = f"{spec.steps[0].command}; include discovery hints: {hint_text}"
        elif spec.phase == "access":
            spec.max_calls = max(spec.max_calls, 30)
            for tool_name in (
                "validator_validate_field_binding",
                "validator_validate_access_control",
                "validator_validate_xss_reflection",
                "validator_validate_open_redirect",
                "validator_validate_sqli",
            ):
                if tool_name not in spec.tools:
                    spec.tools.append(tool_name)
    (workdir / "specs.json").write_text(dump_specs(specs), encoding="utf-8")

    manifest: dict[str, Any] = {
        "schema": SCHEMA,
        "status": "starting",
        "qa_mode": qa_mode,
        "run_id": eff_run_id,
        "target": base,
        "models": models,
        "provider_kind": auth["provider_kind"],
        "allowed_methods": allowed_methods,
        "runtime_index": str(index),
        "runtime_index_sha256": preflight.sha256(index),
        "llm_calls": 0,
        "target_requests": 0,
    }
    manifest_path = directory / "launch.json"
    dump(manifest_path, manifest)

    broker: PythonBroker | None = None
    try:
        with launcher.host_environment(home, workdir, runtime):
            engine = PolicyEngine(
                cco_home=str(home),
                repo_root=str(runtime),
                scope_file=str(runtime / ".codex/scope.json"),
                program_policy_file=str(policy_path),
            )
            mcp_permissions = {f"{group}_{tool}": "allow" for group, names in CATALOG.items() for tool in names}
            dump(home / "permissions.json", {"default": "deny", "tools": mcp_permissions})
            for group, names in CATALOG.items():
                for tool in names:
                    engine.grant_approval(
                        f"{group}_{tool}",
                        "127.0.0.1",
                        ttl_seconds=limits["seconds_per_seed"],
                        reason="external owned loopback target session",
                    )
            prepare_trust()
            resolved_att: Any = write_isolation_attestation
            if isinstance(resolved_att, Path):
                resolved_att = str(resolved_att)
            elif (
                resolved_att is None
                and auto_issue_write_isolation
                and any(m.upper() in {"POST", "PUT", "PATCH"} for m in allowed_methods)
            ):
                resolved_att = write_isolation.issue_attestation(
                    base,
                    eff_run_id,
                    ttl_seconds=float(limits["seconds_per_seed"]),
                )
            external_config = {
                "target": base,
                "run_id": eff_run_id,
                "qa_mode": qa_mode,
                "qa_policy": qa_policy_doc,
                "allowed_methods": allowed_methods,
                "discovery_hints": discovery_hints,
                "login_path": login_path,
                "session_check_path": session_check_path,
                "write_isolation": resolved_att,
                "actors": {
                    alias: {
                        "alias": alias,
                        "role": info["role"],
                        "app_role": info["app_role"],
                        "tenant": info["tenant"],
                        "identifiers": info.get("identifiers", [alias]),
                    }
                    for alias, info in signed_in.items()
                },
            }
            broker = PythonBroker(
                budget=budget,
                engine=engine,
                executor=LocalMCPExecutor(home),
                workdir=workdir,
                private=private,
                provider=provider["url"],
                models=provider["models"],
                api_key=api_key,
                api_key_header=provider.get("api_key_header", "Authorization"),
            )
            try:
                with (private / "setup.log").open("w", encoding="utf-8") as log, redirect_stdout(log), redirect_stderr(log):
                    broker.load_catalog(home)
                    bindings = provision_external_sessions(
                        broker,
                        signed_in,
                        base,
                        home,
                        verify_checks="all",
                    )
                broker.tasks = TaskRegistry(specs, workdir, bindings, setup_checks_passed=False)
                broker.runtime_policy = runtime_policy
                dump(private / "runtime-policy.json", broker.runtime_policy.snapshot())
                dump(private / "task-specs.json", [spec.to_dict() for spec in broker.tasks.specs])
                solver = PythonSolver(broker, model=models["worker"].split("/", 1)[1], external_config=external_config)
                manifest.update(solver.run())
                manifest["schema"] = SCHEMA
            finally:
                broker.close()
    except KeyboardInterrupt:
        manifest["status"] = "interrupted"
    except Exception as exc:
        manifest.update(status="launch_failed", error=type(exc).__name__, error_detail=str(exc)[:300])
    finally:
        shutil.rmtree(stage_root, ignore_errors=True)
        findings = _collect_external_findings(private, workdir)
        probable_findings = _collect_probable_findings(private, workdir)
        dump(directory / "external-findings.json", findings)
        dump(directory / "probable-findings.json", probable_findings)
        snap = budget.snapshot()
        manifest.update(
            budget=snap,
            llm_calls=broker.calls if broker else 0,
            target_requests=snap["used"]["http"],
            findings_count=len(findings),
            findings_artifact=str(directory / "external-findings.json"),
            probable_findings_count=len(probable_findings),
            probable_findings_artifact=str(directory / "probable-findings.json"),
            wall_clock_seconds=time.monotonic() - started,
        )
        dump(private / "budget.json", snap)
        dump(manifest_path, manifest)
        dump(directory / "manifest.json", manifest)
    return manifest_path, manifest


def main(argv: list[str] | None = None) -> int:
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--target", default="", help="Owned loopback target origin http://127.0.0.1:<port>/")
    parser.add_argument("--credentials-file", type=Path, default=None, help="Optional operator credentials JSON")
    parser.add_argument("--provider-config", type=Path, default=llm_config.default_config())
    parser.add_argument("--model", default="")
    parser.add_argument("--worker-model", default="")
    parser.add_argument("--api-key-env", default=None)
    parser.add_argument("--output-dir", type=Path, required=True)
    parser.add_argument("--http-budget", type=int, default=550)
    parser.add_argument("--token-budget", type=int, default=180_000)
    parser.add_argument("--seconds-budget", type=int, default=900)
    parser.add_argument("--login-path", default="/api/v1/access/sign-in")
    parser.add_argument("--session-check-path", default="/api/v1/access/session")
    parser.add_argument("--max-member-accounts", type=int, default=6)
    parser.add_argument("--max-admin-accounts", type=int, default=2)
    parser.add_argument("--qa-policy", type=Path, default=None, help="Optional qa-expectation-policy/1 JSON")
    parser.add_argument("--write-isolation-attestation", default=None, help="Optional write-isolation attestation path or JSON")
    parser.add_argument("--no-auto-write-isolation", action="store_true", help="Disable automatic host write-isolation attestation issuance")
    parser.add_argument("--run-id", default="", help="Optional explicit run ID")
    parser.add_argument("--execute", action="store_true")
    parser.add_argument("--authorize-live-provider", action="store_true")
    parser.add_argument("--live-authorization-reason", default="")
    args = parser.parse_args(argv)
    path, doc = run_external_target(
        target=args.target,
        credentials_file=args.credentials_file,
        provider_config=args.provider_config,
        model=args.model,
        worker_model=args.worker_model,
        api_key_env=args.api_key_env,
        output_dir=args.output_dir,
        http_budget=args.http_budget,
        token_budget=args.token_budget,
        seconds_budget=args.seconds_budget,
        login_path=args.login_path,
        session_check_path=args.session_check_path,
        max_member_accounts=args.max_member_accounts,
        max_admin_accounts=args.max_admin_accounts,
        qa_policy=args.qa_policy,
        write_isolation_attestation=args.write_isolation_attestation,
        auto_issue_write_isolation=not args.no_auto_write_isolation,
        run_id=args.run_id,
        execute=args.execute,
        authorize_live_provider=args.authorize_live_provider,
        live_authorization_reason=args.live_authorization_reason,
    )
    print(json.dumps({
        "artifact": str(path),
        "mode": doc.get("mode"),
        "qa_mode": doc.get("qa_mode"),
        "status": doc.get("status"),
        "target": doc.get("target"),
        "llm_calls": doc.get("llm_calls"),
        "target_requests": doc.get("target_requests"),
        "findings_count": doc.get("findings_count"),
        "probable_findings_count": doc.get("probable_findings_count"),
        "verdict_ledger": doc.get("verdict_ledger"),
    }))
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
