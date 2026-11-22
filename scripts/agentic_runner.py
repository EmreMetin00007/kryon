#!/usr/bin/env python3
"""Launch the general-purpose AgenticInvestigator against an owned loopback target."""
from __future__ import annotations

import argparse
import json
import os
from pathlib import Path
import sys
import time
from typing import Any, Sequence
import uuid

SCRIPTS = Path(__file__).resolve().parent
_REPO_ROOT = SCRIPTS.parent
for _p in (str(_REPO_ROOT), str(SCRIPTS)):
    if _p not in sys.path:
        sys.path.insert(0, _p)

import agentic_auth_import  # noqa: E402
import agentic_report  # noqa: E402
import agentic_seed  # noqa: E402
import agentic_vault  # noqa: E402
import llm_config  # noqa: E402
import target_bootstrap  # noqa: E402
from provider_auth import authorize_provider  # noqa: E402
from agentic_http import ActorManager, AgenticHTTPClient  # noqa: E402
from agentic_investigator import (  # noqa: E402
    _EPOCH_HARD_CHAR_LIMIT,
    _PROMPT_HARD_CHAR_LIMIT,
    AgenticInvestigator,
)
from agentic_receipts import ReceiptStore  # noqa: E402
from agentic_tools import canonicalize_and_deduplicate_findings  # noqa: E402
from full_agent_budget import SharedBudget  # noqa: E402
from full_agent_provider import MeteredProviderTransport, SessionGate, dump  # noqa: E402

SCHEMA = "agentic-target-run/1"


def _parse_bool_flag(raw: Any) -> bool:
    val = str(raw).strip().lower()
    if val in {"1", "true", "yes", "on"}:
        return True
    if val in {"0", "false", "no", "off"}:
        return False
    raise argparse.ArgumentTypeError(f"invalid boolean flag value: {raw!r}; expected true|false")


def _parse_allowed_methods(
    cli_methods: Sequence[str] | None,
    scope_rules: dict[str, Any],
) -> list[str]:
    if cli_methods:
        parsed: list[str] = []
        for item in cli_methods:
            for part in str(item).split(","):
                clean = part.strip().upper()
                if clean and clean not in parsed:
                    parsed.append(clean)
        if parsed:
            return parsed
    raw = scope_rules.get("allowed_methods")
    if isinstance(raw, list) and raw:
        cleaned = [str(m).strip().upper() for m in raw if isinstance(m, str) and m.strip()]
        if cleaned:
            return cleaned
    return ["GET"]


def run_agentic_target(
    *,
    target: str = "",
    credentials_file: Path | None = None,
    provider_config: Path = llm_config.default_config(),
    model: str = "",
    worker_model: str = "",
    scout_model: str = "",
    scout_turns: int = 22,
    scout_token_share: float = 0.40,
    api_key_env: str | None = None,
    output_dir: Path,
    http_budget: int | None = None,
    token_budget: int = 1_000_000,
    seconds_budget: int = 900,
    allowed_methods: Sequence[str] | None = None,
    discovery_hints: Sequence[str] | None = None,
    login_path: str = "/api/v1/access/sign-in",
    session_check_path: str = "/api/v1/access/session",
    max_member_accounts: int = 6,
    max_admin_accounts: int = 2,
    max_turns: int = 75,
    reasoning_effort: str = "low",
    resume: bool = False,
    run_id: str = "",
    execute: bool = False,
    authorize_live_provider: bool = False,
    live_authorization_reason: str = "",
    use_bsag: bool = False,
    scheduler: str = "prompt_only",
    verification_gate: str = "differential",
    intervention: str = "off",
    execution_mode: str = "monolithic",
    max_shards: int = 3,
    bootstrap_turns: int = 12,
    shard_turns: int = 25,
    shard_token_quota: int = 0,
    bootstrap_model: str = "",
    epoch_char_limit: int = 0,
    cache_token_weight: float = 0.10,
    scope_file: Path | None = None,
    allow_non_loopback: bool = False,
    max_degradation_streak: int = 5,
    vault_home: Path | None = None,
    vault_key_name: str = "",
    storage_states: Sequence[str] | None = None,
    seed_surface_files: Sequence[Path] | None = None,
    tech_hints: Sequence[str] | None = None,
) -> tuple[Path, dict[str, Any]]:
    """Run (or plan when execute=False) AgenticInvestigator against an authorized target."""
    if isinstance(cache_token_weight, bool):
        raise ValueError("cache_token_weight must be between 0.0 and 1.0")
    eff_cache_weight = float(cache_token_weight)
    if not (0.0 <= eff_cache_weight <= 1.0):
        raise ValueError(f"cache_token_weight must be between 0.0 and 1.0, got {cache_token_weight!r}")
    vault_storage_payload: dict[str, Any] | None = None
    if credentials_file is not None:
        bundle = target_bootstrap.load_credentials_bundle(credentials_file)
    elif vault_home is not None and str(vault_key_name or "").strip():
        loaded_vault = agentic_vault.load_vault_credentials(vault_home, str(vault_key_name).strip())
        if loaded_vault.get("schema") == "agentic-vault-storage-state/1":
            vault_storage_payload = loaded_vault
            bundle = {"target_url": loaded_vault.get("target_url") or ""}
        else:
            bundle = loaded_vault
    else:
        bundle = {}
    base, scope_meta = target_bootstrap.resolve_target_origin(
        target or str(bundle.get("target_url") or ""),
        scope_file=scope_file,
        allow_non_loopback=bool(allow_non_loopback),
    )
    eff_excluded_paths = list(scope_meta.get("excluded_paths") or [])
    eff_run_id = str(run_id or bundle.get("run_id") or "").strip() or uuid.uuid4().hex
    raw_scope = bundle.get("scope_rules")
    scope_rules: dict[str, Any] = raw_scope if isinstance(raw_scope, dict) else {}
    eff_methods = _parse_allowed_methods(allowed_methods, scope_rules)
    bundle_max_req = scope_rules.get("max_requests")
    eff_http_budget = int(
        http_budget
        if http_budget is not None
        else (bundle_max_req if isinstance(bundle_max_req, int) and bundle_max_req > 0 else 300)
    )
    eff_discovery_hints = [
        str(item).strip()
        for item in (discovery_hints if discovery_hints else (bundle.get("discovery") or []))
        if isinstance(item, str) and str(item).strip()
    ] or ["/"]
    seed_data: dict[str, Any] | None = None
    if seed_surface_files:
        seed_data = agentic_seed.load_seed_surface_files(
            seed_surface_files,
            base_url=base,
            excluded_paths=eff_excluded_paths,
        )
        for hint in seed_data.get("discovery_hints") or []:
            if hint not in eff_discovery_hints:
                eff_discovery_hints.append(hint)
    if tech_hints:
        eff_discovery_hints = agentic_seed.enrich_tech_discovery_hints(
            tech_hints,
            existing_hints=eff_discovery_hints,
        )
    accounts = target_bootstrap.select_representative_accounts(
        bundle.get("test_accounts") or [],
        max_members=max_member_accounts,
        max_admins=max_admin_accounts,
    )
    if vault_storage_payload is not None:
        accounts.append(
            agentic_auth_import.load_storage_state_actor(
                vault_storage_payload.get("storage_state") or {},
                base_url=base,
                alias=str(vault_storage_payload.get("alias") or "browser-user"),
                role=str(vault_storage_payload.get("role") or "member"),
                tenant=str(vault_storage_payload.get("tenant") or ""),
            )
        )
    for raw_spec in storage_states or ():
        s_alias, s_role, s_tenant, s_path = agentic_auth_import.parse_storage_state_spec(str(raw_spec))
        accounts.append(
            agentic_auth_import.load_storage_state_actor(
                s_path,
                base_url=base,
                alias=s_alias,
                role=s_role,
                tenant=s_tenant,
            )
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
    eff_scout_model = str(scout_model or "").strip()
    scout_model_id = ""
    if eff_scout_model:
        scout_sel = llm_config.model_selection(provider_config, model=models["worker"], worker_model=eff_scout_model)
        scout_provider = llm_config.provider_settings(provider_config, scout_sel)
        provider["models"] = set(provider["models"]) | set(scout_provider["models"])
        models = {**models, "scout": scout_sel["worker"]}
        scout_model_id = scout_sel["worker"].split("/", 1)[1]
    eff_bootstrap_model = str(bootstrap_model or "").strip()
    bootstrap_model_id = ""
    if eff_bootstrap_model:
        boot_sel = llm_config.model_selection(provider_config, model=models["worker"], worker_model=eff_bootstrap_model)
        boot_provider = llm_config.provider_settings(provider_config, boot_sel)
        provider["models"] = set(provider["models"]) | set(boot_provider["models"])
        models = {**models, "bootstrap": boot_sel["worker"]}
        bootstrap_model_id = boot_sel["worker"].split("/", 1)[1]

    raw_epoch_limit = int(epoch_char_limit)
    eff_epoch_char_limit = max(
        _PROMPT_HARD_CHAR_LIMIT,
        _EPOCH_HARD_CHAR_LIMIT if raw_epoch_limit <= 0 else raw_epoch_limit,
    )

    output = Path(output_dir).expanduser().resolve()
    output.mkdir(parents=True, exist_ok=True)
    limits = {
        "http_requests": eff_http_budget,
        "llm_tokens": int(token_budget),
        "seconds": int(seconds_budget),
        "max_turns": int(max_turns),
        "epoch_char_limit": eff_epoch_char_limit,
        "cache_token_weight": eff_cache_weight,
    }

    ablation_cfg = {
        "use_bsag": bool(use_bsag),
        "scheduler": str(scheduler or "ucb").strip().lower(),
        "verification_gate": str(verification_gate or "differential").strip().lower(),
        "intervention": str(intervention or "lazy").strip().lower(),
        "execution_mode": str(execution_mode or "ephemeral").strip().lower(),
    }
    sharding_cfg: dict[str, Any] = {
        "max_shards": max(1, int(max_shards)),
        "bootstrap_turns": max(1, int(bootstrap_turns)),
        "shard_turns": max(1, int(shard_turns)),
    }
    eff_shard_token_quota = max(0, int(shard_token_quota))
    if eff_shard_token_quota > 0:
        sharding_cfg["shard_token_quota"] = eff_shard_token_quota
    if eff_bootstrap_model:
        sharding_cfg["bootstrap_model"] = models["bootstrap"]

    if not execute:
        plan_path = output / "agentic-plan.json"
        plan = {
            "schema": SCHEMA,
            "mode": "plan_only",
            "target": base,
            "scope": {
                "loopback_only": bool(scope_meta.get("loopback_only", True)),
                "scope_file": scope_meta.get("scope_file"),
                "excluded_paths_count": len(eff_excluded_paths),
                "max_degradation_streak": max(0, int(max_degradation_streak)),
            },
            "run_id": eff_run_id,
            "models": models,
            "provider_kind": auth["provider_kind"],
            "provider_host": auth["provider_host"],
            "allowed_methods": eff_methods,
            "discovery_hints": eff_discovery_hints,
            "seed_surface": dict(seed_data.get("stats") or {}) if seed_data is not None else None,
            "ablation": ablation_cfg,
            "sharding": sharding_cfg,
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
    private_dir = output / "private"
    private_dir.mkdir(mode=0o700, parents=True, exist_ok=True)

    budget = SharedBudget(
        http=eff_http_budget,
        tokens=int(token_budget),
        seconds=int(seconds_budget),
    )
    session_gate = SessionGate()
    transport = MeteredProviderTransport(
        budget=budget,
        private=private_dir,
        provider=provider["url"],
        models=provider["models"],
        api_key=api_key,
        api_key_header=provider.get("api_key_header", "Authorization"),
        session_gate=session_gate,
        provider_options=provider.get("provider_options"),
        cache_token_weight=eff_cache_weight,
    )
    receipt_store = ReceiptStore(output)
    actors = ActorManager(
        accounts,
        login_path=login_path,
        session_check_path=session_check_path,
    )
    http_client = AgenticHTTPClient(
        base_url=base,
        receipt_store=receipt_store,
        actors=actors,
        allowed_methods=eff_methods,
        max_requests=eff_http_budget,
        excluded_paths=eff_excluded_paths,
        max_degradation_streak=max(0, int(max_degradation_streak)),
    )

    scope_summary = {
        "loopback_only": bool(scope_meta.get("loopback_only", True)),
        "scope_file": scope_meta.get("scope_file"),
        "excluded_paths_count": len(eff_excluded_paths),
        "max_degradation_streak": max(0, int(max_degradation_streak)),
    }
    manifest: dict[str, Any] = {
        "schema": SCHEMA,
        "mode": "agentic",
        "status": "starting",
        "run_id": eff_run_id,
        "target": base,
        "scope": scope_summary,
        "models": models,
        "provider_kind": auth["provider_kind"],
        "allowed_methods": eff_methods,
        "discovery_hints": eff_discovery_hints,
        "seed_surface": dict(seed_data.get("stats") or {}) if seed_data is not None else None,
        "ablation": ablation_cfg,
        "sharding": sharding_cfg,
        "limits": limits,
    }
    manifest_path = output / "manifest.json"
    dump(manifest_path, manifest)

    investigator: AgenticInvestigator | None = None
    try:
        worker_model_id = models["worker"].split("/", 1)[1]
        investigator = AgenticInvestigator(
            http_client=http_client,
            receipt_store=receipt_store,
            transport=transport,
            budget=budget,
            model=worker_model_id,
            root_dir=output,
            discovery_hints=eff_discovery_hints,
            max_turns=max_turns,
            reasoning_effort=reasoning_effort,
            use_bsag=ablation_cfg["use_bsag"],
            scheduler_mode=ablation_cfg["scheduler"],
            verification_gate=ablation_cfg["verification_gate"],
            intervention_mode=ablation_cfg["intervention"],
            execution_mode=ablation_cfg["execution_mode"],
            enable_telemetry=True,
            scout_model=scout_model_id or None,
            scout_max_turns=scout_turns,
            scout_token_share=scout_token_share,
            max_shards=sharding_cfg["max_shards"],
            bootstrap_turns=sharding_cfg["bootstrap_turns"],
            shard_turns=sharding_cfg["shard_turns"],
            shard_token_quota=eff_shard_token_quota,
            bootstrap_model=bootstrap_model_id or None,
            epoch_char_limit=eff_epoch_char_limit,
            cache_token_weight=eff_cache_weight,
            seed_surface=seed_data,
        )
        run_info = investigator.run(resume=resume)
        manifest.update(run_info)
    except KeyboardInterrupt:
        manifest["status"] = "interrupted"
    except Exception as exc:
        manifest.update(status="failed", error=type(exc).__name__, error_detail=str(exc)[:300])
    finally:
        http_client.close()
        transport.close_upstream()
        findings_file = output / "findings.json"
        if not findings_file.is_file():
            dump(findings_file, [])
        try:
            findings_list = json.loads(findings_file.read_text(encoding="utf-8"))
        except (OSError, ValueError):
            findings_list = []
        if isinstance(findings_list, list) and findings_list:
            actor_meta_map = {
                row["alias"]: {
                    "alias": row["alias"],
                    "role": str(row.get("role") or "").lower(),
                    "tenant": str(row.get("tenant") or "").lower(),
                }
                for row in actors.summaries()
            }
            findings_list = canonicalize_and_deduplicate_findings(
                findings_list,
                actor_meta_map=actor_meta_map,
                receipt_store=receipt_store,
            )
            dump(findings_file, findings_list)
        snap = budget.snapshot()
        if investigator is not None:
            if isinstance(findings_list, list):
                investigator.dispatcher.findings = findings_list
            m_json, m_md, metrics_doc = investigator.write_metrics()
            manifest["process_metrics_json"] = str(m_json)
            manifest["process_metrics_md"] = str(m_md)
            manifest["process_metrics"] = metrics_doc
        manifest.update(
            budget=snap,
            llm_calls=transport.calls,
            target_requests=http_client.budget.used,
            findings_count=len(findings_list) if isinstance(findings_list, list) else 0,
            findings_artifact=str(findings_file),
            receipts_dir=str(receipt_store.receipts_dir),
            wall_clock_seconds=round(time.monotonic() - started, 2),
        )
        dump(private_dir / "budget.json", snap)
        dump(manifest_path, manifest)
        dump(output / "launch.json", manifest)
        try:
            rep = agentic_report.generate_run_reports(output)
            if rep.get("markdown_path"):
                manifest["report_md"] = rep["markdown_path"]
            if rep.get("sarif_path"):
                manifest["report_sarif"] = rep["sarif_path"]
        except Exception as report_exc:
            manifest["report_error"] = type(report_exc).__name__
        dump(manifest_path, manifest)
        dump(output / "launch.json", manifest)
    return manifest_path, manifest


def main(argv: list[str] | None = None) -> int:
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--target", default="", help="Owned loopback target origin http://127.0.0.1:<port>/")
    parser.add_argument("--credentials-file", "--credentials", dest="credentials_file", type=Path, default=None)
    parser.add_argument("--provider-config", type=Path, default=llm_config.default_config())
    parser.add_argument("--model", default="")
    parser.add_argument("--worker-model", default="")
    parser.add_argument("--scout-model", default="", help="Optional Phase 1 scout model (same provider) for 2-phase handoff")
    parser.add_argument("--scout-turns", type=int, default=22, help="Max Phase 1 scout turns before handoff")
    parser.add_argument("--scout-token-share", type=float, default=0.40, help="Max token budget fraction for Phase 1 scout")
    parser.add_argument("--api-key-env", default=None)
    parser.add_argument("--output-dir", "--output", dest="output_dir", type=Path, required=True)
    parser.add_argument("--http-budget", "--max-requests", dest="http_budget", type=int, default=None)
    parser.add_argument("--token-budget", type=int, default=1_000_000)
    parser.add_argument("--seconds-budget", type=int, default=900)
    parser.add_argument("--allowed-methods", action="append", default=None, help="Allowed HTTP methods (e.g. GET,POST,PUT)")
    parser.add_argument("--discovery-hint", action="append", dest="discovery_hints", default=None, help="Initial discovery entry path(s)")
    parser.add_argument("--login-path", default="/api/v1/access/sign-in")
    parser.add_argument("--session-check-path", default="/api/v1/access/session")
    parser.add_argument("--max-member-accounts", type=int, default=6)
    parser.add_argument("--max-admin-accounts", type=int, default=2)
    parser.add_argument("--max-turns", type=int, default=75)
    parser.add_argument("--reasoning-effort", default="low")
    parser.add_argument("--resume", action="store_true")
    parser.add_argument("--run-id", default="")
    parser.add_argument("--execute", action="store_true")
    parser.add_argument("--authorize-live-provider", action="store_true")
    parser.add_argument("--live-authorization-reason", default="")
    parser.add_argument("--use-bsag", type=_parse_bool_flag, default=False, help="Enable external BSAG (true|false)")
    parser.add_argument("--scheduler", choices=["ucb", "prompt_only", "round_robin"], default="prompt_only")
    parser.add_argument("--verification-gate", choices=["differential", "llm_self_judge"], default="differential")
    parser.add_argument("--intervention", choices=["lazy", "always_on", "off"], default="off")
    parser.add_argument("--execution-mode", choices=["ephemeral", "monolithic", "sharded"], default="monolithic")
    parser.add_argument("--max-shards", type=int, default=3, help="Max subsystem shards for sharded mode")
    parser.add_argument("--bootstrap-turns", type=int, default=12, help="Stage 1 bootstrap turns for sharded mode")
    parser.add_argument("--shard-turns", type=int, default=25, help="Stage 2 per-shard turn budget for sharded mode")
    parser.add_argument(
        "--shard-token-quota",
        type=int,
        default=0,
        help="Optional per-shard soft token quota for sharded mode (0 = auto-balanced from remaining tokens)",
    )
    parser.add_argument(
        "--bootstrap-model",
        default="",
        help="Optional Stage 1 discovery-only bootstrap model (same provider) for sharded mode",
    )
    parser.add_argument(
        "--epoch-char-limit",
        type=int,
        default=0,
        help="Optional per-epoch serialized byte limit before advancing epoch (0 = default 80000)",
    )
    parser.add_argument(
        "--cache-token-weight",
        type=float,
        default=0.10,
        help="Effective token weight in [0.0, 1.0] for cached prompt tokens (default: 0.10)",
    )
    parser.add_argument(
        "--scope-file",
        type=Path,
        default=None,
        help="Optional explicit scope.json file (required when --allow-non-loopback is set)",
    )
    parser.add_argument(
        "--allow-non-loopback",
        action="store_true",
        help="Allow non-loopback http(s) target origin explicitly verified by --scope-file",
    )
    parser.add_argument(
        "--max-degradation-streak",
        type=int,
        default=5,
        help="Stop gracefully after N consecutive 429/502/503/504 responses (0 disables, default: 5)",
    )
    parser.add_argument(
        "--vault-home",
        type=Path,
        default=None,
        help="Optional CredentialVault directory for encrypted credential bundle lookup",
    )
    parser.add_argument(
        "--vault-key-name",
        default="",
        help="Credential bundle key name inside --vault-home",
    )
    parser.add_argument(
        "--storage-state",
        action="append",
        dest="storage_states",
        default=None,
        help="Playwright storage_state.json spec (alias=/path or alias:role:tenant=/path); repeatable",
    )
    parser.add_argument(
        "--seed-surface",
        action="append",
        dest="seed_surface_files",
        type=Path,
        default=None,
        help="Offline discovery seed file (HAR/mitm_scope/ZAP/ffuf/nuclei/URL list); repeatable",
    )
    parser.add_argument(
        "--tech-hint",
        action="append",
        dest="tech_hints",
        default=None,
        help="Optional technology stack hint (e.g. nextjs, django, spring) to enrich initial discovery paths",
    )
    args = parser.parse_args(argv)
    if not (0.0 <= float(args.cache_token_weight) <= 1.0):
        parser.error("--cache-token-weight must be between 0.0 and 1.0")

    path, doc = run_agentic_target(
        target=args.target,
        credentials_file=args.credentials_file,
        provider_config=args.provider_config,
        model=args.model,
        worker_model=args.worker_model,
        scout_model=args.scout_model,
        scout_turns=args.scout_turns,
        scout_token_share=args.scout_token_share,
        api_key_env=args.api_key_env,
        output_dir=args.output_dir,
        http_budget=args.http_budget,
        token_budget=args.token_budget,
        seconds_budget=args.seconds_budget,
        allowed_methods=args.allowed_methods,
        discovery_hints=args.discovery_hints,
        login_path=args.login_path,
        session_check_path=args.session_check_path,
        max_member_accounts=args.max_member_accounts,
        max_admin_accounts=args.max_admin_accounts,
        max_turns=args.max_turns,
        reasoning_effort=args.reasoning_effort,
        resume=args.resume,
        run_id=args.run_id,
        execute=args.execute,
        authorize_live_provider=args.authorize_live_provider,
        live_authorization_reason=args.live_authorization_reason,
        use_bsag=args.use_bsag,
        scheduler=args.scheduler,
        verification_gate=args.verification_gate,
        intervention=args.intervention,
        execution_mode=args.execution_mode,
        max_shards=args.max_shards,
        bootstrap_turns=args.bootstrap_turns,
        shard_turns=args.shard_turns,
        shard_token_quota=args.shard_token_quota,
        bootstrap_model=args.bootstrap_model,
        epoch_char_limit=args.epoch_char_limit,
        cache_token_weight=args.cache_token_weight,
        scope_file=args.scope_file,
        allow_non_loopback=args.allow_non_loopback,
        max_degradation_streak=args.max_degradation_streak,
        vault_home=args.vault_home,
        vault_key_name=args.vault_key_name,
        storage_states=args.storage_states,
        seed_surface_files=args.seed_surface_files,
        tech_hints=args.tech_hints,
    )
    print(json.dumps({
        "artifact": str(path),
        "mode": doc.get("mode"),
        "status": doc.get("status"),
        "target": doc.get("target"),
        "llm_calls": doc.get("llm_calls"),
        "target_requests": doc.get("target_requests"),
        "findings_count": doc.get("findings_count"),
        "findings_artifact": doc.get("findings_artifact"),
    }))
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
