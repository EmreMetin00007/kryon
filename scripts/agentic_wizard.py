#!/usr/bin/env python3
"""Interactive zero-flag launcher (`cco-agent start`) for Kryon."""
from __future__ import annotations

import argparse
from datetime import datetime, timezone
import json
import os
from pathlib import Path
import re
import sys
from typing import Any, Callable, Sequence
from urllib.parse import urlsplit

_SCRIPTS_DIR = Path(__file__).resolve().parent
_REPO_ROOT = _SCRIPTS_DIR.parent
for _p in (str(_REPO_ROOT), str(_SCRIPTS_DIR)):
    if _p not in sys.path:
        sys.path.insert(0, _p)

import agentic_presets  # noqa: E402
import agentic_runner  # noqa: E402
import llm_config  # noqa: E402
import target_bootstrap  # noqa: E402
from agentic_http import parse_custom_headers  # noqa: E402
from provider_auth import authorize_provider  # noqa: E402

_PRESET_MENU: tuple[tuple[str, str], ...] = (
    ("1", "quick"),
    ("2", "standard"),
    ("3", "bounty-safe"),
    ("4", "deep"),
)
_PRESET_BY_CHOICE: dict[str, str] = {
    **{num: name for num, name in _PRESET_MENU},
    **{name: name for _, name in _PRESET_MENU},
}
_SENSITIVE_HEADER_TOKENS: tuple[str, ...] = (
    "key",
    "token",
    "secret",
    "auth",
    "cookie",
    "pass",
    "credential",
)


def _default_workdir() -> Path:
    raw = os.environ.get("CCO_WORKDIR", "~/cco-work").strip() or "~/cco-work"
    return Path(raw).expanduser()


def _detect_default_scope_file(cwd: Path | None = None) -> Path | None:
    base = cwd or Path.cwd()
    for cand in (base / ".codex" / "scope.json", Path("~/.codex/data/scope.json").expanduser()):
        try:
            if cand.is_file() and not cand.is_symlink():
                return cand
        except OSError:
            continue
    return None


def _is_loopback_url(raw_url: str) -> bool:
    try:
        target_bootstrap.normalize_loopback_origin(raw_url)
        return True
    except ValueError:
        return False


def _default_output_dir(target_url: str, *, workdir: Path | None = None) -> Path:
    parsed = urlsplit(target_url)
    host = parsed.hostname or "target"
    slug = re.sub(r"[^A-Za-z0-9._-]+", "-", host).strip("-") or "target"
    stamp = datetime.now(timezone.utc).strftime("%Y%m%d-%H%M%S")
    root = workdir or _default_workdir()
    return root / f"{slug}-{stamp}"


def _classify_auth_file(raw_spec: str) -> tuple[str, str]:
    """Return ``('storage_state', spec)`` or ``('credentials_file', path)``."""
    text = raw_spec.strip()
    if "=" in text:
        alias_part, path_part = text.split("=", 1)
        if alias_part.strip() and path_part.strip():
            resolved = str(Path(path_part.strip()).expanduser())
            return "storage_state", f"{alias_part.strip()}={resolved}"
    path = Path(text).expanduser()
    if not path.is_file():
        raise ValueError(f"dosya bulunamadi: {path}")
    try:
        data = json.loads(path.read_text(encoding="utf-8"))
    except (OSError, ValueError) as exc:
        raise ValueError(f"gecersiz JSON dosyasi: {path}") from exc
    if isinstance(data, dict) and ("cookies" in data or "origins" in data):
        return "storage_state", f"member={path}"
    return "credentials_file", str(path)


def _is_yes(raw: str) -> bool:
    return str(raw or "").strip().lower() in {"e", "evet", "y", "yes"}


def _is_sensitive_header_name(name: str) -> bool:
    low = name.strip().lower()
    return any(tok in low for tok in _SENSITIVE_HEADER_TOKENS)


def _write_reusable_run_config(
    output_dir: Path,
    *,
    preset: str,
    target: str,
    provider_config: Path,
    scope_file: Path | None,
    allowed_methods: list[str] | None,
    custom_headers: dict[str, str],
    storage_states: list[str],
    credentials_file: Path | None,
) -> Path:
    """Save a safe ``cco-run/1`` config (chmod 0600, omitting sensitive header values)."""
    cfg: dict[str, Any] = {
        "schema": agentic_presets.RUN_CONFIG_SCHEMA,
        "preset": preset,
        "target": target,
        "provider_config": str(provider_config),
        "output_dir": str(output_dir),
    }
    if scope_file is not None:
        cfg["scope_file"] = str(scope_file)
    if allowed_methods:
        cfg["allowed_methods"] = list(allowed_methods)
    safe_headers = {k: v for k, v in custom_headers.items() if not _is_sensitive_header_name(k)}
    if safe_headers:
        cfg["custom_headers"] = safe_headers
    if storage_states:
        cfg["storage_states"] = list(storage_states)
    if credentials_file is not None:
        cfg["credentials_file"] = str(credentials_file)

    output_dir.mkdir(parents=True, exist_ok=True)
    cfg_path = output_dir / "run.json"
    cfg_path.write_text(json.dumps(cfg, indent=2, ensure_ascii=False) + "\n", encoding="utf-8")
    try:
        cfg_path.chmod(0o600)
    except OSError:
        pass
    return cfg_path


def run_wizard(
    *,
    provider_config: Path | None = None,
    input_fn: Callable[[str], str] = input,
    output_fn: Callable[[str], None] = print,
    runner_main: Callable[[list[str]], int] | None = None,
    workdir: Path | None = None,
    cwd: Path | None = None,
    environ: dict[str, str] | None = None,
) -> int:
    """Guide the operator through a zero-flag plan + optional confirmed live TUI run."""
    env_map = os.environ if environ is None else environ
    eff_provider_cfg = (provider_config or llm_config.default_config()).expanduser()
    try:
        models = llm_config.model_selection(eff_provider_cfg)
        provider_info = llm_config.provider_settings(eff_provider_cfg, models)
    except (ValueError, OSError, TypeError) as exc:
        output_fn(f"[HATA] LLM yapilandirmasi gecersiz ({eff_provider_cfg}): {type(exc).__name__}")
        return 2

    output_fn("=== Kryon Hizli Baslatici (cco-agent start) ===")
    output_fn(f"Aktif model: {models['worker']} | Saglayici: {provider_info['name']}")
    output_fn("")

    # 1. Target URL
    raw_target = ""
    while not raw_target:
        entered = input_fn("1) Hedef URL (orn. https://hedef.com veya http://127.0.0.1:8000): ").strip()
        if not entered:
            output_fn("   Hedef URL bos olamaz.")
            continue
        parsed = urlsplit(entered)
        if parsed.scheme not in {"http", "https"} or not parsed.netloc:
            output_fn("   Gecerli bir http:// veya https:// URL girin.")
            continue
        raw_target = entered

    loopback = _is_loopback_url(raw_target)

    # 2. Scope file (required if non-loopback; optional if loopback)
    detected_scope = _detect_default_scope_file(cwd=cwd)
    scope_file: Path | None = None
    if not loopback:
        while scope_file is None:
            hint = f" [{detected_scope}]" if detected_scope is not None else ""
            entered_scope = input_fn(f"2) Kapsam dosyasi (scope.json){hint}: ").strip()
            chosen = Path(entered_scope).expanduser() if entered_scope else detected_scope
            if chosen is None:
                output_fn("   Dis (non-loopback) hedefler icin scope.json zorunludur.")
                continue
            try:
                target_bootstrap.resolve_target_origin(raw_target, scope_file=chosen, allow_non_loopback=True)
                scope_file = chosen.resolve()
            except ValueError as exc:
                output_fn(f"   Kapsam hatasi: {exc}")
    else:
        hint = f" [Enter=atla, mevcut={detected_scope}]" if detected_scope is not None else " [Enter=atla]"
        entered_scope = input_fn(f"2) Kapsam dosyasi (opsiyonel){hint}: ").strip()
        if entered_scope:
            cand = Path(entered_scope).expanduser()
            try:
                target_bootstrap.resolve_target_origin(raw_target, scope_file=cand, allow_non_loopback=False)
                scope_file = cand.resolve()
            except ValueError as exc:
                output_fn(f"   Kapsam dosyasi gecersiz ({exc}), kapsam dosyasi olmadan devam ediliyor.")

    # 3. Preset selection
    output_fn("3) Profil secin:")
    for num, pname in _PRESET_MENU:
        desc = agentic_presets.PRESETS[pname]["description"]
        mark = " (varsayilan)" if pname == "bounty-safe" else ""
        output_fn(f"   {num}) {pname}{mark} - {desc}")
    preset = ""
    while not preset:
        choice = input_fn("   Secim [3]: ").strip().lower() or "3"
        if choice in _PRESET_BY_CHOICE:
            preset = _PRESET_BY_CHOICE[choice]
        else:
            output_fn("   1-4 arasi bir secim veya profil adi girin.")

    # 4. Allowed HTTP methods
    preset_opts = agentic_presets.get_preset_options(preset)
    default_methods = list(preset_opts.get("allowed_methods") or ["GET", "HEAD"])
    default_methods_str = ",".join(default_methods)
    methods_raw = input_fn(f"4) Izinli HTTP metotlari [{default_methods_str}] (yazma icin GET,HEAD,POST): ").strip()
    allowed_methods = (
        [m.strip().upper() for m in methods_raw.split(",") if m.strip()]
        if methods_raw
        else default_methods
    )

    # 5. Optional custom headers
    raw_custom_headers: list[str] = []
    output_fn("5) Ozel HTTP basliklari (orn. Pentest: Cyberbounty) - bitirmek icin bos Enter:")
    while True:
        hdr = input_fn("   Baslik (Ad: Deger) [bos=gec]: ").strip()
        if not hdr:
            break
        try:
            parse_custom_headers([hdr])
        except ValueError as exc:
            output_fn(f"   Gecersiz baslik: {exc}")
            continue
        raw_custom_headers.append(hdr)

    # 6. Optional test account / Playwright storage_state
    storage_states: list[str] = []
    credentials_file: Path | None = None
    while True:
        auth_raw = input_fn("6) Test hesabi (storage_state.json veya credentials.json yolu) [bos=anonim]: ").strip()
        if not auth_raw:
            break
        try:
            kind, value = _classify_auth_file(auth_raw)
        except ValueError as exc:
            output_fn(f"   {exc}")
            continue
        if kind == "storage_state":
            storage_states.append(value)
        else:
            credentials_file = Path(value)
        break

    # 7. Output directory
    default_out = _default_output_dir(raw_target, workdir=workdir)
    out_raw = input_fn(f"7) Cikti klasoru [{default_out}]: ").strip()
    output_dir = Path(out_raw).expanduser().resolve() if out_raw else default_out.resolve()

    parsed_headers = parse_custom_headers(raw_custom_headers)

    # Save reusable run.json & generate zero-traffic plan first
    cfg_path = _write_reusable_run_config(
        output_dir,
        preset=preset,
        target=raw_target,
        provider_config=eff_provider_cfg,
        scope_file=scope_file,
        allowed_methods=allowed_methods,
        custom_headers=parsed_headers,
        storage_states=storage_states,
        credentials_file=credentials_file,
    )

    plan_path, plan = agentic_runner.run_agentic_target(
        target=raw_target,
        provider_config=eff_provider_cfg,
        output_dir=output_dir,
        preset=preset,
        allowed_methods=allowed_methods,
        custom_headers=raw_custom_headers or None,
        scope_file=scope_file,
        allow_non_loopback=not loopback,
        storage_states=storage_states or None,
        credentials_file=credentials_file,
        execute=False,
    )

    auth_probe = authorize_provider(
        eff_provider_cfg,
        execute=False,
    )
    provider_kind = str(auth_probe.get("provider_kind") or "local")
    api_key_env = str(provider_info.get("api_key_env") or "")
    has_api_key = bool(env_map.get(api_key_env, "").strip()) if api_key_env else True

    output_fn("")
    output_fn("=== Plan Hazir (0 Ag Istegi) ===")
    output_fn(f"Hedef       : {plan.get('target')}")
    output_fn(f"Profil      : {plan.get('preset') or preset} ({plan.get('ablation', {}).get('execution_mode')})")
    output_fn(f"Model       : {plan.get('models', {}).get('worker')} ({provider_kind})")
    output_fn(f"Metotlar    : {', '.join(plan.get('allowed_methods') or [])}")
    hdr_names = plan.get("request_headers") or []
    output_fn(f"Basliklar   : {', '.join(hdr_names) if hdr_names else '(yok)'}")
    output_fn(f"Cikti       : {output_dir}")
    output_fn(f"Plan / Ayar : {plan_path} | {cfg_path}")
    output_fn("")

    if provider_kind == "remote" and not has_api_key:
        output_fn(f"[UYARI] Canli calistirma icin ortam degiskeni eksik: {api_key_env}")
        output_fn(f'        Once terminalde su komutu calistirin: export {api_key_env}="<ANAHTAR>"')
        output_fn(f"        Plan kaydedildi: {plan_path}")
        return 0

    confirm = input_fn("Bu planla canli taramayi TUI ile baslatayim mi? [e/H]: ")
    if not _is_yes(confirm):
        output_fn(f"Iptal edildi (0 trafik). Plan burada kayitli: {plan_path}")
        return 0

    exec_argv: list[str] = [
        "--preset", preset,
        "--target", raw_target,
        "--provider-config", str(eff_provider_cfg),
        "--output-dir", str(output_dir),
        "--allowed-methods", ",".join(allowed_methods),
        "--execute",
        "--tui",
    ]
    if scope_file is not None:
        exec_argv.extend(["--scope-file", str(scope_file)])
    if not loopback:
        exec_argv.append("--allow-non-loopback")
    if provider_kind == "remote":
        exec_argv.extend([
            "--authorize-live-provider",
            "--live-authorization-reason",
            "interactive-wizard-approved",
        ])
    for hdr in raw_custom_headers:
        exec_argv.extend(["-H", hdr])
    for spec in storage_states:
        exec_argv.extend(["--storage-state", spec])
    if credentials_file is not None:
        exec_argv.extend(["--credentials-file", str(credentials_file)])

    runner = runner_main or agentic_runner.main
    return int(runner(exec_argv))


def main(argv: Sequence[str] | None = None) -> int:
    parser = argparse.ArgumentParser(
        prog="cco-agent start",
        description="Interactive zero-flag Kryon launcher (plan -> confirm -> live TUI).",
    )
    parser.add_argument(
        "--provider-config",
        type=Path,
        default=None,
        help="Optional cco-llm/1 provider config path (default: CCO_LLM_CONFIG or config/llm.json)",
    )
    args = parser.parse_args(list(argv) if argv is not None else None)
    try:
        return run_wizard(provider_config=args.provider_config)
    except (KeyboardInterrupt, EOFError):
        print("\nIptal edildi.")
        return 130


if __name__ == "__main__":
    raise SystemExit(main())
