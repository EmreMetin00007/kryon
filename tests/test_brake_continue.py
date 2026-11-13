import importlib.util
import json
import sys
from pathlib import Path

REPO_ROOT = Path(__file__).resolve().parents[1]


def _load(name):
    path = REPO_ROOT / "scripts" / f"{name}.py"
    spec = importlib.util.spec_from_file_location(name, path)
    module = importlib.util.module_from_spec(spec)
    sys.modules[name] = module
    spec.loader.exec_module(module)
    return module


def _write_scope(tmp_path, data):
    codex = tmp_path / ".codex"
    codex.mkdir(exist_ok=True)
    scope = codex / "scope.json"
    scope.write_text(json.dumps(data))
    return scope


def _engine(tmp_path, monkeypatch, tag="brake2"):
    module = _load("policy_engine")
    _write_scope(tmp_path, {"in_scope": [{"asset": "example.com",
                                          "type": "web"}]})
    monkeypatch.setenv("CCO_WORKDIR", str(tmp_path / "work"))
    engine = module.PolicyEngine(cco_home=str(tmp_path / f".cco-{tag}"),
                                 repo_root=str(REPO_ROOT))
    engine.grant_approval("kali-tools_*", "example.com", ttl_seconds=600,
                          reason="test")
    return engine


def _brake_run(engine):
    last = None
    for flag in ("-A", "-K", "-x"):
        last = engine.validate_tool_invocation("kali-tools_curl_request", {
            "url": "https://example.com/a", "extra_args": flag})
    return last


def test_brake_reason_keeps_prefix_and_carries_exit(tmp_path, monkeypatch):
    last = _brake_run(_engine(tmp_path, monkeypatch))
    assert last is not None and last["allowed"] is False
    assert last["reason"].startswith(
        "blocked_repeat_brake: blocked_unsafe_arguments"), last
    assert "synthesize" in last["reason"], last


def test_brake_guidance_names_resend_exit(tmp_path, monkeypatch):
    last = _brake_run(_engine(tmp_path, monkeypatch))
    assert "not a lockout" in last["guidance"], last
    assert "brain.py synthesize" in last["guidance"], last


def _seeded_workdir(tmp_path, monkeypatch):
    al = _load("attempt_ledger")
    home = tmp_path / "home"
    home.mkdir()
    monkeypatch.setenv("CCO_HOME", str(home))
    monkeypatch.delenv("CCO_ATTEMPT_HMAC_KEY", raising=False)
    workdir = tmp_path / "run"
    workdir.mkdir()
    al.append_record(al.ledger_path(workdir), {
        "vector": "ssrf", "endpoint": "/hook", "identity": "own",
        "verdict": "no_signal", "status": 200})
    al.append_record(al.ledger_path(workdir), {
        "vector": "ssrf", "endpoint": "/hook", "identity": "own",
        "verdict": "clean", "status": 200, "control": 1})
    return workdir


def test_synthesize_ledger_summary_readonly(tmp_path, monkeypatch, capsys):
    brain = _load("brain")
    workdir = _seeded_workdir(tmp_path, monkeypatch)
    before = sorted(p.name for p in workdir.iterdir())
    assert brain.main(["synthesize", "--workdir", str(workdir),
                       "--kind", "ledger-summary"]) == 0
    data = json.loads(capsys.readouterr().out)
    assert data["records"] == 2 and data["trusted"] == 2
    assert data["by_vector"] == {"ssrf": 2}
    assert data["by_verdict"] == {"no_signal": 1, "clean": 1}
    assert sorted(p.name for p in workdir.iterdir()) == before


def test_synthesize_coverage_count(tmp_path, monkeypatch, capsys):
    brain = _load("brain")
    workdir = _seeded_workdir(tmp_path, monkeypatch)
    assert brain.main(["synthesize", "--workdir", str(workdir),
                       "--kind", "coverage-count"]) == 0
    data = json.loads(capsys.readouterr().out)
    assert data["ssrf"]["controls"] == 1
    assert data["ssrf"]["tried"] == []


def test_synthesize_rejects_unknown_kind(tmp_path, monkeypatch):
    brain = _load("brain")
    workdir = tmp_path / "run"
    workdir.mkdir()
    assert brain.main(["synthesize", "--workdir", str(workdir),
                       "--kind", "nope"]) == 2


def test_synthesize_command_is_gate_local(tmp_path, monkeypatch):
    engine = _engine(tmp_path, monkeypatch)
    verdict = engine.validate_tool_invocation("bash", {
        "command": "python3 scripts/brain.py synthesize --workdir /tmp/x "
                   "--kind ledger-summary"})
    assert verdict["allowed"] is True, verdict
