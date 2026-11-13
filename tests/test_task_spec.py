"""Task spec şeması + paralel havuz testleri (offline)."""
import importlib.util
import sys
from pathlib import Path

REPO_ROOT = Path(__file__).resolve().parents[1]
sys.path.insert(0, str(REPO_ROOT / "scripts"))

from task_spec import (  # noqa: E402
    build_worker_prompt,
    partition_kinds,
    validate_task_spec,
)


def _load_swarm():
    spec = importlib.util.spec_from_file_location(
        "swarm_orchestrator_spec", REPO_ROOT / "scripts" / "swarm_orchestrator.py")
    mod = importlib.util.module_from_spec(spec)
    sys.modules[spec.name] = mod
    spec.loader.exec_module(mod)
    return mod


def _valid_spec():
    return {
        "target": "https://lab.test/",
        "scope_ref": ".codex/scope.json",
        "objective": "yüzey haritası çıkar",
        "commands": ["curl -s https://lab.test/ -o $EVID/out.body"],
        "evidence_dir": "$CCO_WORKDIR/wsa-t/evidence",
        "output_format": "koşulan URL listesi + durum kodları",
    }


def test_valid_spec_passes():
    assert validate_task_spec(_valid_spec()) == {"valid": True, "missing": [], "errors": []}


def test_each_required_field_rejected_when_missing():
    from task_spec import REQUIRED_FIELDS
    for field in REQUIRED_FIELDS:
        spec = _valid_spec()
        del spec[field]
        check = validate_task_spec(spec)
        assert check["valid"] is False
        assert field in check["missing"]


def test_bad_types_rejected():
    spec = _valid_spec()
    spec["commands"] = "tek string degil liste olmali"
    assert validate_task_spec(spec)["valid"] is False
    spec = _valid_spec()
    spec["budget_requests"] = "cok"
    assert validate_task_spec(spec)["valid"] is False


def test_build_prompt_round_trip_and_refusal():
    prompt = build_worker_prompt(_valid_spec())
    for needle in ("https://lab.test/", ".codex/scope.json", "KANIT DİZİNİ", "ÇIKTI FORMATI"):
        assert needle in prompt
    try:
        build_worker_prompt({})
    except ValueError as exc:
        assert "eksik alanlar" in str(exc)
    else:
        raise AssertionError("geçersiz spec kabul edildi")


def test_partition_kinds_round_robin():
    assert partition_kinds(["a", "b", "c", "d"], 3) == [["a", "d"], ["b"], ["c"]]
    assert partition_kinds([], 4) == [[], [], [], []]
    flat = partition_kinds(["a", "b", "c"], 2)
    assert sorted(sum(flat, [])) == ["a", "b", "c"]


def test_swarm_rejects_incomplete_spec():
    swarm = _load_swarm()
    orch = swarm.SwarmOrchestrator()
    bad = {"target": "https://lab.test/"}
    try:
        orch.create_task(swarm.AgentRole.RECON, "t", {"task_spec": bad})
    except ValueError as exc:
        assert "eksik alanlar" in str(exc)
    else:
        raise AssertionError("eksik spec kabul edildi")
    tid = orch.create_task(swarm.AgentRole.RECON, "t", {"task_spec": _valid_spec()})
    assert tid in orch.tasks


def test_pool_caps_workers_to_kinds(tmp_path):
    """workers > kind sayısıysa fazlalık boş filtreyle (hepsini kaparak) koşmaz."""
    sys.path.insert(0, str(REPO_ROOT / "scripts"))
    import worker_pool
    seen = []

    class _FakeProc:
        def wait(self):
            return 0

    def _fake_popen(cmd, env=None):
        seen.append((cmd, env))
        return _FakeProc()

    import subprocess
    original = subprocess.Popen
    try:
        subprocess.Popen = _fake_popen
        summary = worker_pool.run_pool(
            1, 4, ["recon", "fuzz"], 3, [],
            base_env={"CCO_HOME": str(tmp_path / "home"),
                      "CCO_WORKDIR": str(tmp_path / "work"),
                      "PATH": "/usr/bin:/bin"},
        )
    finally:
        subprocess.Popen = original
    assert summary["workers_requested"] == 4
    assert summary["workers"] == 2
    assert len(seen) == 2
    kinds_args = []
    for cmd, _env in seen:
        i = cmd.index("--kinds")
        kinds_args.append(cmd[i + 1])
    assert sorted(kinds_args) == ["fuzz", "recon"]


def test_pool_env_isolates_evidence_shares_db(tmp_path, monkeypatch):
    sys.path.insert(0, str(REPO_ROOT / "scripts"))
    import worker_pool
    base = {"CCO_HOME": str(tmp_path / "cco-home"), "CCO_WORKDIR": str(tmp_path / "work"),
            "PATH": "/usr/bin:/bin"}
    env0 = worker_pool.build_worker_env(base, base["CCO_WORKDIR"], 0)
    env1 = worker_pool.build_worker_env(base, base["CCO_WORKDIR"], 1)
    assert env0["CCO_HOME"] == env1["CCO_HOME"] == base["CCO_HOME"]
    assert env0["CCO_WORKDIR"] != env1["CCO_WORKDIR"]
    assert env0["CCO_WORKDIR"].endswith("pool/w0")
