import importlib.util
import json
import sys
from pathlib import Path

from conftest import make_signed_validation

REPO_ROOT = Path(__file__).resolve().parents[1]


def _load(name):
    path = REPO_ROOT / "scripts" / f"{name}.py"
    spec = importlib.util.spec_from_file_location(name, path)
    module = importlib.util.module_from_spec(spec)
    sys.modules[name] = module
    spec.loader.exec_module(module)
    return module


def _summary(phase, status="done", **extra):
    data = {"phase": phase, "target": "t", "status": status,
            "evidence": [], "findings": [], "next": ""}
    data.update(extra)
    return data


def _confirmed_finding(kind):
    record = make_signed_validation("http://127.0.0.1:8899", kind)
    return {"band": "CONFIRMED", "type": kind,
            "validation_id": record["validation_id"]}


def test_vector_spec_renders_and_passes_gate(tmp_path):
    ts = _load("orchestration_spec")
    brain = _load("brain")
    engine_module = _load("policy_engine")
    specs = brain.build_plan("http://127.0.0.1:8899", "/tmp/run", kind="authed")
    access = next(s for s in specs if s.phase == "access")
    access.vector = "injection-sqli"
    brain.apply_vector(access)
    prompt = ts.render_task_prompt(access)
    assert "Vector: injection-sqli" in prompt
    assert "validator_validate_sqli" in prompt
    assert "vector_result" in prompt
    engine = engine_module.PolicyEngine(
        cco_home=str(tmp_path / ".cco"), repo_root=str(tmp_path))
    assert engine._task_spec_violation(
        "task", {"subagent_type": "worker", "prompt": prompt}) is None
    assert ts.TaskSpec.from_dict(access.to_dict()).vector == "injection-sqli"


def test_blocked_vector_rotates_then_confirmed_advances():
    brain = _load("brain")
    hl = _load("hypothesis_ledger")
    specs = brain.build_plan("http://127.0.0.1:8899", "/tmp/run")
    ledger = hl.init_ledger("http://127.0.0.1:8899",
                            vectors=["injection-sqli", "ssrf"], max_attempts=2)
    base = {"recon-1": _summary("recon"), "enum-2": _summary("enum")}

    dispatch, _ = brain.next_dispatch(specs, dict(base), ledger)
    assert dispatch.phase == "access" and dispatch.vector == "injection-sqli"

    entry = brain.ingest_access_summary(ledger, _summary(
        "access", "blocked", vector="injection-sqli", vector_result="blocked"))
    assert entry["status"] == "blocked" and entry["attempts"] == 1

    dispatch, _ = brain.next_dispatch(specs, dict(base), ledger)
    assert dispatch.phase == "access" and dispatch.vector == "ssrf"

    entry = brain.ingest_access_summary(ledger, _summary(
        "access", "done", vector="ssrf",
        findings=[{"band": "CONFIRMED", "type": "ssrf"}]))
    assert entry["status"] == "blocked"

    ledger = hl.init_ledger("http://127.0.0.1:8899",
                            vectors=["ssrf"], max_attempts=2)
    hl.claim_next(ledger)
    entry = brain.ingest_access_summary(ledger, _summary(
        "access", "done", vector="ssrf",
        findings=[_confirmed_finding("ssrf")]),
        validator_verified=True)
    assert entry["status"] == "confirmed"

    base["access-3"] = _summary(
        "access", "done", vector="ssrf",
        findings=[{"band": "CONFIRMED", "type": "ssrf"}])
    dispatch, _ = brain.next_dispatch(specs, dict(base), ledger)
    assert dispatch.phase == "report"  # exhausted ledger advances


def test_ingest_idempotent_and_tested_clean_exhausts():
    brain = _load("brain")
    hl = _load("hypothesis_ledger")
    ledger = hl.init_ledger("http://h:8080", vectors=["csrf", "ssrf"])
    hl.claim_next(ledger)
    summary = _summary("access", "partial", vector="csrf")
    assert brain.ingest_access_summary(ledger, summary)["attempts"] == 1
    assert brain.ingest_access_summary(ledger, summary) is None  # no double burn
    assert ledger["hypotheses"][0]["attempts"] == 1

    entry = brain.ingest_access_summary(
        ledger, _summary("access", "done", vector="ssrf"))
    assert entry["status"] == "exhausted"  # tested clean, not silently advanced


def test_cli_next_loops_access_over_ledger(tmp_path, capsys):
    brain = _load("brain")
    ts = _load("orchestration_spec")
    hl = _load("hypothesis_ledger")
    workdir = tmp_path / "run"
    summaries = workdir / "summaries"
    summaries.mkdir(parents=True)
    specs = brain.build_plan("http://127.0.0.1:8899", str(workdir))
    spec_file = workdir / "specs.json"
    spec_file.write_text(ts.dump_specs(specs))
    hl.save_ledger(workdir, hl.init_ledger(
        "http://127.0.0.1:8899", vectors=["injection-sqli", "ssrf"]))
    for name, phase in (("recon-1", "recon"), ("enum-2", "enum")):
        (summaries / f"{name}.json").write_text(json.dumps(_summary(phase)))

    argv = ["next", "--spec", str(spec_file), "--summaries", str(summaries),
            "--workdir", str(workdir)]
    assert brain.main(argv) == 0
    assert "Vector: injection-sqli" in capsys.readouterr().out

    (summaries / "access-3.json").write_text(json.dumps(_summary(
        "access", "blocked", vector="injection-sqli", vector_result="blocked")))
    assert brain.main(argv) == 0
    out = capsys.readouterr().out
    assert "Vector: ssrf" in out
    assert (summaries / "consumed" / "access-3-injection-sqli.json").is_file()
    ledger = hl.load_ledger(workdir)
    assert ledger["hypotheses"][0]["status"] == "blocked"
    assert ledger["hypotheses"][1]["status"] == "active"


def test_confirmed_vector_does_not_end_loop():
    brain = _load("brain")
    hl = _load("hypothesis_ledger")
    specs = brain.build_plan("http://127.0.0.1:8899", "/tmp/run")
    ledger = hl.init_ledger("http://127.0.0.1:8899",
                            vectors=["injection-sqli", "ssrf"], max_attempts=2)
    base = {"recon-1": _summary("recon"), "enum-2": _summary("enum")}
    hl.claim_next(ledger)
    entry = brain.ingest_access_summary(ledger, _summary(
        "access", "done", vector="injection-sqli",
        findings=[_confirmed_finding("sql_injection")]),
        validator_verified=True)
    assert entry["status"] == "confirmed"
    dispatch, _ = brain.next_dispatch(specs, dict(base), ledger)
    assert dispatch.phase == "access" and dispatch.vector == "ssrf"


def test_exhausted_ledger_without_access_summary_advances():
    brain = _load("brain")
    hl = _load("hypothesis_ledger")
    specs = brain.build_plan("http://127.0.0.1:8899", "/tmp/run")
    ledger = hl.init_ledger("http://127.0.0.1:8899",
                            vectors=["ssrf"], max_attempts=2)
    base = {"recon-1": _summary("recon"), "enum-2": _summary("enum")}
    hl.claim_next(ledger)
    entry = brain.ingest_access_summary(ledger, _summary(
        "access", "done", vector="ssrf",
        findings=[_confirmed_finding("ssrf")]),
        validator_verified=True)
    assert entry["status"] == "confirmed"
    dispatch, _ = brain.next_dispatch(specs, dict(base), ledger)
    assert dispatch.phase == "report"


def test_claim_next_skips_confirmed_vectors():
    hl = _load("hypothesis_ledger")
    ledger = hl.init_ledger("http://127.0.0.1:8899",
                            vectors=["injection-sqli", "ssrf"], max_attempts=2)
    hl.claim_next(ledger)
    hl.mark(ledger, "injection-sqli", "confirmed", note="validator artifact")
    claimed = hl.claim_next(ledger)
    assert claimed["vector"] == "ssrf" and claimed["status"] == "active"


def _closure_run(tmp_path, entries):
    brain = _load("brain")
    hl = _load("hypothesis_ledger")
    ts = _load("orchestration_spec")
    workdir = tmp_path / "run"
    workdir.mkdir()
    specs = brain.build_plan("http://127.0.0.1:8899", str(workdir))
    spec_file = workdir / "specs.json"
    spec_file.write_text(ts.dump_specs(specs))
    ledger = hl.init_ledger("http://127.0.0.1:8899",
                            vectors=[vector for vector, _, _ in entries],
                            max_attempts=2)
    for vector, status, note in entries:
        if status == "untried":
            continue
        if status in ("blocked",):
            hl.mark(ledger, vector, status, note=note)
            continue
        target = hl.claim_next(ledger)
        assert target is not None and target["vector"] == vector
        hl.mark(ledger, vector, status, note=note)
        if status == "confirmed":
            record = make_signed_validation(ledger["target"], brain._VALIDATOR_VECTOR_TYPES[vector])
            target.update(brain._confirmation_reference(record))
    hl.save_ledger(workdir, ledger)
    return brain.main(["check", "--spec", str(spec_file),
                       "--workdir", str(workdir), "--closure"])


def test_closure_gate_rejects_untried_vector(tmp_path):
    assert _closure_run(tmp_path, [("injection-sqli", "confirmed", "v1"),
                                   ("ssrf", "untried", "")]) == 2


def test_closure_gate_accepts_all_terminal(tmp_path):
    assert _closure_run(tmp_path, [("injection-sqli", "confirmed", "v1"),
                                   ("ssrf", "not_applicable",
                                    "auth:not-required: policy-closed: "
                                    "no approval")]) == 0


def test_closure_gate_rejects_unjustified_not_applicable(tmp_path):
    assert _closure_run(tmp_path, [("injection-sqli", "confirmed", "v1"),
                                   ("ssrf", "not_applicable", "")]) == 2


def test_closure_gate_rejects_retryable_blocked(tmp_path):
    assert _closure_run(tmp_path, [("injection-sqli", "confirmed", "v1"),
                                   ("ssrf", "blocked", "attempt 1")]) == 2


def _bare_check_run(tmp_path, extra_args, ledger_text=None):
    brain = _load("brain")
    ts = _load("orchestration_spec")
    workdir = tmp_path / "run"
    workdir.mkdir()
    specs = brain.build_plan("http://127.0.0.1:8899", str(workdir))
    spec_file = workdir / "specs.json"
    spec_file.write_text(ts.dump_specs(specs))
    if ledger_text is not None:
        (workdir / "hypotheses.json").write_text(ledger_text)
    return brain.main(["check", "--spec", str(spec_file),
                       "--workdir", str(workdir)] + extra_args)


def test_closure_gate_fails_without_ledger(tmp_path, capsys):
    assert _bare_check_run(tmp_path, ["--closure"]) == 2
    assert "no readable hypotheses ledger" in capsys.readouterr().out


def test_closure_gate_fails_with_corrupt_ledger(tmp_path):
    assert _bare_check_run(tmp_path, ["--closure"],
                           ledger_text="NOT JSON {{{") == 2


def test_plain_check_passes_without_ledger(tmp_path):
    assert _bare_check_run(tmp_path, []) == 0


def _pool_check_run(tmp_path, monkeypatch, pool_data, entries, records, capsys):
    brain = _load("brain")
    hl = _load("hypothesis_ledger")
    ts = _load("orchestration_spec")
    home = tmp_path / "home"
    home.mkdir()
    monkeypatch.setenv("CCO_HOME", str(home))
    monkeypatch.delenv("CCO_ATTEMPT_HMAC_KEY", raising=False)
    workdir = tmp_path / "run"
    workdir.mkdir()
    specs = brain.build_plan("http://127.0.0.1:8899", str(workdir))
    spec_file = workdir / "specs.json"
    spec_file.write_text(ts.dump_specs(specs))
    (workdir / "object-pool.json").write_text(json.dumps(pool_data))
    ledger = hl.init_ledger("http://127.0.0.1:8899",
                            vectors=[vector for vector, _, _ in entries],
                            max_attempts=2)
    for vector, status, note in entries:
        if status == "untried":
            continue
        if status == "blocked":
            hl.mark(ledger, vector, status, note=note)
            continue
        target = hl.claim_next(ledger)
        assert target is not None and target["vector"] == vector
        hl.mark(ledger, vector, status, note=note)
    hl.save_ledger(workdir, ledger)
    for vector, endpoint, verdict, extra in records:
        argv = ["attempts", "add", "--workdir", str(workdir),
               "--vector", vector, "--endpoint", endpoint,
               "--identity", "own", "--verdict", verdict]
        for flag, value in extra:
            argv += [flag, str(value)]
        assert brain.main(argv) == 0
    capsys.readouterr()
    code = brain.main(["check", "--spec", str(spec_file),
                       "--workdir", str(workdir)])
    return code, capsys.readouterr().out


def test_exhausted_pool_vector_rejected_on_empty_pool(tmp_path, monkeypatch,
                                                      capsys):
    pool = {"routes": 3, "own_ids": [], "docs_ids": [], "radius": 25,
            "candidates": []}
    code, out = _pool_check_run(
        tmp_path, monkeypatch, pool,
        [("authz-idor", "exhausted", "")],
        [("authz-idor", "/items", "control_own_200",
          [("--status", 200), ("--size", 10)])], capsys)
    assert code == 2
    assert "empty/untried pool" in out


def test_exhausted_pool_vector_passes_with_tried_candidate(tmp_path,
                                                           monkeypatch,
                                                           capsys):
    pool = {"routes": 3, "own_ids": [5], "docs_ids": [], "radius": 25,
            "candidates": [7]}
    code, _ = _pool_check_run(
        tmp_path, monkeypatch, pool,
        [("authz-idor", "exhausted", "")],
        [("authz-idor", "/items/5", "control_own_200",
          [("--control", 5), ("--status", 200), ("--size", 10)]),
         ("authz-idor", "/items/7", "probe_404_no_foreign_read",
          [("--candidate", 7), ("--status", 404), ("--size", 9)])], capsys)
    assert code == 0


def test_exhausted_rejected_even_with_empty_tenant_flag(tmp_path, monkeypatch,
                                                        capsys):
    pool = {"routes": 0, "own_ids": [], "docs_ids": [], "radius": 25,
            "candidates": [], "empty_tenant": True}
    code, _ = _pool_check_run(
        tmp_path, monkeypatch, pool,
        [("authz-idor", "exhausted", "")],
        [("authz-idor", "/items", "control_own_200",
          [("--status", 200), ("--size", 10)])], capsys)
    assert code == 2


def test_blocked_pool_vector_allowed_on_empty_tenant(tmp_path, monkeypatch,
                                                     capsys):
    pool = {"routes": 0, "own_ids": [], "docs_ids": [], "radius": 25,
            "candidates": [], "empty_tenant": True}
    code, _ = _pool_check_run(
        tmp_path, monkeypatch, pool,
        [("authz-idor", "blocked", "no own objects to anchor")],
        [], capsys)
    assert code == 0


def test_pool_command_marks_empty_tenant(tmp_path):
    brain = _load("brain")
    workdir = tmp_path / "run"
    workdir.mkdir()
    summary = workdir / "enum.json"
    summary.write_text(json.dumps({"surface": {"routes": [], "docs": []}}))
    assert brain.main(["hypotheses", "pool", "--workdir", str(workdir),
                       "--summary", str(summary)]) == 0
    pool = json.loads((workdir / "object-pool.json").read_text())
    assert pool["candidates"] == [] and pool["empty_tenant"] is True


def _xss_ledger():
    hl = _load("hypothesis_ledger")
    ledger = hl.init_ledger("http://127.0.0.1:8899",
                            vectors=["xss-stored"], max_attempts=2)
    hl.claim_next(ledger)
    return ledger


def test_xss_verdict_without_readback_pair_blocked():
    brain = _load("brain")
    entry = brain.ingest_access_summary(
        _xss_ledger(), _summary("access", "done", vector="xss-stored"))
    assert entry["status"] == "blocked"
    assert "readback" in entry["note"]


def test_xss_tested_clean_with_unrendered_pair_exhausts():
    brain = _load("brain")
    entry = brain.ingest_access_summary(_xss_ledger(), _summary(
        "access", "done", vector="xss-stored",
        readback={"submitted": "ticket/canary.marker",
                  "readback": "ticket/readback.body",
                  "rendered": False}))
    assert entry["status"] == "exhausted"


def test_xss_confirmed_requires_rendered_marker():
    brain = _load("brain")
    rendered = _summary(
        "access", "done", vector="xss-stored",
        findings=[_confirmed_finding("xss")],
        readback={"submitted": "ticket/canary.marker",
                  "readback": "ticket/readback.body",
                  "rendered": True})
    entry = brain.ingest_access_summary(
        _xss_ledger(), rendered, validator_verified=True)
    assert entry["status"] == "confirmed"
    entry = brain.ingest_access_summary(
        _xss_ledger(), dict(rendered, readback={
            "submitted": "ticket/canary.marker",
            "readback": "ticket/readback.body", "rendered": False}),
        validator_verified=True)
    assert entry["status"] == "blocked"


def test_pool_command_preserves_opaque_id_refs(tmp_path):
    brain = _load("brain")
    workdir = tmp_path / "run"
    workdir.mkdir()
    summary = workdir / "enum.json"
    summary.write_text(json.dumps({"surface": {"routes": [], "docs": []}}))
    assert brain.main(["hypotheses", "pool", "--workdir", str(workdir),
                       "--summary", str(summary),
                       "--own-ids", "shipments:fd7044b1-df54-42fc-b54b-4599a3484b5d,docs:1001"]) == 0
    pool = json.loads((workdir / "object-pool.json").read_text())
    assert {"family": "shipments",
            "id": "fd7044b1-df54-42fc-b54b-4599a3484b5d"} in pool["own_ids"]
    assert {"family": "docs", "id": "1001"} in pool["own_ids"]
    assert all({"family": "docs", "format": "int", "value": value} in pool["candidates"]
               for value in (1001, 1000))
    assert {"family": "shipments", "format": "uuid",
            "value": "fd7044b1-df54-42fc-b54b-4599a3484b5d"} in pool["candidates"]
    assert 42 not in pool["candidates"]
    assert pool["empty_tenant"] is False


def test_pool_command_rejects_host_like_family_tokens(tmp_path):
    brain = _load("brain")
    workdir = tmp_path / "run"
    workdir.mkdir()
    summary = workdir / "enum.json"
    summary.write_text(json.dumps({"surface": {"routes": [], "docs": []}}))
    assert brain.main(["hypotheses", "pool", "--workdir", str(workdir),
                       "--summary", str(summary),
                       "--own-ids", "192.0.2.10:8080,docs:1001"]) == 0
    pool = json.loads((workdir / "object-pool.json").read_text())
    assert {"family": "", "id": "192.0.2.10:8080"} in pool["own_ids"]
    assert {"family": "docs", "id": "1001"} in pool["own_ids"]
    assert 8080 not in pool["candidates"] and 8079 not in pool["candidates"]
    assert {"family": "docs", "format": "int", "value": 1001} in pool["candidates"]
