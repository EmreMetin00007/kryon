import importlib.util
import json
import os
import sys
import time
from pathlib import Path

REPO_ROOT = Path(__file__).resolve().parents[1]


def _load(name):
    path = REPO_ROOT / "scripts" / f"{name}.py"
    spec = importlib.util.spec_from_file_location(name, path)
    module = importlib.util.module_from_spec(spec)
    sys.modules[name] = module
    spec.loader.exec_module(module)
    return module


def _valid_spec(ts, **overrides):
    data = dict(
        id="recon-1", phase="recon", target="http://127.0.0.1:8899",
        tools=["kali-tools_nmap_scan"], commands=["scan"],
        evidence_dir="/tmp/run/recon", max_calls=20,
    )
    data.update(overrides)
    return ts.TaskSpec(**data)


def test_core_inventory_matches_config_and_capabilities():
    ts = _load("orchestration_spec")
    config = json.loads((REPO_ROOT / "config" / "mcp-core-tools.json").read_text())
    assert set(config["core_tools"]) == set(ts.CORE_TOOLS)
    caps = json.loads((REPO_ROOT / "config" / "tool-capabilities.json").read_text())
    import fnmatch
    registered = set(caps.get("tools", {}))
    patterns = [p["pattern"] for p in caps.get("patterns", [])]
    for tool in ts.CORE_TOOLS:
        assert tool in registered or any(
            fnmatch.fnmatch(tool, pattern) for pattern in patterns
        ), tool


def test_native_handoff_prompt_keeps_exact_vector_and_session_reference_contract():
    ts = _load("orchestration_spec")
    helper = "kali-tools_ledger_prepare_handoff"
    assert helper not in ts.CORE_TOOLS and len(ts.CORE_TOOLS) == 29
    for phase, vector, expected in (("enum", "", "access"), ("seed", "", "authz"),
                                    ("enum", "file-access", "file-access")):
        spec = _valid_spec(ts, phase=phase, tools=[helper], vector=vector,
                           tool_justification="local deterministic handoff")
        prompt = ts.render_task_prompt(spec)
        assert f"vector={expected}." in prompt
        assert "session_bindings_json" in prompt and "otherwise use []" in prompt
        assert "A partial summary always needs a steps list" in prompt
        assert "Session-health CONFIRMED" in prompt


def test_validate_spec_accepts_core_and_bash_exception():
    ts = _load("orchestration_spec")
    assert ts.validate_spec(_valid_spec(ts)) == []
    bash_spec = _valid_spec(
        ts, tools=["bash"], bash_justification="local file sort"
    )
    assert ts.validate_spec(bash_spec) == []


def test_validate_spec_rejects_gaps():
    ts = _load("orchestration_spec")
    assert ts.validate_spec(_valid_spec(ts, tools=[]))
    assert ts.validate_spec(_valid_spec(ts, tools=["bash"]))
    assert ts.validate_spec(_valid_spec(ts, tools=["kali-tools_made_up_tool"]))
    assert ts.validate_spec(_valid_spec(ts, max_calls=31))
    assert ts.validate_spec(_valid_spec(ts, evidence_dir=""))


def test_rendered_prompt_passes_gate_task_spec_check(tmp_path):
    ts = _load("orchestration_spec")
    brain = _load("brain")
    engine_module = _load("policy_engine")
    specs = brain.build_plan("http://127.0.0.1:8899", "/tmp/run")
    engine = engine_module.PolicyEngine(
        cco_home=str(tmp_path / ".cco"), repo_root=str(tmp_path)
    )
    for spec in specs:
        prompt = ts.render_task_prompt(spec)
        assert "Tools:" in prompt
        assert engine._task_spec_violation(
            "task", {"subagent_type": "worker", "prompt": prompt}
        ) is None


def test_summary_schema_and_finding_bands():
    ts = _load("orchestration_spec")
    good = {
        "phase": "recon", "target": "t", "status": "done",
        "evidence": [], "findings": [], "next": "enum",
    }
    assert ts.validate_summary(good) == []
    assert ts.validate_summary({"phase": "recon"})
    assert ts.classify_finding(False, 0.99) == "POSSIBLE"
    assert ts.classify_finding(True, 0.5) == "LIKELY"
    assert ts.classify_finding(True, 0.9) == "CONFIRMED"


def _summary(phase, status="done"):
    return {
        "phase": phase, "target": "t", "status": status,
        "evidence": [], "findings": [], "next": "",
    }


def test_max_minutes_deadline_render_and_bounds():
    ts = _load("orchestration_spec")
    prompt = ts.render_task_prompt(_valid_spec(ts, max_minutes=25))
    assert "Deadline:" in prompt and "25" in prompt
    assert "Deadline:" not in ts.render_task_prompt(_valid_spec(ts))
    assert ts.validate_spec(_valid_spec(ts, max_minutes=-1))
    assert ts.validate_spec(_valid_spec(ts, max_minutes=181))


def test_chain_validation_catches_bad_dependencies():
    ts = _load("orchestration_spec")
    recon = _valid_spec(ts)
    enum = _valid_spec(ts, id="enum-2", phase="enum", depends_on=["recon-1"])
    assert ts.validate_chain([recon, enum]) == []
    assert ts.validate_chain([enum, recon])  # dependency comes later
    ghost = _valid_spec(ts, id="enum-2", phase="enum", depends_on=["nope-9"])
    assert ts.validate_chain([recon, ghost])
    selfish = _valid_spec(ts, id="enum-2", phase="enum", depends_on=["enum-2"])
    assert ts.validate_chain([recon, selfish])


def test_brain_next_gates_dispatch_on_summaries():
    ts = _load("orchestration_spec")
    brain = _load("brain")
    specs = brain.build_plan("http://127.0.0.1:8899", "/tmp/run")
    assert [s.depends_on for s in specs] == [[], ["recon-1"], ["enum-2"], ["access-3"]]

    nxt, reason = brain.next_spec(specs, {})
    assert nxt is not None and nxt.id == "recon-1" and reason == ""

    nxt, reason = brain.next_spec(specs, {"recon-1": _summary("recon")})
    assert nxt is not None and nxt.id == "enum-2"

    nxt, reason = brain.next_spec(specs, {"recon-1": _summary("recon", "blocked")})
    assert nxt is None and "blocked" in reason

    nxt, reason = brain.next_spec(specs, {"recon-1": {"phase": "recon"}})
    assert nxt is None and reason

    all_done = {s.id: _summary(s.phase) for s in specs}
    nxt, reason = brain.next_spec(specs, all_done)
    assert nxt is None and "complete" in reason


def test_steps_fallback_render_and_partial_advances():
    ts = _load("orchestration_spec")
    brain = _load("brain")
    specs = brain.build_plan("http://127.0.0.1:8899", "/tmp/run")
    enum = specs[1]
    fuzz = [s for s in enum.steps if s.id == "route-fuzz"]
    assert fuzz and fuzz[0].optional and "extra_args" in fuzz[0].fallback
    prompt = ts.render_task_prompt(enum)
    assert "route-fuzz" in prompt and "NOT TESTED" in prompt

    partial = dict(_summary("recon"), status="partial",
                   steps=[{"id": "scan", "status": "done"},
                          {"id": "fuzz", "status": "not_tested"}])
    assert ts.validate_summary(partial) == []
    nxt, reason = brain.next_spec(specs, {"recon-1": partial})
    assert nxt is not None and nxt.id == "enum-2"


def test_summary_step_honesty_rules():
    ts = _load("orchestration_spec")
    lying_done = dict(_summary("recon"),
                      steps=[{"id": "fuzz", "status": "not_tested"}])
    assert ts.validate_summary(lying_done)  # done cannot hide a skipped step
    bare_partial = dict(_summary("recon"), status="partial")
    assert ts.validate_summary(bare_partial)  # partial must name its steps
    bad_step = dict(_summary("recon"), status="partial",
                    steps=[{"id": "fuzz", "status": "maybe"}])
    assert ts.validate_summary(bad_step)


def test_authed_kind_seed_chain():
    brain = _load("brain")
    specs = brain.build_plan("http://127.0.0.1:8899", "/tmp/run", kind="authed")
    assert [s.phase for s in specs] == ["seed", "authz", "access", "report"]
    assert [s.depends_on for s in specs] == [[], ["seed-1"], ["authz-2"], ["access-3"]]
    seed_steps = [s.id for s in specs[0].steps]
    assert seed_steps == ["entry-point", "own-identity", "verify-session"]
    assert "operator-provided" in specs[0].steps[1].command


def test_brain_kind_presets_and_next_cli(tmp_path, capsys):
    brain = _load("brain")
    host = brain.build_plan("10.0.0.5", "/tmp/run", kind="host")
    assert "kali-tools_nmap_scan" in host[0].tools
    assert "kali-tools_ledger_attempt_add_batch" in host[0].tools
    llm = brain.build_plan("http://127.0.0.1:8899", "/tmp/run", kind="llm")
    assert [s.phase for s in llm] == ["recon", "enum", "llm"]

    assert brain.main([
        "plan", "--target", "http://127.0.0.1:8899",
        "--workdir", str(tmp_path / "run"),
    ]) == 0
    spec_file = tmp_path / "specs.json"
    spec_file.write_text(capsys.readouterr().out)
    summaries = tmp_path / "summaries"
    summaries.mkdir()
    assert brain.main([
        "next", "--spec", str(spec_file), "--summaries", str(summaries),
    ]) == 0
    assert "recon-1" in capsys.readouterr().out
    (summaries / "recon-1.json").write_text(json.dumps(_summary("recon")))
    assert brain.main([
        "next", "--spec", str(spec_file), "--summaries", str(summaries),
    ]) == 0
    assert "enum-2" in capsys.readouterr().out


def test_brain_cli_plan_check_render(tmp_path, capsys):
    brain = _load("brain")
    assert brain.main([
        "plan", "--target", "http://127.0.0.1:8899",
        "--workdir", str(tmp_path / "run"),
    ]) == 0
    specs = json.loads(capsys.readouterr().out)
    spec_file = tmp_path / "specs.json"
    spec_file.write_text(json.dumps(specs))
    assert brain.main(["check", "--spec", str(spec_file)]) == 0
    capsys.readouterr()
    assert brain.main([
        "render", "--spec", str(spec_file), "--id", "recon-1",
    ]) == 0
    out = capsys.readouterr().out
    assert "Tools: kali-tools_nmap_scan" in out


def test_render_includes_skeleton_first_instruction():
    ts = _load("orchestration_spec")
    prompt = ts.render_task_prompt(_valid_spec(ts))
    assert "skeleton" in prompt.lower()
    assert "/tmp/run/summaries/recon-1.json" in prompt


def test_skeleton_summary_is_deterministic_and_valid():
    sys.path.insert(0, str(REPO_ROOT / "scripts"))
    ts = _load("orchestration_spec")
    spec = _valid_spec(ts, steps=[ts.Step(id="scan", command="scan"),
                                  ts.Step(id="fetch", command="fetch")])
    skeleton = ts.skeleton_summary(spec)
    # İlk seferde geçerli iskelet: faz/hedef spec'ten gelir (işçi elle yazmaz),
    # adımlar spec'ten önceden doldurulur.
    assert skeleton["phase"] == "recon"
    assert skeleton["target"] == spec.target
    assert ts.is_skeleton_summary(skeleton) is True
    assert skeleton["evidence"] == [] and skeleton["findings"] == []
    assert skeleton["steps"] == [{"id": "scan", "status": "not_tested"},
                                 {"id": "fetch", "status": "not_tested"}]
    # Terminal hale çevrilmiş hali (adımlar done) doğrulamadan geçer.
    terminal = dict(skeleton, status="done",
                    steps=[{"id": "scan", "status": "done"},
                           {"id": "fetch", "status": "done"}])
    assert ts.validate_summary(terminal) == []


def test_brain_summary_scaffold_and_validate_cli(tmp_path, capsys):
    sys.path.insert(0, str(REPO_ROOT / "scripts"))
    brain = _load("brain")
    specs = brain.build_plan("http://127.0.0.1:8899", str(tmp_path / "run"))
    spec_file = tmp_path / "specs.json"
    spec_file.write_text(json.dumps([s.to_dict() for s in specs]))
    summaries = tmp_path / "run" / "summaries"
    rc = brain.main(["summary", "scaffold", "--spec", str(spec_file),
                     "--id", specs[0].id, "--summaries", str(summaries)])
    assert rc == 0
    written = json.loads((summaries / f"{specs[0].id}.json").read_text())
    assert written["phase"] == specs[0].phase
    assert written["status"] == "in-progress"
    # validate: iskelet geçerli sayılır, bozuk özet aynı hatalarla reddedilir.
    rc = brain.main(["summary", "validate", "--spec", str(spec_file),
                     "--id", specs[0].id, "--summaries", str(summaries)])
    assert rc == 0
    bad = dict(written, phase="wrong-phase", status="done")
    (summaries / f"{specs[0].id}.json").write_text(json.dumps(bad))
    rc = brain.main(["summary", "validate", "--spec", str(spec_file),
                     "--id", specs[0].id, "--summaries", str(summaries)])
    assert rc == 2
    out = capsys.readouterr().out
    assert "phase" in out
    # scaffold terminal özeti ezmez.
    rc = brain.main(["summary", "scaffold", "--spec", str(spec_file),
                     "--id", specs[0].id, "--summaries", str(summaries)])
    assert rc == 2
    assert json.loads((summaries / f"{specs[0].id}.json").read_text()) == bad


def test_brain_waits_on_skeleton_instead_of_stopping():
    ts = _load("orchestration_spec")
    brain = _load("brain")
    specs = brain.build_plan("http://127.0.0.1:8899", "/tmp/run")
    skeleton = {"phase": "recon", "target": "http://127.0.0.1:8899",
                "status": "in-progress", "evidence": [], "findings": [], "next": ""}
    assert ts.is_skeleton_summary(skeleton) is True
    nxt, reason = brain.next_spec(specs, {"recon-1": skeleton})
    assert nxt is None and "in-progress" in reason


def test_ingest_skips_skeleton_without_burning_attempt():
    brain = _load("brain")
    ledger = {"target": "t", "target_key": "k", "max_attempts": 2, "hypotheses": [
        {"vector": "csrf", "status": "active", "attempts": 0, "evidence": [], "note": ""}]}
    skeleton = {"phase": "authz", "target": "t", "status": "in-progress",
                "vector": "csrf", "evidence": [], "findings": [], "next": ""}
    assert brain.ingest_access_summary(ledger, skeleton) is None
    assert ledger["hypotheses"][0]["attempts"] == 0
    assert ledger["hypotheses"][0]["status"] == "active"


def _enum_summary(**overrides):
    data = {
        "phase": "enum", "target": "t", "status": "done",
        "evidence": ["enum/routes.json"], "findings": [], "next": "",
        "surface": {"routes": [], "params": []},
    }
    data.update(overrides)
    return data


def test_enum_surface_gate_rejects_empty_surface_with_evidence():
    ts = _load("orchestration_spec")
    assert ts.validate_summary(_enum_summary())
    filled = _enum_summary(surface={
        "routes": ["/api/docs"], "params": [],
        "id_formats": [{"family": "docs", "format": "int", "example": "1001"}],
        "docs_probes": [{"url": "http://t/api/docs", "status": 200}]})
    assert ts.validate_summary(filled) == []
    assert ts.validate_summary(
        _enum_summary(surface={"routes": [], "params": ["q"]})) == []


def test_enum_surface_gate_requires_id_formats_with_routes():
    ts = _load("orchestration_spec")
    missing = _enum_summary(surface={"routes": ["/api/docs/1001"], "params": []})
    assert ts.validate_summary(missing)
    mistyped = _enum_summary(surface={"routes": ["/api/docs/1001"], "params": [],
                                      "id_formats": [{"family": "docs"}]})
    assert ts.validate_summary(mistyped)
    bad_format = _enum_summary(surface={
        "routes": ["/api/docs/1001"], "params": [],
        "id_formats": [{"family": "docs", "format": "snowflake",
                        "example": "01X"}]})
    assert ts.validate_summary(bad_format)
    valid = _enum_summary(surface={
        "routes": ["/api/docs/1001"], "params": [],
        "id_formats": [{"family": "docs", "format": "int", "example": "1001"},
                       {"family": "shipments", "format": "uuid",
                        "example": "fd7044b1-0000-4000-8000-000000000000"}],
        "docs_probes": [{"url": "http://t/api/docs", "status": 200}]})
    assert ts.validate_summary(valid) == []
    params_only = _enum_summary(surface={"routes": [], "params": ["q"]})
    assert ts.validate_summary(params_only) == []


def test_enum_surface_gate_exempts_objectless_routes():
    ts = _load("orchestration_spec")
    static = _enum_summary(surface={"routes": ["/", "/pricing", "/login"],
                                    "params": []})
    assert ts.validate_summary(static) == []
    versioned = _enum_summary(
        surface={"routes": ["http://t:8080/api/v2/status"], "params": []})
    assert ts.validate_summary(versioned) == []
    placeholder = _enum_summary(
        surface={"routes": ["/api/docs/:id"], "params": []})
    assert ts.validate_summary(placeholder)


def _doc_surface(routes, **extra):
    surface = {
        "routes": routes, "params": [],
        "id_formats": [{"family": "f", "format": "int", "example": "1"}],
    }
    surface.update(extra)
    return _enum_summary(surface=surface)


def test_enum_surface_gate_requires_docs_probe():
    ts = _load("orchestration_spec")
    assert ts.validate_summary(_doc_surface(["/api/docs"]))
    fetched = _doc_surface(
        ["/api/docs"],
        docs_probes=[{"url": "http://t/api/docs", "status": 200}])
    assert ts.validate_summary(fetched) == []
    absent = _doc_surface(
        ["/api/docs"],
        docs_probes=[{"url": "http://t/api/docs", "status": 404}])
    assert ts.validate_summary(absent) == []
    unstarted = _doc_surface(
        ["/openapi.json", "/api/docs"],
        docs_probes=[{"url": "http://t/api/docs", "status": 200}])
    assert ts.validate_summary(unstarted)
    mistyped = _doc_surface(
        ["/api/docs"],
        docs_probes=[{"url": "http://t/api/docs", "status": "200"}])
    assert ts.validate_summary(mistyped)
    unrelated = _doc_surface(["/login"])
    assert ts.validate_summary(unrelated) == []


def test_enum_surface_gate_rejects_missing_or_mistyped_surface():
    ts = _load("orchestration_spec")
    missing = _enum_summary()
    del missing["surface"]
    assert ts.validate_summary(missing)
    assert ts.validate_summary(_enum_summary(surface={"routes": "a,b", "params": []}))
    assert ts.validate_summary(_enum_summary(surface=["routes"]))
    # No evidence, no inventory duty: vacuous summaries still validate.
    assert ts.validate_summary(_enum_summary(evidence=[])) == []
    bare = {"phase": "enum", "target": "t", "status": "done",
            "evidence": [], "findings": [], "next": ""}
    assert ts.validate_summary(bare) == []
    assert ts.validate_summary(_summary("recon")) == []


def test_host_enum_without_surface_still_advances():
    brain = _load("brain")
    specs = brain.build_plan("10.0.0.5", "/tmp/run", kind="host")
    enum = dict(_summary("enum"), evidence=["enum/ports.json"])
    nxt, reason = brain.next_spec(
        specs, {"recon-1": _summary("recon"), "enum-2": enum})
    assert nxt is not None and nxt.phase == "access", reason
    web_specs = brain.build_plan("http://127.0.0.1:8899", "/tmp/run")
    nxt, reason = brain.next_spec(
        web_specs, {"recon-1": _summary("recon"), "enum-2": enum})
    assert nxt is None and "surface" in reason


def test_brain_stops_before_phase_after_empty_enum_surface(tmp_path, capsys):
    ts = _load("orchestration_spec")
    brain = _load("brain")
    specs = brain.build_plan("http://127.0.0.1:8899", "/tmp/run")
    summaries = {"recon-1": _summary("recon"), "enum-2": _enum_summary()}
    nxt, reason = brain.next_spec(specs, summaries)
    assert nxt is None and "surface" in reason

    workdir = tmp_path / "run"
    summaries_dir = workdir / "summaries"
    summaries_dir.mkdir(parents=True)
    specs = brain.build_plan("http://127.0.0.1:8899", str(workdir))
    spec_file = workdir / "specs.json"
    spec_file.write_text(ts.dump_specs(specs))
    (summaries_dir / "recon-1.json").write_text(json.dumps(_summary("recon")))
    (summaries_dir / "enum-2.json").write_text(json.dumps(_enum_summary()))
    assert brain.main([
        "next", "--spec", str(spec_file), "--summaries", str(summaries_dir),
    ]) == 2
    out = capsys.readouterr().out
    assert "STOP" in out and "surface" in out


def test_brain_pool_writes_object_pool(tmp_path, capsys):
    brain = _load("brain")
    workdir = tmp_path / "run"
    workdir.mkdir()
    summary = dict(_summary("enum"), evidence=["enum/routes.json"],
                   surface={"routes": ["/api/documents/1043/download"], "params": []})
    summary_file = workdir / "enum-2.json"
    summary_file.write_text(json.dumps(summary))
    assert brain.main([
        "hypotheses", "pool", "--workdir", str(workdir),
        "--summary", str(summary_file), "--own-ids", "7", "--docs-ids", "1001",
    ]) == 0
    pool = json.loads((workdir / "object-pool.json").read_text())
    for value in (1043, 7, 1001, 1042, 1044):
        assert value in pool["candidates"]
    assert brain.main([
        "hypotheses", "pool", "--workdir", str(workdir),
        "--summary", str(workdir / "missing.json"), "--own-ids", "7",
    ]) == 2


def test_authz_template_references_object_pool():
    brain = _load("brain")
    ts = _load("orchestration_spec")
    specs = brain.build_plan("http://127.0.0.1:8899", "/tmp/run", kind="authed")
    authz = next(s for s in specs if s.phase == "authz")
    prompt = ts.render_task_prompt(authz)
    assert "/tmp/run/object-pool.json" in prompt
    assert "authorized test accounts" in prompt.lower() and "tested-clean" in prompt.lower()


def test_authz_dispatch_requires_object_pool(tmp_path, capsys):
    brain = _load("brain")
    ts = _load("orchestration_spec")
    workdir = tmp_path / "run"
    summaries_dir = workdir / "summaries"
    summaries_dir.mkdir(parents=True)
    specs = brain.build_plan("http://127.0.0.1:8899", str(workdir), kind="authed")
    spec_file = workdir / "specs.json"
    spec_file.write_text(ts.dump_specs(specs))
    (summaries_dir / "seed-1.json").write_text(json.dumps(_summary("seed")))
    argv = ["next", "--spec", str(spec_file), "--summaries", str(summaries_dir),
           "--workdir", str(workdir)]
    assert brain.main(argv) == 2
    assert "object-pool" in capsys.readouterr().out
    (workdir / "object-pool.json").write_text(json.dumps({"candidates": [7]}))
    assert brain.main([
        "handoff", "--workdir", str(workdir), "--vector", "authz",
    ]) == 0
    capsys.readouterr()
    assert brain.main(argv) == 0
    assert "authz-2" in capsys.readouterr().out


def test_check_closes_active_race_and_dispatch_defaults_closed(tmp_path, capsys):
    brain = _load("brain")
    hl = _load("hypothesis_ledger")
    workdir, _, spec_file, policy_file = _race_run(
        tmp_path, {"race_burst": {"enabled": False}})
    ledger = hl.load_ledger(workdir)
    hl.mark(ledger, "race-business", "active")
    hl.save_ledger(workdir, ledger)
    assert brain.main([
        "check", "--spec", str(spec_file), "--workdir", str(workdir),
        "--policy", str(policy_file),
    ]) == 0
    ledger = hl.load_ledger(workdir)
    race = next(e for e in ledger["hypotheses"] if e["vector"] == "race-business")
    assert race["status"] == "not_applicable"

    specs = brain.build_plan("http://127.0.0.1:8899", "/tmp/run")
    ledger = hl.init_ledger("http://127.0.0.1:8899",
                            vectors=["race-business", "csrf"])
    base = {"recon-1": _summary("recon"), "enum-2": _summary("enum")}
    dispatch, _ = brain.next_dispatch(specs, dict(base), ledger)
    assert dispatch.vector == "csrf"
    race = next(e for e in ledger["hypotheses"] if e["vector"] == "race-business")
    assert race["status"] == "not_applicable"


def test_resolve_policy_merges_profile_race_burst(tmp_path):
    brain = _load("brain")
    root = tmp_path / "repo"
    (root / ".codex").mkdir(parents=True)
    (root / ".codex" / "program-policy.json").write_text(
        json.dumps({"profile": "lab", "time_budget_max_seconds": 3600}))
    profiles = root / "config" / "program-profiles"
    profiles.mkdir(parents=True)
    (profiles / "lab.json").write_text(json.dumps({
        "profile": "lab",
        "race_burst": {"enabled": True, "approval_ref": "lab-race-9"},
    }))
    policy = brain._resolve_policy("", repo_root=root)
    allowed, detail = brain.race_launch_allowed(policy)
    assert allowed is True and "lab-race-9" in detail
    assert policy["time_budget_max_seconds"] == 3600


def test_skeleton_stale_marks_old_heartbeats():
    brain = _load("brain")
    assert brain.skeleton_stale(1000.0, 1000.0 + 14 * 60, 15) is False
    assert brain.skeleton_stale(1000.0, 1000.0 + 16 * 60, 15) is True
    assert brain.skeleton_stale(None, 99999.0, 15) is False
    assert brain.skeleton_stale(1000.0, 99999.0, 0) is False


def test_brain_next_stops_on_stale_skeleton():
    brain = _load("brain")
    specs = brain.build_plan("http://127.0.0.1:8899", "/tmp/run")
    skeleton = {"phase": "recon", "target": "t", "status": "in-progress",
                "evidence": [], "findings": [], "next": ""}
    now = 2000000.0
    fresh, reason = brain.next_spec(specs, {"recon-1": skeleton},
                                    mtimes={"recon-1": now - 60}, now=now)
    assert fresh is None and "in-progress" in reason and "stale" not in reason
    stale, reason = brain.next_spec(specs, {"recon-1": skeleton},
                                    mtimes={"recon-1": now - 3600}, now=now)
    assert stale is None and "stale" in reason and "recon-1" in reason
    aged, reason = brain.next_spec(specs, {"recon-1": skeleton})
    assert aged is None and "stale" not in reason


def test_stale_skeleton_cli_recovers_on_terminal_summary(tmp_path, capsys):
    brain = _load("brain")
    ts = _load("orchestration_spec")
    workdir = tmp_path / "run"
    summaries_dir = workdir / "summaries"
    summaries_dir.mkdir(parents=True)
    specs = brain.build_plan("http://127.0.0.1:8899", str(workdir))
    spec_file = workdir / "specs.json"
    spec_file.write_text(ts.dump_specs(specs))
    skeleton = {"phase": "recon", "target": "http://127.0.0.1:8899",
                "status": "in-progress", "evidence": [], "findings": [], "next": ""}
    skeleton_file = summaries_dir / "recon-1.json"
    skeleton_file.write_text(json.dumps(skeleton))
    old = time.time() - 3600
    os.utime(skeleton_file, (old, old))
    argv = ["next", "--spec", str(spec_file), "--summaries", str(summaries_dir)]
    assert brain.main(argv) == 2
    out = capsys.readouterr().out
    assert "stale" in out and str(skeleton_file) in out
    skeleton_file.write_text(json.dumps(_summary("recon")))
    assert brain.main(argv) == 0
    assert "enum-2" in capsys.readouterr().out


def test_race_policy_helpers_default_closed():
    brain = _load("brain")
    assert brain.race_launch_allowed(None)[0] is False
    assert brain.race_launch_allowed({})[0] is False
    assert brain.race_launch_allowed({"race_burst": {"enabled": True}})[0] is False
    allowed, detail = brain.race_launch_allowed(
        {"race_burst": {"enabled": True, "approval_ref": "lab-race-001"}})
    assert allowed is True and "lab-race-001" in detail


def _race_run(tmp_path, policy):
    brain = _load("brain")
    ts = _load("orchestration_spec")
    hl = _load("hypothesis_ledger")
    workdir = tmp_path / "run"
    summaries_dir = workdir / "summaries"
    summaries_dir.mkdir(parents=True)
    specs = brain.build_plan("http://127.0.0.1:8899", str(workdir))
    spec_file = workdir / "specs.json"
    spec_file.write_text(ts.dump_specs(specs))
    hl.save_ledger(workdir, hl.init_ledger(
        "http://127.0.0.1:8899", vectors=["race-business", "csrf"]))
    policy_file = workdir / "policy.json"
    policy_file.write_text(json.dumps(policy))
    return workdir, summaries_dir, spec_file, policy_file


def test_brain_check_closes_race_without_approval(tmp_path, capsys):
    brain = _load("brain")
    hl = _load("hypothesis_ledger")
    workdir, _, spec_file, policy_file = _race_run(
        tmp_path, {"race_burst": {"enabled": False}})
    assert brain.main([
        "check", "--spec", str(spec_file), "--workdir", str(workdir),
        "--policy", str(policy_file),
    ]) == 0
    ledger = hl.load_ledger(workdir)
    race = next(e for e in ledger["hypotheses"] if e["vector"] == "race-business")
    assert race["status"] == "not_applicable" and "not_tested" in race["note"]
    assert "race" in capsys.readouterr().out.lower()


def test_brain_next_skips_unauthorized_race(tmp_path, capsys):
    brain = _load("brain")
    hl = _load("hypothesis_ledger")
    workdir, summaries_dir, spec_file, policy_file = _race_run(
        tmp_path, {"race_burst": {"enabled": False}})
    for name, phase in (("recon-1", "recon"), ("enum-2", "enum")):
        (summaries_dir / f"{name}.json").write_text(json.dumps(_summary(phase)))
    assert brain.main([
        "next", "--spec", str(spec_file), "--summaries", str(summaries_dir),
        "--workdir", str(workdir), "--policy", str(policy_file),
    ]) == 0
    assert "Vector: csrf" in capsys.readouterr().out
    ledger = hl.load_ledger(workdir)
    race = next(e for e in ledger["hypotheses"] if e["vector"] == "race-business")
    assert race["status"] == "not_applicable" and "not_tested" in race["note"]


def test_brain_next_authorizes_race_with_approval(tmp_path, capsys):
    brain = _load("brain")
    workdir, summaries_dir, spec_file, policy_file = _race_run(tmp_path, {
        "race_burst": {"enabled": True, "approval_ref": "lab-race-001",
                       "max_items": 10, "methods": ["GET", "POST"]}})
    for name, phase in (("recon-1", "recon"), ("enum-2", "enum")):
        (summaries_dir / f"{name}.json").write_text(json.dumps(_summary(phase)))
    assert brain.main([
        "next", "--spec", str(spec_file), "--summaries", str(summaries_dir),
        "--workdir", str(workdir), "--policy", str(policy_file),
    ]) == 0
    out = capsys.readouterr().out
    assert "Vector: race-business" in out
    assert "approval_ref=lab-race-001" in out and "summary evidence" in out


def test_pool_rejects_malformed_summary(tmp_path):
    brain = _load("brain")
    workdir = tmp_path / "run"
    workdir.mkdir()
    bad = workdir / "bad.json"
    bad.write_text("[]")
    assert brain.main([
        "hypotheses", "pool", "--workdir", str(workdir),
        "--summary", str(bad), "--own-ids", "7",
    ]) == 2
    bad2 = workdir / "bad2.json"
    bad2.write_text(json.dumps(dict(_summary("enum"), surface={"routes": "a,b"})))
    assert brain.main([
        "hypotheses", "pool", "--workdir", str(workdir),
        "--summary", str(bad2), "--own-ids", "7",
    ]) == 2


def test_authz_gate_without_workdir_uses_spec_dir(tmp_path, capsys):
    brain = _load("brain")
    ts = _load("orchestration_spec")
    workdir = tmp_path / "run"
    summaries_dir = workdir / "summaries"
    summaries_dir.mkdir(parents=True)
    specs = brain.build_plan("http://127.0.0.1:8899", str(workdir), kind="authed")
    spec_file = workdir / "specs.json"
    spec_file.write_text(ts.dump_specs(specs))
    (summaries_dir / "seed-1.json").write_text(json.dumps(_summary("seed")))
    argv = ["next", "--spec", str(spec_file), "--summaries", str(summaries_dir)]
    assert brain.main(argv) == 2
    assert "object pool" in capsys.readouterr().out
    (workdir / "object-pool.json").write_text("NOT JSON {{{")
    assert brain.main(argv) == 2
    (workdir / "object-pool.json").write_text(json.dumps({"candidates": [7]}))
    assert brain.main([
        "handoff", "--workdir", str(workdir), "--vector", "authz",
    ]) == 0
    capsys.readouterr()
    assert brain.main(argv) == 0
    assert "authz-2" in capsys.readouterr().out


def test_access_idor_dispatch_requires_valid_pool(tmp_path, capsys):
    brain = _load("brain")
    ts = _load("orchestration_spec")
    hl = _load("hypothesis_ledger")
    workdir = tmp_path / "run"
    summaries_dir = workdir / "summaries"
    summaries_dir.mkdir(parents=True)
    specs = brain.build_plan("http://127.0.0.1:8899", str(workdir))
    spec_file = workdir / "specs.json"
    spec_file.write_text(ts.dump_specs(specs))
    hl.save_ledger(workdir, hl.init_ledger(
        "http://127.0.0.1:8899", vectors=["authz-idor"]))
    for name, phase in (("recon-1", "recon"), ("enum-2", "enum")):
        (summaries_dir / f"{name}.json").write_text(json.dumps(_summary(phase)))
    argv = ["next", "--spec", str(spec_file), "--summaries", str(summaries_dir),
            "--workdir", str(workdir)]
    assert brain.main(argv) == 2
    assert "object pool" in capsys.readouterr().out
    (workdir / "object-pool.json").write_text(json.dumps({"candidates": [5]}))
    assert brain.main([
        "handoff", "--workdir", str(workdir), "--vector", "authz-idor",
    ]) == 0
    capsys.readouterr()
    assert brain.main(argv) == 0
    assert "Vector: authz-idor" in capsys.readouterr().out


def test_ingest_requires_pool_coverage_for_tested_clean():
    brain = _load("brain")
    hl = _load("hypothesis_ledger")
    clean = {"phase": "access", "target": "t", "status": "done",
             "vector": "authz-idor", "vector_result": "tested_clean",
             "evidence": ["ev.bin"], "findings": [], "next": ""}
    ledger = hl.init_ledger("http://h:8080", vectors=["authz-idor"])
    hl.claim_next(ledger)
    entry = brain.ingest_access_summary(ledger, clean, pool_candidates=10)
    assert entry["status"] == "blocked" and "pool" in entry["note"]
    ledger = hl.init_ledger("http://h:8080", vectors=["authz-idor"])
    hl.claim_next(ledger)
    covered = dict(clean, pool_probed=10)
    entry = brain.ingest_access_summary(ledger, covered, pool_candidates=10)
    assert entry["status"] == "exhausted"


def _attempt_run(tmp_path):
    brain = _load("brain")
    ts = _load("orchestration_spec")
    hl = _load("hypothesis_ledger")
    workdir = tmp_path / "run"
    summaries_dir = workdir / "summaries"
    summaries_dir.mkdir(parents=True)
    specs = brain.build_plan("http://127.0.0.1:8899", str(workdir))
    spec_file = workdir / "specs.json"
    spec_file.write_text(ts.dump_specs(specs))
    hl.save_ledger(workdir, hl.init_ledger(
        "http://127.0.0.1:8899", vectors=["authz-idor"]))
    (workdir / "object-pool.json").write_text(json.dumps({"candidates": [5, 6]}))
    return brain, hl, workdir, summaries_dir, spec_file


def test_ingest_blocked_when_attempt_coverage_missing():
    brain = _load("brain")
    hl = _load("hypothesis_ledger")
    clean = {"phase": "access", "target": "t", "status": "done",
             "vector": "authz-idor", "vector_result": "tested_clean",
             "evidence": ["ev.bin"], "findings": [], "next": "",
             "pool_probed": 10}
    ledger = hl.init_ledger("http://h:8080", vectors=["authz-idor"])
    hl.claim_next(ledger)
    entry = brain.ingest_access_summary(
        ledger, clean, pool_candidates=10,
        coverage_block="untried pool candidates: [9]")
    assert entry["status"] == "blocked" and "untried" in entry["note"]


def test_ingest_cli_enforces_attempt_coverage(tmp_path):
    brain, hl, workdir, summaries_dir, spec_file = _attempt_run(tmp_path)
    clean = {"phase": "access", "target": "t", "status": "done",
             "vector": "authz-idor", "vector_result": "tested_clean",
             "evidence": ["ev.bin"], "findings": [], "next": "",
             "pool_probed": 2}
    (summaries_dir / "access-3.json").write_text(json.dumps(clean))
    assert brain.main([
        "ingest", "--spec", str(spec_file), "--summaries", str(summaries_dir),
        "--workdir", str(workdir),
    ]) == 0
    ledger = hl.load_ledger(workdir)
    entry = next(e for e in ledger["hypotheses"] if e["vector"] == "authz-idor")
    assert entry["status"] == "blocked"
    assert "attempt coverage incomplete" in entry["note"]


def test_ingest_cli_accepts_full_coverage(tmp_path):
    brain, hl, workdir, summaries_dir, _ = _attempt_run(tmp_path)
    attempts_mod = _load("attempt_ledger")
    attempts = tmp_path / "run" / "attempts.jsonl"
    for candidate in (4, 5, 6):
        attempts_mod.append_record(attempts, {
            "vector": "authz-idor",
            "endpoint": f"/api/documents/{candidate}/download",
            "identity": "own", "candidate": candidate, "control": 4,
            "status": 403, "size": 10, "verdict": "miss",
        })
    clean = {"phase": "access", "target": "t", "status": "done",
             "vector": "authz-idor", "vector_result": "tested_clean",
             "evidence": ["ev.bin"], "findings": [], "next": "",
             "pool_probed": 2}
    (summaries_dir / "access-3.json").write_text(json.dumps(clean))
    assert brain.main([
        "ingest", "--spec", str(tmp_path / "run" / "specs.json"),
        "--summaries", str(summaries_dir), "--workdir", str(workdir),
    ]) == 0
    ledger = hl.load_ledger(workdir)
    entry = next(e for e in ledger["hypotheses"] if e["vector"] == "authz-idor")
    assert entry["status"] == "exhausted"


def test_check_prints_coverage_matrix(tmp_path, capsys):
    brain = _load("brain")
    _, hl, workdir, _, spec_file = _attempt_run(tmp_path)
    _load("attempt_ledger").append_record(workdir / "attempts.jsonl", {
        "vector": "authz-idor", "endpoint": "/api/documents/5/download",
        "identity": "own", "candidate": 5, "control": 4,
        "status": 403, "size": 10, "verdict": "miss",
    })
    assert brain.main([
        "check", "--spec", str(spec_file), "--workdir", str(workdir),
    ]) == 0
    out = capsys.readouterr().out
    assert "coverage authz-idor" in out and "untried" in out and "6" in out


def _handoff_run(tmp_path):
    brain = _load("brain")
    workdir = tmp_path / "run"
    workdir.mkdir()
    (workdir / "object-pool.json").write_text(json.dumps({"candidates": [5, 6, 7]}))
    (workdir / "ev.bin").write_bytes(b"B" * 2000)
    _load("attempt_ledger").append_record(workdir / "attempts.jsonl", {
        "vector": "authz-idor", "endpoint": "/api/documents/5/download",
        "identity": "own", "candidate": 5, "control": 4,
        "status": 403, "size": 2000, "artifact": "ev.bin", "verdict": "miss",
    })
    return brain, workdir


def test_handoff_packet_deterministic_and_capped(tmp_path, capsys):
    brain, workdir = _handoff_run(tmp_path)
    assert brain.main([
        "handoff", "--workdir", str(workdir), "--vector", "authz-idor",
    ]) == 0
    first = capsys.readouterr().out
    packet = json.loads(first)
    assert packet["untried"] == [6, 7]
    assert packet["recent"][0]["excerpt"].startswith("BBB")
    assert packet["recent"][0]["artifact"] == "ev.bin"
    assert (workdir / "handoff-authz-idor.json").read_text() == first
    assert brain.main([
        "handoff", "--workdir", str(workdir), "--vector", "authz-idor",
        "--max-chars", "600",
    ]) == 0
    capped = capsys.readouterr().out
    assert len(capped) <= 600
    assert json.loads(capped)["untried"] == [6, 7]


def test_task_template_references_handoff_packet():
    brain = _load("brain")
    ts = _load("orchestration_spec")
    specs = brain.build_plan("http://127.0.0.1:8899", "/tmp/run", kind="authed")
    authz = next(s for s in specs if s.phase == "authz")
    prompt = ts.render_task_prompt(authz)
    assert "/tmp/run/handoff-authz.json" in prompt
    assert "INCOMPLETE_SPEC" in prompt
    access = next(s for s in specs if s.phase == "access")
    access.vector = "authz-idor"
    prompt = ts.render_task_prompt(access)
    assert "/tmp/run/handoff-authz-idor.json" in prompt


def test_idor_dispatch_requires_handoff_packet(tmp_path, capsys):
    brain = _load("brain")
    ts = _load("orchestration_spec")
    hl = _load("hypothesis_ledger")
    workdir = tmp_path / "run"
    summaries_dir = workdir / "summaries"
    summaries_dir.mkdir(parents=True)
    specs = brain.build_plan("http://127.0.0.1:8899", str(workdir))
    spec_file = workdir / "specs.json"
    spec_file.write_text(ts.dump_specs(specs))
    hl.save_ledger(workdir, hl.init_ledger(
        "http://127.0.0.1:8899", vectors=["authz-idor"]))
    for name, phase in (("recon-1", "recon"), ("enum-2", "enum")):
        (summaries_dir / f"{name}.json").write_text(json.dumps(_summary(phase)))
    (workdir / "object-pool.json").write_text(json.dumps({"candidates": [5]}))
    argv = ["next", "--spec", str(spec_file), "--summaries", str(summaries_dir),
           "--workdir", str(workdir)]
    assert brain.main(argv) == 2
    assert "handoff" in capsys.readouterr().out
    (workdir / "handoff-authz-idor.json").write_text(json.dumps({"vector": "authz-idor"}))
    assert brain.main(argv) == 2
    assert "handoff" in capsys.readouterr().out
    assert brain.main([
        "handoff", "--workdir", str(workdir), "--vector", "authz-idor",
    ]) == 0
    capsys.readouterr()
    assert brain.main(argv) == 0
    assert "Vector: authz-idor" in capsys.readouterr().out


def test_coverage_block_applies_to_non_pool_vectors(tmp_path):
    brain = _load("brain")
    attempts_mod = _load("attempt_ledger")
    workdir = tmp_path / "run"
    workdir.mkdir()
    assert brain._ledger_coverage_block(str(workdir), "csrf")
    attempts_mod.append_record(workdir / "attempts.jsonl", {
        "vector": "csrf", "endpoint": "/profile/update",
        "identity": "own", "status": 403, "size": 12, "verdict": "miss",
    })
    assert brain._ledger_coverage_block(str(workdir), "csrf") is None


def _persist_validator_artifact(validation_id, vuln_type="IDOR"):
    validator_dir = str(REPO_ROOT / "mcp-servers" / "mcp-validator")
    if validator_dir not in sys.path:
        sys.path.insert(0, validator_dir)
    from cco_validator_core import persist_result

    validations = Path(os.environ["CCO_HOME"]) / "validations"
    return persist_result({
        "schema_version": "2.0",
        "validator": "cco-deterministic-validator",
        "validator_version": "2.0.0",
        "validation_id": validation_id,
        "vuln_type": vuln_type,
        "target": "http://127.0.0.1:8899",
        "verdict": "CONFIRMED",
        "confidence": 0.95,
        "severity": "high",
        "oracle": "test",
        "evidence": {},
        "reproduction": [],
        "request_evidence": [],
        "guard": {"transport_ok": True, "decision_rule": "test"},
        "false_positive_guard": "test",
        "notes": "test",
        "timestamp": "2026-10-27T00:00:00Z",
    }, str(validations))


def test_ingest_cli_confirmed_requires_validator_artifact(tmp_path):
    brain, hl, workdir, summaries_dir, spec_file = _attempt_run(tmp_path)
    summary = {
        "phase": "access", "target": "http://127.0.0.1:8899",
        "status": "done", "vector": "authz-idor",
        "vector_result": "confirmed", "evidence": [], "next": "",
        "findings": [{"band": "CONFIRMED", "type": "idor",
                      "validation_id": "a" * 32}],
    }
    (summaries_dir / "access-3.json").write_text(json.dumps(summary))
    assert brain.main([
        "ingest", "--spec", str(spec_file), "--summaries", str(summaries_dir),
        "--workdir", str(workdir),
    ]) == 0
    ledger = hl.load_ledger(workdir)
    entry = next(e for e in ledger["hypotheses"] if e["vector"] == "authz-idor")
    assert entry["status"] == "blocked" and "validator" in entry["note"]


def test_ingest_cli_accepts_persisted_validator_artifact(tmp_path):
    brain, hl, workdir, summaries_dir, spec_file = _attempt_run(tmp_path)
    _persist_validator_artifact("b" * 32)
    summary = {
        "phase": "access", "target": "http://127.0.0.1:8899",
        "status": "done", "vector": "authz-idor",
        "vector_result": "confirmed", "evidence": [], "next": "",
        "findings": [{"band": "CONFIRMED", "type": "idor",
                      "validation_id": "b" * 32}],
    }
    (summaries_dir / "access-3.json").write_text(json.dumps(summary))
    assert brain.main([
        "ingest", "--spec", str(spec_file), "--summaries", str(summaries_dir),
        "--workdir", str(workdir),
    ]) == 0
    ledger = hl.load_ledger(workdir)
    entry = next(e for e in ledger["hypotheses"] if e["vector"] == "authz-idor")
    assert entry["status"] == "confirmed"


def test_handoff_rejects_tampered_artifact_and_stale_packet(tmp_path, capsys):
    brain, workdir = _handoff_run(tmp_path)
    assert brain.main([
        "handoff", "--workdir", str(workdir), "--vector", "authz-idor",
    ]) == 0
    packet = json.loads(capsys.readouterr().out)
    assert packet["recent"][0]["excerpt"].startswith("BBB")
    (workdir / "ev.bin").write_bytes(b"X" * 2000)
    assert brain.main([
        "handoff", "--workdir", str(workdir), "--vector", "authz-idor",
    ]) == 0
    packet = json.loads(capsys.readouterr().out)
    assert packet["recent"][0]["excerpt"] == ""


def test_handoff_hard_cap_keeps_untrusted_metadata_bounded(tmp_path, capsys):
    brain, workdir = _handoff_run(tmp_path)
    assert brain.main([
        "handoff", "--workdir", str(workdir), "--vector", "authz-idor",
        "--max-chars", "350",
    ]) == 0
    capped = capsys.readouterr().out
    assert len(capped) <= 350
    assert json.loads(capped)["vector"] == "authz-idor"


def test_budget_warning_fires_when_chain_exceeds_budget(capsys):
    brain = _load("brain")
    specs = brain.build_plan("http://127.0.0.1:8899", "/tmp/run")
    total = brain.chain_time_estimate_minutes(specs)
    assert total > 0
    assert brain.budget_warning(specs, 1) is not None
    assert brain.budget_warning(specs, total * 60) is None
    assert "BUDGET-WARN" in (brain.budget_warning(specs, 1) or "")
