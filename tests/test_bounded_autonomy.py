import importlib.util
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


def _spec(tools, **extra):
    ts = _load("orchestration_spec")
    data = {"id": "access-3", "phase": "access", "target": "http://t/",
            "tools": tools, "commands": ["probe"], "evidence_dir": "/tmp/ev",
            "max_calls": 25}
    data.update(extra)
    return ts, ts.TaskSpec.from_dict(data)


def test_core_tool_needs_no_justification():
    ts, spec = _spec(["kali-tools_curl_request"])
    assert ts.validate_spec(spec) == []


def test_noncore_registered_tool_with_justification_accepted():
    ts, spec = _spec(["hunter_build_authz_matrix"],
                     tool_justification="cross-tenant matrix for BOLA")
    assert ts.validate_spec(spec) == []


def test_noncore_tool_without_justification_rejected():
    ts, spec = _spec(["hunter_build_authz_matrix"])
    errors = ts.validate_spec(spec)
    assert any("tool_justification" in e for e in errors), errors


def test_unregistered_tool_rejected_even_with_justification():
    ts, spec = _spec(["zzz_fake_tool"],
                     tool_justification="not a real tool")
    errors = ts.validate_spec(spec)
    assert any("not registered" in e for e in errors), errors


def test_tool_justification_roundtrip():
    ts, spec = _spec(["kali-tools_curl_request"],
                     tool_justification="why")
    assert ts.TaskSpec.from_dict(spec.to_dict()).tool_justification == "why"


def test_rendered_tools_line_lists_opt_in_tool():
    ts, spec = _spec(["kali-tools_curl_request", "hunter_build_authz_matrix"],
                     tool_justification="BOLA matrix")
    prompt = ts.render_task_prompt(spec)
    tools_line = next(line for line in prompt.splitlines()
                      if line.startswith("Tools:"))
    assert "hunter_build_authz_matrix" in tools_line


def _plan_file(tmp_path):
    brain = _load("brain")
    ts = _load("orchestration_spec")
    workdir = tmp_path / "run"
    workdir.mkdir()
    specs = brain.build_plan("http://127.0.0.1:8899", str(workdir))
    spec_file = workdir / "specs.json"
    spec_file.write_text(ts.dump_specs(specs))
    return brain, ts, spec_file


def test_spec_customize_adds_commands_and_tools(tmp_path):
    brain, ts, spec_file = _plan_file(tmp_path)
    extra = tmp_path / "extra.txt"
    extra.write_text("Probe /api/v2/webhooks/verify with X-Signature variants\n")
    assert brain.main(["spec-customize", "--spec", str(spec_file),
                       "--id", "access-3",
                       "--add-commands-file", str(extra),
                       "--add-tools", "hunter_build_authz_matrix",
                       "--tool-justification", "BOLA matrix"]) == 0
    specs = ts.load_specs(spec_file.read_text())
    access = next(s for s in specs if s.id == "access-3")
    assert "hunter_build_authz_matrix" in access.tools
    assert any("X-Signature" in c for c in access.custom_commands)
    assert "BOLA matrix" in access.tool_justification
    assert ts.validate_spec(access) == []


def test_apply_vector_preserves_custom_commands(tmp_path):
    brain, ts, spec_file = _plan_file(tmp_path)
    extra = tmp_path / "extra.txt"
    extra.write_text("Probe /api/v2/webhooks/verify with X-Signature variants\n")
    assert brain.main(["spec-customize", "--spec", str(spec_file),
                       "--id", "access-3",
                       "--add-commands-file", str(extra)]) == 0
    access = next(s for s in ts.load_specs(spec_file.read_text())
                  if s.id == "access-3")
    access.vector = "csrf"
    rendered = brain.apply_vector(access)
    assert any("X-Signature" in c for c in rendered.commands)
    assert any("CSRF controls" in c and "untested" in c for c in rendered.commands)


def test_spec_customize_bash_justification(tmp_path):
    brain, ts, spec_file = _plan_file(tmp_path)
    assert brain.main(["spec-customize", "--spec", str(spec_file),
                       "--id", "access-3", "--add-tools", "bash",
                       "--bash-justification",
                       "helper-compute: HMAC variants"]) == 0
    access = next(s for s in ts.load_specs(spec_file.read_text())
                  if s.id == "access-3")
    assert "bash" in access.tools
    assert ts.validate_spec(access) == []
    tools_line = next(line for line in ts.render_task_prompt(access)
                      .splitlines() if line.startswith("Tools:"))
    assert "bash (helper-compute: HMAC variants)" in tools_line


def test_spec_customize_bash_without_justification_rejected(tmp_path):
    brain, ts, spec_file = _plan_file(tmp_path)
    before = spec_file.read_bytes()
    assert brain.main(["spec-customize", "--spec", str(spec_file),
                       "--id", "access-3", "--add-tools", "bash"]) == 2
    assert spec_file.read_bytes() == before


def test_spec_customize_rejects_unregistered_tool(tmp_path):
    brain, ts, spec_file = _plan_file(tmp_path)
    before = spec_file.read_bytes()
    assert brain.main(["spec-customize", "--spec", str(spec_file),
                       "--id", "access-3",
                       "--add-tools", "zzz_fake_tool",
                       "--tool-justification", "nope"]) == 2
    assert spec_file.read_bytes() == before


def test_spec_customize_enforces_add_limits(tmp_path):
    brain, ts, spec_file = _plan_file(tmp_path)
    extra = tmp_path / "extra.txt"
    extra.write_text("one\ntwo\nthree\nfour\nfive\n")
    before = spec_file.read_bytes()
    assert brain.main(["spec-customize", "--spec", str(spec_file),
                       "--id", "access-3",
                       "--add-commands-file", str(extra)]) == 2
    assert brain.main(["spec-customize", "--spec", str(spec_file),
                       "--id", "access-3", "--add-tools",
                       "a_x,b_x,c_x,d_x,e_x"]) == 2
    assert spec_file.read_bytes() == before


def _pool_run(tmp_path, routes, own_ids="", docs_ids="", extra=()):
    import json
    brain = _load("brain")
    workdir = tmp_path / "run"
    workdir.mkdir(exist_ok=True)
    summary = workdir / "enum.json"
    summary.write_text(json.dumps({"surface": {"routes": routes,
                                              "docs": []}}))
    code = brain.main(["hypotheses", "pool", "--workdir", str(workdir),
                       "--summary", str(summary), "--own-ids", own_ids,
                       "--docs-ids", docs_ids, *extra])
    pool = json.loads((workdir / "object-pool.json").read_text())
    return code, pool


def test_pool_auto_narrows_radius_to_budget(tmp_path):
    code, pool = _pool_run(tmp_path, ["/api/documents/1043/download"],
                           own_ids="7", docs_ids="1001")
    assert code == 0
    assert pool["radius"] == 5
    assert pool["estimated_calls"] <= pool["budget_calls"]
    for value in (1043, 7, 1001, 1042, 1044):
        assert value in pool["candidates"]


def test_pool_auto_keeps_full_ladder_for_small_pool(tmp_path):
    code, pool = _pool_run(tmp_path, [], own_ids="docs:1001")
    assert code == 0
    assert pool["radius"] == 25
    for value in (1001, 976):
        assert {"family": "docs", "format": "int", "value": value} in pool["candidates"]


def test_pool_explicit_radius_over_budget_exits_two(tmp_path):
    import json
    brain = _load("brain")
    workdir = tmp_path / "run"
    workdir.mkdir()
    summary = workdir / "enum.json"
    summary.write_text(json.dumps({"surface": {"routes": [], "docs": []}}))
    assert brain.main(["hypotheses", "pool", "--workdir", str(workdir),
                       "--summary", str(summary), "--own-ids", "7",
                       "--radius", "25", "--budget-calls", "10"]) == 2
    assert not (workdir / "object-pool.json").exists()


def test_pool_truncates_and_reports_when_seeds_overflow(tmp_path):
    own = ",".join(f"docs:{1000 + i}" for i in range(30))
    code, pool = _pool_run(tmp_path, [], own_ids=own)
    assert code == 0
    assert pool["truncated"] is True
    assert len(pool["candidates"]) + 4 <= pool["budget_calls"]
    assert pool["dropped"] == 30 - len(pool["candidates"])


def _load_server():
    path = REPO_ROOT / "mcp-servers" / "mcp-kali-tools" / "server.py"
    spec = importlib.util.spec_from_file_location("kali_server_batch_test",
                                                  path)
    module = importlib.util.module_from_spec(spec)
    sys.modules[spec.name] = module
    spec.loader.exec_module(module)
    return module


def _batch_run(tmp_path, monkeypatch):
    server = _load_server()
    monkeypatch.setenv("CCO_HOME", str(tmp_path / ".cco"))
    monkeypatch.setenv("CCO_WORKDIR", str(tmp_path))
    monkeypatch.delenv("CCO_ATTEMPT_HMAC_KEY", raising=False)
    run = tmp_path / "run"
    run.mkdir()
    (run / "hypotheses.json").write_text("{}")
    return server, run


def _item(vector, verdict, **extra):
    record = {"vector": vector, "endpoint": "/p", "identity": "own",
              "verdict": verdict}
    record.update(extra)
    return record


def test_ledger_batch_appends_all(tmp_path, monkeypatch):
    import json
    server, run = _batch_run(tmp_path, monkeypatch)
    out = json.loads(server.ledger_attempt_add_batch(
        str(run), json.dumps([_item("ssrf", "a"), _item("ssrf", "b"),
                              _item("ssrf", "c")])))
    assert [r["ok"] for r in out["results"]] == [True, True, True]
    assert [r["seq"] for r in out["results"]] == [1, 2, 3]


def test_ledger_batch_partial_failure_continues(tmp_path, monkeypatch):
    import json
    server, run = _batch_run(tmp_path, monkeypatch)
    bad = {"endpoint": "/p", "identity": "own", "verdict": "x"}
    out = json.loads(server.ledger_attempt_add_batch(
        str(run), json.dumps([_item("ssrf", "a"), bad, _item("ssrf", "c")])))
    assert [r["ok"] for r in out["results"]] == [True, False, True]
    assert "vector" in out["results"][1]["error"]


def test_ledger_batch_rejects_non_list_input(tmp_path, monkeypatch):
    import json
    server, run = _batch_run(tmp_path, monkeypatch)
    for raw in ('{"a": 1}', '"str"', '5', '[]', 'null', 'NOT JSON'):
        out = json.loads(server.ledger_attempt_add_batch(str(run), raw))
        assert "error" in out, raw
    assert not (run / "attempts.jsonl").exists()


def test_ledger_batch_halts_on_broken_chain(tmp_path, monkeypatch):
    import json
    server, run = _batch_run(tmp_path, monkeypatch)
    (run / "attempts.jsonl").write_text("NOT JSON {{{\n")
    out = json.loads(server.ledger_attempt_add_batch(
        str(run), json.dumps([_item("ssrf", "a"), _item("ssrf", "b")])))
    assert [r["ok"] for r in out["results"]] == [False, False]
    assert "halted" in out["results"][0]["error"]
    assert (run / "attempts.jsonl").read_text() == "NOT JSON {{{\n"


def _curl_server(tmp_path, monkeypatch):
    server = _load_server()
    monkeypatch.setenv("CCO_WORKDIR", str(tmp_path))
    captured = {}
    def _fake(cmd, timeout=300, cwd=None, retries=1):
        captured["cmd"] = cmd
        return {"stdout": "done", "stderr": "", "returncode": 0}

    monkeypatch.setattr(server, "run_command", _fake)
    return server, captured


def test_curl_multipart_fields(tmp_path, monkeypatch):
    server, captured = _curl_server(tmp_path, monkeypatch)
    server.curl_request("http://t/upload", method="POST",
                        multipart="name=avatar;desc=hello")
    assert "-F name=avatar" in captured["cmd"]
    assert "-F desc=hello" in captured["cmd"]


def test_curl_multipart_file_inside_workdir(tmp_path, monkeypatch):
    server, captured = _curl_server(tmp_path, monkeypatch)
    target = tmp_path / "ev" / "up.bin"
    target.parent.mkdir(parents=True)
    target.write_bytes(b"x")
    server.curl_request("http://t/upload", method="POST",
                        multipart=f"f=@{target}")
    assert "-F f=@" in captured["cmd"]


def test_curl_multipart_file_outside_rejected(tmp_path, monkeypatch):
    server, captured = _curl_server(tmp_path, monkeypatch)
    out = server.curl_request("http://t/upload", method="POST",
                              multipart="f=@/etc/passwd")
    assert "HATA" in out and "cmd" not in captured


def test_curl_multipart_malformed_rejected(tmp_path, monkeypatch):
    server, captured = _curl_server(tmp_path, monkeypatch)
    out = server.curl_request("http://t/upload", method="POST",
                              multipart="no-equals-here")
    assert "HATA" in out and "cmd" not in captured


def test_curl_insecure_tls_flag(tmp_path, monkeypatch):
    server, captured = _curl_server(tmp_path, monkeypatch)
    server.curl_request("https://t/", insecure_tls=True)
    assert " -k " in captured["cmd"]
    captured.clear()
    server.curl_request("https://t/")
    assert " -k " not in captured["cmd"]


def test_check_warns_on_noncanonical_vector(tmp_path, monkeypatch, capsys):
    import json
    brain = _load("brain")
    hl = _load("hypothesis_ledger")
    ts = _load("orchestration_spec")
    al = _load("attempt_ledger")
    home = tmp_path / "home"
    home.mkdir()
    monkeypatch.setenv("CCO_HOME", str(home))
    monkeypatch.delenv("CCO_ATTEMPT_HMAC_KEY", raising=False)
    workdir = tmp_path / "run"
    workdir.mkdir()
    specs = brain.build_plan("http://127.0.0.1:8899", str(workdir))
    spec_file = workdir / "specs.json"
    spec_file.write_text(ts.dump_specs(specs))
    ledger = hl.init_ledger("http://127.0.0.1:8899", vectors=["csrf"],
                            max_attempts=2)
    hl.save_ledger(workdir, ledger)
    al.append_record(al.ledger_path(workdir), {
        "vector": "csrf-logout", "endpoint": "/logout", "identity": "own",
        "verdict": "probe", "status": 200})
    assert brain.main(["check", "--spec", str(spec_file),
                       "--workdir", str(workdir)]) == 0
    assert "not canonical" in capsys.readouterr().out
