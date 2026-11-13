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


def _run(tmp_path, monkeypatch, entries, records=()):
    brain = _load("brain")
    hl = _load("hypothesis_ledger")
    ts = _load("orchestration_spec")
    al = _load("attempt_ledger")
    home = tmp_path / "home"
    home.mkdir(exist_ok=True)
    monkeypatch.setenv("CCO_HOME", str(home))
    monkeypatch.delenv("CCO_ATTEMPT_HMAC_KEY", raising=False)
    workdir = tmp_path / "run"
    workdir.mkdir(exist_ok=True)
    specs = brain.build_plan("http://127.0.0.1:8899", str(workdir))
    spec_file = workdir / "specs.json"
    spec_file.write_text(ts.dump_specs(specs))
    ledger = hl.init_ledger("http://127.0.0.1:8899",
                            vectors=[vector for vector, _, _ in entries],
                            max_attempts=2)
    for vector, status, note in entries:
        if status == "untried":
            continue
        target = hl.claim_next(ledger)
        assert target is not None and target["vector"] == vector
        hl.mark(ledger, vector, status, note=note)
        if status == "confirmed":
            record = make_signed_validation(ledger["target"], brain._VALIDATOR_VECTOR_TYPES[vector])
            target.update(brain._confirmation_reference(record))
    hl.save_ledger(workdir, ledger)
    for record in records:
        al.append_record(al.ledger_path(workdir), record)
    return brain, workdir, spec_file


def test_session_save_load_roundtrip(tmp_path):
    store = _load("session_store")
    workdir = tmp_path / "run"
    workdir.mkdir()
    (workdir / "seed").mkdir()
    (workdir / "seed" / "jar.txt").write_text("cookie-jar")
    saved = store.save_session(workdir, "owner", "seed/jar.txt")
    assert saved["identity"] == "owner"
    assert store.load_session(workdir)["jar_pointer"] == "seed/jar.txt"
    assert store.session_status(workdir)["state"] == "ok"


def test_session_status_missing(tmp_path):
    store = _load("session_store")
    workdir = tmp_path / "run"
    workdir.mkdir()
    assert store.session_status(workdir)["state"] == "missing"


def test_session_status_stale_when_jar_gone(tmp_path):
    store = _load("session_store")
    workdir = tmp_path / "run"
    workdir.mkdir()
    (workdir / "seed").mkdir()
    jar = workdir / "seed" / "jar.txt"
    jar.write_text("cookie-jar")
    store.save_session(workdir, "owner", "seed/jar.txt")
    jar.unlink()
    status = store.session_status(workdir)
    assert status["state"] == "stale"


def test_session_status_broken_on_bad_json(tmp_path):
    store = _load("session_store")
    workdir = tmp_path / "run"
    workdir.mkdir()
    (workdir / "target-session.json").write_text("NOT JSON {{{")
    assert store.session_status(workdir)["state"] == "broken"


def test_session_save_refuses_secret_values(tmp_path):
    store = _load("session_store")
    workdir = tmp_path / "run"
    workdir.mkdir()
    try:
        store.save_session(workdir, "owner; rb_session=abc123", "seed/jar.txt")
    except ValueError:
        pass
    else:
        raise AssertionError("cookie-like identity accepted")
    try:
        store.save_session(workdir, "owner", "/tmp/abs.jar")
    except ValueError:
        pass
    else:
        raise AssertionError("absolute pointer accepted")
    try:
        store.save_session(workdir, "owner", "../escape.jar")
    except ValueError:
        pass
    else:
        raise AssertionError("parent-escape pointer accepted")


def test_session_save_refuses_bare_token(tmp_path):
    store = _load("session_store")
    workdir = tmp_path / "run"
    workdir.mkdir()
    jwt = ("eyJhbGciOiJIUzI1NiJ9.eyJzdWIiOiIxMjM0NTY3ODkwIn0"
           ".dBjftJeZ4CVP-mB92K27uhbUJU1p1r_wW1gFWFOEjXk")
    try:
        store.save_session(workdir, jwt, "seed/jar.txt")
    except ValueError:
        pass
    else:
        raise AssertionError("bare JWT identity accepted")
    try:
        store.save_session(workdir, "owner", jwt)
    except ValueError:
        pass
    else:
        raise AssertionError("bare JWT pointer accepted")


def test_session_save_refuses_escaping_symlink(tmp_path):
    store = _load("session_store")
    workdir = tmp_path / "run"
    (workdir / "seed").mkdir(parents=True)
    outside = tmp_path / "outside.txt"
    outside.write_text("secret")
    link = workdir / "seed" / "jar.txt"
    link.symlink_to(outside)
    try:
        store.save_session(workdir, "owner", "seed/jar.txt")
    except ValueError:
        pass
    else:
        raise AssertionError("escaping symlink pointer accepted")


def test_session_status_broken_on_escaping_symlink(tmp_path):
    store = _load("session_store")
    workdir = tmp_path / "run"
    (workdir / "seed").mkdir(parents=True)
    outside = tmp_path / "outside.txt"
    outside.write_text("secret")
    (workdir / "seed" / "jar.txt").symlink_to(outside)
    (workdir / "target-session.json").write_text(json.dumps(
        {"identity": "owner", "jar_pointer": "seed/jar.txt"}))
    status = store.session_status(workdir)
    assert status["state"] == "broken"
    assert "escapes" in status["detail"]


def test_session_status_broken_on_valid_json_bad_schema(tmp_path):
    store = _load("session_store")
    workdir = tmp_path / "run"
    workdir.mkdir()
    (workdir / "target-session.json").write_text(json.dumps({"foo": 1}))
    assert store.session_status(workdir)["state"] == "broken"


def test_session_status_command_reports_and_guides(tmp_path, monkeypatch, capsys):
    brain = _load("brain")
    workdir = tmp_path / "run"
    workdir.mkdir()
    assert brain.main(["session", "status", "--workdir", str(workdir)]) == 0
    out = capsys.readouterr().out
    assert '"missing"' in out and "re-login" in out


def test_closure_rejects_auth_park_without_recovery(tmp_path, monkeypatch, capsys):
    brain, workdir, spec_file = _run(
        tmp_path, monkeypatch,
        [("ssrf", "confirmed", "validator artifact"),
         ("authn-session", "not_applicable",
          "not_tested: auth:recovered session lost; re-login pending")])
    assert brain.main(["check", "--spec", str(spec_file),
                       "--workdir", str(workdir), "--closure"]) == 2
    assert "session-recovery" in capsys.readouterr().out


def test_closure_accepts_auth_park_with_recovery(tmp_path, monkeypatch):
    brain, workdir, spec_file = _run(
        tmp_path, monkeypatch, [
            ("ssrf", "confirmed", "validator artifact"),
            ("authn-session", "not_applicable",
             "not_tested: auth:recovered re-login still 401; session dead")],
        records=[{"vector": "authn-session", "endpoint": "/login",
                  "identity": "owner", "verdict": "session-recovery",
                  "status": 401,
                  "note": "re-login attempt with seeded account"}])
    assert brain.main(["check", "--spec", str(spec_file),
                       "--workdir", str(workdir), "--closure"]) == 0


def test_closure_accepts_attested_non_auth_park(tmp_path, monkeypatch):
    brain, workdir, spec_file = _run(
        tmp_path, monkeypatch,
        [("ssrf", "confirmed", "validator artifact"),
         ("injection-sqli", "not_applicable",
          "auth:not-required: no such surface")])
    assert brain.main(["check", "--spec", str(spec_file),
                       "--workdir", str(workdir), "--closure"]) == 0


def test_closure_rejects_missing_attestation(tmp_path, monkeypatch, capsys):
    brain, workdir, spec_file = _run(
        tmp_path, monkeypatch,
        [("ssrf", "confirmed", "validator artifact"),
         ("injection-sqli", "not_applicable", "no such surface")])
    assert brain.main(["check", "--spec", str(spec_file),
                       "--workdir", str(workdir), "--closure"]) == 2
    assert "auth attestation" in capsys.readouterr().out


def test_closure_rejects_recovery_on_wrong_vector(tmp_path, monkeypatch):
    brain, workdir, spec_file = _run(
        tmp_path, monkeypatch, [
            ("ssrf", "confirmed", "validator artifact"),
            ("authn-session", "not_applicable",
             "not_tested: auth:recovered session lost")],
        records=[{"vector": "ssrf", "endpoint": "/login",
                  "identity": "owner", "verdict": "session-recovery",
                  "status": 200}])
    assert brain.main(["check", "--spec", str(spec_file),
                       "--workdir", str(workdir), "--closure"]) == 2


def test_closure_rejects_forged_recovery_record(tmp_path, monkeypatch):
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
    ledger = hl.init_ledger("http://127.0.0.1:8899",
                            vectors=["authn-session"], max_attempts=2)
    hl.claim_next(ledger)
    hl.mark(ledger, "authn-session", "not_applicable",
            note="not_tested: auth:recovered re-login done")
    hl.save_ledger(workdir, ledger)
    forged = {"vector": "authn-session", "endpoint": "/login",
              "identity": "owner", "verdict": "session-recovery",
              "status": 200, "seq": 1, "prev_hash": "0" * 64,
              "record_hash": "f" * 64, "signature_alg": "hmac-sha256:v1",
              "signature": "0" * 64}
    al.ledger_path(workdir).write_text(json.dumps(forged) + "\n")
    assert brain.main(["check", "--spec", str(spec_file),
                       "--workdir", str(workdir), "--closure"]) == 2


def test_closure_rejects_foreign_key_recovery(tmp_path, monkeypatch):
    brain = _load("brain")
    hl = _load("hypothesis_ledger")
    ts = _load("orchestration_spec")
    al = _load("attempt_ledger")
    home_a = tmp_path / "home-a"
    home_a.mkdir()
    home_b = tmp_path / "home-b"
    home_b.mkdir()
    workdir = tmp_path / "run"
    workdir.mkdir()
    monkeypatch.setenv("CCO_HOME", str(home_b))
    monkeypatch.delenv("CCO_ATTEMPT_HMAC_KEY", raising=False)
    al.append_record(al.ledger_path(workdir), {
        "vector": "authn-session", "endpoint": "/login", "identity": "own",
        "verdict": "session-recovery", "status": 200})
    monkeypatch.setenv("CCO_HOME", str(home_a))
    specs = brain.build_plan("http://127.0.0.1:8899", str(workdir))
    spec_file = workdir / "specs.json"
    spec_file.write_text(ts.dump_specs(specs))
    ledger = hl.init_ledger("http://127.0.0.1:8899",
                            vectors=["authn-session"], max_attempts=2)
    hl.claim_next(ledger)
    hl.mark(ledger, "authn-session", "not_applicable",
            note="not_tested: auth:recovered re-login done")
    hl.save_ledger(workdir, ledger)
    assert brain.main(["check", "--spec", str(spec_file),
                       "--workdir", str(workdir), "--closure"]) == 2
