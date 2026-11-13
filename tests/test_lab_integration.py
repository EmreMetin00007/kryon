"""Embedded and external loopback e2e validation for Hunter + Validator."""

import importlib.util
import os
import threading
import time


REPO = os.path.dirname(os.path.dirname(os.path.abspath(__file__)))


def _load(path, name):
    spec = importlib.util.spec_from_file_location(name, path)
    module = importlib.util.module_from_spec(spec)
    spec.loader.exec_module(module)
    return module


def _load_lab_validate():
    return _load(os.path.join(REPO, "scripts", "lab-validate.py"), "lab_validate_test")


def _load_vuln_lab():
    return _load(os.path.join(REPO, "scripts", "lab", "vuln_lab.py"), "vuln_lab_test")


def test_lab_validation_embedded_mode():
    lab_validate = _load_lab_validate()
    result = lab_validate.run_validation(skip_rag=True, quiet=True)
    assert result["all_passed"] is True, [row for row in result["checks"] if not row["passed"]]
    assert result["passed"] == result["total"]
    names = {item["name"] for item in result["checks"]}
    assert "validator XSS reflection-only candidate" in names
    assert "BOLA confirmed" in names
    assert "discover ingest" in names
    assert "discover wordlist from js/openapi" in names
    assert "parse_zap fixture" in names
    assert "confirmed count" in names
    assert "fuzz XSS likely" in names
    assert "exploit_confirmed SQLi pack" in names
    assert "web loop confirmed" in names
    assert "validator safe auth bypass unconfirmed" in names
    assert "validator WAF SQLi retry confirmed" in names
    assert "lab WAF blocks canonical SQLi" in names


def test_lab_validation_external_base_url_mode():
    vuln_lab = _load_vuln_lab()
    lab_validate = _load_lab_validate()
    server = vuln_lab.serve(0)
    thread = threading.Thread(target=server.serve_forever, daemon=True)
    thread.start()
    try:
        time.sleep(0.2)
        base = f"http://127.0.0.1:{server.server_address[1]}"
        result = lab_validate.run_validation(base_url=base, skip_rag=True, quiet=True)
        assert result["all_passed"] is True, [row for row in result["checks"] if not row["passed"]]
        assert any(item["name"] == "validator safe open redirect unconfirmed" for item in result["checks"])
    finally:
        server.shutdown()
