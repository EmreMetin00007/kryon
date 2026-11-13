"""
CCO pytest konfigürasyonu — testler izole bir CCO_HOME kullanır,
gerçek ~/.cco verisine dokunmaz. Tüm testler OFFLINE çalışır (network yok).
"""
import os
import sys
import tempfile
import importlib.util

import pytest

REPO_ROOT = os.path.dirname(os.path.dirname(os.path.abspath(__file__)))
SERVERS_DIR = os.path.join(REPO_ROOT, "mcp-servers")


@pytest.hookimpl(tryfirst=True)
def pytest_configure(config):
    """Set isolation before pytest imports test modules during collection."""
    config._cco_test_previous_env = {
        key: os.environ.get(key) for key in ("CCO_HOME", "CCO_GRAPH_BACKEND", "CCO_VAULT_KEY", "CCO_USE_KEYRING")
    }
    config._cco_test_home = tempfile.TemporaryDirectory(prefix="cco_pytest_")
    os.environ["CCO_HOME"] = config._cco_test_home.name
    os.environ.pop("CCO_VAULT_KEY", None)
    os.environ["CCO_USE_KEYRING"] = "0"
    # Kuzu's single-writer lock is tested separately with its own fixture.
    os.environ["CCO_GRAPH_BACKEND"] = "networkx"


def pytest_unconfigure(config):
    previous = getattr(config, "_cco_test_previous_env", {})
    for key, value in previous.items():
        if value is None:
            os.environ.pop(key, None)
        else:
            os.environ[key] = value
    home = getattr(config, "_cco_test_home", None)
    if home is not None:
        home.cleanup()


@pytest.fixture(scope="session", autouse=True)
def isolated_cco_home(request):
    """Expose the same isolated home initialized before collection."""
    yield request.config._cco_test_home.name


def load_server(name: str):
    """mcp-<name>/server.py modülünü izole şekilde yükle, modülü döndür."""
    path = os.path.join(SERVERS_DIR, f"mcp-{name}", "server.py")
    spec = importlib.util.spec_from_file_location(f"cco_{name.replace('-', '_')}", path)
    mod = importlib.util.module_from_spec(spec)
    sys.modules[spec.name] = mod
    spec.loader.exec_module(mod)
    return mod


def list_tool_names(mod):
    import asyncio
    return [t.name for t in asyncio.run(mod.mcp.list_tools())]


class FakeCDPSession:
    """Protocol double for unit tests; never counts as Chromium evidence."""
    def __init__(self):
        self.handlers, self.calls = {}, []
        self.detached = False

    def send(self, method, params=None):
        self.calls.append((method, params))
        return {"targetInfo": {"targetId": "owned-test-target", "browserContextId": "owned-test-context"}}

    def on(self, event, handler):
        self.handlers[event] = handler

    def detach(self):
        self.detached = True


class FakeCDPContext:
    def close(self):
        pass

    def new_page(self):
        page = type("OwnedPage", (), {"wait_for_timeout": lambda self, _ms: None})()
        self.pages.append(page)
        return page

    @property
    def browser(self):
        return self

    def new_browser_cdp_session(self):
        self.cdp_root = FakeBrowserCDPSession()
        return self.cdp_root

    def new_cdp_session(self, frame):
        if not hasattr(self, "cdp_sessions"):
            self.cdp_sessions = []
        session = FakeCDPSession()
        self.cdp_sessions.append(session)
        return session


class FakeCDPFrame:
    page = object()


class FakeBrowserCDPSession(FakeCDPSession):
    def __init__(self):
        super().__init__()
        self.protocol_calls = []

    def send(self, method, params=None):
        import json
        self.calls.append((method, params))
        if method == "Target.getTargets":
            return {"targetInfos": [{"targetId": "owned-test-target", "browserContextId": "owned-test-context",
                                     "type": "page"}]}
        elif method == "Target.attachToTarget":
            self.handlers["Target.attachedToTarget"]({"sessionId": "owned-session", "waitingForDebugger": False,
                "targetInfo": {"targetId": "owned-test-target", "browserContextId": "owned-test-context", "type": "page"}})
            return {"sessionId": "owned-session"}
        elif method == "Target.sendMessageToTarget":
            message = json.loads(params["message"])
            self.protocol_calls.append((message["method"], message["params"]))
            self.handlers["Target.receivedMessageFromTarget"]({"sessionId": params["sessionId"],
                "message": json.dumps({"id": message["id"], "result": {}})})
        return {}

    def emit(self, method, params):
        import json
        self.handlers["Target.receivedMessageFromTarget"]({"sessionId": "owned-session",
            "message": json.dumps({"method": method, "params": params})})


def make_signed_validation(target: str, kind: str) -> dict:
    """A real persisted test artifact; never replace verification with a bool."""
    import uuid
    from pathlib import Path

    validator_dir = os.path.join(SERVERS_DIR, "mcp-validator")
    if validator_dir not in sys.path:
        sys.path.insert(0, validator_dir)
    from cco_validator_core.evidence import SCHEMA_VERSION, persist_result

    return persist_result({
        "schema_version": SCHEMA_VERSION, "validation_id": str(uuid.uuid4()),
        "target": target, "vuln_type": kind, "verdict": "CONFIRMED",
        "oracle": "offline-test", "evidence": {"marker": "synthetic"},
    }, str(Path(os.environ["CCO_HOME"]) / "validations"))
