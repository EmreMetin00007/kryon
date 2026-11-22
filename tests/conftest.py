"""Kryon pytest configuration — isolated CCO_HOME per test session, offline by default."""
from __future__ import annotations

import os
import tempfile

import pytest

REPO_ROOT = os.path.dirname(os.path.dirname(os.path.abspath(__file__)))


@pytest.hookimpl(tryfirst=True)
def pytest_configure(config):
    """Set isolation before pytest imports test modules during collection."""
    config._cco_test_previous_env = {
        key: os.environ.get(key) for key in ("CCO_HOME", "CCO_VAULT_KEY", "CCO_USE_KEYRING")
    }
    config._cco_test_home = tempfile.TemporaryDirectory(prefix="cco_pytest_")
    os.environ["CCO_HOME"] = config._cco_test_home.name
    os.environ.pop("CCO_VAULT_KEY", None)
    os.environ["CCO_USE_KEYRING"] = "0"


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
