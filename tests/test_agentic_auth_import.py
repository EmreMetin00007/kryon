"""Unit tests for zero-runtime-overhead Playwright storage_state importer and vault helper."""
from __future__ import annotations

import json
import os
from pathlib import Path
import subprocess
import sys
from typing import Any

import pytest

REPO_ROOT = Path(__file__).resolve().parent.parent
SCRIPTS_DIR = REPO_ROOT / "scripts"
if str(SCRIPTS_DIR) not in sys.path:
    sys.path.insert(0, str(SCRIPTS_DIR))

import agentic_auth_import as auth_import  # noqa: E402
import agentic_vault  # noqa: E402
from agentic_http import ActorManager  # noqa: E402


# ---------------------------------------------------------------------------
# 1. parse_storage_state_spec
# ---------------------------------------------------------------------------


def test_parse_storage_state_spec_all_supported_formats() -> None:
    assert auth_import.parse_storage_state_spec("buyer=/tmp/buyer.json") == (
        "buyer",
        "member",
        "",
        Path("/tmp/buyer.json"),
    )
    assert auth_import.parse_storage_state_spec("ops:admin=/tmp/ops.json") == (
        "ops",
        "admin",
        "",
        Path("/tmp/ops.json"),
    )
    assert auth_import.parse_storage_state_spec("ops:admin:acme=/tmp/ops.json") == (
        "ops",
        "admin",
        "acme",
        Path("/tmp/ops.json"),
    )
    assert auth_import.parse_storage_state_spec("/tmp/plain-state.json") == (
        "browser-user",
        "member",
        "",
        Path("/tmp/plain-state.json"),
    )
    # Path containing '=' is preserved via maxsplit=1; blank role defaults to member.
    assert auth_import.parse_storage_state_spec("u1::tenant_a=/tmp/dir=1/state.json") == (
        "u1",
        "member",
        "tenant_a",
        Path("/tmp/dir=1/state.json"),
    )
    alias, role, tenant, expanded = auth_import.parse_storage_state_spec("u2=~/auth/state.json")
    assert (alias, role, tenant) == ("u2", "member", "")
    assert expanded == Path("~/auth/state.json").expanduser()


@pytest.mark.parametrize(
    "bad_spec",
    [
        "",
        "   ",
        "anon=/tmp/state.json",
        "ANON:member=/tmp/state.json",
        "=/tmp/state.json",
        ":admin=/tmp/state.json",
        "buyer=",
        "buyer:member=",
        "a:b:c:d=/tmp/state.json",
        "bad alias=/tmp/state.json",
        "buyer=/tmp/bad\npath.json",
    ],
)
def test_parse_storage_state_spec_rejects_invalid_inputs(bad_spec: str) -> None:
    with pytest.raises(ValueError):
        auth_import.parse_storage_state_spec(bad_spec)


# ---------------------------------------------------------------------------
# 2. load_storage_state_actor: cookie scoping, expiry, secure policy
# ---------------------------------------------------------------------------


def test_load_storage_state_actor_cookie_scoping_expiry_and_duplicate_precedence() -> None:
    now_ts = 1_750_000_000.0
    state: dict[str, Any] = {
        "cookies": [
            # Exact host match
            {
                "name": "host_sid",
                "value": "exact-host-cookie",
                "domain": "app.example.com",
                "path": "/",
                "expires": now_ts + 3600,
                "secure": True,
            },
            # Leading-dot wildcard parent domain match
            {
                "name": "sso_shared",
                "value": "parent-domain-cookie",
                "domain": ".example.com",
                "path": "/",
                "expires": -1,
                "secure": True,
            },
            # Duplicate cookie name: parent domain vs exact host -> exact host must win
            {
                "name": "dup_cookie",
                "value": "from-parent",
                "domain": ".example.com",
                "path": "/",
                "expires": -1,
                "secure": True,
            },
            {
                "name": "dup_cookie",
                "value": "from-exact-host",
                "domain": "app.example.com",
                "path": "/",
                "expires": -1,
                "secure": True,
            },
            # Duplicate cookie name on same host: root '/' must win over narrower '/sub'
            {
                "name": "path_dup",
                "value": "from-root",
                "domain": "app.example.com",
                "path": "/",
                "expires": 0,
                "secure": False,
            },
            {
                "name": "path_dup",
                "value": "from-subpath",
                "domain": "app.example.com",
                "path": "/sub",
                "expires": 0,
                "secure": False,
            },
            # Cross-domain cookies: MUST be excluded
            {
                "name": "evil_cookie",
                "value": "evil-val",
                "domain": "evil.com",
                "path": "/",
                "expires": now_ts + 3600,
                "secure": True,
            },
            {
                "name": "sibling_cookie",
                "value": "sibling-val",
                "domain": "other.example.com",
                "path": "/",
                "expires": now_ts + 3600,
                "secure": True,
            },
            {
                "name": "suffix_trick",
                "value": "trick-val",
                "domain": "notexample.com",
                "path": "/",
                "expires": now_ts + 3600,
                "secure": True,
            },
            {
                "name": "tld_supercookie",
                "value": "tld-val",
                "domain": ".com",
                "path": "/",
                "expires": now_ts + 3600,
                "secure": True,
            },
            # Expired cookie: MUST be excluded
            {
                "name": "expired_sid",
                "value": "stale-val",
                "domain": "app.example.com",
                "path": "/",
                "expires": now_ts - 10,
                "secure": True,
            },
            # Cookie CSRF token on scoped host
            {
                "name": "XSRF-TOKEN",
                "value": "cookie-csrf-9988",
                "domain": ".example.com",
                "path": "/",
                "expires": now_ts + 3600,
                "secure": True,
            },
            # Cross-domain CSRF cookie: MUST be ignored
            {
                "name": "csrftoken",
                "value": "cross-domain-csrf",
                "domain": "other.example.com",
                "path": "/",
                "expires": now_ts + 3600,
                "secure": True,
            },
        ],
        "origins": [],
    }

    actor = auth_import.load_storage_state_actor(
        state,
        base_url="https://app.example.com/",
        alias="member1",
        role="editor",
        tenant="acme",
        now=now_ts,
    )
    assert actor["alias"] == "member1"
    assert actor["role"] == "editor"
    assert actor["tenant"] == "acme"
    assert actor["source"] == "storage_state"
    assert actor["authenticated"] is True
    assert actor["cookies"] == {
        "host_sid": "exact-host-cookie",
        "sso_shared": "parent-domain-cookie",
        "dup_cookie": "from-exact-host",
        "path_dup": "from-root",
        "XSRF-TOKEN": "cookie-csrf-9988",
    }
    assert actor["csrf_token"] == "cookie-csrf-9988"
    assert actor["headers"] == {}
    assert actor["auth_header"] == ""
    assert actor["access_token"] == ""


def test_load_storage_state_actor_secure_cookie_policy() -> None:
    def _state_for(domain: str) -> dict[str, Any]:
        return {
            "cookies": [
                {
                    "name": "sec_cookie",
                    "value": "sec-val",
                    "domain": domain,
                    "path": "/",
                    "expires": -1,
                    "secure": True,
                },
                {
                    "name": "plain_cookie",
                    "value": "plain-val",
                    "domain": domain,
                    "path": "/",
                    "expires": -1,
                    "secure": False,
                },
            ],
            "origins": [],
        }

    # HTTPS allows secure=True
    https_actor = auth_import.load_storage_state_actor(
        _state_for("app.example.com"),
        base_url="https://app.example.com/",
    )
    assert https_actor["cookies"] == {"sec_cookie": "sec-val", "plain_cookie": "plain-val"}

    # Loopback HTTP (127.0.0.1, localhost, [::1]) allows secure=True
    for loopback_host, loopback_url in (
        ("127.0.0.1", "http://127.0.0.1:8080/"),
        ("localhost", "http://localhost:3000/"),
        ("::1", "http://[::1]:8080/"),
    ):
        lb_actor = auth_import.load_storage_state_actor(
            _state_for(loopback_host),
            base_url=loopback_url,
        )
        assert lb_actor["cookies"] == {"sec_cookie": "sec-val", "plain_cookie": "plain-val"}

    # Non-loopback HTTP skips secure=True but keeps secure=False
    http_remote_actor = auth_import.load_storage_state_actor(
        _state_for("staging.example.com"),
        base_url="http://staging.example.com:8080/",
    )
    assert http_remote_actor["cookies"] == {"plain_cookie": "plain-val"}

    # If ONLY a secure cookie exists on non-loopback HTTP, authenticated is False
    only_secure = {
        "cookies": [
            {
                "name": "sec_only",
                "value": "sec-val",
                "domain": "staging.example.com",
                "path": "/",
                "expires": -1,
                "secure": True,
            }
        ],
        "origins": [],
    }
    unauth_actor = auth_import.load_storage_state_actor(
        only_secure,
        base_url="http://staging.example.com/",
    )
    assert unauth_actor["cookies"] == {}
    assert unauth_actor["authenticated"] is False


# ---------------------------------------------------------------------------
# 3. load_storage_state_actor: localStorage bearer & CSRF + origin isolation
# ---------------------------------------------------------------------------


def test_load_storage_state_actor_localstorage_extraction_and_origin_isolation() -> None:
    state: dict[str, Any] = {
        "cookies": [],
        "origins": [
            # Wrong host -> MUST be ignored
            {
                "origin": "https://other.example.com",
                "localStorage": [
                    {"name": "access_token", "value": "other-host-jwt"},
                    {"name": "csrf_token", "value": "other-host-csrf"},
                ],
            },
            # Wrong scheme -> MUST be ignored
            {
                "origin": "http://app.example.com",
                "localStorage": [
                    {"name": "access_token", "value": "http-scheme-jwt"},
                ],
            },
            # Wrong port -> MUST be ignored
            {
                "origin": "https://app.example.com:8443",
                "localStorage": [
                    {"name": "access_token", "value": "wrong-port-jwt"},
                ],
            },
            # Matching origin (explicit :443 matches default https :443)
            {
                "origin": "https://app.example.com:443",
                "localStorage": [
                    {"name": "id_token", "value": "lower-priority-id-tok"},
                    {"name": "accessToken", "value": "Bearer   real-jwt-payload-123"},
                    {"name": "x-xsrf-token", "value": "ls-csrf-token-456"},
                ],
            },
        ],
    }

    actor = auth_import.load_storage_state_actor(
        state,
        base_url="https://app.example.com/dashboard",
        alias="spa_user",
        role="member",
    )
    assert actor["authenticated"] is True
    assert actor["cookies"] == {}
    assert actor["access_token"] == "real-jwt-payload-123"
    assert actor["auth_header"] == "Bearer real-jwt-payload-123"
    assert actor["headers"] == {"Authorization": "Bearer real-jwt-payload-123"}
    assert actor["csrf_token"] == "ls-csrf-token-456"

    # Verify seamless compatibility with ActorManager
    manager = ActorManager([actor])
    session = manager.get("spa_user")
    assert session.authenticated is True
    assert session.access_token == "real-jwt-payload-123"
    assert session.csrf_token == "ls-csrf-token-456"
    post_headers = session.build_headers("POST")
    assert post_headers["Authorization"] == "Bearer real-jwt-payload-123"
    assert post_headers["X-CSRF-Token"] == "ls-csrf-token-456"


@pytest.mark.parametrize(
    "token_key",
    [
        "token",
        "access_token",
        "accessToken",
        "auth_token",
        "authToken",
        "id_token",
        "idToken",
        "jwt",
        "bearer_token",
    ],
)
def test_load_storage_state_actor_supports_all_standard_token_keys(token_key: str) -> None:
    state = {
        "cookies": [],
        "origins": [
            {
                "origin": "http://127.0.0.1:8080",
                "localStorage": [{"name": token_key, "value": '"Bearer synth-tok-val"'}],
            }
        ],
    }
    actor = auth_import.load_storage_state_actor(state, base_url="http://127.0.0.1:8080/")
    assert actor["access_token"] == "synth-tok-val"
    assert actor["auth_header"] == "Bearer synth-tok-val"
    assert actor["authenticated"] is True


def test_load_storage_state_actor_ignores_crlf_injection_and_empty_bearer() -> None:
    state = {
        "cookies": [
            {
                "name": "bad_cookie",
                "value": "ok\r\nX-Injected: 1",
                "domain": "127.0.0.1",
                "path": "/",
                "expires": -1,
            }
        ],
        "origins": [
            {
                "origin": "http://127.0.0.1:8080",
                "localStorage": [
                    {"name": "token", "value": "Bearer   "},
                    {"name": "auth_token", "value": "tok\r\ninjected"},
                    {"name": "csrf_token", "value": "csrf\ninjected"},
                ],
            }
        ],
    }
    actor = auth_import.load_storage_state_actor(state, base_url="http://127.0.0.1:8080/")
    assert actor["cookies"] == {}
    assert actor["access_token"] == ""
    assert actor["auth_header"] == ""
    assert actor["csrf_token"] == ""
    assert actor["authenticated"] is False


# ---------------------------------------------------------------------------
# 4. File safety: symlink rejection, size cap, malformed JSON, zero secret echo
# ---------------------------------------------------------------------------


def test_file_safety_symlink_size_cap_and_no_secret_echo(tmp_path: Path) -> None:
    canary = "CANARY_SUPER_SECRET_COOKIE_VAL_88421"
    valid_path = tmp_path / "state.json"
    valid_path.write_text(
        json.dumps(
            {
                "cookies": [
                    {
                        "name": "sid",
                        "value": canary,
                        "domain": "127.0.0.1",
                        "path": "/",
                        "expires": -1,
                    }
                ],
                "origins": [],
            }
        ),
        encoding="utf-8",
    )

    loaded = auth_import.load_storage_state_actor(valid_path, base_url="http://127.0.0.1:8080/")
    assert loaded["cookies"] == {"sid": canary}

    # Symlink to valid file must be rejected.
    sym = tmp_path / "state-link.json"
    sym.symlink_to(valid_path)
    with pytest.raises(ValueError, match="symlink"):
        auth_import.load_storage_state_actor(sym, base_url="http://127.0.0.1:8080/")

    # Dangling symlink must be rejected.
    dangling = tmp_path / "dangling-link.json"
    dangling.symlink_to(tmp_path / "does-not-exist.json")
    with pytest.raises(ValueError, match="symlink"):
        auth_import.load_storage_state_actor(dangling, base_url="http://127.0.0.1:8080/")

    # Directory (non-regular file) must be rejected.
    with pytest.raises(ValueError, match="regular file"):
        auth_import.load_storage_state_actor(tmp_path, base_url="http://127.0.0.1:8080/")

    # Oversized file (> 5 MB) must be rejected.
    huge_path = tmp_path / "huge.json"
    huge_path.write_bytes(b" " * (auth_import.MAX_STORAGE_STATE_BYTES + 16))
    with pytest.raises(ValueError, match="maximum allowed size"):
        auth_import.load_storage_state_actor(huge_path, base_url="http://127.0.0.1:8080/")

    # Malformed JSON must NOT echo secrets in error text or chained exceptions.
    bad_json = tmp_path / "malformed.json"
    bad_json.write_text(f'{{"cookies": [{{"value": "{canary}"', encoding="utf-8")
    with pytest.raises(ValueError, match="valid JSON") as exc_info:
        auth_import.load_storage_state_actor(bad_json, base_url="http://127.0.0.1:8080/")
    assert canary not in str(exc_info.value)
    assert exc_info.value.__cause__ is None
    assert exc_info.value.__context__ is None

    # Invalid top-level JSON structures must NOT echo secrets.
    for filename, payload_text in (
        ("array.json", json.dumps([canary])),
        ("bad_cookies.json", json.dumps({"cookies": canary})),
        ("bad_origins.json", json.dumps({"origins": canary})),
        ("unrelated.json", json.dumps({"unrelated_secret": canary})),
    ):
        bad_file = tmp_path / filename
        bad_file.write_text(payload_text, encoding="utf-8")
        with pytest.raises(ValueError) as bad_exc:
            auth_import.load_storage_state_actor(bad_file, base_url="http://127.0.0.1:8080/")
        assert canary not in str(bad_exc.value)
        assert bad_exc.value.__cause__ is None


# ---------------------------------------------------------------------------
# 5. Encrypted vault roundtrip & zero secret exposure
# ---------------------------------------------------------------------------


def test_vault_storage_state_roundtrip_and_secret_free_summary(tmp_path: Path) -> None:
    cookie_secret = "SYNTHETIC_VAULT_COOKIE_SECRET_7741"
    bearer_secret = "SYNTHETIC_VAULT_BEARER_SECRET_9912"
    csrf_secret = "SYNTHETIC_VAULT_CSRF_SECRET_3319"

    state_file = tmp_path / "browser-storage.json"
    state_file.write_text(
        json.dumps(
            {
                "cookies": [
                    {
                        "name": "session_id",
                        "value": cookie_secret,
                        "domain": ".shop.example.test",
                        "path": "/",
                        "expires": -1,
                        "secure": True,
                    },
                    {
                        "name": "other_site",
                        "value": "OTHER_SITE_SECRET_0001",
                        "domain": "unrelated.example.net",
                        "path": "/",
                        "expires": -1,
                        "secure": True,
                    },
                ],
                "origins": [
                    {
                        "origin": "https://app.shop.example.test",
                        "localStorage": [
                            {"name": "access_token", "value": f"Bearer {bearer_secret}"},
                            {"name": "csrf_token", "value": csrf_secret},
                        ],
                    }
                ],
            }
        ),
        encoding="utf-8",
    )

    vault_home = tmp_path / "cco_home"
    summary = auth_import.save_storage_state_to_vault(
        vault_home,
        "shop_buyer_state",
        state_file,
        alias="shop_buyer",
        role="customer",
        tenant="retail_tr",
        target_url="https://app.shop.example.test/",
    )

    assert summary == {
        "saved": True,
        "key_name": "shop_buyer_state",
        "alias": "shop_buyer",
        "cookie_count": 2,
        "origin_count": 1,
    }
    serialized_summary = json.dumps(summary)
    for secret in (cookie_secret, bearer_secret, csrf_secret, "OTHER_SITE_SECRET_0001"):
        assert secret not in serialized_summary

    # Vault index on disk must never contain plaintext secrets.
    index_text = (vault_home / "agentic_vault_index.json").read_text(encoding="utf-8")
    for secret in (cookie_secret, bearer_secret, csrf_secret):
        assert secret not in index_text

    # Roundtrip load using stored metadata
    actor = auth_import.load_storage_state_actor_from_vault(
        vault_home,
        "shop_buyer_state",
        base_url="https://app.shop.example.test/",
    )
    assert actor == {
        "alias": "shop_buyer",
        "role": "customer",
        "tenant": "retail_tr",
        "cookies": {"session_id": cookie_secret},
        "cookie_records": [
            {
                "name": "session_id",
                "value": cookie_secret,
                "domain": ".shop.example.test",
                "path": "/",
                "secure": True,
                "host_only": False,
            }
        ],
        "headers": {"Authorization": f"Bearer {bearer_secret}"},
        "local_storage": {
            "access_token": f"Bearer {bearer_secret}",
            "csrf_token": csrf_secret,
        },
        "local_storage_by_origin": {
            "https://app.shop.example.test": {
                "access_token": f"Bearer {bearer_secret}",
                "csrf_token": csrf_secret,
            }
        },
        "auth_header": f"Bearer {bearer_secret}",
        "access_token": bearer_secret,
        "csrf_token": csrf_secret,
        "authenticated": True,
        "source": "storage_state",
    }

    # Explicit alias/role/tenant overrides take precedence
    overridden = auth_import.load_storage_state_actor_from_vault(
        vault_home,
        "shop_buyer_state",
        base_url="https://app.shop.example.test/",
        alias="override_actor",
        role="admin",
        tenant="retail_eu",
    )
    assert overridden["alias"] == "override_actor"
    assert overridden["role"] == "admin"
    assert overridden["tenant"] == "retail_eu"
    assert overridden["authenticated"] is True


def test_vault_storage_state_fail_closed_cases(tmp_path: Path) -> None:
    # 1. Missing vault home fails closed without creating directory or key
    missing_home = tmp_path / "never_created"
    with pytest.raises(ValueError):
        auth_import.load_storage_state_actor_from_vault(
            missing_home,
            "missing_key",
            base_url="https://app.example.test/",
        )
    assert not missing_home.exists()

    # 2. Symlink input file to save_storage_state_to_vault is rejected
    real_file = tmp_path / "real.json"
    real_file.write_text(json.dumps({"cookies": [], "origins": []}), encoding="utf-8")
    sym_file = tmp_path / "sym.json"
    sym_file.symlink_to(real_file)
    vault_home = tmp_path / "vault"
    with pytest.raises(ValueError, match="symlink"):
        auth_import.save_storage_state_to_vault(vault_home, "k1", sym_file)

    # 3. Non-storage-state vault payload fails closed without echoing secret
    canary = "RAW_NON_STORAGE_SECRET_5512"
    agentic_vault.save_vault_credentials(
        vault_home,
        "other_bundle",
        {"target_url": "https://app.example.test/", "secret": canary},
    )
    with pytest.raises(ValueError, match="storage_state") as exc_info:
        auth_import.load_storage_state_actor_from_vault(
            vault_home,
            "other_bundle",
            base_url="https://app.example.test/",
        )
    assert canary not in str(exc_info.value)

    # 4. Unknown key raises KeyError
    with pytest.raises(KeyError):
        auth_import.load_storage_state_actor_from_vault(
            vault_home,
            "unknown_key",
            base_url="https://app.example.test/",
        )


# ---------------------------------------------------------------------------
# 6. Import hygiene: zero legacy / network / Playwright imports
# ---------------------------------------------------------------------------


def test_agentic_auth_import_has_zero_legacy_or_network_imports() -> None:
    env = dict(os.environ)
    env["PYTHONPATH"] = str(SCRIPTS_DIR)
    code = (
        "import json, sys, agentic_auth_import; "
        "print(json.dumps(sorted(sys.modules.keys())))"
    )
    proc = subprocess.run(
        [sys.executable, "-c", code],
        env=env,
        capture_output=True,
        text=True,
        check=True,
    )
    loaded = set(json.loads(proc.stdout))
    forbidden_exact = {
        "requests",
        "playwright",
        "external_target_runner",
        "full_agent_python_solver",
        "full_agent_python_broker",
        "full_agent_broker",
        "full_agent_budget",
        "full_agent_provider",
        "brain",
        "campaign_runtime",
        "campaign_worker",
        "policy_engine",
    }
    assert loaded.isdisjoint(forbidden_exact), f"Forbidden modules loaded: {sorted(loaded & forbidden_exact)}"
    prefixed_hits = [m for m in loaded if m.startswith(("full_agent_", "campaign_", "playwright."))]
    assert not prefixed_hits, f"Forbidden prefixed modules loaded: {sorted(prefixed_hits)}"
