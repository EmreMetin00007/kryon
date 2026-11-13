"""Faz C: identity_provision OAuth PKCE — code yoksa URL+verifier, varsa token değişimi."""
import base64
import hashlib
import sys
from pathlib import Path

REPO_ROOT = Path(__file__).resolve().parents[1]
sys.path.insert(0, str(REPO_ROOT / "scripts"))

from identity_provision import pkce_pair, provision  # noqa: E402


def _sender(method, url, headers, body, timeout):
    assert "grant_type=authorization_code" in body
    assert "code_verifier=ver-1" in body
    return {"ok": True, "status": 200, "len": 20,
            "text": '{"access_token": "tok-oauth"}', "headers": {}, "error": None}


def test_pkce_challenge_matches_verifier():
    verifier, challenge = pkce_pair()
    expected = base64.urlsafe_b64encode(
        hashlib.sha256(verifier.encode()).digest()).rstrip(b"=").decode()
    assert challenge == expected


def test_oauth_provision_paths():
    cfg = {"identities": [
        {"name": "sso-code-yok",
         "oauth": {"authorize_url": "https://idp.example.com/authorize",
                   "client_id": "app", "redirect_uri": "https://app/cb"}},
        {"name": "sso-ok",
         "oauth": {"token_url": "https://idp.example.com/token",
                   "client_id": "app", "redirect_uri": "https://app/cb",
                   "code": "code-1", "code_verifier": "ver-1"}},
    ]}
    out = provision(cfg, sender=_sender)
    assert out["identities"]["sso-ok"]["Authorization"] == "Bearer tok-oauth"
    reasons = {h["name"]: h["reason"] for h in out["human_needed"]}
    assert "code_challenge" in reasons["sso-code-yok"]
    assert "code_verifier=" in reasons["sso-code-yok"]
