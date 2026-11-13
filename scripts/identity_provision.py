#!/usr/bin/env python3
"""Kimlik tedarik hattı (Faz 3): tarif -> canlı oturum -> identities JSON.

Config:
{
  "identities": [
    {"name": "userA", "login": {"url": "...", "method": "POST",
                                "body": {...}, "token_path": "access_token"}},
    {"name": "userB", "headers": {"Authorization": "Bearer ..."}},
    {"name": "admin", "kind": "browser"}
  ]
}

Üretilemeyen kimlik sessizce atlanmaz: human_needed listesine gerekçesiyle düşer.
Çıktı dosyası 0600 yazılır (header değerleri sırdır); stdout yalnızca isim basar.

Kullanım: python3 scripts/identity_provision.py --config ids.json --out ~/cco-work/identities.json
"""
from __future__ import annotations

import argparse
import json
import os
import sys

sys.path.insert(0, os.path.dirname(os.path.abspath(__file__)))

from chain_executor import SessionRuntime, _default_sender  # noqa: E402


def pkce_pair() -> tuple[str, str]:
    """(code_verifier, S256 code_challenge) üretir."""
    import base64
    import hashlib
    import secrets
    verifier = secrets.token_urlsafe(48)
    challenge = base64.urlsafe_b64encode(
        hashlib.sha256(verifier.encode()).digest()).rstrip(b"=").decode()
    return verifier, challenge


def _oauth_exchange(entry: dict, sender) -> dict | None:
    """code + verifier -> token yanıtı (dict) veya None."""
    oauth = entry.get("oauth") or {}
    form = {
        "grant_type": "authorization_code",
        "code": str(oauth.get("code") or ""),
        "redirect_uri": str(oauth.get("redirect_uri") or ""),
        "client_id": str(oauth.get("client_id") or ""),
        "code_verifier": str(oauth.get("code_verifier") or ""),
    }
    if oauth.get("client_secret"):
        form["client_secret"] = str(oauth["client_secret"])
    from urllib.parse import urlencode
    resp = sender("POST", str(oauth.get("token_url") or ""),
                  {"Content-Type": "application/x-www-form-urlencoded"},
                  urlencode(form), 20)
    if not resp.get("ok"):
        return None
    try:
        data = json.loads(resp.get("text") or "")
    except Exception:  # noqa: BLE001
        return None
    return data if isinstance(data, dict) and data.get("access_token") else None


def provision(config: dict, sender=None) -> dict:
    sender = sender or _default_sender
    identities: dict[str, dict] = {}
    human_needed: list[dict] = []
    for entry in (config or {}).get("identities") or []:
        name = str(entry.get("name") or "").strip()
        if not name:
            continue
        if isinstance(entry.get("headers"), dict) and entry["headers"]:
            identities[name] = dict(entry["headers"])
            continue
        if isinstance(entry.get("oauth"), dict) and entry["oauth"]:
            oauth = entry["oauth"]
            if not oauth.get("code"):
                verifier, challenge = pkce_pair()
                from urllib.parse import urlencode
                auth_url = str(oauth.get("authorize_url") or "") + "?" + urlencode({
                    "response_type": "code",
                    "client_id": str(oauth.get("client_id") or ""),
                    "redirect_uri": str(oauth.get("redirect_uri") or ""),
                    "scope": str(oauth.get("scope") or "openid"),
                    "code_challenge": challenge,
                    "code_challenge_method": "S256",
                    "state": "cco-provision",
                })
                human_needed.append({
                    "name": name,
                    "reason": "OAuth PKCE: tarayıcıda açıp code alın: " + auth_url +
                              f" | sonra config'e oauth.code + oauth.code_verifier={verifier} ekleyin"})
                continue
            data = _oauth_exchange(entry, sender)
            if data is None:
                human_needed.append({"name": name,
                                     "reason": "OAuth token değişimi başarısız (code/verifier/token_url kontrol)"})
                continue
            identities[name] = {
                "Authorization": f"{oauth.get('token_scheme', 'Bearer ')}{data['access_token']}"}
            continue
        recipe = entry.get("login") or {}
        if entry.get("kind") == "browser" or not recipe.get("url"):
            human_needed.append({
                "name": name,
                "reason": "tarayıcı auth gerekli (save_browser_auth.py ile cookie üretip "
                          "config'e headers olarak verin)"})
            continue
        runtime = SessionRuntime(recipe=recipe, sender=sender)
        runtime._login()
        if runtime.state != "active":
            human_needed.append({"name": name,
                                 "reason": "login tarifi oturum üretemedi (yanıt/alanları kontrol edin)"})
            continue
        headers = dict(runtime._auth_headers)
        cookie = runtime.jar.header_value()
        if cookie:
            headers["Cookie"] = cookie
        probe = entry.get("probe_url") or recipe.get("probe_url")
        if probe:
            resp = runtime.request("GET", str(probe), {}, None, 15)
            if not (resp.get("ok") and isinstance(resp.get("status"), int)
                    and 200 <= resp["status"] < 300):
                human_needed.append({"name": name,
                                     "reason": f"probe başarısız: status={resp.get('status')}"})
                continue
        identities[name] = headers
    return {"identities": identities, "human_needed": human_needed}


def main(argv: list[str] | None = None) -> int:
    ap = argparse.ArgumentParser(description=__doc__)
    ap.add_argument("--config", required=True)
    ap.add_argument("--out", required=True)
    args = ap.parse_args(argv)
    with open(args.config, encoding="utf-8") as fh:
        config = json.load(fh)
    result = provision(config)
    fd = os.open(args.out, os.O_WRONLY | os.O_CREAT | os.O_TRUNC, 0o600)
    with os.fdopen(fd, "w", encoding="utf-8") as fh:
        json.dump(result, fh, indent=2, ensure_ascii=False)
    print(f"uretilen kimlikler: {sorted(result['identities'])}")
    for item in result["human_needed"]:
        print(f"human_needed: {item['name']} — {item['reason']}")
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
