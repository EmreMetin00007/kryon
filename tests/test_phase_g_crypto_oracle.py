"""Faz G: crypto token iskeleti — padding-oracle validator + CBC dovme.

Offline birim testleri (network yok; _request monkeypatch ile).
Kritik regresyon: lab vakasi (tum iyi-yapili varyantlar 302, malformed 500)
UNCONFIRMED kalmali — decode-hatasi 500 oracle sinyali degildir.
"""
import base64
import json
import urllib.parse

from conftest import load_server


def _v():
    return load_server("validator")


def _core():
    import os
    import sys
    sys.path.insert(0, os.path.join(os.path.dirname(__file__), "..",
                                    "mcp-servers", "mcp-validator"))
    import cco_validator_core.crypto_token as ct
    return ct


SAMPLE_RAW = bytes(range(32))  # IV[16] || C[16]
SAMPLE_VALUE = base64.b64encode(SAMPLE_RAW).decode()


def _resp(status, ok=True):
    return {"ok": ok, "status": status, "len": 100 if status == 200 else 0,
            "time": 0.05, "text": "x", "headers": {}, "location": "",
            "final_url": "http://t.local/my-account", "error": None}


def test_core_structure_and_masking():
    ct = _core()
    raw = ct.decode_token_sample(urllib.parse.quote(SAMPLE_VALUE))
    assert raw == SAMPLE_RAW
    st = ct.token_structure(raw)
    assert st["length_bytes"] == 32
    assert st["block16_aligned"] is True
    assert len(st["sha256"]) == 64
    assert SAMPLE_VALUE not in json.dumps(st)
    assert raw.hex() not in json.dumps(st)


def test_core_wellformed_controls():
    ct = _core()
    assert ct.is_wellformed_token_text(SAMPLE_VALUE) is True
    assert ct.is_wellformed_token_text("!!!not-a-token!!!") is False
    assert ct.is_wellformed_token_text(SAMPLE_VALUE[:-2]) is False  # dolgu bozuk


def test_core_forge_property():
    ct = _core()
    iv, c = SAMPLE_RAW[:16], SAMPLE_RAW[16:]
    known = b"wiener:peter" + bytes([4, 4, 4, 4])
    target = b"administrator" + bytes([3, 3, 3])  # 13 + 3 = 16 bayt
    assert len(target) == 16
    new_iv = ct.forge_cbc_iv(iv, known, target)
    # Ozellik: new_iv XOR iv == known XOR target (=> ayni C ile hedef cozulur)
    prop = bytes(a ^ b for a, b in zip(new_iv, iv))
    expect = bytes(a ^ b for a, b in zip(known, target))
    assert prop == expect
    # Tutarli senaryo: D = iv XOR known (yani known gercekten dogru),
    # o zaman dovme cookie hedef duz-metni cozer.
    d_const = bytes(a ^ b for a, b in zip(iv, known))
    forged_pt = bytes(a ^ b for a, b in zip(d_const, new_iv))
    assert forged_pt == target
    forged = ct.encode_token_value(new_iv + c)
    assert ct.is_wellformed_token_text(forged) is True


def test_forge_tool_errors():
    mod = _v()
    out = json.loads(mod.forge_cbc_token(SAMPLE_VALUE, "zz", "00" * 16))
    assert out["verdict"] == "ERROR"
    out = json.loads(mod.forge_cbc_token("MQ==", "00" * 16, "00" * 16))
    assert out["verdict"] == "ERROR"  # tek blok degil


def test_forge_tool_success_property():
    mod = _v()
    known = (b"wiener:peter" + bytes([4, 4, 4, 4])).hex()
    target = (b"administrator" + bytes([3, 3, 3])).hex()
    out = json.loads(mod.forge_cbc_token(SAMPLE_VALUE, known, target))
    assert out["verdict"] == "FORGED"
    assert out["evidence"]["iv_xor_property_holds"] is True
    assert "forged_token" in out
    assert SAMPLE_VALUE not in json.dumps(out["evidence"])


def test_padding_oracle_confirms_on_split_groups(monkeypatch):
    """Gercek oracle: flip 500 + truncate 302 (baseline 200) -> CONFIRMED."""
    flip_val = base64.b64encode(bytes(b ^ 0x01 if i == 16 else b for i, b in
                                      enumerate(SAMPLE_RAW))).decode()
    trunc_val = base64.b64encode(SAMPLE_RAW[:27]).decode()
    mod = _v()

    def fake_request(method, url, *, params=None, data=None, headers=None,
                     allow_redirects=True, timeout=30):
        cookie = (headers or {}).get("Cookie", "")
        # SIRA ONEMLI: trunc b64'u SAMPLE'in prefixidir; baseline once bakilir.
        if SAMPLE_VALUE in cookie and "session=" + SAMPLE_VALUE in cookie:
            return _resp(200)
        if flip_val in cookie:
            return _resp(500)
        if trunc_val in cookie:
            return _resp(302)
        if "!!!" in cookie:
            return _resp(500)
        return _resp(302)

    monkeypatch.setattr(mod, "_request", fake_request)
    out = json.loads(mod.validate_token_differential(
        "http://t.local/my-account", SAMPLE_VALUE, carrier="cookie",
        name="session"))
    assert out["verdict"] == "CONFIRMED", out
    assert out["oracle"] == "token_differential"
    assert out["evidence"]["flip_status"] == 500
    assert out["evidence"]["malformed_status"] == 500


def test_padding_oracle_lab_case_is_unconfirmed(monkeypatch):
    """LAB REGRESYONU: baz 200, tum iyi-yapili 302, malformed 500 -> UNCONFIRMED.

    Decode-hatasi 500 oracle sinyali degildir; tek kumeli iyi-yapili
    varyantlar hukmu UNCONFIRMED tutmali.
    """
    mod = _v()

    def fake_request(method, url, *, params=None, data=None, headers=None,
                     allow_redirects=True, timeout=30):
        cookie = (headers or {}).get("Cookie", "")
        if "!!!" in cookie:
            return _resp(500)
        if SAMPLE_VALUE in cookie:
            return _resp(200)
        return _resp(302)

    monkeypatch.setattr(mod, "_request", fake_request)
    out = json.loads(mod.validate_token_differential(
        "http://t.local/my-account", SAMPLE_VALUE, carrier="cookie",
        name="session"))
    assert out["verdict"] == "UNCONFIRMED", out
    assert out["evidence"]["flip_status"] == 302
    assert out["evidence"]["malformed_status"] == 500


def test_padding_oracle_rejected_baseline_is_unconfirmed(monkeypatch):
    mod = _v()

    def fake_request(method, url, *, params=None, data=None, headers=None,
                     allow_redirects=True, timeout=30):
        return _resp(302)

    monkeypatch.setattr(mod, "_request", fake_request)
    out = json.loads(mod.validate_token_differential(
        "http://t.local/my-account", SAMPLE_VALUE))
    assert out["verdict"] == "UNCONFIRMED", out


def test_dispatcher_routes_padding_oracle(monkeypatch):
    mod = _v()

    def fake_request(method, url, *, params=None, data=None, headers=None,
                     allow_redirects=True, timeout=30):
        return _resp(302)

    monkeypatch.setattr(mod, "_request", fake_request)
    out = json.loads(mod.validate_finding(
        "token differential", "http://t.local/my-account",
        json.dumps({"sample_value": SAMPLE_VALUE})))
    assert out["vuln_type"] == "Token Differential (Opaque Carrier)", out
    assert out["verdict"] == "UNCONFIRMED", out


def _appflow_fake(mode):
    """mode: full | static_cookie | no_reflect | no_cookie."""
    ciphers = {"cco-oracle-probe-aaa-001": "Q0lQSEVSMS0tQUFBQUFBQUFB",
               "cco-oracle-probe-bbb-002": "Q0lQSEVSMS0tQkJCQkJCQkJC"}

    def fake_request(method, url, *, params=None, data=None, headers=None,
                     allow_redirects=True, timeout=30):
        payload = {}
        if isinstance(params, dict):
            payload.update(params)
        if isinstance(data, dict):
            payload.update(data)
        if "comment" in url or "encrypt" in url:
            canary = payload.get("email", "")
            if mode == "no_cookie":
                return {"ok": True, "status": 200, "len": 10, "time": 0.05,
                        "text": "ok", "headers": {}, "location": "",
                        "final_url": url, "error": None}
            cookie = "Q0lQSEVSMS0tU1RBVElD" if mode == "static_cookie" else ciphers.get(
                canary, "Q0lQSEVSMS0tVU5LTk9XTg==")
            return {"ok": True, "status": 302, "len": 0, "time": 0.05,
                    "text": "", "headers": {"Set-Cookie": f"notification={cookie}; Path=/"},
                    "location": "/post", "final_url": url, "error": None}
        body = ""
        if mode == "full":
            cookie = (headers or {}).get("Cookie", "")
            for canary, cipher in ciphers.items():
                if cipher in cookie:
                    body = f"Invalid email address: {canary}"
        return {"ok": True, "status": 200, "len": len(body), "time": 0.05,
                "text": body, "headers": {}, "location": "",
                "final_url": url, "error": None}

    return fake_request


def test_appflow_oracle_confirms_roundtrip(monkeypatch):
    mod = _v()
    monkeypatch.setattr(mod, "_request", _appflow_fake("full"))
    out = json.loads(mod.validate_token_roundtrip(
        "http://t.local/post/comment", "http://t.local/post?postId=1",
        field="email", cookie_name="notification"))
    assert out["verdict"] == "CONFIRMED", out
    assert out["oracle"] == "token_roundtrip"
    assert out["evidence"]["ciphers_differ"] is True
    assert out["evidence"]["canary_reflected"] is True
    assert "Q0lQSEVSMS" not in json.dumps(out["evidence"])


def test_appflow_oracle_static_cookie_is_unconfirmed(monkeypatch):
    mod = _v()
    monkeypatch.setattr(mod, "_request", _appflow_fake("static_cookie"))
    out = json.loads(mod.validate_token_roundtrip(
        "http://t.local/post/comment", "http://t.local/post?postId=1"))
    assert out["verdict"] == "UNCONFIRMED", out


def test_appflow_oracle_no_reflect_is_unconfirmed(monkeypatch):
    mod = _v()
    monkeypatch.setattr(mod, "_request", _appflow_fake("no_reflect"))
    out = json.loads(mod.validate_token_roundtrip(
        "http://t.local/post/comment", "http://t.local/post?postId=1"))
    assert out["verdict"] == "UNCONFIRMED", out
    assert out["evidence"]["canary_reflected"] is False


def test_appflow_oracle_no_cookie_is_unconfirmed(monkeypatch):
    mod = _v()
    monkeypatch.setattr(mod, "_request", _appflow_fake("no_cookie"))
    out = json.loads(mod.validate_token_roundtrip(
        "http://t.local/post/comment", "http://t.local/post?postId=1"))
    assert out["verdict"] == "UNCONFIRMED", out


def test_core_cut_requires_block_alignment():
    ct = _core()
    raw = bytes(range(64))
    assert ct.cut_leading_bytes(raw, 32) == raw[32:]
    for bad in (0, 23, 64, 65):
        try:
            ct.cut_leading_bytes(raw, bad)
        except ValueError:
            continue
        raise AssertionError(f"drop={bad} hata vermeli")


def test_splice_tool_roundtrip_and_errors():
    mod = _v()
    raw = bytes(range(64))
    sample = base64.b64encode(raw).decode()
    out = json.loads(mod.splice_cbc_token(sample, 32))
    assert out["verdict"] == "SPLICED", out
    assert out["evidence"]["structure_after"]["length_bytes"] == 32
    assert out["evidence"]["dropped_bytes"] == 32
    assert raw.hex() not in json.dumps(out["evidence"])
    bad = json.loads(mod.splice_cbc_token(sample, 23))
    assert bad["verdict"] == "ERROR"
    empty = json.loads(mod.splice_cbc_token("", 16))
    assert empty["verdict"] == "ERROR"


def test_appflow_captures_pre_redirect_cookie(monkeypatch):
    """Worker duzeltmesi regresyonu: sifreli tasiyici 302 uzerinde gelir;
    redirect takip edilirse hedef tuketir/temizler. Validator takip ETMEMELI."""
    mod = _v()
    ciphers = {"cco-oracle-probe-aaa-001": "Q0lQSEVSMS0tQUFBQUFBQUFB",
               "cco-oracle-probe-bbb-002": "Q0lQSEVSMS0tQkJCQkJCQkJC"}

    def fake_request(method, url, *, params=None, data=None, headers=None,
                     allow_redirects=True, timeout=30):
        payload = {}
        if isinstance(params, dict):
            payload.update(params)
        if isinstance(data, dict):
            payload.update(data)
        if "comment" in url:
            canary = payload.get("email", "")
            if allow_redirects:
                # Takip edilen 302: hedef cookie'yi tuketti/temizledi.
                return {"ok": True, "status": 200, "len": 5, "time": 0.05,
                        "text": "taken", "headers": {}, "location": "",
                        "final_url": url, "error": None}
            cookie = ciphers.get(canary, "Q0lQSEVSMS0tVU5LTk9XTg==")
            return {"ok": True, "status": 302, "len": 0, "time": 0.05,
                    "text": "", "headers": {"Set-Cookie": f"notification={cookie}; Path=/"},
                    "location": "/post", "final_url": url, "error": None}
        body = ""
        cookie = (headers or {}).get("Cookie", "")
        for canary, cipher in ciphers.items():
            if cipher in cookie:
                body = f"Invalid email address: {canary}"
        return {"ok": True, "status": 200, "len": len(body), "time": 0.05,
                "text": body, "headers": {}, "location": "",
                "final_url": url, "error": None}

    monkeypatch.setattr(mod, "_request", fake_request)
    out = json.loads(mod.validate_token_roundtrip(
        "http://t.local/post/comment", "http://t.local/post?postId=1",
        field="email", cookie_name="notification"))
    assert out["verdict"] == "CONFIRMED", out


def test_appflow_refreshes_single_use_csrf(monkeypatch):
    """Tek-kullanimlik CSRF: her sifrele POST'u taze token ister.

    csrf_url verilmezse ikinci POST olur ve kume bozulur (UNCONFIRMED);
    verilirse her POST taze token alir (CONFIRMED).
    """
    mod = _v()
    state = {"n": 0, "live": set()}
    ciphers = {"cco-oracle-probe-aaa-001": "Q0lQSEVSMS0tQUFBQUFBQUFB",
               "cco-oracle-probe-bbb-002": "Q0lQSEVSMS0tQkJCQkJCQkJC"}

    def fake_request(method, url, *, params=None, data=None, headers=None,
                     allow_redirects=True, timeout=30):
        payload = {}
        if isinstance(params, dict):
            payload.update(params)
        if isinstance(data, dict):
            payload.update(data)
        if url.endswith("/form"):
            state["n"] += 1
            tok = f"tok{state['n']}"
            state["live"].add(tok)
            html = f'<input name="csrf" value="{tok}">'
            return {"ok": True, "status": 200, "len": len(html), "time": 0.01,
                    "text": html, "headers": {}, "location": "",
                    "final_url": url, "error": None}
        if "comment" in url:
            tok = payload.get("csrf", "")
            if tok not in state["live"]:
                cookie = "RklYRURfS0FSQVJfRVJST1I="
            else:
                state["live"].discard(tok)
                cookie = ciphers.get(payload.get("email", ""),
                                     "Q0lQSEVSMS0tVU5LTk9XTg==")
            return {"ok": True, "status": 302, "len": 0, "time": 0.01,
                    "text": "", "headers": {"Set-Cookie": f"notification={cookie}; Path=/"},
                    "location": "/post", "final_url": url, "error": None}
        body = ""
        cookie = (headers or {}).get("Cookie", "")
        for canary, cipher in ciphers.items():
            if cipher in cookie:
                body = f"Invalid email address: {canary}"
        return {"ok": True, "status": 200, "len": len(body), "time": 0.01,
                "text": body, "headers": {}, "location": "",
                "final_url": url, "error": None}

    monkeypatch.setattr(mod, "_request", fake_request)
    stale = {"csrf": "tok-dead", "comment": "x", "name": "n",
             "website": "http://e.com/", "postId": "1"}
    out = json.loads(mod.validate_token_roundtrip(
        "http://t.local/post/comment", "http://t.local/post?postId=1",
        field="email", cookie_name="notification",
        extra_fields_json=json.dumps(stale)))
    assert out["verdict"] == "UNCONFIRMED", out
    fresh = {"comment": "x", "name": "n",
             "website": "http://e.com/", "postId": "1"}
    out = json.loads(mod.validate_token_roundtrip(
        "http://t.local/post/comment", "http://t.local/post?postId=1",
        field="email", cookie_name="notification",
        extra_fields_json=json.dumps(fresh),
        csrf_url="http://t.local/form"))
    assert out["verdict"] == "CONFIRMED", out


def test_appflow_dead_session_is_inconclusive(monkeypatch):
    """Olu oturum: gosterge yoksa olcu yapilmaz (INCONCLUSIVE, UNCONFIRMED degil)."""
    mod = _v()

    def fake_request(method, url, *, params=None, data=None, headers=None,
                     allow_redirects=True, timeout=30):
        return {"ok": True, "status": 302, "len": 0, "time": 0.01,
                "text": "login page", "headers": {}, "location": "/login",
                "final_url": url, "error": None}

    monkeypatch.setattr(mod, "_request", fake_request)
    out = json.loads(mod.validate_token_roundtrip(
        "http://t.local/post/comment", "http://t.local/post?postId=1",
        session_check_url="http://t.local/my-account",
        session_marker="wiener"))
    assert out["verdict"] == "INCONCLUSIVE", out


def test_dispatcher_routes_appflow_without_target_injection(monkeypatch):
    mod = _v()
    monkeypatch.setattr(mod, "_request", _appflow_fake("full"))
    out = json.loads(mod.validate_finding(
        "token roundtrip", "http://t.local/ignored",
        json.dumps({"encrypt_url": "http://t.local/post/comment",
                    "decrypt_url": "http://t.local/post?postId=1"})))
    assert out["vuln_type"] == "Token Round-Trip (Application Flow)", out
    assert out["verdict"] == "CONFIRMED", out
