"""Offline JWT, opaque token, and serialization inspector + JWT confusion test builder.

Zero network calls and zero raw secret echoing.
"""
from __future__ import annotations

import base64
import binascii
import hashlib
import hmac
import json
from pathlib import Path
import re
import sys
import time
from typing import Any, Callable
from urllib.parse import unquote

_REPO_ROOT = Path(__file__).resolve().parent.parent
if str(_REPO_ROOT) not in sys.path:
    sys.path.insert(0, str(_REPO_ROOT))

_MAX_CLAIM_STR_LEN = 120
_HEX_RE = re.compile(r"^[0-9a-fA-F]+$")
_B64_STD_RE = re.compile(r"^[A-Za-z0-9+/]+={0,2}$")
_B64_URL_RE = re.compile(r"^[A-Za-z0-9_-]+={0,2}$")
_BEARER_PREFIX_RE = re.compile(r"^\s*bearer\s+", re.I)
_PHP_OBJECT_RE = re.compile(rb'^(?:O|C):(\d+):"([^"]{1,120})":(\d+):\{')
_PHP_ARRAY_RE = re.compile(rb"^a:(\d+):\{")
_JAVA_MAGIC = b"\xac\xed\x00\x05"
_DOTNET_MAGIC = b"\x00\x01\x00\x00\x00\xff\xff\xff\xff"
_VIEWSTATE_MAGIC = b"\xff\x01"
_PICKLE_PROTO_MAGICS = (b"\x80\x02", b"\x80\x03", b"\x80\x04", b"\x80\x05")
_PICKLE_ASCII_PREFIXES = (b"(dp0\n", b"cos\n", b"cposix\n", b"c__builtin__\n", b"cbuiltins\n")

_AUTHZ_CLAIM_KEYS = frozenset({
    "role",
    "roles",
    "scope",
    "scopes",
    "scp",
    "permission",
    "permissions",
    "perm",
    "perms",
    "group",
    "groups",
    "admin",
    "is_admin",
    "isadmin",
    "authorities",
    "authority",
    "entitlement",
    "entitlements",
    "privilege",
    "privileges",
    "access_level",
    "tenant_id",
    "org_id",
    "tier",
    "plan",
})

_VALIDATOR_LOADED = False
_CRYPTO_TOKEN_MOD: Any = None
_DESER_MOD: Any = None


def _load_validator_helpers() -> tuple[Any, Any]:
    """Lazily import passive analyzers from kryon_core.validator with fallback."""
    global _VALIDATOR_LOADED, _CRYPTO_TOKEN_MOD, _DESER_MOD
    if _VALIDATOR_LOADED:
        return _CRYPTO_TOKEN_MOD, _DESER_MOD
    _VALIDATOR_LOADED = True
    try:
        if str(_REPO_ROOT) not in sys.path:
            sys.path.insert(0, str(_REPO_ROOT))
        from kryon_core.validator import crypto_token, deser

        _CRYPTO_TOKEN_MOD = crypto_token
        _DESER_MOD = deser
    except Exception:
        _CRYPTO_TOKEN_MOD = None
        _DESER_MOD = None
    return _CRYPTO_TOKEN_MOD, _DESER_MOD


_HMAC_ALGS: dict[str, Any] = {
    "HS256": hashlib.sha256,
    "HS384": hashlib.sha384,
    "HS512": hashlib.sha512,
}


def _b64url_encode(raw: bytes) -> str:
    return base64.urlsafe_b64encode(raw).decode("ascii").rstrip("=")


def _b64url_decode_segment(segment: str) -> bytes | None:
    """Base64url-decode a single JWT segment safely with padding."""
    if not segment or not _B64_URL_RE.fullmatch(segment):
        return None
    if len(segment) % 4 == 1:
        return None
    padded = segment + "=" * (-len(segment) % 4)
    try:
        return base64.urlsafe_b64decode(padded.encode("ascii"))
    except (binascii.Error, ValueError, UnicodeEncodeError):
        return None


def _sanitize_claims(obj: Any, *, depth: int = 0) -> Any:
    """Truncate/redact long string claim values (>120 chars) recursively."""
    if depth > 6:
        return "<nested-truncated>"
    if isinstance(obj, str):
        if len(obj) > _MAX_CLAIM_STR_LEN:
            return f"{obj[:64]}...<redacted:len={len(obj)}>"
        return obj
    if isinstance(obj, dict):
        return {str(k): _sanitize_claims(v, depth=depth + 1) for k, v in obj.items()}
    if isinstance(obj, list):
        return [_sanitize_claims(item, depth=depth + 1) for item in obj[:50]]
    return obj


def _strip_bearer(value: str) -> str:
    return _BEARER_PREFIX_RE.sub("", str(value or "").strip()).strip()


def analyze_jwt(token: str) -> dict[str, Any]:
    """Decode a JWT header/payload offline and return objective posture findings."""
    invalid: dict[str, Any] = {
        "kind": "jwt",
        "valid_jwt": False,
        "header": {},
        "payload": {},
        "findings": [],
    }
    raw = _strip_bearer(token)
    parts = raw.split(".")
    if len(parts) != 3:
        return invalid

    header_bytes = _b64url_decode_segment(parts[0])
    payload_bytes = _b64url_decode_segment(parts[1])
    if header_bytes is None or payload_bytes is None:
        return invalid
    if parts[2] and not _B64_URL_RE.fullmatch(parts[2]):
        return invalid

    try:
        header_raw = json.loads(header_bytes.decode("utf-8"))
        payload_raw = json.loads(payload_bytes.decode("utf-8"))
    except (UnicodeDecodeError, ValueError):
        return invalid

    if not isinstance(header_raw, dict) or not isinstance(payload_raw, dict):
        return invalid

    findings: list[str] = []
    alg = str(header_raw.get("alg") or "").strip()
    alg_lower = alg.lower()
    alg_upper = alg.upper()

    if not alg_lower or alg_lower == "none":
        findings.append("alg_none")
    elif alg_upper.startswith("HS"):
        findings.append("symmetric_alg")

    exp = payload_raw.get("exp")
    if exp is None:
        findings.append("missing_exp")
    elif isinstance(exp, (int, float)) and not isinstance(exp, bool):
        if float(exp) < time.time():
            findings.append("expired")

    if header_raw.get("kid") not in (None, ""):
        findings.append("kid_header_present")

    if header_raw.get("jku") not in (None, "") or header_raw.get("x5u") not in (None, ""):
        findings.append("jku_or_x5u_present")

    if any(str(k).strip().lower() in _AUTHZ_CLAIM_KEYS for k in payload_raw.keys()):
        findings.append("authorization_claims_present")

    return {
        "kind": "jwt",
        "valid_jwt": True,
        "header": _sanitize_claims(header_raw),
        "payload": _sanitize_claims(payload_raw),
        "findings": findings,
    }


def _decode_encoded_value(value: str) -> tuple[bytes, str]:
    """Decode hex, base64, base64url, or raw text while preferring hex over base64."""
    text = unquote(str(value or "").strip())
    if not text:
        return b"", "empty"

    if len(text) >= 2 and len(text) % 2 == 0 and _HEX_RE.fullmatch(text):
        try:
            return bytes.fromhex(text), "hex"
        except ValueError:
            pass

    if len(text) % 4 != 1:
        if _B64_STD_RE.fullmatch(text):
            padded = text + "=" * (-len(text) % 4)
            try:
                return base64.b64decode(padded, validate=True), "base64"
            except (binascii.Error, ValueError):
                pass
        if _B64_URL_RE.fullmatch(text):
            padded = text + "=" * (-len(text) % 4)
            try:
                return base64.urlsafe_b64decode(padded), "base64url"
            except (binascii.Error, ValueError):
                pass

    return text.encode("utf-8", "ignore"), "raw"


def _token_structure_fallback(raw: bytes) -> dict[str, Any]:
    n = len(raw)
    return {
        "length_bytes": n,
        "block16_aligned": n > 0 and n % 16 == 0,
        "block8_aligned": n > 0 and n % 8 == 0,
        "sha256": hashlib.sha256(raw).hexdigest() if raw else "",
    }


def analyze_opaque_token(value: str) -> dict[str, Any]:
    """Inspect byte length, 8/16-byte cipher block alignment, and structure metadata."""
    cleaned = _strip_bearer(value)
    raw, encoding = _decode_encoded_value(cleaned)
    crypto_mod, _ = _load_validator_helpers()

    struct: dict[str, Any]
    if crypto_mod is not None and hasattr(crypto_mod, "token_structure"):
        try:
            struct = dict(crypto_mod.token_structure(raw))
        except Exception:
            struct = _token_structure_fallback(raw)
    else:
        struct = _token_structure_fallback(raw)

    wellformed_b64 = False
    if encoding in {"base64", "base64url"}:
        if crypto_mod is not None and hasattr(crypto_mod, "is_wellformed_token_text"):
            try:
                wellformed_b64 = bool(crypto_mod.is_wellformed_token_text(cleaned))
            except Exception:
                wellformed_b64 = encoding == "base64" and len(cleaned) % 4 == 0
        else:
            wellformed_b64 = encoding == "base64" and len(cleaned) % 4 == 0

    observations: list[str] = []
    if struct.get("block16_aligned"):
        observations.append("block16_aligned")
    if struct.get("block8_aligned"):
        observations.append("block8_aligned")

    return {
        "kind": "opaque",
        "encoding": encoding,
        "length_bytes": int(struct.get("length_bytes", len(raw))),
        "block8_aligned": bool(struct.get("block8_aligned", False)),
        "block16_aligned": bool(struct.get("block16_aligned", False)),
        "sha256": str(struct.get("sha256") or ""),
        "wellformed_base64": wellformed_b64,
        "structure": struct,
        "observations": observations,
    }


def _java_class_name_fallback(raw: bytes) -> str:
    try:
        if not raw.startswith(_JAVA_MAGIC):
            return ""
        pos = 4
        if raw[pos : pos + 1] == b"\x73":
            pos += 1
        if raw[pos : pos + 1] != b"\x72":
            return ""
        pos += 1
        if pos + 2 > len(raw):
            return ""
        name_len = int.from_bytes(raw[pos : pos + 2], "big")
        pos += 2
        if name_len <= 0 or pos + name_len > len(raw):
            return ""
        return raw[pos : pos + name_len].decode("utf-8", "ignore")[:160]
    except Exception:
        return ""


def _detect_format_bytes(raw: bytes, deser_mod: Any) -> tuple[str, str]:
    """Identify serialization format and safe class/type name from raw bytes."""
    if not raw:
        return "unknown", ""

    if raw.startswith(_JAVA_MAGIC):
        cls_name = ""
        if deser_mod is not None and hasattr(deser_mod, "java_class_name"):
            try:
                cls_name = str(deser_mod.java_class_name(raw) or "")[:160]
            except Exception:
                cls_name = _java_class_name_fallback(raw)
        else:
            cls_name = _java_class_name_fallback(raw)
        return "java", cls_name

    php_obj = _PHP_OBJECT_RE.match(raw)
    if php_obj:
        return "php", php_obj.group(2).decode("utf-8", "ignore")[:120]
    if _PHP_ARRAY_RE.match(raw):
        return "php", ""

    if raw.startswith(_PICKLE_PROTO_MAGICS) or raw.startswith(_PICKLE_ASCII_PREFIXES):
        return "python_pickle", ""

    if raw.startswith(_DOTNET_MAGIC):
        return "dotnet", ""

    if raw.startswith(_VIEWSTATE_MAGIC):
        return "viewstate", ""

    if b"_$$ND_FUNC$$_" in raw or b"_$$ND_DATE$$_" in raw:
        cls_hint = "IIFE" if b"_$$ND_FUNC$$_function" in raw and b"()" in raw else "function"
        return "node_serialize", cls_hint

    if deser_mod is not None and hasattr(deser_mod, "detect_format"):
        try:
            detected = str(deser_mod.detect_format(raw) or "unknown")
            if detected != "unknown":
                cls_name = ""
                if detected == "java" and hasattr(deser_mod, "java_class_name"):
                    cls_name = str(deser_mod.java_class_name(raw) or "")[:160]
                return detected, cls_name
        except Exception:
            pass

    return "unknown", ""


def detect_serialization(value: str) -> dict[str, Any]:
    """Identify Java, PHP, Python pickle, .NET, or ViewState serialized payloads offline."""
    text = unquote(str(value or "").strip())
    if not text:
        return {
            "kind": "serialization",
            "detected": False,
            "format": "unknown",
            "encoding": "empty",
            "length_bytes": 0,
            "class_name": "",
            "sha256": "",
        }

    _, deser_mod = _load_validator_helpers()

    # Check decoded representation and raw UTF-8 bytes so both encoded
    # (hex aced0005, base64 rO0AB / /wEP) and raw textual streams (PHP O:...) work.
    candidates: list[tuple[bytes, str]] = []
    primary_raw, primary_enc = _decode_encoded_value(text)
    candidates.append((primary_raw, primary_enc))

    raw_utf8 = text.encode("utf-8", "ignore")
    if raw_utf8 != primary_raw:
        candidates.append((raw_utf8, "raw"))

    if deser_mod is not None and hasattr(deser_mod, "decode_sample"):
        try:
            deser_raw: bytes = deser_mod.decode_sample(text)
            if deser_raw and all(deser_raw != c[0] for c in candidates):
                candidates.append((deser_raw, "decoded"))
        except Exception:
            pass

    best_fmt = "unknown"
    best_cls = ""
    best_raw = primary_raw
    best_enc = primary_enc

    for cand_raw, cand_enc in candidates:
        fmt, cls_name = _detect_format_bytes(cand_raw, deser_mod)
        if fmt != "unknown":
            best_fmt = fmt
            best_cls = cls_name
            best_raw = cand_raw
            best_enc = cand_enc
            break

    # Explicit base64 text prefix checks for truncated samples (e.g. "rO0AB" or "/wEP")
    if best_fmt == "unknown":
        if text.startswith("rO0AB"):
            best_fmt = "java"
            best_enc = "base64"
        elif text.lower().startswith("aced0005"):
            best_fmt = "java"
            best_enc = "hex"
        elif text.startswith(("/wEP", "/wEY")):
            best_fmt = "viewstate"
            best_enc = "base64"

    return {
        "kind": "serialization",
        "detected": best_fmt != "unknown",
        "format": best_fmt,
        "encoding": best_enc,
        "length_bytes": len(best_raw),
        "class_name": best_cls,
        "sha256": hashlib.sha256(best_raw).hexdigest() if best_raw else "",
    }


def _jwk_rsa_to_spki_pem(raw_key_text: str) -> str:
    """Convert an RSA JWK or JWKS JSON string into SubjectPublicKeyInfo PEM when possible."""
    stripped = str(raw_key_text or "").strip()
    if not stripped.startswith("{"):
        return ""
    try:
        parsed = json.loads(stripped)
    except ValueError:
        return ""
    if not isinstance(parsed, dict):
        return ""
    candidates: list[dict[str, Any]] = []
    if isinstance(parsed.get("keys"), list):
        candidates = [k for k in parsed["keys"] if isinstance(k, dict) and str(k.get("kty") or "").upper() == "RSA"]
        sig_cands = [k for k in candidates if str(k.get("use") or "").lower() == "sig"]
        if sig_cands:
            candidates = sig_cands + [k for k in candidates if k not in sig_cands]
    elif str(parsed.get("kty") or "").upper() == "RSA":
        candidates = [parsed]
    if not candidates:
        return ""
    chosen = candidates[0]
    n_bytes = _b64url_decode_segment(str(chosen.get("n") or "").strip())
    e_bytes = _b64url_decode_segment(str(chosen.get("e") or "").strip())
    if not n_bytes or not e_bytes:
        return ""
    try:
        from cryptography.hazmat.primitives import serialization
        from cryptography.hazmat.primitives.asymmetric import rsa

        pub_num = rsa.RSAPublicNumbers(
            int.from_bytes(e_bytes, "big"),
            int.from_bytes(n_bytes, "big"),
        )
        pem_bytes = pub_num.public_key().public_bytes(
            serialization.Encoding.PEM,
            serialization.PublicFormat.SubjectPublicKeyInfo,
        )
        return pem_bytes.decode("ascii")
    except Exception:
        return ""


def _sign_jwt(
    header: dict[str, Any],
    payload: dict[str, Any],
    *,
    sign_alg: str,
    key_bytes: bytes | None = None,
) -> str:
    hdr = dict(header)
    hdr["alg"] = sign_alg
    hdr.setdefault("typ", "JWT")
    h_seg = _b64url_encode(json.dumps(hdr, ensure_ascii=False, separators=(",", ":")).encode("utf-8"))
    p_seg = _b64url_encode(json.dumps(payload, ensure_ascii=False, separators=(",", ":")).encode("utf-8"))
    signing_input = f"{h_seg}.{p_seg}"
    if sign_alg.lower() == "none" or key_bytes is None:
        return f"{signing_input}."
    hash_fn = _HMAC_ALGS[sign_alg.upper()]
    sig = hmac.new(key_bytes, signing_input.encode("ascii"), hash_fn).digest()
    return f"{signing_input}.{_b64url_encode(sig)}"


def build_jwt_test_variants(
    value: str = "",
    *,
    alg: str = "",
    hmac_key: str = "",
    claim_overrides: dict[str, Any] | None = None,
    base_header: dict[str, Any] | None = None,
    base_payload: dict[str, Any] | None = None,
) -> dict[str, Any]:
    """Build JWT alg=none or HMAC key-confusion test tokens locally without network calls."""
    header: dict[str, Any] = {}
    payload: dict[str, Any] = {}
    parsed_from_claims = False

    if isinstance(base_header, dict) or isinstance(base_payload, dict):
        header = dict(base_header or {"typ": "JWT"})
        payload = dict(base_payload or {})
    else:
        raw = _strip_bearer(value)
        parts = raw.split(".") if raw else []
        if len(parts) == 3:
            hb = _b64url_decode_segment(parts[0])
            pb = _b64url_decode_segment(parts[1])
            if hb is None or pb is None:
                raise ValueError("invalid base64url JWT segments in value")
            try:
                h_obj = json.loads(hb.decode("utf-8"))
                p_obj = json.loads(pb.decode("utf-8"))
            except (UnicodeDecodeError, ValueError) as exc:
                raise ValueError("invalid JSON in base JWT segments") from exc
            if not isinstance(h_obj, dict) or not isinstance(p_obj, dict):
                raise ValueError("JWT header and payload must be JSON objects")
            header, payload = dict(h_obj), dict(p_obj)
        elif raw.startswith("{"):
            try:
                p_obj = json.loads(raw)
            except ValueError as exc:
                raise ValueError("invalid JSON payload in value") from exc
            if not isinstance(p_obj, dict):
                raise ValueError("JWT JSON value must decode to an object")
            header = {"typ": "JWT"}
            payload = dict(p_obj)
            parsed_from_claims = True
        elif not raw and isinstance(claim_overrides, dict):
            header = {"typ": "JWT"}
            payload = {}
            parsed_from_claims = True
        else:
            raise ValueError(
                "jwt_test expects value as a JWT ('eyJ...'), JSON payload object, or 'actor:<alias>'"
            )

    if isinstance(claim_overrides, dict):
        payload.update(claim_overrides)

    now = int(time.time())
    if parsed_from_claims:
        if "iat" not in payload and "exp" not in payload:
            payload["iat"] = now
            payload["exp"] = now + 3600
    elif isinstance(payload.get("exp"), (int, float)) and not isinstance(payload.get("exp"), bool):
        if float(payload["exp"]) < now and (not isinstance(claim_overrides, dict) or "exp" not in claim_overrides):
            payload["exp"] = now + 3600

    eff_key = str(hmac_key or "")
    key_source = "literal" if eff_key else "none"
    if eff_key.startswith(("-----BEGIN ", "-----BEGIN\t")) and "\n" not in eff_key and "\\n" in eff_key:
        eff_key = eff_key.replace("\\r\\n", "\n").replace("\\n", "\n")
    jwk_pem = _jwk_rsa_to_spki_pem(eff_key)
    if jwk_pem:
        eff_key = jwk_pem
        key_source = "jwks_rsa_pem"

    req_alg = str(alg or "").strip()
    norm_upper = req_alg.upper()
    variants: list[dict[str, str]] = []
    seen_tokens: set[str] = set()

    def _add_variant(label: str, sign_alg: str, key_bytes: bytes | None) -> None:
        tok = _sign_jwt(header, payload, sign_alg=sign_alg, key_bytes=key_bytes)
        if tok in seen_tokens:
            return
        seen_tokens.add(tok)
        variants.append({"label": label, "alg": sign_alg, "token": tok})

    if norm_upper in _HMAC_ALGS:
        key_bytes = eff_key.encode("utf-8")
        _add_variant(f"{norm_upper.lower()}_exact", norm_upper, key_bytes)
        stripped_key = eff_key.strip("\r\n")
        if eff_key and stripped_key != eff_key:
            _add_variant(f"{norm_upper.lower()}_stripped", norm_upper, stripped_key.encode("utf-8"))
    elif req_alg.lower() == "none":
        _add_variant("alg_none", req_alg, None)
        alt_none = "None" if req_alg == "none" else "none"
        _add_variant("alg_none_alt", alt_none, None)
    elif req_alg.lower() == "strip_sig":
        orig_alg = str(header.get("alg") or "RS256")
        _add_variant("strip_sig", orig_alg, None)
    elif req_alg.lower() in {"", "confusion", "auto"}:
        if eff_key:
            _add_variant("hs256_exact", "HS256", eff_key.encode("utf-8"))
            stripped_key = eff_key.strip("\r\n")
            if stripped_key != eff_key:
                _add_variant("hs256_stripped", "HS256", stripped_key.encode("utf-8"))
            _add_variant("alg_none", "none", None)
        else:
            _add_variant("alg_none", "none", None)
            _add_variant("alg_none_title", "None", None)
            _add_variant("hs256_empty", "HS256", b"")
            orig_alg = str(header.get("alg") or "").strip()
            if orig_alg and orig_alg.lower() != "none":
                _add_variant("strip_sig", orig_alg, None)
    else:
        raise ValueError(
            f"unsupported jwt_test alg: {alg!r}; expected none, HS256, HS384, HS512, confusion, or strip_sig"
        )

    primary = variants[0]
    return {
        "kind": "jwt_test",
        "alg": primary["alg"],
        "token": primary["token"],
        "auth_header": f"Bearer {primary['token']}",
        "header": {**header, "alg": primary["alg"], "typ": header.get("typ", "JWT")},
        "payload": _sanitize_claims(payload),
        "hmac_key_len": len(eff_key.encode("utf-8")) if eff_key else 0,
        "hmac_key_sha256_8": hashlib.sha256(eff_key.encode("utf-8")).hexdigest()[:8] if eff_key else "",
        "hmac_key_source": key_source,
        "variants": variants,
    }


def analyze_token(
    value: str,
    *,
    kind: str = "auto",
    alg: str = "",
    hmac_key: str = "",
    claim_overrides: dict[str, Any] | None = None,
) -> dict[str, Any]:
    """Offline token/format auditor + optional JWT alg/key-confusion test token builder."""
    mode = str(kind or "auto").strip().lower()
    if mode in {"jwt_test", "jwt_forge", "jwt_confusion"} or (
        mode in {"auto", "jwt"} and (str(alg or "").strip() or str(hmac_key or "") or claim_overrides is not None)
    ):
        return build_jwt_test_variants(
            value,
            alg=alg,
            hmac_key=hmac_key,
            claim_overrides=claim_overrides,
        )
    dispatch: dict[str, Callable[[str], dict[str, Any]]] = {
        "jwt": analyze_jwt,
        "opaque": analyze_opaque_token,
        "serialization": detect_serialization,
    }
    if mode in dispatch:
        return dispatch[mode](value)
    if mode != "auto":
        raise ValueError(f"unsupported token analysis kind: {kind!r}")

    stripped = _strip_bearer(value)
    if len(stripped.split(".")) == 3:
        jwt_res = analyze_jwt(value)
        if jwt_res.get("valid_jwt"):
            return jwt_res

    ser_res = detect_serialization(value)
    if ser_res.get("detected"):
        return ser_res

    return analyze_opaque_token(value)
