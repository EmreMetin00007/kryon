"""Izole kimlik havuzu cekirdegi (saf fonksiyonlar, ag yok).

Model token'lari elinde tasimaz: her kimlik icin ayri istek atilir, yanitlar
burada deterministik kiyaslanir. Cikti ciftleri analyze_authz_result ile
formal CONFIRMED hukmune baglanir.
"""
import hashlib
import json
import re

# Degeri her istekte degisen (veri tasimayan) alanlar.
_VOLATILE_KEY_RE = re.compile(
    r"(csrf|xsrf|nonce|token|timestamp|_ts$|date|time|request_?id|trace|"
    r"session|etag|expires|generated|rnd|random|signature)",
    re.I,
)


def _sig(body):
    if body is None:
        return None, 0
    raw = body.encode("utf-8", "ignore") if isinstance(body, str) else bytes(body)
    return hashlib.sha256(raw).hexdigest(), len(raw)


def _flatten(value, prefix="", out=None):
    if out is None:
        out = {}
    if isinstance(value, dict):
        for key in sorted(value.keys(), key=str):
            if _VOLATILE_KEY_RE.search(str(key)):
                continue
            path = f"{prefix}.{key}" if prefix else str(key)
            _flatten(value[key], path, out)
    elif isinstance(value, list):
        for item in value:
            _flatten(item, f"{prefix}[]", out)
    else:
        leaf = json.dumps(value, sort_keys=True, ensure_ascii=False, default=str)
        out[prefix] = hashlib.sha256(leaf.encode("utf-8")).hexdigest()[:16]
    return out


def field_signature(body):
    """JSON govde -> veri-alanlari parmak izi (volatile haric); JSON degilse None."""
    if isinstance(body, (dict, list)):
        parsed = body
    elif isinstance(body, (str, bytes)):
        try:
            parsed = json.loads(body.decode("utf-8", "ignore") if isinstance(body, bytes) else body)
        except Exception:
            return None
    else:
        return None
    flat = _flatten(parsed)
    material = json.dumps(flat, sort_keys=True, ensure_ascii=False)
    return hashlib.sha256(material.encode("utf-8")).hexdigest()


def field_equivalent(body_a, body_b) -> bool:
    """Iki govde ayni veri alanlarini tasiyor mu (volatile alanlar haric)?"""
    sig_a, sig_b = field_signature(body_a), field_signature(body_b)
    return sig_a is not None and sig_a == sig_b


def diff_verdict(responses, *, identities=None, resource=None):
    """Kimlik basina yanitlari kiyasla, ihlal adaylarini bul.

    Args:
        responses: {kimlik_adi: {"status": int, "body": str}}.

    Returns:
        dict: {table: [...], violations: [...], isolation_ok: bool} —
        violations: ayni 2xx icerigi alan farkli kimlik ciftleri
        (byte-identical hash). isolation_ok: hicbir cift eslesmedi.
    """
    table = []
    bodies: dict[str, object] = {}
    for name, resp in (responses or {}).items():
        status = int((resp or {}).get("status", 0) or 0)
        h, ln = _sig((resp or {}).get("body"))
        bodies[name] = (resp or {}).get("body")
        table.append({"identity": name, "status": status,
                      "body_hash": h, "body_len": ln,
                      "field_hash": field_signature((resp or {}).get("body")),
                      "ok_2xx": 200 <= status < 300})
    violations = []
    oks = [t for t in table if t["ok_2xx"] and t["body_hash"]]
    for i in range(len(oks)):
        for j in range(i + 1, len(oks)):
            a, b = oks[i], oks[j]
            if a["body_hash"] and a["body_hash"] == b["body_hash"]:
                match = "byte_identical"
            elif a["field_hash"] and a["field_hash"] == b["field_hash"]:
                match = "field_equivalent"
            else:
                continue
            if identities is not None:
                from authz_matrix import object_access_blocked, same_principal
                owner = identities.get(a["identity"]) or {}
                other = identities.get(b["identity"]) or {}
                if (same_principal(owner, other) is not False
                        or object_access_blocked(resource or {}, owner, other)):
                    continue
            violations.append({
                "pair": [a["identity"], b["identity"]],
                "status": a["status"], "body_len": a["body_len"],
                "match": match,
                "meaning": f"{b['identity']} kimligi {a['identity']} ile ayni "
                           "icerigi aldi — BOLA/tenant izolasyon ihlali adayi. "
                           "analyze_authz_result ile formal dogrula.",
            })
    return {"table": table, "violations": violations,
            "isolation_ok": not violations}


def authorization_coverage(identities, resources):
    """Expose evidence-based coverage without carrying credentials into the result."""
    from authz_matrix import build_identity_matrix
    return build_identity_matrix(identities, resources)
