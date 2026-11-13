"""Lossless, single-slot mutation of an observed request. No transport or guessing."""
from __future__ import annotations

import copy
import json
from urllib.parse import parse_qsl, quote, quote_plus, unquote_plus, urlsplit, urlunsplit


def json_slot(value, path):
    cursor = value
    for part in path:
        if isinstance(cursor, list):
            if not isinstance(part, int) or isinstance(part, bool) or not 0 <= part < len(cursor):
                raise ValueError("invalid_array_slot")
        elif not isinstance(cursor, dict) or not isinstance(part, str) or part not in cursor:
            raise ValueError("missing_json_slot")
        cursor = cursor[part]
    return cursor


def replace_json_slot(value, path, replacement):
    """Keep types and siblings, including arrays; never create a missing path."""
    if not isinstance(path, (list, tuple)) or not path:
        raise ValueError("missing_json_path")
    out = copy.deepcopy(value)
    json_slot(out, path)
    parent = json_slot(out, path[:-1])
    parent[path[-1]] = copy.deepcopy(replacement)
    return out


def replace_pairs(pairs, name, replacement, occurrence=None):
    positions = [i for i, (key, _) in enumerate(pairs) if key == name]
    if not positions:
        raise ValueError("unobserved_parameter")
    if occurrence is None:
        if len(positions) != 1:
            raise ValueError("ambiguous_repeated_parameter")
        occurrence = 0
    if (not isinstance(occurrence, int) or isinstance(occurrence, bool)
            or not 0 <= occurrence < len(positions)):
        raise ValueError("invalid_parameter_occurrence")
    out = list(pairs)
    out[positions[occurrence]] = (name, replacement)
    return out


def replace_encoded_slot(encoded, name, replacement, occurrence=None):
    """Retain the original encoding, ordering and separators of sibling pairs."""
    parts = encoded.split("&")
    pairs = [(unquote_plus(part.partition("=")[0]), part) for part in parts]
    # Use the same ambiguity/occurrence checks as decoded request inspection.
    changed = replace_pairs(pairs, name, None, occurrence)
    index = next(i for i, (_, part) in enumerate(changed) if part is None)
    key = parts[index].partition("=")[0]
    parts[index] = key + "=" + quote_plus(str(replacement))
    return "&".join(parts)


def request_slot(request, carrier, name, path=None, occurrence=None):
    carrier = {"body": "form"}.get(carrier, carrier)
    if carrier == "json":
        return json_slot(request.get("json_body"), path or [name])
    if carrier in {"query", "form"}:
        pairs = parse_qsl(urlsplit(request["url"]).query if carrier == "query"
                          else str(request.get("data") or ""), keep_blank_values=True)
        replace_pairs(pairs, name, "", occurrence)
        values = [v for k, v in pairs if k == name]
        return values[occurrence or 0]
    if carrier == "header":
        keys = [k for k in request.get("headers", {}) if k.lower() == name.lower()]
        if len(keys) != 1:
            raise ValueError("missing_or_ambiguous_header")
        return request["headers"][keys[0]]
    if carrier == "cookie":
        headers = request.get("headers") or {}
        cookies = [v for k, v in headers.items() if k.lower() == "cookie"]
        if len(cookies) != 1:
            raise ValueError("missing_or_ambiguous_cookie")
        pairs = [p.strip().partition("=")[::2] for p in cookies[0].split(";") if p.strip()]
        replace_pairs(pairs, name, "", occurrence)
        return [v for k, v in pairs if k == name][occurrence or 0]
    if carrier == "path":
        # A concrete path slot must come from an observed template, not a guessed ID.
        if not isinstance(path, list) or len(path) != 1 or not isinstance(path[0], int) or isinstance(path[0], bool):
            raise ValueError("missing_path_slot")
        segments = urlsplit(request["url"]).path.split("/")
        if not 0 < path[0] < len(segments) or not segments[path[0]]:
            raise ValueError("invalid_path_slot")
        from urllib.parse import unquote
        return unquote(segments[path[0]])
    raise ValueError("unsupported_carrier")


def mutate_request(request, carrier, name, replacement, path=None, occurrence=None):
    """Mutate exactly one observed slot, preserving method and every other field."""
    request_slot(request, carrier, name, path, occurrence)
    out = copy.deepcopy(request)
    carrier = {"body": "form"}.get(carrier, carrier)
    if carrier == "json":
        out["json_body"] = replace_json_slot(out["json_body"], path or [name], replacement)
    elif carrier in {"query", "form"}:
        parsed = urlsplit(out["url"])
        encoded = parsed.query if carrier == "query" else str(out.get("data") or "")
        encoded = replace_encoded_slot(encoded, name, replacement, occurrence)
        if carrier == "query":
            out["url"] = urlunsplit(parsed._replace(query=encoded))
        else:
            out["data"] = encoded
    elif carrier == "header":
        if any(c in str(replacement) for c in "\r\n\x00"):
            raise ValueError("invalid_header_value")
        key = next(k for k in out["headers"] if k.lower() == name.lower())
        out["headers"][key] = replacement
    elif carrier == "cookie":
        if any(c in str(replacement) for c in ";\r\n\x00"):
            raise ValueError("invalid_cookie_value")
        key = next(k for k in out["headers"] if k.lower() == "cookie")
        pairs = [p.strip().partition("=")[::2] for p in out["headers"][key].split(";") if p.strip()]
        pairs = replace_pairs(pairs, name, replacement, occurrence)
        out["headers"][key] = "; ".join(f"{k}={v}" for k, v in pairs)
    else:
        parsed = urlsplit(out["url"])
        segments = parsed.path.split("/")
        segments[path[0]] = quote(str(replacement), safe="")
        out["url"] = urlunsplit(parsed._replace(path="/".join(segments)))
    # These transport-derived values are recalculated after a body change.
    if carrier in {"json", "form"}:
        out["headers"] = {k: v for k, v in out.get("headers", {}).items() if k.lower() != "content-length"}
    return out


def wire_body(request):
    if request.get("json_body") is not None:
        return json.dumps(request["json_body"], ensure_ascii=False, separators=(",", ":")).encode()
    data = request.get("data")
    return data.encode() if isinstance(data, str) else data
