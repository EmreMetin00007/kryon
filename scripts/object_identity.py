"""Lossless object identifiers for legacy integer and typed ID records."""
from __future__ import annotations

import json
import re
import uuid


def normalize_object_id(value):
    """Return a legacy integer or a canonical {family, format, value} ref."""
    family = ""
    explicit_format = ""
    if isinstance(value, dict):
        if set(value) - {"family", "format", "value", "id"}:
            raise ValueError("object identifier contains unknown fields")
        family = value.get("family", "")
        explicit_format = value.get("format", "")
        value = value.get("value", value.get("id"))
        if not isinstance(family, str) or not re.fullmatch(r"[A-Za-z0-9_-]{0,64}", family):
            raise ValueError("invalid object identifier family")
        if explicit_format not in ("", "int", "uuid", "opaque", "composite"):
            raise ValueError("invalid object identifier format")
    if explicit_format == "composite":
        if (not isinstance(value, dict) or not 1 <= len(value) <= 8
                or any(not isinstance(k, str) or not re.fullmatch(r"[A-Za-z_][A-Za-z0-9_]{0,63}", k)
                       for k in value)):
            raise ValueError("invalid composite object identifier")
        if any(isinstance(v, dict) and v.get("format") == "composite" for v in value.values()):
            raise ValueError("nested composite object identifier")
        parts = {k: normalize_object_id(v) for k, v in value.items()}
        return {"family": family, "format": "composite", "value": parts}
    if isinstance(value, bool):
        raise ValueError("object identifier cannot be boolean")
    if isinstance(value, int):
        if value <= 0 or explicit_format not in ("", "int"):
            raise ValueError("invalid integer object identifier")
        return {"family": family, "format": "int", "value": value} if family else value
    if not isinstance(value, str) or not value or len(value) > 256 or not value.isprintable():
        raise ValueError("invalid object identifier value")
    if value != value.strip():
        raise ValueError("object identifier has surrounding whitespace")
    if value.isdecimal() and str(int(value)) == value and explicit_format in ("", "int"):
        number = int(value)
        if number <= 0:
            raise ValueError("invalid integer object identifier")
        return {"family": family, "format": "int", "value": number} if family else number
    try:
        parsed = uuid.UUID(value)
        is_uuid = str(parsed) == value.lower()
    except (ValueError, AttributeError):
        is_uuid = False
    kind = explicit_format or ("uuid" if is_uuid else "opaque")
    if kind == "int" or (kind == "uuid" and not is_uuid):
        raise ValueError("identifier value does not match its format")
    return {"family": family, "format": kind, "value": value}


def object_id_key(value) -> str:
    return json.dumps(normalize_object_id(value), sort_keys=True, separators=(",", ":"), ensure_ascii=False)


def object_id_sort_key(value):
    normalized = normalize_object_id(value)
    if isinstance(normalized, int):
        return (0, normalized, "", "")
    return (1, normalized["family"], normalized["format"], str(normalized["value"]))


def bind_resource_route(template, observed_url, bindings):
    """Bind named path slots only when every supplied ID matches the observed route.

    Multi-slot routes require explicit bindings; UUID shape never chooses a slot.
    """
    from urllib.parse import quote, urlsplit, unquote
    left, right = urlsplit(template), urlsplit(observed_url)
    if (left.scheme, left.netloc, left.query) != (right.scheme, right.netloc, right.query):
        raise ValueError("route origin or query mismatch")
    slots = re.findall(r"\{([A-Za-z_][A-Za-z0-9_]*)\}", left.path)
    if not slots or set(slots) != set(bindings):
        raise ValueError("explicit bindings required for every route slot")
    path = left.path
    for slot, value in bindings.items():
        normalized = normalize_object_id(value)
        raw = normalized["value"] if isinstance(normalized, dict) else normalized
        path = path.replace("{" + slot + "}", quote(str(raw), safe=""))
    if ([unquote(p) for p in path.split("/")] != [unquote(p) for p in right.path.split("/")]
            or left.fragment or right.fragment):
        raise ValueError("identifier does not match observed route")
    return {"template": template, "url": observed_url,
            "bindings": {k: normalize_object_id(v) for k, v in bindings.items()}}


class ResourceReferences:
    """Transient list/detail/export ledger partitioned by tenant and resource family."""
    def __init__(self):
        self.resources = {}

    def observe(self, *, tenant, family, resource_id, stage, evidence, route=None):
        if not tenant or not family or stage not in {"list", "detail", "download", "export"} or not evidence:
            raise ValueError("observed stage and evidence required")
        key = json.dumps([tenant, family, object_id_key(resource_id)], separators=(",", ":"))
        entry = self.resources.setdefault(key, {"tenant": tenant, "family": family,
            "resource_id": normalize_object_id(resource_id), "observations": []})
        entry["observations"].append({"stage": stage, "evidence": evidence, "route": route})
        return key


def valid_resource_binding(resource):
    """Recheck supplied route evidence at both candidate and validator handoffs."""
    if not any(k in resource for k in ("route_template", "route_bindings", "resource_param")):
        return True  # Legacy exact observed URLs have no inferred slot.
    try:
        bindings = resource["route_bindings"]
        param = resource["resource_param"]
        if object_id_key(bindings[param]) != object_id_key(resource["resource_id"]):
            return False
        bind_resource_route(resource["route_template"], resource["url"], bindings)
        return True
    except (KeyError, TypeError, ValueError):
        return False
