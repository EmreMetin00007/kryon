"""Bounded, document-local OpenAPI request schema extraction.

Schema samples are labelled suggestions, not observed requests or proof that a
request satisfies every constraint. External references never cause I/O.
"""
from __future__ import annotations

import math
from typing import Any
from urllib.parse import unquote

from .normalize import safe_sample

_MISSING = object()
_TYPES = {"string", "integer", "number", "boolean", "object", "array", "null"}


def _properties(node):
    value = node.get("properties")
    return value if isinstance(value, dict) else {}


def _required(node):
    value = node.get("required")
    return [name for name in value if isinstance(name, str)] if isinstance(value, list) else []


def _bounded_sample(value, depth=0, budget=None):
    """Schema examples can contain YAML aliases or deeply nested containers."""
    if budget is None:
        budget = [512]
    budget[0] -= 1
    if depth > 8 or budget[0] < 0:
        return "<unavailable>"
    if isinstance(value, dict):
        if len(value) > 64:
            return "<unavailable>"
        return {str(key): _bounded_sample(child, depth + 1, budget) for key, child in value.items()}
    if isinstance(value, list):
        if len(value) > 64:
            return "<unavailable>"
        return [_bounded_sample(child, depth + 1, budget) for child in value]
    if isinstance(value, float) and not math.isfinite(value):
        return "<unavailable>"
    return value


class LocalSchema:
    def __init__(self, document: dict):
        self.document = document
        self.budget = 512

    def resolve(self, value) -> dict:
        node = dict(value) if isinstance(value, dict) else {}
        seen = set()
        for _ in range(32):
            if "$ref" not in node:
                return node
            ref = node["$ref"]
            if not isinstance(ref, str) or not ref.startswith("#/") or ref in seen:
                return node
            seen.add(ref)
            target = self.document
            try:
                for part in unquote(ref[2:]).split("/"):
                    part = part.replace("~1", "/").replace("~0", "~")
                    target = target[int(part)] if isinstance(target, list) else target[part]
                if not isinstance(target, dict):
                    return node
            except (KeyError, IndexError, ValueError, TypeError):
                return node
            node = {**target, **{key: value for key, value in node.items() if key != "$ref"}}
        return node

    def schema(self, value, depth=0) -> dict:
        self.budget -= 1
        if depth > 8 or self.budget < 0:
            return {"$ref": "<bounded>"}
        node = self.resolve(value)
        branches = node.get("allOf")
        if isinstance(branches, list):
            merged: dict[str, Any] = {}
            for branch in [*branches, {key: value for key, value in node.items() if key != "allOf"}]:
                child = self.schema(branch, depth + 1)
                props = dict(_properties(merged))
                for name, prop in _properties(child).items():
                    if name in props:
                        props[name] = {**self.resolve(props[name]), **self.resolve(prop)}
                    else:
                        props[name] = prop
                required = list(dict.fromkeys([*_required(merged), *_required(child)]))
                merged.update(child)
                if props:
                    merged["properties"] = props
                if required:
                    merged["required"] = required
            node = merged
        return node

    @staticmethod
    def type_of(schema):
        typ = schema.get("type")
        if isinstance(typ, list):
            typ = next((item for item in typ if item != "null"), "null")
        if isinstance(typ, str) and typ in _TYPES:
            return typ
        return "object" if isinstance(schema.get("properties"), dict) else ""

    @staticmethod
    def hint(node):
        for key, source in (("example", "openapi_example"), ("default", "openapi_default")):
            if key in node:
                return node[key], source
        if isinstance(node.get("examples"), list) and node["examples"]:
            return node["examples"][0], "openapi_example"
        if isinstance(node.get("enum"), list) and node["enum"]:
            return node["enum"][0], "openapi_enum"
        return _MISSING, ""

    def sample(self, schema, depth=0):
        if depth > 8 or "$ref" in schema or "oneOf" in schema or "anyOf" in schema:
            return "<unavailable>", "schema_unresolved"
        value, source = self.hint(schema)
        if value is not _MISSING:
            return value, source
        if schema.get("format") or schema.get("pattern"):
            # IDs, files, timestamps, and constrained strings need an example
            # or observed value; a generic string is not a valid baseline.
            return "<unavailable>", "schema_unresolved"
        typ = self.type_of(schema)
        if typ == "object":
            value = {}
            for name, child in list(_properties(schema).items())[:64]:
                child = self.schema(child, depth + 1)
                if child.get("readOnly") is not True:
                    value[name] = self.sample(child, depth + 1)[0]
            return value, "schema_generated"
        if typ == "array":
            # Arrays remain one carrier, as with observed JSON requests.
            count = schema.get("minItems", 0)
            if not isinstance(count, int) or not 0 <= count <= 16:
                return "<unavailable>", "schema_unresolved"
            item = self.schema(schema.get("items"), depth + 1)
            return [self.sample(item, depth + 1)[0] for _ in range(count)], "schema_generated"
        if typ in {"integer", "number"}:
            minimum = schema.get("minimum")
            maximum = schema.get("maximum")
            value = minimum if isinstance(minimum, (int, float)) else 1
            if isinstance(maximum, (int, float)):
                value = min(value, maximum)
            if isinstance(value, float) and not math.isfinite(value):
                return "<unavailable>", "schema_unresolved"
            if typ == "integer":
                value = math.ceil(value)
                if isinstance(maximum, (int, float)) and value > maximum:
                    return "<unavailable>", "schema_unresolved"
            return value, "schema_generated"
        if typ == "boolean":
            return False, "schema_generated"
        if typ == "null":
            return None, "schema_generated"
        length = schema.get("minLength", 0)
        if not isinstance(length, int) or not 0 <= length <= 120:
            return "<unavailable>", "schema_unresolved"
        return "a" * length, "schema_generated"

    def describe(self, schema, depth=0):
        """Keep constraints and alternatives, excluding example/default values."""
        if depth > 8:
            return {"unresolved": True}
        node = self.schema(schema, depth)
        out = {}
        for key in ("type", "format", "nullable", "minimum", "maximum", "minLength", "maxLength",
                    "minItems", "maxItems", "uniqueItems", "required", "pattern", "readOnly"):
            if key in node:
                out[key] = _bounded_sample(node[key])
        if node.get("nullable") is True or isinstance(node.get("type"), list) and "null" in node["type"]:
            out["nullable"] = True
        if isinstance(node.get("enum"), list):
            out["enum"] = _bounded_sample(node["enum"])
        if "$ref" in node:
            out["unresolved"] = True
        if "items" in node:
            out["items"] = self.describe(node["items"], depth + 1)
        if _properties(node):
            out["properties"] = {str(name): self.describe(child, depth + 1)
                                 for name, child in list(_properties(node).items())[:64]}
        for key in ("oneOf", "anyOf"):
            if isinstance(node.get(key), list):
                out[key] = [self.describe(child, depth + 1) for child in node[key][:16]]
        return out


def request_media(document, operation):
    body = LocalSchema(document).resolve(operation.get("requestBody"))
    raw_content = body.get("content")
    content: dict[str, Any] = raw_content if isinstance(raw_content, dict) else {}
    kind = next((kind for kind in content if kind == "application/json" or kind.endswith("+json")), "")
    if not kind:
        kind = next((kind for kind in ("application/x-www-form-urlencoded", "multipart/form-data")
                     if kind in content), "")
    media = content.get(kind) if isinstance(content.get(kind), dict) else {}
    return kind, media


def openapi_parameters(document: dict, operation: dict, inherited=None) -> list[dict]:
    resolver = LocalSchema(document)
    params: dict[tuple[str, str], dict[str, Any]] = {}

    def add(name, location, schema, required=False, path=None, hint=_MISSING, source="", depth=0, encoding=None):
        schema = resolver.schema(schema, depth)
        if schema.get("readOnly") is True:
            return
        if depth > 8:
            schema = {"$ref": "<bounded>"}
        properties = schema.get("properties")
        if (location == "json" and isinstance(properties, dict) and properties and "$ref" not in schema
                and hint is not None and "oneOf" not in schema and "anyOf" not in schema):
            own_hint, own_source = resolver.hint(schema)
            if hint is _MISSING:
                hint, source = own_hint, own_source
            for child_name, child_schema in properties.items():
                if len(params) >= 64:
                    break
                child_path = [*(path or []), str(child_name)]
                child_hint = hint.get(child_name, _MISSING) if isinstance(hint, dict) else _MISSING
                add(".".join(child_path), location, child_schema,
                    child_name in _required(schema), child_path,
                    child_hint, source if child_hint is not _MISSING else "", depth + 1)
            return
        if len(params) >= 64 or not name:
            return
        if hint is _MISSING:
            hint, source = resolver.sample(schema, depth)
        entry = {"name": str(name), "in": location, "sample": safe_sample(str(name), _bounded_sample(hint)),
                 "required": bool(required), "sample_source": source}
        entry["schema_context"] = safe_sample("", resolver.describe(schema))
        if safe_sample(str(name), "") == "<redacted>" and "enum" in entry["schema_context"]:
            entry["schema_context"]["enum"] = "<redacted>"
        entry["schema_version"] = str(document.get("openapi") or document.get("swagger") or "")[:32]
        for key in ("nullable", "enum", "format"):
            if key in entry["schema_context"]:
                entry[key] = entry["schema_context"][key]
        if isinstance(encoding, dict):
            entry["encoding"] = {key: encoding[key] for key in ("contentType", "style", "explode")
                                 if key in encoding and isinstance(encoding[key], (str, bool))}
        if schema.get("format") == "binary" and location == "body":
            entry["file_part"] = True
        typ = resolver.type_of(schema)
        if typ == "array" and location == "body" and (not encoding or encoding.get("explode", True)):
            entry["repeated"] = True
        if typ:
            entry["type"] = typ
        if path:
            entry["path"] = path
        if "$ref" in schema or source == "schema_unresolved":
            entry["schema_unresolved"] = True
        params[(location, str(name))] = entry

    # Operation parameters override inherited parameters by (name, carrier).
    items = {}
    inherited_list = inherited if isinstance(inherited, list) else []
    raw_op_params = operation.get("parameters")
    op_params_list = raw_op_params if isinstance(raw_op_params, list) else []
    for raw in [*inherited_list, *op_params_list]:
        item = resolver.resolve(raw)
        name, location = item.get("name"), item.get("in", "query")
        if name and location in {"query", "body", "json", "header", "cookie", "path"}:
            items[(location, str(name))] = item
    for (location, name), item in items.items():
        hint, source = resolver.hint(item)
        add(name, location, item.get("schema") or item, item.get("required", location == "path"),
            hint=hint, source=source)

    body = resolver.resolve(operation.get("requestBody"))
    media_type, media = request_media(document, operation)
    schema = resolver.schema(media.get("schema"))
    hint, source = resolver.hint(media)
    if hint is _MISSING and isinstance(media.get("examples"), dict):
        for example in media["examples"].values():
            example = resolver.resolve(example)
            if "value" in example:
                hint, source = example["value"], "openapi_example"
                break
    if hint is _MISSING:
        hint, source = resolver.hint(schema)
    location = "body" if media_type in {"application/x-www-form-urlencoded", "multipart/form-data"} else "json"
    properties = dict(_properties(schema))
    for name in _required(schema):
        properties.setdefault(name, {"$ref": "<missing required property>"})
    for name, child in properties.items():
        child_hint = hint.get(name, _MISSING) if isinstance(hint, dict) else _MISSING
        add(name, location, child, name in _required(schema),
            [str(name)] if location == "json" else None,
            child_hint, source if child_hint is not _MISSING else "",
            encoding=(media.get("encoding") or {}).get(name) if isinstance(media.get("encoding"), dict) else None)
    if media_type and not properties and location == "json":
        add("$body", "json", schema, body.get("required", False), hint=hint, source=source)
        if ("json", "$body") in params:
            params[("json", "$body")]["body_root"] = True
    return list(params.values())
