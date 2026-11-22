"""Pure operation descriptors; no raw GraphQL document or account values stored."""
from __future__ import annotations

import hashlib
import json
import re
from typing import Any
from urllib.parse import urlsplit

_TOKEN = re.compile(r'\s+|#[^\r\n]*|,|"""(?:\\.|(?!""")[\s\S])*"""|"(?:\\.|[^"\\])*"|\.\.\.|[_A-Za-z][_0-9A-Za-z]*|-?\d+(?:\.\d+)?(?:[eE][+-]?\d+)?|[^\s]', re.S)
_NAME = re.compile(r"[_A-Za-z][_0-9A-Za-z]*\Z")


def _selection_fields(definition, fragments, prefix="", visiting=()):
    """Bounded field inventory from the already selected operation tokens."""
    fields: list[str] = []
    depth = 0
    start = None
    for index, token in enumerate(definition):
        depth += (token == "(") - (token == ")")
        if token == "{" and depth == 0:
            start = index + 1
            break
    if start is None or len(visiting) > 32:
        return fields

    def selection(pos, path):
        while pos < len(definition) and definition[pos] != "}":
            token = definition[pos]
            if token == "...":
                name = definition[pos + 1] if pos + 1 < len(definition) else ""
                if name in fragments and name not in visiting:
                    fields.extend(_selection_fields(fragments[name], fragments, path, (*visiting, name)))
                    pos += 2
                    continue
                # Inline fragments retain the current access path.
                while pos < len(definition) and definition[pos] not in {"{", "}"}:
                    pos += 1
                if pos < len(definition) and definition[pos] == "{":
                    pos = selection(pos + 1, path)
                continue
            if not _NAME.fullmatch(token):
                pos += 1
                continue
            name = token
            pos += 1
            if pos + 1 < len(definition) and definition[pos] == ":":
                name = definition[pos + 1]  # Record schema field, not response alias.
                pos += 2
            field = path + "." + name if path else name
            fields.append(field)
            # Skip argument values and directives, including nested input objects.
            while pos < len(definition):
                if definition[pos] == "@":
                    pos += 2
                elif definition[pos] == "(":
                    balance = 1
                    pos += 1
                    while pos < len(definition) and balance:
                        balance += (definition[pos] == "(") - (definition[pos] == ")")
                        pos += 1
                else:
                    break
            if pos < len(definition) and definition[pos] == "{":
                if field.count(".") > 32:
                    return len(definition)
                pos = selection(pos + 1, field)
            if len(fields) >= 256:
                return len(definition)
        return pos + 1

    selection(start, prefix)
    return list(dict.fromkeys(fields))[:256]


def graphql_operation(document: Any, operation_name: str = "") -> dict:
    descriptor = {"protocol": "graphql", "kind": "unknown", "name": "", "selection": "unavailable"}
    if not isinstance(document, str) or not document.strip() or len(document) > 32768:
        return descriptor
    tokens = [m.group() for m in _TOKEN.finditer(document)
              if not m.group().isspace() and not m.group().startswith("#") and m.group() != ","]
    operations, fragments = [], {}
    pos = 0
    while pos < len(tokens):
        start = pos
        kind = tokens[pos]
        name = ""
        if kind == "{":
            kind = "query"
        elif kind in {"query", "mutation", "subscription", "fragment"}:
            pos += 1
            if pos < len(tokens) and _NAME.fullmatch(tokens[pos]):
                name = tokens[pos]
                pos += 1
        else:
            return {**descriptor, "selection": "invalid"}
        parens = brackets = 0
        while pos < len(tokens):
            token = tokens[pos]
            if token == "{" and parens == brackets == 0:
                break
            parens += (token == "(") - (token == ")")
            brackets += (token == "[") - (token == "]")
            pos += 1
        if pos == len(tokens):
            return {**descriptor, "selection": "invalid"}
        header = tokens[start:pos]
        depth = 1
        pos += 1
        while pos < len(tokens) and depth:
            depth += (tokens[pos] == "{") - (tokens[pos] == "}")
            pos += 1
        if depth:
            return {**descriptor, "selection": "invalid"}
        definition = tokens[start:pos]
        if kind == "fragment":
            if not name or name in fragments:
                return {**descriptor, "selection": "invalid"}
            fragments[name] = definition
        else:
            operations.append((kind, name, definition, header))
    chosen = [op for op in operations if op[1] == operation_name] if operation_name else operations
    if len(chosen) != 1:
        return {**descriptor, "selection": "ambiguous" if not operation_name else "not_found",
                "document_hash": hashlib.sha256(" ".join(tokens).encode()).hexdigest()}
    kind, name, selected, header = chosen[0]
    dependencies: dict[str, list[str]] = {}
    pending = [selected]
    while pending and len(dependencies) <= 32:
        definition = pending.pop()
        for index, token in enumerate(definition[:-1]):
            dependency = definition[index + 1]
            if token != "..." or dependency == "on" or not _NAME.fullmatch(dependency):
                continue
            if dependency not in fragments:
                return {**descriptor, "selection": "missing_fragment"}
            if dependency not in dependencies:
                dependencies[dependency] = fragments[dependency]
                pending.append(fragments[dependency])
    if pending:
        return {**descriptor, "selection": "bounded"}
    canonical = [selected, *(dependencies[key] for key in sorted(dependencies))]
    variables = []
    for index, token in enumerate(header[:-3]):
        if token != "$" or header[index + 2] != ":":
            continue
        type_tokens = []
        for part in header[index + 3:]:
            if part in {"[", "]", "!"} or _NAME.fullmatch(part):
                type_tokens.append(part)
            else:
                break
        variable: dict[str, Any] = {"name": header[index + 1], "type": "".join(type_tokens)}
        after_type = index + 3 + len(type_tokens)
        if after_type < len(header) and header[after_type] == "=":
            variable["has_default"] = True
        variables.append(variable)
    return {"protocol": "graphql", "kind": kind, "name": name, "selection": "selected",
            "fields": _selection_fields(selected, dependencies),
            "variables": variables[:32],
            "document_hash": hashlib.sha256(json.dumps(canonical, separators=(",", ":")).encode()).hexdigest()}


def operation_descriptor(record: dict) -> dict:
    supplied = record.get("operation")
    if isinstance(supplied, dict) and supplied.get("protocol") == "graphql":
        descriptor: dict[str, Any] = {key: str(supplied.get(key) or "") for key in ("protocol", "kind", "name", "selection")}
        if descriptor["kind"] not in {"query", "mutation", "subscription", "unknown"}:
            descriptor["kind"] = "unknown"
        if descriptor["name"] and not _NAME.fullmatch(descriptor["name"]):
            descriptor["name"] = ""
        if len(descriptor["name"]) > 128:
            descriptor["name"] = ""
        if descriptor["selection"] not in {"selected", "unavailable", "invalid", "ambiguous", "not_found", "missing_fragment", "bounded"}:
            descriptor["selection"] = "unavailable"
        descriptor["variables"] = [{"name": v["name"], "type": v["type"],
                                    **({"has_default": True} if v.get("has_default") is True else {})}
                                   for v in supplied.get("variables") or []
                                   if isinstance(v, dict) and isinstance(v.get("name"), str) and _NAME.fullmatch(v["name"])
                                   and isinstance(v.get("type"), str) and re.fullmatch(r"[\[\]!_A-Za-z0-9]{1,128}", v["type"])][:32]
        descriptor["fields"] = [f for f in supplied.get("fields") or [] if isinstance(f, str)
                                and re.fullmatch(r"[_A-Za-z][_0-9A-Za-z]*(?:\.[_A-Za-z][_0-9A-Za-z]*){0,33}", f)][:256]
        digest = supplied.get("document_hash")
        if isinstance(digest, str) and re.fullmatch(r"[a-f0-9]{64}", digest):
            descriptor["document_hash"] = digest
        else:
            descriptor.update(kind="unknown", selection="unavailable")
        return descriptor
    params = {p.get("name"): p.get("sample") for p in record.get("params") or [] if isinstance(p, dict)}
    raw_gql = record.get("graphql")
    if "graphql" in urlsplit(str(record.get("url") or "")).path.lower() or isinstance(raw_gql, dict):
        envelope: dict[Any, Any] = raw_gql if isinstance(raw_gql, dict) else params
        return graphql_operation(envelope.get("query"), str(envelope.get("operationName") or ""))
    return {"protocol": "http", "kind": "http", "name": "", "selection": "route"}


def operation_id(url: str, method: str, descriptor: dict) -> str:
    parsed = urlsplit(url)
    origin = (parsed.scheme.lower(), (parsed.hostname or "").lower(),
              parsed.port or (443 if parsed.scheme == "https" else 80))
    discriminator = {key: descriptor.get(key) for key in ("protocol", "kind", "document_hash", "selection")}
    raw = json.dumps([origin, method.upper(), parsed.path or "/", discriminator], sort_keys=True, separators=(",", ":"))
    return "op-" + hashlib.sha256(raw.encode()).hexdigest()[:32]
