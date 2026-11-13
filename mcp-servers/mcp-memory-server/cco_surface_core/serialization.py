"""Bounded request decoding without network, file access, or inferred secrets."""
from __future__ import annotations

import base64
import copy
from email import policy
from email.parser import BytesParser
import json
from urllib.parse import parse_qsl, urlsplit

from .normalize import json_parameters, safe_sample

MAX_BODY = 1024 * 1024


def media_type(content_type):
    return str(content_type or "").split(";", 1)[0].strip().lower()


def pair_parameters(pairs, location="body"):
    grouped = {}
    for name, value in pairs:
        if name:
            grouped.setdefault(name, []).append(value)
    return [{"name": name, "in": location,
             "sample": safe_sample(name, values[0] if len(values) == 1 else values),
             **({"repeated": True} if len(values) > 1 else {})}
            for name, values in grouped.items()]


def multipart_parts(body, content_type):
    raw = body.encode() if isinstance(body, str) else body
    if not isinstance(raw, bytes) or len(raw) > MAX_BODY:
        raise ValueError("multipart body unavailable or exceeds bound")
    if any(c in str(content_type) for c in "\r\n"):
        raise ValueError("invalid multipart content type")
    message = BytesParser(policy=policy.default).parsebytes(
        ("Content-Type: " + str(content_type) + "\r\nMIME-Version: 1.0\r\n\r\n").encode() + raw)
    if not message.is_multipart() or message.defects:
        raise ValueError("multipart boundary missing or invalid")
    parts = []
    for part in message.iter_parts():
        name = part.get_param("name", header="content-disposition")
        if not name or part.is_multipart() or len(parts) >= 64 or part.defects:
            raise ValueError("multipart fields missing, nested or exceed bound")
        value = part.get_payload(decode=True) or b""
        filename = part.get_filename()
        if filename is not None:
            try:
                content = value.decode("utf-8")
                encoding = "utf-8"
            except UnicodeDecodeError:
                content, encoding = base64.b64encode(value).decode(), "base64"
            value = {"filename": filename, "content": content, "content_type": part.get_content_type(),
                     "content_encoding": encoding}
        else:
            value = value.decode(part.get_content_charset() or "utf-8")
        parts.append((str(name), value))
    return parts


def decoded_body(body, content_type):
    kind = media_type(content_type)
    if isinstance(body, (dict, list)):
        return copy.deepcopy(body)
    if "json" in kind and (body is None or isinstance(body, (bool, int, float))):
        return copy.deepcopy(body)
    if kind == "multipart/form-data":
        return dict(multipart_parts(body, content_type))
    if isinstance(body, bytes):
        body = body.decode("utf-8")
    if not isinstance(body, str) or len(body) > MAX_BODY:
        raise ValueError("request body unavailable or exceeds bound")
    if kind == "application/x-www-form-urlencoded":
        return dict(parse_qsl(body, keep_blank_values=True, max_num_fields=64))
    if kind == "application/graphql":
        return {"query": body}
    if "json" in kind or body.lstrip().startswith(("{", "[")):
        return json.loads(body)
    return dict(parse_qsl(body, keep_blank_values=True, max_num_fields=64))


def body_parameters(body, content_type):
    kind = media_type(content_type)
    try:
        if isinstance(body, (str, bytes)) and len(body) > MAX_BODY:
            raise ValueError("request body exceeds bound")
        if kind == "multipart/form-data":
            parts = multipart_parts(body, content_type)
            params = pair_parameters(parts)
            for param in params:
                if any(name == param["name"] and isinstance(value, dict) for name, value in parts):
                    param["file_part"] = True
            return params
        if kind == "application/x-www-form-urlencoded" or (not kind and isinstance(body, str)
                and not body.lstrip().startswith(("{", "["))):
            if isinstance(body, dict):
                return pair_parameters(body.items())
            return pair_parameters(parse_qsl(body, keep_blank_values=True, max_num_fields=64))
        data = decoded_body(body, content_type)
        if kind == "application/graphql":
            return [{"name": "query", "in": "body", "sample": safe_sample("query", data["query"])}]
        if isinstance(data, dict) and data:
            return json_parameters(data)
        # A root array/scalar is a single carrier, just like nested arrays.
        return [{"name": "$body", "in": "json", "body_root": True, "sample": safe_sample("", data)}]
    except (ValueError, TypeError, LookupError):
        return [{"name": "unavailable_body", "in": "body", "sample": "<unavailable>"}]


def graphql_envelope(body, content_type, url="", method="POST", *, resolve_files=True):
    try:
        envelope = (dict(parse_qsl(urlsplit(url).query, keep_blank_values=True, max_num_fields=64))
                    if method == "GET" else decoded_body(body, content_type))
        multipart = envelope if isinstance(envelope, dict) and "operations" in envelope else None
        if multipart is not None:
            envelope = json.loads(multipart["operations"])
            mapping = json.loads(multipart.get("map", "{}")) if resolve_files else {}
            if not isinstance(mapping, dict) or len(mapping) > 64:
                return {}
            for name, paths in mapping.items():
                part = multipart.get(name)
                if (not isinstance(part, dict) or "filename" not in part
                        or not isinstance(paths, list) or len(paths) > 64):
                    return {}
                for path in paths[:64]:
                    if not isinstance(path, str) or not path.startswith("variables."):
                        return {}
                    segments = path.split(".")
                    cursor = envelope
                    for segment in segments[:-1]:
                        cursor = cursor[int(segment)] if isinstance(cursor, list) else cursor[segment]
                    leaf = int(segments[-1]) if isinstance(cursor, list) else segments[-1]
                    if cursor[leaf] is not None:
                        return {}
                    # This reference denotes an existing MIME part. The wire
                    # packet retains the actual bytes and original upload map.
                    cursor[leaf] = {"$multipart_file": name}
        if not isinstance(envelope, dict):
            return {}
        for name in ("variables", "extensions"):
            if isinstance(envelope.get(name), str):
                envelope[name] = json.loads(envelope[name])
        return envelope
    except (ValueError, TypeError, LookupError, AttributeError):
        return {}


def multipart_files(params):
    files = {}
    for param in params:
        if param.get("in") != "body":
            continue
        value = copy.deepcopy(param.get("sample"))
        values = value if param.get("repeated") and isinstance(value, list) else [value]
        encoded = []
        for value in values:
            if param.get("file_part"):
                if not isinstance(value, dict) or "content" not in value:
                    raise ValueError("multipart file content unavailable")
                content = value["content"]
                if value.get("content_encoding") == "base64":
                    content = base64.b64decode(content, validate=True)
                encoded.append((value["filename"], content, value["content_type"]))
            else:
                text = (json.dumps(value, separators=(",", ":"), ensure_ascii=False)
                        if isinstance(value, (dict, list, bool)) or value is None else str(value))
                encoded.append((None, text))
        files[param["name"]] = encoded if len(encoded) > 1 else encoded[0]
    # requests accepts repeated parts as pairs rather than a mapping of lists.
    if any(param.get("repeated") for param in params if param.get("in") == "body"):
        return [(name, part) for name, value in files.items()
                for part in (value if isinstance(value, list) else [value])]
    return files


def form_pairs(params, overrides=None):
    """Encode declared form arrays/objects; captured packets retain wire order."""
    pairs = []
    overrides = overrides or {}
    for param in params:
        if param.get("in") != "body":
            continue
        name = param["name"]
        value = overrides.get(name, param.get("sample", ""))
        encoding = param.get("encoding") or {}
        def scalar(value):
            return json.dumps(value, separators=(",", ":"), ensure_ascii=False) if (
                value is None or isinstance(value, (bool, dict, list))) else str(value)
        if "json" in encoding.get("contentType", ""):
            pairs.append((name, json.dumps(value, separators=(",", ":"), ensure_ascii=False)))
        elif isinstance(value, list):
            if param.get("repeated") or encoding.get("explode", True):
                pairs.extend((name, scalar(child)) for child in value)
            else:
                pairs.append((name, ",".join(scalar(child) for child in value)))
        elif isinstance(value, dict):
            if encoding.get("style") == "deepObject":
                pairs.extend((f"{name}[{key}]", scalar(child)) for key, child in value.items())
            elif encoding.get("explode", True):
                pairs.extend((str(key), scalar(child)) for key, child in value.items())
            else:
                pairs.append((name, ",".join(str(item) for pair in value.items() for item in pair)))
        else:
            pairs.append((name, scalar(value)))
    return pairs
