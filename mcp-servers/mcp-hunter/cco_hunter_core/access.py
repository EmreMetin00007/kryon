"""Pure access-control classification and differential helpers."""

import hashlib
import json
import re


OBJ_ID_RE = re.compile(
    r"(/\d+)(/|$|\?)|[?&](id|uid|user_id|account|order|invoice|doc|file|"
    r"pid|oid|number|ref)=|/(users?|accounts?|orders?|invoices?|documents?|"
    r"files?|messages?|profiles?)/[\w-]+",
    re.I,
)
PRIV_PATH_RE = re.compile(
    r"(admin|manage|internal|config|settings|console|dashboard|approve|"
    r"delete|grant|role|permission|audit|users?/all|export|backup)",
    re.I,
)


def resource_kind(url):
    privileged = bool(PRIV_PATH_RE.search(url or ""))
    has_numeric_id = bool(re.search(r"/\d+(/|$|\?)|[?&]\w*id=\d+", url or "", re.I))
    object_level = bool(OBJ_ID_RE.search(url or ""))
    if privileged and not has_numeric_id:
        return "function_level"
    if object_level:
        return "object_level"
    if privileged:
        return "function_level"
    return "generic"


def parse_list(value):
    value = (value or "").strip()
    if not value:
        return []
    if value.startswith("["):
        try:
            return [str(item) for item in json.loads(value)]
        except Exception:
            pass
    return [item.strip() for item in value.split(",") if item.strip()]


def substitute_id(url, object_id):
    if re.search(r"[?&](id|uid|user_id|account|order|invoice|doc|file|pid|oid|number|ref)=", url, re.I):
        return re.sub(
            r"([?&](?:id|uid|user_id|account|order|invoice|doc|file|pid|oid|number|ref)=)[^&]*",
            lambda match: match.group(1) + str(object_id), url, flags=re.I,
        )
    if re.search(r"/\d+(/|$|\?)", url):
        return re.sub(r"/\d+(/|$|\?)", f"/{object_id}" + r"\1", url, count=1)
    if re.search(r"/(users?|accounts?|orders?|invoices?|documents?|files?|messages?|profiles?)/[\w-]+", url, re.I):
        return re.sub(
            r"(/(?:users?|accounts?|orders?|invoices?|documents?|files?|messages?|profiles?)/)[\w-]+",
            lambda match: match.group(1) + str(object_id), url, count=1, flags=re.I,
        )
    separator = "&" if "?" in url else "?"
    return f"{url}{separator}id={object_id}"


def body_signature(entry):
    body_hash = entry.get("body_hash")
    if not body_hash and entry.get("body") is not None:
        body_hash = hashlib.sha256(
            str(entry["body"]).encode("utf-8", "ignore")
        ).hexdigest()
    body_length = entry.get(
        "body_len",
        len(str(entry.get("body", ""))) if entry.get("body") is not None else None,
    )
    return body_hash, body_length
