"""Pure-Python GraphQL introspection schema analyzer and safe read-only probe planner."""
from __future__ import annotations

import re
from typing import Any, Sequence

SCHEMA = "agentic-graphql-schema/1"

_BUILTIN_SCALARS: frozenset[str] = frozenset({"String", "Int", "Float", "Boolean", "ID"})
_ROOT_OPERATION_KINDS: frozenset[str] = frozenset({"OBJECT", "INTERFACE"})
_CUSTOM_TYPE_KINDS: frozenset[str] = frozenset({"OBJECT", "INPUT_OBJECT", "INTERFACE", "UNION", "ENUM"})

_CAMEL_BOUNDARY_RE = re.compile(r"([a-z0-9])([A-Z])")
_TOKEN_SPLIT_RE = re.compile(r"[^a-z0-9]+")
_CAMEL_ID_RE = re.compile(r"^[a-z][A-Za-z0-9]*(?:Id|Uuid|Guid|Uid)$")
_TYPE_DECORATOR_RE = re.compile(r"[\[\]!\s]")

_ID_ARG_EXACT: frozenset[str] = frozenset({"id", "uuid", "guid", "uid", "slug"})
_ID_ARG_SUFFIXES: tuple[str, ...] = ("_id", "_uuid", "_guid", "_uid")

_ADMIN_TOKENS: frozenset[str] = frozenset({
    "admin",
    "administrator",
    "superadmin",
    "superuser",
    "staff",
    "internal",
    "audit",
    "audits",
    "auditlog",
    "auditlogs",
    "backoffice",
    "mgmt",
    "manage",
    "system",
    "debug",
    "impersonate",
    "role",
    "roles",
    "permission",
    "permissions",
    "privilege",
    "privileges",
    "config",
    "settings",
    "metrics",
    "export",
    "moderator",
    "grant",
    "promote",
    "demote",
    "ban",
    "suspend",
})

_ADMIN_SNAKE_PHRASES: tuple[str, ...] = (
    "all_users",
    "all_orders",
    "all_accounts",
    "audit_log",
    "audit_logs",
    "admin_audit",
    "list_all",
)

_AUTH_TOKENS: frozenset[str] = frozenset({
    "auth",
    "authenticate",
    "login",
    "signin",
    "logout",
    "signout",
    "register",
    "signup",
    "token",
    "refresh",
    "password",
    "passwd",
    "otp",
    "mfa",
    "totp",
    "session",
    "sso",
    "oauth",
    "verify",
})

_AUTH_SNAKE_PHRASES: tuple[str, ...] = (
    "sign_in",
    "sign_up",
    "sign_out",
    "log_in",
    "log_out",
    "change_password",
    "reset_password",
    "forgot_password",
)

_DESTRUCTIVE_TOKENS: frozenset[str] = frozenset({
    "delete",
    "drop",
    "destroy",
    "purge",
    "deactivate",
    "remove",
    "wipe",
    "erase",
    "terminate",
    "revoke",
    "cancel",
    "disable",
    "suspend",
    "ban",
    "truncate",
    "reset",
    "kill",
    "shutdown",
    "nuke",
    "clear",
})

_SENSITIVE_OP_TOKENS: frozenset[str] = _ADMIN_TOKENS | frozenset({
    "user",
    "users",
    "account",
    "accounts",
    "profile",
    "profiles",
    "order",
    "orders",
    "invoice",
    "invoices",
    "payment",
    "payments",
    "billing",
    "wallet",
    "token",
    "secret",
    "key",
    "credential",
    "credentials",
    "password",
    "ssn",
    "balance",
    "credit",
    "card",
    "iban",
    "me",
    "viewer",
    "session",
    "private",
    "report",
    "reports",
    "notes",
})

_SENSITIVE_FIELD_EXACT: frozenset[str] = frozenset({
    "email",
    "e_mail",
    "phone",
    "phone_number",
    "mobile",
    "ssn",
    "social_security",
    "social_security_number",
    "tax_id",
    "tin",
    "passport",
    "national_id",
    "password",
    "password_hash",
    "passwd",
    "passphrase",
    "pwd",
    "secret",
    "client_secret",
    "api_secret",
    "mfa_secret",
    "totp_secret",
    "token",
    "access_token",
    "refresh_token",
    "id_token",
    "auth_token",
    "reset_token",
    "session_token",
    "api_key",
    "apikey",
    "private_key",
    "secret_key",
    "signing_key",
    "role",
    "roles",
    "is_admin",
    "admin",
    "is_staff",
    "is_superuser",
    "permission",
    "permissions",
    "scopes",
    "privileges",
    "balance",
    "credit_card",
    "card_number",
    "cvv",
    "cvc",
    "iban",
    "bank_account",
    "routing_number",
    "salary",
    "income",
    "address",
    "street_address",
    "home_address",
    "dob",
    "date_of_birth",
    "birth_date",
    "internal_notes",
    "internal_note",
    "admin_notes",
    "private_notes",
    "otp",
    "pin",
    "pin_hash",
    "session_id",
})

_SENSITIVE_FIELD_SUBSTRINGS: tuple[str, ...] = (
    "password",
    "passwd",
    "passphrase",
    "secret",
    "api_key",
    "apikey",
    "private_key",
    "credit_card",
    "card_number",
    "internal_note",
    "admin_note",
)

_SENSITIVE_FIELD_SUFFIXES: tuple[str, ...] = (
    "_token",
    "_secret",
    "_api_key",
    "_apikey",
    "_password",
    "_ssn",
    "_iban",
)

_PREFERRED_SCALAR_FIELDS: tuple[str, ...] = (
    "id",
    "name",
    "title",
    "email",
    "role",
    "status",
    "owner",
    "total",
    "action",
)


def _to_snake_tokens(name: str) -> tuple[str, list[str]]:
    snake = _CAMEL_BOUNDARY_RE.sub(r"\1_\2", str(name or "")).strip().lower().replace("-", "_")
    tokens = [tok for tok in _TOKEN_SPLIT_RE.split(snake) if tok]
    return snake, tokens


def _sanitize_ident(raw: Any, *, max_len: int = 128) -> str:
    text = str(raw or "").strip()
    if not text:
        return ""
    cleaned = "".join(ch for ch in text if 32 <= ord(ch) < 127)
    return cleaned[:max_len]


def _extract_schema_root(schema_doc: dict[str, Any]) -> dict[str, Any]:
    if not isinstance(schema_doc, dict):
        raise ValueError("schema_doc must be a JSON object")
    raw_data = schema_doc.get("data")
    if isinstance(raw_data, dict) and isinstance(raw_data.get("__schema"), dict):
        return raw_data["__schema"]
    if isinstance(schema_doc.get("__schema"), dict):
        return schema_doc["__schema"]
    if any(k in schema_doc for k in ("queryType", "mutationType", "subscriptionType", "types")):
        return schema_doc
    raise ValueError("schema_doc does not contain a valid GraphQL introspection __schema")


def _unwrap_type_ref(type_ref: Any, *, depth: int = 0) -> dict[str, Any]:
    """Decode nested GraphQL NON_NULL/LIST introspection type objects."""
    if not isinstance(type_ref, dict) or depth >= 12:
        return {
            "type": "Unknown",
            "base_name": "Unknown",
            "base_kind": "SCALAR",
            "required": False,
            "is_list": False,
        }

    kind = str(type_ref.get("kind") or "").strip().upper()
    name = _sanitize_ident(type_ref.get("name"))
    of_type = type_ref.get("ofType")

    if kind == "NON_NULL" and isinstance(of_type, dict):
        inner = _unwrap_type_ref(of_type, depth=depth + 1)
        return {
            "type": f"{inner['type']}!",
            "base_name": inner["base_name"],
            "base_kind": inner["base_kind"],
            "required": True,
            "is_list": bool(inner["is_list"]),
        }
    if kind == "LIST" and isinstance(of_type, dict):
        inner = _unwrap_type_ref(of_type, depth=depth + 1)
        return {
            "type": f"[{inner['type']}]",
            "base_name": inner["base_name"],
            "base_kind": inner["base_kind"],
            "required": False,
            "is_list": True,
        }
    eff_name = name or "Unknown"
    return {
        "type": eff_name,
        "base_name": eff_name,
        "base_kind": kind or "SCALAR",
        "required": False,
        "is_list": False,
    }


def _base_type_from_expr(type_expr: str) -> str:
    return _TYPE_DECORATOR_RE.sub("", str(type_expr or ""))


def _is_id_arg(name: str, base_type: str) -> bool:
    if base_type == "ID":
        return True
    snake, _tokens = _to_snake_tokens(name)
    if not snake:
        return False
    if snake in _ID_ARG_EXACT or snake.endswith(_ID_ARG_SUFFIXES):
        return True
    return bool(_CAMEL_ID_RE.fullmatch(name.strip()))


def _is_sensitive_field(field_name: str) -> bool:
    snake, tokens = _to_snake_tokens(field_name)
    if not snake:
        return False
    if snake in _SENSITIVE_FIELD_EXACT:
        return True
    if any(sub in snake for sub in _SENSITIVE_FIELD_SUBSTRINGS):
        return True
    if any(snake.endswith(sfx) for sfx in _SENSITIVE_FIELD_SUFFIXES):
        return True
    if snake.startswith(("internal_", "private_")):
        return True
    return any(tok in {"ssn", "iban", "password", "passwd", "secret", "apikey", "cvv", "cvc"} for tok in tokens)


def _is_admin_operation(name: str, return_base: str = "") -> bool:
    snake, tokens = _to_snake_tokens(name)
    ret_snake, ret_tokens = _to_snake_tokens(return_base)
    if any(tok in _ADMIN_TOKENS for tok in tokens):
        return True
    if any(phrase in snake for phrase in _ADMIN_SNAKE_PHRASES):
        return True
    if any(tok in {"admin", "audit", "auditlog", "auditlogs", "superuser"} for tok in ret_tokens):
        return True
    return any(phrase in ret_snake for phrase in ("audit_log", "admin_"))


def _is_auth_operation(name: str) -> bool:
    snake, tokens = _to_snake_tokens(name)
    if any(tok in _AUTH_TOKENS for tok in tokens):
        return True
    return any(phrase in snake for phrase in _AUTH_SNAKE_PHRASES)


def _is_destructive_operation(name: str) -> bool:
    _snake, tokens = _to_snake_tokens(name)
    return any(tok in _DESTRUCTIVE_TOKENS for tok in tokens)


def _is_sensitive_operation(
    name: str,
    *,
    is_id_lookup: bool,
    is_admin_like: bool,
    return_base: str,
    sensitive_types: set[str],
) -> bool:
    if is_id_lookup or is_admin_like or return_base in sensitive_types:
        return True
    _snake, tokens = _to_snake_tokens(name)
    return any(tok in _SENSITIVE_OP_TOKENS for tok in tokens)


def _parse_args_list(raw_args: Any) -> list[dict[str, Any]]:
    args: list[dict[str, Any]] = []
    if not isinstance(raw_args, list):
        return args
    for raw_arg in raw_args:
        if not isinstance(raw_arg, dict):
            continue
        aname = _sanitize_ident(raw_arg.get("name"))
        if not aname or aname.startswith("__"):
            continue
        tinfo = _unwrap_type_ref(raw_arg.get("type"))
        args.append({
            "name": aname,
            "type": tinfo["type"],
            "required": bool(tinfo["required"]),
            "is_id_like": _is_id_arg(aname, tinfo["base_name"]),
        })
    return args


def _collect_type_index(
    raw_types: list[Any],
) -> tuple[dict[str, dict[str, Any]], dict[str, dict[str, Any]]]:
    """Index raw schema types by name and return custom non-introspection, non-scalar types."""
    raw_by_name: dict[str, dict[str, Any]] = {}
    for type_obj in raw_types:
        if not isinstance(type_obj, dict):
            continue
        tname = _sanitize_ident(type_obj.get("name"))
        if tname:
            raw_by_name[tname] = type_obj
    return raw_by_name, {}


def _build_custom_type_entry(type_obj: dict[str, Any]) -> dict[str, Any]:
    tname = _sanitize_ident(type_obj.get("name"))
    tkind = str(type_obj.get("kind") or "OBJECT").strip().upper()
    fields_out: list[dict[str, Any]] = []
    for f in type_obj.get("fields") or []:
        if not isinstance(f, dict):
            continue
        fname = _sanitize_ident(f.get("name"))
        if not fname or fname.startswith("__"):
            continue
        tinfo = _unwrap_type_ref(f.get("type"))
        f_args = _parse_args_list(f.get("args"))
        fields_out.append({
            "name": fname,
            "type": tinfo["type"],
            "base_type": tinfo["base_name"],
            "base_kind": tinfo["base_kind"],
            "has_required_args": any(bool(a.get("required")) for a in f_args),
        })

    input_fields_out: list[dict[str, Any]] = []
    for inf in type_obj.get("inputFields") or []:
        if not isinstance(inf, dict):
            continue
        iname = _sanitize_ident(inf.get("name"))
        if not iname or iname.startswith("__"):
            continue
        tinfo = _unwrap_type_ref(inf.get("type"))
        input_fields_out.append({
            "name": iname,
            "type": tinfo["type"],
            "base_type": tinfo["base_name"],
            "required": bool(tinfo["required"]),
        })

    enum_values = [
        _sanitize_ident(ev.get("name"))
        for ev in (type_obj.get("enumValues") or [])
        if isinstance(ev, dict) and _sanitize_ident(ev.get("name"))
    ]
    return {
        "name": tname,
        "kind": tkind,
        "fields": fields_out,
        "input_fields": input_fields_out,
        "enum_values": enum_values,
    }


def _sample_return_fields(
    base_name: str,
    type_entries: dict[str, dict[str, Any]],
    *,
    limit: int = 10,
) -> list[str]:
    tentry = type_entries.get(base_name)
    if not isinstance(tentry, dict):
        return []
    fields = [f for f in (tentry.get("fields") or []) if isinstance(f, dict)]
    if not fields:
        return []
    scalars: list[str] = []
    nested: list[str] = []
    for f in fields:
        fname = str(f.get("name") or "")
        if not fname:
            continue
        bkind = str(f.get("base_kind") or "SCALAR").upper()
        bname = str(f.get("base_type") or "")
        if bkind in {"SCALAR", "ENUM"} or bname in _BUILTIN_SCALARS:
            scalars.append(fname)
        else:
            nested.append(fname)
    ordered = [*scalars, *nested]
    return ordered[: max(1, int(limit))]


def parse_introspection_schema(schema_doc: dict[str, Any]) -> dict[str, Any]:
    """Parse a GraphQL introspection JSON document into structured operations and risk metadata."""
    schema = _extract_schema_root(schema_doc)

    raw_qt = schema.get("queryType")
    raw_mt = schema.get("mutationType")
    raw_st = schema.get("subscriptionType")
    query_type = _sanitize_ident(raw_qt.get("name") if isinstance(raw_qt, dict) else raw_qt)
    mutation_type = _sanitize_ident(raw_mt.get("name") if isinstance(raw_mt, dict) else raw_mt)
    subscription_type = _sanitize_ident(raw_st.get("name") if isinstance(raw_st, dict) else raw_st)

    raw_types = schema.get("types")
    if not isinstance(raw_types, list):
        raw_types = []

    raw_by_name, _ = _collect_type_index(raw_types)
    root_names = {n for n in (query_type, mutation_type, subscription_type) if n}

    type_entries: dict[str, dict[str, Any]] = {}
    custom_types: list[dict[str, Any]] = []
    sensitive_fields: list[str] = []
    seen_sensitive: set[str] = set()
    sensitive_types: set[str] = set()

    for tname, type_obj in raw_by_name.items():
        if tname.startswith("__"):
            continue
        entry = _build_custom_type_entry(type_obj)
        type_entries[tname] = entry
        tkind = str(entry.get("kind") or "").upper()
        if tkind == "SCALAR" or tname in _BUILTIN_SCALARS:
            continue
        if tname not in root_names and tkind in _CUSTOM_TYPE_KINDS:
            custom_types.append(entry)
            for f in entry.get("fields") or []:
                fname = str(f.get("name") or "")
                if fname and _is_sensitive_field(fname):
                    fq = f"{tname}.{fname}"
                    if fq not in seen_sensitive:
                        seen_sensitive.add(fq)
                        sensitive_fields.append(fq)
                    sensitive_types.add(tname)
            for inf in entry.get("input_fields") or []:
                iname = str(inf.get("name") or "")
                if iname and _is_sensitive_field(iname):
                    fq = f"{tname}.{iname}"
                    if fq not in seen_sensitive:
                        seen_sensitive.add(fq)
                        sensitive_fields.append(fq)

    custom_types.sort(key=lambda item: str(item.get("name") or ""))

    queries: list[dict[str, Any]] = []
    if query_type and query_type in raw_by_name:
        for field in raw_by_name[query_type].get("fields") or []:
            if not isinstance(field, dict):
                continue
            qname = _sanitize_ident(field.get("name"))
            if not qname or qname.startswith("__"):
                continue
            args = _parse_args_list(field.get("args"))
            ret = _unwrap_type_ref(field.get("type"))
            ret_base = str(ret["base_name"])
            is_id_lookup = any(bool(a["is_id_like"]) for a in args)
            is_admin = _is_admin_operation(qname, ret_base)
            is_sensitive = _is_sensitive_operation(
                qname,
                is_id_lookup=is_id_lookup,
                is_admin_like=is_admin,
                return_base=ret_base,
                sensitive_types=sensitive_types,
            )
            queries.append({
                "name": qname,
                "args": args,
                "return_type": ret["type"],
                "return_fields_sample": _sample_return_fields(ret_base, type_entries),
                "is_id_lookup": is_id_lookup,
                "is_admin_like": is_admin,
                "is_sensitive": is_sensitive,
            })

    mutations: list[dict[str, Any]] = []
    if mutation_type and mutation_type in raw_by_name:
        for field in raw_by_name[mutation_type].get("fields") or []:
            if not isinstance(field, dict):
                continue
            mname = _sanitize_ident(field.get("name"))
            if not mname or mname.startswith("__"):
                continue
            args = _parse_args_list(field.get("args"))
            ret = _unwrap_type_ref(field.get("type"))
            ret_base = str(ret["base_name"])
            mutations.append({
                "name": mname,
                "args": args,
                "return_type": ret["type"],
                "is_destructive": _is_destructive_operation(mname),
                "is_admin_like": _is_admin_operation(mname, ret_base),
                "is_auth_like": _is_auth_operation(mname),
            })

    id_lookup_queries_count = sum(1 for q in queries if q["is_id_lookup"])
    admin_operations_count = sum(1 for q in queries if q["is_admin_like"]) + sum(
        1 for m in mutations if m["is_admin_like"]
    )
    stats = {
        "queries_count": len(queries),
        "mutations_count": len(mutations),
        "id_lookup_queries_count": id_lookup_queries_count,
        "admin_operations_count": admin_operations_count,
        "sensitive_fields_count": len(sensitive_fields),
        "types_count": len(custom_types),
    }

    return {
        "schema": SCHEMA,
        "query_type": query_type,
        "mutation_type": mutation_type,
        "subscription_type": subscription_type,
        "queries": queries,
        "mutations": mutations,
        "sensitive_fields": sensitive_fields,
        "types": custom_types,
        "stats": stats,
    }


def _synthetic_arg_literal(
    type_expr: str,
    type_index: dict[str, dict[str, Any]],
    *,
    depth: int = 0,
) -> str:
    """Render a synthetic benign typed GraphQL argument literal."""
    raw = str(type_expr or "").strip()
    is_list = "[" in raw and "]" in raw
    base = _base_type_from_expr(raw)

    if base in {"ID", "String"}:
        scalar_lit = '"1"'
    elif base in {"Int", "Float"}:
        scalar_lit = "1"
    elif base == "Boolean":
        scalar_lit = "false"
    else:
        tentry = type_index.get(base)
        tkind = str((tentry or {}).get("kind") or "").upper()
        if tkind == "ENUM":
            enum_vals = (tentry or {}).get("enum_values") or []
            scalar_lit = str(enum_vals[0]) if enum_vals else '"1"'
        elif tkind == "INPUT_OBJECT" and depth < 2:
            pairs: list[str] = []
            for inf in (tentry or {}).get("input_fields") or []:
                if not isinstance(inf, dict):
                    continue
                if inf.get("required") or len(pairs) == 0:
                    iname = str(inf.get("name") or "")
                    itype = str(inf.get("type") or "String")
                    if iname:
                        pairs.append(f"{iname}: {_synthetic_arg_literal(itype, type_index, depth=depth + 1)}")
                if len(pairs) >= 4:
                    break
            scalar_lit = "{ " + ", ".join(pairs) + " }" if pairs else "{}"
        else:
            scalar_lit = '"1"'

    return f"[{scalar_lit}]" if is_list else scalar_lit


def _is_leaf_field(field_info: dict[str, Any], type_index: dict[str, dict[str, Any]]) -> bool:
    bkind = str(field_info.get("base_kind") or "").upper()
    btype = str(field_info.get("base_type") or "")
    if bkind in {"SCALAR", "ENUM"} or btype in _BUILTIN_SCALARS:
        return True
    tentry = type_index.get(btype)
    if tentry is None:
        return True
    return str(tentry.get("kind") or "").upper() in {"SCALAR", "ENUM"}


def _build_selection_set(
    type_name: str,
    type_index: dict[str, dict[str, Any]],
    fallback_fields: Sequence[str] = (),
    *,
    depth: int = 1,
    max_depth: int = 2,
    visited: frozenset[str] = frozenset(),
) -> str:
    """Build a minimal valid GraphQL selection set bounded to depth <= 2."""
    clean_base = _base_type_from_expr(type_name)
    if not clean_base or clean_base in _BUILTIN_SCALARS:
        return ""

    tentry = type_index.get(clean_base)
    if tentry is None:
        # Handle parsed schemas that omit `types` by trusting safe fallback scalar names if provided.
        if fallback_fields:
            picked = [_sanitize_ident(f) for f in fallback_fields[:4] if _sanitize_ident(f)]
            return "{ " + " ".join(picked) + " }" if picked else ""
        return ""

    tkind = str(tentry.get("kind") or "").upper()
    if tkind in {"SCALAR", "ENUM"}:
        return ""
    if tkind == "UNION":
        return "{ __typename }"

    raw_fields = [f for f in (tentry.get("fields") or []) if isinstance(f, dict) and not f.get("has_required_args")]
    scalar_names: list[str] = []
    nested_candidates: list[tuple[str, str]] = []
    for f in raw_fields:
        fname = _sanitize_ident(f.get("name"))
        if not fname or fname.startswith("__"):
            continue
        if _is_leaf_field(f, type_index):
            scalar_names.append(fname)
        else:
            btype = str(f.get("base_type") or "")
            if btype and btype not in visited:
                nested_candidates.append((fname, btype))

    # Prefer well-known ID/scalar fields first while preserving determinism.
    pref_rank = {name: idx for idx, name in enumerate(_PREFERRED_SCALAR_FIELDS)}
    scalar_names_sorted = sorted(
        dict.fromkeys(scalar_names),
        key=lambda n: (pref_rank.get(n.lower(), 999), scalar_names.index(n)),
    )
    selected_parts: list[str] = scalar_names_sorted[:5]

    if depth < max_depth and nested_candidates and len(selected_parts) < 4:
        next_visited = visited | {clean_base}
        for n_name, n_type in nested_candidates:
            sub_sel = _build_selection_set(
                n_type,
                type_index,
                depth=depth + 1,
                max_depth=max_depth,
                visited=next_visited,
            )
            if sub_sel:
                selected_parts.append(f"{n_name} {sub_sel}")
                break

    if not selected_parts:
        return "{ __typename }"
    return "{ " + " ".join(selected_parts) + " }"


def _format_query_document(
    query_item: dict[str, Any],
    type_index: dict[str, dict[str, Any]],
) -> str:
    qname = str(query_item.get("name") or "")
    args = [a for a in (query_item.get("args") or []) if isinstance(a, dict) and a.get("name")]
    arg_parts: list[str] = []
    for arg in args:
        aname = str(arg["name"])
        atype = str(arg.get("type") or "String")
        if bool(arg.get("required")) or bool(arg.get("is_id_like")) or len(args) <= 2:
            lit = _synthetic_arg_literal(atype, type_index)
            arg_parts.append(f"{aname}: {lit}")
    args_clause = f"({', '.join(arg_parts)})" if arg_parts else ""
    sel = _build_selection_set(
        str(query_item.get("return_type") or ""),
        type_index,
        fallback_fields=query_item.get("return_fields_sample") or (),
        depth=1,
        max_depth=2,
    )
    body_part = f"{qname}{args_clause} {sel}".strip()
    return f"query {{ {body_part} }}"


def build_safe_graphql_probes(
    parsed_schema: dict[str, Any],
    *,
    allowed_methods: Sequence[str] = ("POST",),
    max_probes: int = 8,
) -> list[dict[str, Any]]:
    """Build deterministic, strictly non-destructive read-only GraphQL test probes."""
    if not isinstance(parsed_schema, dict) or isinstance(max_probes, bool) or int(max_probes) <= 0:
        return []
    cap = int(max_probes)

    methods = {str(m).strip().upper() for m in (allowed_methods or ()) if str(m).strip()}
    can_post = "POST" in methods
    can_get = "GET" in methods
    if not can_post and not can_get:
        return []

    queries = [
        q
        for q in (parsed_schema.get("queries") or [])
        if isinstance(q, dict) and str(q.get("name") or "").strip() and not _is_destructive_operation(str(q.get("name") or ""))
    ]
    if not queries:
        return []

    type_index = {
        str(t["name"]): t
        for t in (parsed_schema.get("types") or [])
        if isinstance(t, dict) and t.get("name")
    }

    def _priority_key(item: tuple[int, dict[str, Any]]) -> tuple[int, int, int, int, int, str]:
        idx, q = item
        is_id = bool(q.get("is_id_lookup"))
        is_adm = bool(q.get("is_admin_like"))
        is_sens = bool(q.get("is_sensitive"))
        return (
            0 if (is_id and is_adm) else (1 if is_id else (2 if is_adm else (3 if is_sens else 4))),
            0 if is_id else 1,
            0 if is_adm else 1,
            0 if is_sens else 1,
            idx,
            str(q.get("name") or ""),
        )

    ranked_queries = [q for _, q in sorted(enumerate(queries), key=_priority_key)]

    include_batch = can_post and cap >= 2
    single_cap = (cap - 1) if include_batch else cap
    single_method = "POST" if can_post else "GET"

    probes: list[dict[str, Any]] = []
    rendered_queries: list[tuple[str, str]] = []

    for q in ranked_queries[:single_cap]:
        qname = str(q["name"])
        doc = _format_query_document(q, type_index)
        rendered_queries.append((qname, doc))
        if q.get("is_id_lookup"):
            kind = "id_lookup"
            category = "bola"
        elif q.get("is_admin_like"):
            kind = "admin_query"
            category = "bfla"
        elif q.get("is_sensitive"):
            kind = "sensitive_query"
            category = "data_exposure"
        else:
            kind = "read_query"
            category = "surface_discovery"

        payload: dict[str, Any] = {"query": doc}
        probes.append({
            "probe_id": f"gql-probe-{len(probes) + 1:02d}",
            "kind": kind,
            "category": category,
            "operation": qname,
            "method": single_method,
            "query": doc,
            "payload": payload,
            "json_body": payload if single_method == "POST" else None,
            "read_only": True,
        })

    if include_batch and rendered_queries:
        first_name, first_doc = rendered_queries[0]
        if len(rendered_queries) >= 2:
            second_name, second_doc = rendered_queries[1]
        else:
            second_name, second_doc = first_name, first_doc
        batch_payload: list[dict[str, str]] = [
            {"query": first_doc},
            {"query": second_doc},
        ]
        probes.append({
            "probe_id": f"gql-probe-{len(probes) + 1:02d}",
            "kind": "batching_check",
            "category": "rate_limit_batching",
            "operation": f"{first_name},{second_name}",
            "method": "POST",
            "query": first_doc,
            "payload": batch_payload,
            "json_body": batch_payload,
            "read_only": True,
        })

    return probes[:cap]


def _format_args_sig(args: Sequence[dict[str, Any]]) -> str:
    parts = [f"{a.get('name')}: {a.get('type')}" for a in args[:4] if isinstance(a, dict) and a.get("name")]
    if len(args) > 4:
        parts.append("...")
    return f"({', '.join(parts)})" if parts else ""


def format_graphql_schema_handoff(
    parsed_schema: dict[str, Any],
    *,
    endpoint: str = "/graphql",
    max_chars: int = 1600,
) -> str:
    """Format a compact, bounded, secret-free Turn-1 LLM summary of parsed GraphQL schema."""
    if isinstance(max_chars, bool) or int(max_chars) <= 0 or not isinstance(parsed_schema, dict):
        return ""
    cap = int(max_chars)
    queries = [q for q in (parsed_schema.get("queries") or []) if isinstance(q, dict)]
    mutations = [m for m in (parsed_schema.get("mutations") or []) if isinstance(m, dict)]
    sensitive_fields = [str(sf) for sf in (parsed_schema.get("sensitive_fields") or []) if str(sf)]
    if not queries and not mutations and not sensitive_fields:
        return ""

    raw_stats = parsed_schema.get("stats")
    stats: dict[str, Any] = raw_stats if isinstance(raw_stats, dict) else {}
    clean_ep = _sanitize_ident(endpoint, max_len=160) or "/graphql"
    q_cnt = int(stats.get("queries_count", len(queries)))
    m_cnt = int(stats.get("mutations_count", len(mutations)))
    id_cnt = int(stats.get("id_lookup_queries_count", sum(1 for q in queries if q.get("is_id_lookup"))))
    adm_cnt = int(
        stats.get(
            "admin_operations_count",
            sum(1 for q in queries if q.get("is_admin_like"))
            + sum(1 for m in mutations if m.get("is_admin_like")),
        )
    )
    sf_cnt = int(stats.get("sensitive_fields_count", len(sensitive_fields)))

    header = (
        f"[GRAPHQL SCHEMA] endpoint={clean_ep} queries={q_cnt} mutations={m_cnt} "
        f"id_lookups={id_cnt} admin_ops={adm_cnt} sensitive_fields={sf_cnt}"
    )

    candidate_lines: list[str] = []
    if queries:
        ranked_q = sorted(
            queries,
            key=lambda q: (
                0 if q.get("is_id_lookup") else 1,
                0 if q.get("is_admin_like") else 1,
                0 if q.get("is_sensitive") else 1,
                str(q.get("name") or ""),
            ),
        )
        candidate_lines.append("Queries (read-only):")
        for q in ranked_q[:8]:
            tags: list[str] = []
            if q.get("is_id_lookup"):
                tags.append("ID_LOOKUP")
            if q.get("is_admin_like"):
                tags.append("ADMIN")
            if q.get("is_sensitive"):
                tags.append("SENSITIVE")
            tag_str = f" [{' '.join(tags)}]" if tags else ""
            sig = _format_args_sig(q.get("args") or [])
            candidate_lines.append(f"- {q.get('name')}{sig} -> {q.get('return_type')}{tag_str}")

    if mutations:
        ranked_m = sorted(
            mutations,
            key=lambda m: (
                0 if m.get("is_admin_like") else 1,
                0 if m.get("is_auth_like") else 1,
                1 if m.get("is_destructive") else 0,
                str(m.get("name") or ""),
            ),
        )
        candidate_lines.append("Mutations:")
        for m in ranked_m[:6]:
            tags = []
            if m.get("is_destructive"):
                tags.append("DESTRUCTIVE")
            if m.get("is_admin_like"):
                tags.append("ADMIN")
            if m.get("is_auth_like"):
                tags.append("AUTH")
            tag_str = f" [{' '.join(tags)}]" if tags else ""
            sig = _format_args_sig(m.get("args") or [])
            candidate_lines.append(f"- {m.get('name')}{sig} -> {m.get('return_type')}{tag_str}")

    if sensitive_fields:
        joined_sf = ", ".join(sensitive_fields[:12])
        if len(sensitive_fields) > 12:
            joined_sf += f" (+{len(sensitive_fields) - 12} more)"
        candidate_lines.append(f"Sensitive fields: {joined_sf}")

    lines: list[str] = [header]
    used = len(header)
    for line in candidate_lines:
        if used + 1 + len(line) > cap:
            break
        lines.append(line)
        used += 1 + len(line)

    rendered = "\n".join(lines)
    if len(rendered) > cap:
        if cap <= 3:
            return rendered[:cap]
        return rendered[: cap - 3].rstrip() + "..."
    return rendered


__all__ = [
    "SCHEMA",
    "build_safe_graphql_probes",
    "format_graphql_schema_handoff",
    "parse_introspection_schema",
]
