"""Hypothesis ledger: per-target vector queue with code-enforced rotation.

The linear phase chain had no second move: a vector that hit its first
block (SQLi 400, SSRF allowlist, race 409) stalled the whole run. The
ledger moves that decision out of the LLM's momentary judgement: each
vector has a persisted status, `blocked` burns an attempt, attempts
running out marks the vector `exhausted`, and `claim_next` hands out
the next untried vector. `confirmed` closes only its own vector.
"""

from __future__ import annotations

import json
import re
from object_identity import normalize_object_id, object_id_key, object_id_sort_key
import sys
from pathlib import Path
from urllib.parse import urlsplit

sys.path.insert(0, str(Path(__file__).resolve().parent))

from target_identity import canonical_target, target_key  # noqa: E402

DEFAULT_VECTORS = (
    "authz-idor",
    "authn-session",
    "csrf",
    "injection-sqli",
    "injection-ssti",
    "ssrf",
    "xss-stored",
    "race-business",
    "file-access",
)

STATUSES = ("untried", "active", "blocked", "exhausted", "confirmed", "not_applicable")
TERMINAL = ("exhausted", "confirmed", "not_applicable")
LEDGER_NAME = "hypotheses.json"

# Candidate windows around each observed id: tight neighbours first, the
# wider net only after. Nothing here is target-specific — every seed comes
# from observed evidence (routes, owned ids, doc numbers).
POOL_WINDOWS = (1, 2, 5, 10, 25)
POOL_MAX_CANDIDATES = 200

# Surface signal -> vector weight. Deterministic: same enum inventory,
# same order. Direct object routes outrank session hygiene; discovered
# feature areas (webhooks/reports/billing/support) outrank everything
# except direct object reads.
SURFACE_RULES = (
    (("documents", ":id", "download", "invoices"), {"authz-idor": 10, "file-access": 6}),
    (("webhook", "webhooks"), {"ssrf": 10}),
    (("report", "reports", "export.csv", "metafields"), {"injection-sqli": 10}),
    (("billing", "promo", "coupon", "redeem", "credits", "credit", "balance"),
     {"race-business": 10}),
    (("support", "ticket", "tickets", "message", "messages", "comment", "inbox",
      "reflect", "xss", "preview"),
     {"xss-stored": 10}),
    (("login", "signup", "signin", "session", "cookie", "jwt", "redirect", "next=",
      "return_to=", "goto="),
     {"authn-session": 5}),
    (("form", "submit", "state-change", "logout"), {"csrf": 3}),
    (("graphql",), {"injection-sqli": 6}),
    (("upload", "avatar", "attachment"), {"file-access": 8}),
    (("admin", "manage", "internal", "debug"), {"authz-idor": 4, "ssrf": 4}),
)


def _surface_tokens(routes: list[str] | None, params: list[str] | None) -> set[str]:
    tokens: set[str] = set()
    for item in list(routes or []) + list(params or []):
        for part in re.split(r"[^a-z0-9:=.]+", str(item).lower()):
            if part:
                tokens.add(part)
                tokens.update(sub for sub in re.split(r"[-_.]", part) if sub)
    return tokens


def _keyword_matches(keyword: str, tokens: set[str], haystack: str) -> bool:
    # Words and wildcards require exact token membership: "code" must
    # not fire on "codes" or "decode". Punctuation keys (export.csv,
    # next=) still scan the joined haystack — they carry their own
    # delimiters, so they cannot false-positive on organic words.
    if any(char in keyword for char in "=.-"):
        return keyword in haystack
    return keyword in tokens


def score_vectors(routes: list[str] | None, params: list[str] | None) -> dict[str, int]:
    """Score ledger vectors from the discovered surface inventory."""
    haystack = " ".join(str(item).lower() for item in list(routes or []) + list(params or []))
    tokens = _surface_tokens(routes, params)
    scores = {vector: 0 for vector in DEFAULT_VECTORS}
    for keywords, weights in SURFACE_RULES:
        if any(_keyword_matches(keyword, tokens, haystack) for keyword in keywords):
            for vector, weight in weights.items():
                scores[vector] = scores.get(vector, 0) + weight
    return scores


def reorder_by_surface(ledger: dict, routes: list[str] | None = None,
                       params: list[str] | None = None) -> dict:
    """Reorder untried vectors by surface score, highest first.

    Active entries keep the head (rotation resumes them), terminal
    entries stay at the tail. Ties keep the default vector order, so
    the result is identical for identical inventories.
    """
    scores = score_vectors(routes, params)
    base = {vector: index for index, vector in enumerate(DEFAULT_VECTORS)}
    entries = list(ledger.get("hypotheses", []))
    active = [e for e in entries if e.get("status") == "active"]
    terminal = [e for e in entries if e.get("status") in TERMINAL]
    rest = [e for e in entries if e.get("status") not in TERMINAL and e.get("status") != "active"]
    rest.sort(key=lambda e: (-scores.get(str(e.get("vector")), 0),
                             base.get(str(e.get("vector")), len(base))))
    ledger["hypotheses"] = active + rest + terminal
    return ledger


def _route_numbers(routes: object) -> list[int]:
    numbers: list[int] = []
    if not isinstance(routes, (list, tuple, set)):
        return numbers
    for route in routes:
        text = str(route.get("url") or route.get("path") or "") if isinstance(route, dict) else str(route)
        if "://" in text:
            text = urlsplit(text).path or text
        numbers.extend(int(segment) for segment in text.split("/") if segment.isdecimal())
    return numbers


def object_candidates(routes: object = None, own_ids: object = None,
                      docs_ids: object = None, radius: object = 25,
                      priority_order: bool = False,
                      max_candidates: int | None = POOL_MAX_CANDIDATES) -> list:
    """Candidate object ids from observed evidence only, no hardcoding.

    Legacy unqualified integers keep their format. Family-qualified integers,
    UUIDs and opaque identifiers retain an explicit family/format/value ref.
    Only integers get a ±window ladder; UUID fragments are never number seeds.
    Default return is sorted; `priority_order` keeps seeds before the ladder.
    """
    observed = list(_route_numbers(routes))
    for values in (own_ids, docs_ids):
        if not isinstance(values, (list, tuple, set)):
            continue
        for value in values:
            if isinstance(value, dict) and not value.get("family"):
                raw = str(value.get("id") or value.get("value") or "")
                if re.fullmatch(r"[A-Za-z0-9.-]+\.([A-Za-z0-9.-]+):\d+", raw):
                    continue  # host:port is not an object identifier
            try:
                observed.append(normalize_object_id(value))
            except ValueError:
                continue
    if isinstance(routes, (list, tuple, set)):
        for route in routes:
            text = str(route.get("url") or route.get("path") or "") if isinstance(route, dict) else str(route)
            parts = [part for part in urlsplit(text).path.split("/") if part]
            for index, part in enumerate(parts):
                try:
                    ref = normalize_object_id({"family": parts[index - 1] if index else "", "id": part})
                    if isinstance(ref, dict) and ref["format"] == "uuid":
                        observed.append(ref)
                except ValueError:
                    continue
    unique = {object_id_key(value): value for value in observed if value != 0}
    observed = sorted(unique.values(), key=object_id_sort_key)
    try:
        radius_value = int(radius)  # type: ignore[arg-type]
    except (TypeError, ValueError):
        radius_value = 25
    windows = [w for w in POOL_WINDOWS if w <= max(0, radius_value)]
    ordered: list = []
    seen: set[str] = set()

    def add(value) -> None:
        try:
            value = normalize_object_id(value)
            key = object_id_key(value)
        except ValueError:
            return
        if key not in seen:
            seen.add(key)
            ordered.append(value)

    for value in observed:
        add(value)
    for window in windows:
        for value in observed:
            if isinstance(value, int):
                add(value - window)
                add(value + window)
            elif value["format"] == "int":
                for number in (value["value"] - window, value["value"] + window):
                    add({**value, "value": number})
    capped = ordered if max_candidates is None else ordered[:max(0, max_candidates)]
    return capped if priority_order else sorted(capped, key=object_id_sort_key)


def ledger_path(workdir: str | Path) -> Path:
    return Path(workdir) / LEDGER_NAME


def init_ledger(target: str, vectors: tuple[str, ...] | list[str] | None = None,
                max_attempts: int = 2) -> dict:
    chosen = list(vectors) if vectors else list(DEFAULT_VECTORS)
    return {
        "target": canonical_target(target),
        "target_key": target_key(target),
        "max_attempts": max(1, int(max_attempts)),
        "hypotheses": [
            {"vector": v, "status": "untried", "attempts": 0, "evidence": [], "note": ""}
            for v in chosen
        ],
    }


def save_ledger(workdir: str | Path, ledger: dict) -> Path:
    path = ledger_path(workdir)
    path.parent.mkdir(parents=True, exist_ok=True)
    path.write_text(json.dumps(ledger, indent=1, ensure_ascii=False))
    return path


def load_ledger(workdir: str | Path) -> dict:
    return json.loads(ledger_path(workdir).read_text())


def _find(ledger: dict, vector: str) -> dict:
    for entry in ledger.get("hypotheses", []):
        if entry.get("vector") == vector:
            return entry
    raise KeyError(f"vector not in ledger: {vector}")


def _next_candidate(ledger: dict) -> dict | None:
    """Rotation order: resume active, then untried, then a second pass
    over blocked vectors that still have attempts left. A wedged vector
    therefore never blocks the queue, but gets its bounded retry once
    every fresher vector has had a turn."""
    max_attempts = int(ledger.get("max_attempts", 2))
    for entry in ledger["hypotheses"]:
        if entry["status"] == "active" and entry["attempts"] < max_attempts:
            return entry
    for entry in ledger["hypotheses"]:
        if entry["status"] == "untried":
            return entry
    for entry in ledger["hypotheses"]:
        if entry["status"] == "blocked" and entry["attempts"] < max_attempts:
            return entry
    return None


def claim_next(ledger: dict) -> dict | None:
    """Hand out the next vector per rotation order and mark it active.

    An active vector whose attempts are spent is exhausted first, so a
    wedged vector can never be handed out twice in a row forever.
    """
    max_attempts = int(ledger.get("max_attempts", 2))
    for entry in ledger["hypotheses"]:
        if entry["status"] == "active" and entry["attempts"] >= max_attempts:
            entry["status"] = "exhausted"
    entry = _next_candidate(ledger)
    if entry is not None:
        entry["status"] = "active"
    return entry


def peek_next(ledger: dict) -> dict | None:
    """What `claim_next` would hand out, without mutating the ledger."""
    return _next_candidate(ledger)


def mark(ledger: dict, vector: str, status: str, evidence: str = "", note: str = "") -> dict:
    if status not in STATUSES:
        raise ValueError(f"status must be one of {STATUSES}")
    entry = _find(ledger, vector)
    if entry["status"] in TERMINAL and status != entry["status"]:
        raise ValueError(f"{vector} is terminal ({entry['status']}); cannot move to {status}")
    if status == "blocked":
        entry["attempts"] = int(entry.get("attempts", 0)) + 1
        if entry["attempts"] >= int(ledger.get("max_attempts", 2)):
            status = "exhausted"
    entry["status"] = status
    if evidence:
        entry.setdefault("evidence", []).append(evidence)
    if note:
        entry["note"] = note
    return entry


def ledger_summary(ledger: dict) -> dict[str, int]:
    counts = {status: 0 for status in STATUSES}
    for entry in ledger.get("hypotheses", []):
        counts[entry.get("status", "untried")] = counts.get(entry.get("status", "untried"), 0) + 1
    return counts


def observation_queue(db_path, target, context=None):
    """Read detailed hypotheses; legacy vector entries remain reporting groups."""
    import sqlite3
    surface = str(Path(__file__).resolve().parents[1] / "mcp-servers" / "mcp-memory-server")
    if surface not in sys.path:
        sys.path.insert(0, surface)
    from cco_surface_core.hypotheses import list_hypotheses
    if not Path(db_path).is_file():
        return []
    with sqlite3.connect(db_path) as conn:
        return list_hypotheses(conn, target, context)
