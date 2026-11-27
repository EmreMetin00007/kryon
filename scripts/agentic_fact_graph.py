"""Thread-safe cross-shard shared fact blackboard with strict secret hygiene."""
from __future__ import annotations

import copy
import json
import os
from pathlib import Path
import re
import tempfile
import threading
from typing import Any, Sequence

from agentic_receipts import redact_secrets

VALID_FACT_TYPES: frozenset[str] = frozenset({
    "internal_host",
    "actor_capability",
    "ssrf_sink",
    "auth_header",
    "verified_primitive",
    "cross_tenant_id",
    "waf_bypass",
})

DEFAULT_MAX_FACTS = 40

_FACT_PRIORITY: dict[str, int] = {
    "verified_primitive": 0,
    "actor_capability": 1,
    "internal_host": 2,
    "ssrf_sink": 3,
    "auth_header": 4,
    "waf_bypass": 5,
    "cross_tenant_id": 6,
}

_RAW_JWT_RE = re.compile(r"eyJ[A-Za-z0-9_-]{8,}\.[A-Za-z0-9_-]{8,}\.[A-Za-z0-9_-]{4,}")
_BEARER_HEADER_RE = re.compile(r"(?i)\bbearer\s+[A-Za-z0-9._~+/=-]{8,}")
_COOKIE_HEADER_RE = re.compile(r"(?i)\b(set-cookie|cookie)\s*:\s*(?!<REDACTED)([^\r\n]+)")
_COOKIE_KV_RE = re.compile(r"(?i)\b(set-cookie|cookie)\s*=\s*(?!<REDACTED)([^\s;,\r\n]{4,}(?:;\s*[^\r\n]*)?)")
_AWS_KEY_RE = re.compile(r"AKIA[0-9A-Z]{16}")
_PEM_KEY_RE = re.compile(r"-----BEGIN [A-Z ]*PRIVATE KEY-----")
_CREDENTIAL_LITERAL_RE = re.compile(
    r"(?i)(?<![A-Za-z0-9_.-])"
    r"((?:api[_-]?key|apikey|client_secret|access[_-]?token|refresh[_-]?token|"
    r"auth[_-]?token|session[_-]?id|private[_-]?key|password|passwd|passphrase|secret|token)"
    r"\b\s*[:=]\s*)(?!<REDACTED)"
    r"(?:'[^'\r\n]{4,}'|\"[^\"\r\n]{4,}\"|[A-Za-z0-9._~+/=-]{6,})"
)
_REDACTED_TAG_RE = re.compile(r"<REDACTED[^>]*>")


def _atomic_write_json(path: Path, data: Any) -> None:
    """Atomically write JSON with 0600 permissions to `path`."""
    path.parent.mkdir(parents=True, exist_ok=True)
    payload = json.dumps(data, indent=2, ensure_ascii=False, allow_nan=False) + "\n"
    with tempfile.NamedTemporaryFile(
        mode="w",
        encoding="utf-8",
        prefix=".shared-facts-",
        suffix=".tmp",
        dir=path.parent,
        delete=False,
    ) as handle:
        tmp_path = Path(handle.name)
        try:
            os.chmod(tmp_path, 0o600)
            handle.write(payload)
            handle.flush()
        except Exception:
            tmp_path.unlink(missing_ok=True)
            raise
    try:
        os.replace(tmp_path, path)
    except Exception:
        tmp_path.unlink(missing_ok=True)
        raise


def _contains_raw_secret(text: str) -> bool:
    """Return True if text directly carries a raw token, JWT, cookie value, or credential literal."""
    if not text:
        return False
    return bool(
        _RAW_JWT_RE.search(text)
        or _BEARER_HEADER_RE.search(text)
        or _COOKIE_HEADER_RE.search(text)
        or _COOKIE_KV_RE.search(text)
        or _AWS_KEY_RE.search(text)
        or _PEM_KEY_RE.search(text)
        or _CREDENTIAL_LITERAL_RE.search(text)
    )


def _scrub_secret_text(text: str, secret_values: Sequence[str] = ()) -> str:
    """Collapse whitespace and redact any raw JWTs, Bearer headers, cookies, or credential literals."""
    if not text:
        return ""
    one_line = " ".join(str(text).split())
    cleaned = redact_secrets(one_line, secret_values)
    cleaned = _RAW_JWT_RE.sub("<REDACTED_JWT>", cleaned)
    cleaned = _BEARER_HEADER_RE.sub("Bearer <REDACTED_TOKEN>", cleaned)
    cleaned = _COOKIE_HEADER_RE.sub(lambda m: f"{m.group(1)}: <REDACTED_COOKIE>", cleaned)
    cleaned = _COOKIE_KV_RE.sub(lambda m: f"{m.group(1)}=<REDACTED_COOKIE>", cleaned)
    cleaned = _AWS_KEY_RE.sub("<REDACTED_KEY>", cleaned)
    cleaned = _PEM_KEY_RE.sub("<REDACTED_PRIVATE_KEY>", cleaned)
    cleaned = _CREDENTIAL_LITERAL_RE.sub(lambda m: f"{m.group(1)}<REDACTED_SECRET>", cleaned)
    return " ".join(cleaned.split())


def _has_meaningful_non_secret_content(scrubbed: str) -> bool:
    """Return True when scrubbed text retains informative non-redacted content."""
    if not scrubbed:
        return False
    stripped = _REDACTED_TAG_RE.sub("", scrubbed)
    stripped = re.sub(r"(?i)\b(?:bearer|cookie|set-cookie)\b", "", stripped)
    stripped = re.sub(r"[^A-Za-z0-9/_.-]+", "", stripped)
    return len(stripped) >= 2


def _normalize_target_families(target_families: Sequence[str] | str | None) -> tuple[str, ...]:
    if target_families is None:
        return ("*",)
    if isinstance(target_families, str):
        raw_items = [s.strip().lower() for s in target_families.split(",") if s.strip()]
    else:
        raw_items = [str(s).strip().lower() for s in target_families if str(s).strip()]
    if not raw_items:
        return ("*",)
    if "*" in raw_items:
        deduped = ["*"] + [x for x in dict.fromkeys(raw_items) if x != "*"]
        return tuple(deduped[:12])
    return tuple(dict.fromkeys(raw_items))[:12]


class SharedFactGraph:
    """Thread-safe cross-shard shared fact blackboard with per-shard delta cursors."""

    def __init__(self, *, max_facts: int = DEFAULT_MAX_FACTS) -> None:
        self._lock = threading.RLock()
        self.max_facts: int = max(1, int(max_facts))
        self._seq: int = 0
        self._facts: list[dict[str, Any]] = []
        self._index_by_key: dict[tuple[str, str], int] = {}
        self._cursors: dict[str, int] = {}

    def publish(
        self,
        fact_type: str,
        canonical_key: str,
        summary: str,
        *,
        source_shard: str,
        source_receipt_id: str = "",
        provenance: str = "host_extracted",
        target_families: Sequence[str] = ("*",),
        confidence: str = "deterministic",
        secret_values: Sequence[str] = (),
    ) -> dict[str, Any] | None:
        """Validate, redact, deduplicate, and store a cross-shard fact."""
        clean_type = str(fact_type or "").strip().lower()
        if clean_type not in VALID_FACT_TYPES:
            return None

        raw_key = " ".join(str(canonical_key or "").split())[:220]
        if not raw_key or _contains_raw_secret(raw_key):
            return None
        clean_key = _scrub_secret_text(raw_key, secret_values)[:220]
        if not clean_key or "<REDACTED" in clean_key:
            return None

        raw_summary = str(summary or "").strip()
        if not raw_summary:
            return None
        clean_summary = _scrub_secret_text(raw_summary, secret_values)[:280]
        if not _has_meaningful_non_secret_content(clean_summary):
            return None

        clean_shard = str(source_shard or "bootstrap").strip()[:64] or "bootstrap"
        clean_rid = str(source_receipt_id or "").strip()[:48]
        clean_prov = str(provenance or "host_extracted").strip()[:48] or "host_extracted"
        clean_conf = str(confidence or "deterministic").strip()[:48] or "deterministic"
        clean_targets = _normalize_target_families(target_families)
        dedup_key = (clean_type, clean_key)

        with self._lock:
            existing_idx = self._index_by_key.get(dedup_key)
            if existing_idx is not None:
                existing = self._facts[existing_idx]
                merged_targets = _normalize_target_families(
                    [*existing.get("target_families", ()), *clean_targets]
                )
                existing["target_families"] = list(merged_targets)
                return copy.deepcopy(existing)

            if len(self._facts) >= self.max_facts:
                return None

            self._seq += 1
            seq = self._seq
            fact: dict[str, Any] = {
                "fact_id": f"sf_{seq:03d}",
                "seq": seq,
                "fact_type": clean_type,
                "canonical_key": clean_key,
                "summary": clean_summary,
                "source_shard": clean_shard,
                "source_receipt_id": clean_rid,
                "provenance": clean_prov,
                "target_families": list(clean_targets),
                "confidence": clean_conf,
            }
            self._index_by_key[dedup_key] = len(self._facts)
            self._facts.append(fact)
            return copy.deepcopy(fact)

    def delta_for_shard(
        self,
        shard_id: str,
        *,
        families: Sequence[str] = (),
        max_items: int = 5,
        max_chars: int = 600,
    ) -> str:
        """Return unseen relevant facts as a compact delta banner, advancing `shard_id`'s cursor."""
        eff_items = max(0, int(max_items))
        eff_chars = max(0, int(max_chars))
        if eff_items <= 0 or eff_chars <= 0:
            return ""
        clean_shard = str(shard_id or "").strip()
        shard_fams = {str(f).strip().lower() for f in (families or ()) if str(f).strip()}

        with self._lock:
            last_seen = self._cursors.get(clean_shard, 0)
            candidates = [f for f in self._facts if int(f.get("seq") or 0) > last_seen]
            if not candidates:
                return ""

            selected: list[str] = []
            evaluated_seq = last_seen

            for fact in candidates:
                seq = int(fact.get("seq") or 0)
                if clean_shard and str(fact.get("source_shard") or "") == clean_shard:
                    evaluated_seq = max(evaluated_seq, seq)
                    continue

                tf_set = {
                    str(x).strip().lower()
                    for x in (fact.get("target_families") or ("*",))
                    if str(x).strip()
                } or {"*"}
                if "*" not in tf_set and not (shard_fams & tf_set):
                    evaluated_seq = max(evaluated_seq, seq)
                    continue

                if len(selected) >= eff_items:
                    break

                fid = str(fact.get("fact_id") or "")
                ftype = str(fact.get("fact_type") or "")
                fsummary = str(fact.get("summary") or "")
                src = str(fact.get("source_shard") or "")
                ckey = str(fact.get("canonical_key") or "")
                key_val = (
                    ckey.split(":", 1)[1]
                    if ":" in ckey and ckey.split(":", 1)[0] in (VALID_FACT_TYPES | {"actor", "header"})
                    else ckey
                )
                if key_val and key_val.lower() not in fsummary.lower():
                    item = f"{fid}[{ftype}@{src}]: {key_val} ({fsummary})"
                else:
                    item = f"{fid}[{ftype}@{src}]: {fsummary}"

                prefix_next = f"\n[SHARED-FACTS +{len(selected) + 1}] "
                joined_next = " | ".join([*selected, item])
                if len(prefix_next) + len(joined_next) <= eff_chars:
                    selected.append(item)
                    evaluated_seq = max(evaluated_seq, seq)
                    continue

                if selected:
                    break

                # First item exceeds `eff_chars`: fit a bounded excerpt so cursor never stalls.
                avail = eff_chars - len(prefix_next)
                if avail <= 3:
                    return ""
                if len(item) > avail:
                    item = item[: avail - 3].rstrip() + "..."
                selected.append(item)
                evaluated_seq = max(evaluated_seq, seq)
                break

            if evaluated_seq > last_seen:
                self._cursors[clean_shard] = evaluated_seq

            if not selected:
                return ""
            out = f"\n[SHARED-FACTS +{len(selected)}] " + " | ".join(selected)
            if len(out) > eff_chars:
                out = out[: eff_chars - 3].rstrip() + "..."
            return out

    def epoch_snapshot(self, *, max_items: int = 15, max_chars: int = 1200) -> str:
        """Return a deterministic compact summary of top active facts for 80K epoch compaction."""
        eff_items = max(0, int(max_items))
        eff_chars = max(0, int(max_chars))
        if eff_items <= 0 or eff_chars <= 0:
            return ""
        with self._lock:
            if not self._facts:
                return ""
            ordered = sorted(
                self._facts,
                key=lambda f: (
                    _FACT_PRIORITY.get(str(f.get("fact_type") or ""), 50),
                    int(f.get("seq") or 0),
                ),
            )[:eff_items]
            total = len(self._facts)

        header = f"[SHARED-FACTS SNAPSHOT ({len(ordered)}/{total})]"
        lines: list[str] = []
        used = len(header)
        for fact in ordered:
            fid = str(fact.get("fact_id") or "")
            ftype = str(fact.get("fact_type") or "")
            src = str(fact.get("source_shard") or "")
            fsummary = str(fact.get("summary") or "")
            line = f"- {fid} [{ftype}@{src}] {fsummary}"
            if len(line) > 160:
                line = line[:157].rstrip() + "..."
            if used + 1 + len(line) > eff_chars:
                break
            lines.append(line)
            used += 1 + len(line)

        if not lines:
            return header[:eff_chars]
        return header + "\n" + "\n".join(lines)

    def all_facts(self) -> list[dict[str, Any]]:
        """Return a deep copy of all stored facts ordered by `seq`."""
        with self._lock:
            return copy.deepcopy(self._facts)

    def to_dict(self) -> dict[str, Any]:
        """Serialize graph state and per-shard cursors into a JSON-safe dictionary."""
        with self._lock:
            return {
                "schema": "agentic-shared-facts/1",
                "max_facts": self.max_facts,
                "seq": self._seq,
                "facts": copy.deepcopy(self._facts),
                "cursors": dict(self._cursors),
            }

    def load_dict(self, data: dict[str, Any]) -> None:
        """Restore graph state and cursors safely from a serialized dictionary."""
        if not isinstance(data, dict):
            return
        with self._lock:
            self._facts = []
            self._index_by_key = {}
            self._cursors = {}
            max_seq = 0
            raw_facts = data.get("facts")
            if isinstance(raw_facts, list):
                sorted_raw = sorted(
                    (f for f in raw_facts if isinstance(f, dict)),
                    key=lambda item: int(item.get("seq") or 0)
                    if not isinstance(item.get("seq"), bool)
                    else 0,
                )
                for raw in sorted_raw:
                    if len(self._facts) >= self.max_facts:
                        break
                    ftype = str(raw.get("fact_type") or "").strip().lower()
                    if ftype not in VALID_FACT_TYPES:
                        continue
                    raw_key = " ".join(str(raw.get("canonical_key") or "").split())[:220]
                    if not raw_key or _contains_raw_secret(raw_key):
                        continue
                    ckey = _scrub_secret_text(raw_key)[:220]
                    if not ckey or "<REDACTED" in ckey:
                        continue
                    csummary = _scrub_secret_text(str(raw.get("summary") or ""))[:280]
                    if not _has_meaningful_non_secret_content(csummary):
                        continue
                    raw_seq = raw.get("seq")
                    seq = (
                        int(raw_seq)
                        if isinstance(raw_seq, int) and not isinstance(raw_seq, bool) and raw_seq > 0
                        else (max_seq + 1)
                    )
                    if seq <= max_seq:
                        seq = max_seq + 1
                    dedup_key = (ftype, ckey)
                    if dedup_key in self._index_by_key:
                        continue
                    fact: dict[str, Any] = {
                        "fact_id": f"sf_{seq:03d}",
                        "seq": seq,
                        "fact_type": ftype,
                        "canonical_key": ckey,
                        "summary": csummary,
                        "source_shard": str(raw.get("source_shard") or "bootstrap").strip()[:64] or "bootstrap",
                        "source_receipt_id": str(raw.get("source_receipt_id") or "").strip()[:48],
                        "provenance": str(raw.get("provenance") or "host_extracted").strip()[:48] or "host_extracted",
                        "target_families": list(_normalize_target_families(raw.get("target_families"))),
                        "confidence": str(raw.get("confidence") or "deterministic").strip()[:48] or "deterministic",
                    }
                    self._index_by_key[dedup_key] = len(self._facts)
                    self._facts.append(fact)
                    max_seq = max(max_seq, seq)

            raw_top_seq = data.get("seq")
            if isinstance(raw_top_seq, int) and not isinstance(raw_top_seq, bool):
                self._seq = max(max_seq, raw_top_seq)
            else:
                self._seq = max_seq

            raw_cursors = data.get("cursors")
            if isinstance(raw_cursors, dict):
                for k, v in raw_cursors.items():
                    if isinstance(v, int) and not isinstance(v, bool) and v >= 0:
                        self._cursors[str(k)] = min(v, self._seq)

    def load_file(self, path: str | Path) -> bool:
        """Load persisted state from `path` if it exists and is valid JSON."""
        file_path = Path(path).expanduser().resolve()
        if not file_path.is_file():
            return False
        try:
            data = json.loads(file_path.read_text(encoding="utf-8"))
        except (OSError, ValueError):
            return False
        if not isinstance(data, dict):
            return False
        self.load_dict(data)
        return True

    def save(self, path: str | Path) -> None:
        """Atomically persist the shared fact graph to `path`."""
        file_path = Path(path).expanduser().resolve()
        with self._lock:
            snapshot = self.to_dict()
        _atomic_write_json(file_path, snapshot)
