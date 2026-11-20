"""Differential behavior observer.

Compares probe observations with a stable baseline using only response
metadata and body *shape*. Bodies, header values and cookie values are never
copied into the result. This module reports anomalies; it does not decide
whether a vulnerability exists.
"""

from __future__ import annotations

import hashlib
import json
import re
from collections import Counter
from statistics import median
from typing import Any

SCHEMA = "cco-differential-observations/1"

# Degeri her istekte degisen (veri tasimayan) alanlar: karsilastirmada yok say.
_VOLATILE_KEY_RE = re.compile(
    r"(csrf|xsrf|nonce|token|timestamp|_ts$|date|time|request_?id|trace|"
    r"session|etag|expires|generated|rnd|random|signature)",
    re.I,
)


def _parse_json(body: Any) -> Any:
    if isinstance(body, (dict, list)):
        return body
    if isinstance(body, bytes):
        try:
            body = body.decode("utf-8", "ignore")
        except Exception:
            return None
    if isinstance(body, str):
        try:
            return json.loads(body)
        except Exception:
            return None
    return None


def _flatten_json(value: Any, prefix: str = "", out: dict | None = None) -> dict:
    """JSON -> {yol: deger-hashi}; volatile yapraklar atlanir, degerler asla saklanmaz."""
    if out is None:
        out = {}
    if isinstance(value, dict):
        for key in sorted(value.keys(), key=str):
            path = f"{prefix}.{key}" if prefix else str(key)
            if _VOLATILE_KEY_RE.search(str(key)):
                continue
            _flatten_json(value[key], path, out)
    elif isinstance(value, list):
        for item in value:
            _flatten_json(item, f"{prefix}[]", out)
    else:
        leaf = json.dumps(value, sort_keys=True, ensure_ascii=False, default=str)
        out[prefix] = hashlib.sha256(leaf.encode("utf-8")).hexdigest()[:16]
    return out


def field_diff(baseline_body: Any, probe_body: Any) -> dict[str, Any]:
    """Iki JSON govde arasinda alan-seviyesi fark (yalniz yol adlari doner)."""
    base = _parse_json(baseline_body)
    probe = _parse_json(probe_body)
    if base is None or probe is None:
        return {"comparable": False, "added": [], "removed": [], "changed": []}
    flat_base = _flatten_json(base)
    flat_probe = _flatten_json(probe)
    added = sorted(set(flat_probe) - set(flat_base))[:20]
    removed = sorted(set(flat_base) - set(flat_probe))[:20]
    changed = sorted(
        k for k in set(flat_base) & set(flat_probe) if flat_base[k] != flat_probe[k]
    )[:20]
    return {"comparable": True, "added": added, "removed": removed, "changed": changed}


def _number(value: Any, default: float = 0.0) -> float:
    try:
        return float(value)
    except Exception:
        return default


def _header_names(headers: Any) -> list[str]:
    if isinstance(headers, dict):
        return [str(k).lower() for k in headers.keys()]
    if isinstance(headers, list):
        out: list[str] = []
        for item in headers:
            if isinstance(item, (list, tuple)) and item:
                out.append(str(item[0]).lower())
            elif isinstance(item, dict) and item.get("name"):
                out.append(str(item["name"]).lower())
            elif isinstance(item, str):
                out.append(item.split(":", 1)[0].lower())
        return out
    return []


def _cookie_shape(cookies: Any) -> list[tuple[str, int | None]]:
    out: list[tuple[str, int | None]] = []
    if not isinstance(cookies, list):
        return out
    for item in cookies:
        if isinstance(item, dict):
            name = str(item.get("name") or "")
            length = item.get("length")
            out.append((name, int(length) if isinstance(length, (int, float)) else None))
        elif isinstance(item, str):
            out.append((item, None))
    return sorted(out)


def _shape(value: Any, depth: int = 0) -> Any:
    if depth > 5:
        return type(value).__name__
    if isinstance(value, dict):
        return {str(k): _shape(value[k], depth + 1)
                for k in sorted(value.keys()) if not _VOLATILE_KEY_RE.search(str(k))}
    if isinstance(value, list):
        return [_shape(value[0], depth + 1)] if value else []
    if isinstance(value, bool):
        return "bool"
    if isinstance(value, (int, float)):
        return "number"
    if value is None:
        return "null"
    return "string"


def _body_schema(body: Any) -> str:
    if body is None:
        return "empty"
    if isinstance(body, (dict, list)):
        shape = _shape(body)
    elif isinstance(body, bytes):
        try:
            body = body.decode("utf-8", "ignore")
        except Exception:
            return "bytes"
        shape = None
    elif isinstance(body, str):
        try:
            shape = _shape(json.loads(body))
        except Exception:
            length = len(body)
            bucket = "0" if length == 0 else "small" if length < 128 else "medium" if length < 4096 else "large"
            return f"text:{bucket}"
    else:
        return type(body).__name__
    return hashlib.sha256(
        json.dumps(shape, sort_keys=True, ensure_ascii=False).encode("utf-8")
    ).hexdigest()[:16]


def _normalize(sample: dict[str, Any], index: int) -> dict[str, Any]:
    length = sample.get("response_length", sample.get("length", sample.get("len")))
    if length is None and sample.get("body") is not None:
        body = sample.get("body")
        length = len(body.encode("utf-8", "ignore")) if isinstance(body, str) else len(str(body))
    return {
        "label": str(sample.get("label") or sample.get("id") or f"sample-{index + 1}"),
        "status": int(_number(sample.get("status"), 0)),
        "elapsed_ms": _number(sample.get("elapsed_ms", sample.get("time_ms", sample.get("duration_ms")))),
        "response_length": int(_number(length)),
        "header_order": _header_names(sample.get("headers")),
        "body_schema": _body_schema(sample.get("body")),
        "cookie_shape": _cookie_shape(sample.get("cookies")),
        "content_type": str(sample.get("content_type") or "").split(";", 1)[0].lower(),
        "_body": sample.get("body"),
    }


def _aggregate(samples: list[dict[str, Any]]) -> list[dict[str, Any]]:
    """Ayni etiketli tekrar olcumleri median ile tek ornege indir (timing gurultusu)."""
    groups: dict[str, list[dict[str, Any]]] = {}
    for sample in samples:
        groups.setdefault(sample["label"], []).append(sample)
    out: list[dict[str, Any]] = []
    for label, group in groups.items():
        if len(group) == 1:
            out.append(group[0])
            continue
        merged = dict(group[0])
        merged["elapsed_ms"] = median([g["elapsed_ms"] for g in group])
        merged["response_length"] = int(median([float(g["response_length"]) for g in group]))
        merged["status"] = _mode([g["status"] for g in group])
        merged["body_schema"] = _mode([g["body_schema"] for g in group])
        out.append(merged)
    return out


def _median_abs_deviation(values: list[float], center: float) -> float:
    if not values:
        return 0.0
    return median([abs(v - center) for v in values]) * 1.4826


def _mode(values: list[Any]) -> Any:
    return Counter(values).most_common(1)[0][0] if values else None


def analyze_differential_observations(
    baseline: list[dict[str, Any]],
    observations: list[dict[str, Any]],
    *,
    min_baseline: int = 3,
) -> dict[str, Any]:
    """Return anomaly clusters for observations relative to baseline."""
    base = [_normalize(s, i) for i, s in enumerate(baseline or []) if isinstance(s, dict)]
    probes = _aggregate(
        [_normalize(s, i) for i, s in enumerate(observations or []) if isinstance(s, dict)]
    )
    base = _aggregate(base)
    unknowns: list[str] = []
    if len(base) < min_baseline:
        unknowns.append(
            f"baseline has {len(base)} samples; timing and distribution claims require at least {min_baseline}"
        )
    if not probes:
        unknowns.append("no observations supplied")

    base_times = [s["elapsed_ms"] for s in base]
    base_lengths = [float(s["response_length"]) for s in base]
    time_center = median(base_times) if base_times else 0.0
    length_center = median(base_lengths) if base_lengths else 0.0
    time_mad = _median_abs_deviation(base_times, time_center)
    length_mad = _median_abs_deviation(base_lengths, length_center)
    status_mode = _mode([s["status"] for s in base])
    header_mode = _mode([tuple(s["header_order"]) for s in base])
    schema_mode = _mode([s["body_schema"] for s in base])
    cookie_mode = _mode([tuple(s["cookie_shape"]) for s in base])

    reference_body = None
    for candidate in base:
        if _parse_json(candidate.get("_body")) is not None:
            reference_body = candidate.get("_body")
            break

    evaluated: list[dict[str, Any]] = []
    for sample in probes:
        signals: list[str] = []
        score = 0
        metrics: dict[str, Any] = {}
        if base and sample["status"] != status_mode:
            signals.append("status")
            score += 3
        if base and sample["body_schema"] != schema_mode:
            signals.append("body_schema")
            score += 3
        if reference_body is not None:
            diff = field_diff(reference_body, sample.get("_body"))
            if diff["comparable"] and (diff["added"] or diff["removed"] or diff["changed"]):
                signals.append("field_diff")
                score += 3
                metrics["field_added"] = diff["added"]
                metrics["field_removed"] = diff["removed"]
                metrics["field_changed"] = diff["changed"]
        length_delta = sample["response_length"] - length_center
        length_pct = abs(length_delta) / max(length_center, 1.0)
        length_z = abs(length_delta) / length_mad if length_mad else (99.0 if length_delta else 0.0)
        if base and abs(length_delta) >= 16 and length_pct >= 0.20 and length_z >= 3.5:
            signals.append("response_length")
            score += 2
            metrics["length_delta"] = int(length_delta)
            metrics["length_z"] = round(length_z, 3)
        if len(base) >= min_baseline:
            time_delta = sample["elapsed_ms"] - time_center
            time_z = time_delta / time_mad if time_mad else (99.0 if time_delta > 0 else 0.0)
            if sample["elapsed_ms"] >= max(time_center * 1.8, time_center + 50) and time_z >= 3.5:
                signals.append("timing")
                score += 2
                metrics["timing_delta_ms"] = round(time_delta, 3)
                metrics["timing_z"] = round(time_z, 3)
        if base and tuple(sample["header_order"]) != header_mode:
            if set(sample["header_order"]) != set(header_mode or ()): 
                signals.append("header_set")
            else:
                signals.append("header_order")
            score += 1
        if base and tuple(sample["cookie_shape"]) != cookie_mode:
            signals.append("cookie_shape")
            score += 1
        verdict = "anomaly" if score >= 2 else ("watch" if score == 1 else "normal")
        evaluated.append({
            "label": sample["label"],
            "verdict": verdict,
            "score": score,
            "signals": signals,
            "metrics": metrics,
        })

    clusters: dict[tuple[str, tuple[str, ...]], dict[str, Any]] = {}
    for item in evaluated:
        key = (item["verdict"], tuple(item["signals"]))
        cluster = clusters.setdefault(key, {
            "id": f"cluster-{len(clusters) + 1}",
            "verdict": item["verdict"],
            "signals": list(item["signals"]),
            "labels": [],
            "max_score": 0,
        })
        cluster["labels"].append(item["label"])
        cluster["max_score"] = max(cluster["max_score"], item["score"])

    return {
        "schema": SCHEMA,
        "baseline": {
            "samples": len(base),
            "status": status_mode,
            "median_elapsed_ms": round(time_center, 3),
            "median_response_length": int(length_center),
            "body_schema": schema_mode,
        },
        "clusters": list(clusters.values()),
        "anomalies": [item for item in evaluated if item["verdict"] == "anomaly"],
        "evaluated": evaluated,
        "unknowns": unknowns,
        "notes": [
            "Anomalies are behavioral evidence, not vulnerability verdicts.",
            "Bodies, header values and cookie values are never emitted.",
        ],
    }


def summarize_differential_evidence(
    baseline_body: Any,
    probe_body: Any,
    *,
    signals: list[str] | None = None,
    baseline_status: int | None = None,
    probe_status: int | None = None,
) -> dict[str, Any]:
    """Build a bounded, value-free differential summary for operator-review artifacts."""
    diff = field_diff(baseline_body, probe_body)
    return {
        "schema": SCHEMA,
        "signals": list(signals or []),
        "baseline_status": baseline_status,
        "probe_status": probe_status,
        "baseline_schema": _body_schema(baseline_body),
        "probe_schema": _body_schema(probe_body),
        "field_diff": diff,
    }
