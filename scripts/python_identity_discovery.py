"""Host-bound reuse of completed observations, never of validation executions."""
from __future__ import annotations

import hashlib
import json
import math
import os
from pathlib import Path
import secrets
import stat
import sys
import time
from typing import Any

from evidence_trust import attest, canonical_bytes, verify

PURPOSE = "python-identity-discovery"
MAX_BYTES = 16 * 1024 * 1024
TTL_SECONDS = 300
CONTEXT_ENV = "CCO_PYTHON_DISCOVERY_INVOCATION"
STATE_ENV = "CCO_PYTHON_DISCOVERY_STATE"
OBSERVATION_PURPOSE = "python-private-discovery-observation"
SOURCE_PURPOSE = "python-private-discovery-source"


def state_path() -> Path:
    configured = os.environ.get(STATE_ENV)
    if not configured:
        raise ValueError("invalid identity discovery state path")
    return Path(configured)


def _check_no_symlink(path: Path) -> None:
    if any(p.is_symlink() for p in (path, *path.parents)):
        raise ValueError("identity discovery reference is a symlink")


def _unlink_if_regular(path: Path) -> None:
    try:
        if not path.is_symlink():
            path.unlink()
    except FileNotFoundError:
        pass


def _read_bounded(path: Path, limit: int = MAX_BYTES) -> bytes:
    if not path.is_absolute() or ".." in path.parts:
        raise ValueError("identity discovery reference must be absolute")
    # Open every lexical component, not just the leaf: parent symlink swaps
    # cannot redirect private reads into an archive or a different host root.
    directory = os.open("/", os.O_RDONLY | os.O_DIRECTORY | os.O_CLOEXEC)
    try:
        for part in path.parts[1:-1]:
            next_fd = os.open(part, os.O_RDONLY | os.O_DIRECTORY | os.O_NOFOLLOW | os.O_CLOEXEC,
                              dir_fd=directory)
            os.close(directory)
            directory = next_fd
        fd = os.open(path.name, os.O_RDONLY | os.O_NOFOLLOW | os.O_CLOEXEC | os.O_NONBLOCK,
                     dir_fd=directory)
    except OSError as exc:
        raise ValueError("identity discovery reference unavailable") from exc
    finally:
        os.close(directory)
    with os.fdopen(fd, "rb") as handle:
        info = os.fstat(handle.fileno())
        if not stat.S_ISREG(info.st_mode):
            raise ValueError("identity discovery reference must be a regular file")
        if info.st_size > limit:
            raise ValueError("identity discovery reference exceeds archive limit")
        raw = handle.read(limit + 1)
    if len(raw) > limit:
        raise ValueError("identity discovery reference exceeds archive limit")
    return raw


def _write_bounded(path: Path, raw: bytes, limit: int = MAX_BYTES) -> None:
    if len(raw) > limit:
        raise ValueError("identity discovery state exceeds archive limit")
    if not path.is_absolute() or ".." in path.parts:
        raise ValueError("identity discovery reference must be absolute")
    _check_no_symlink(path)
    path.parent.mkdir(parents=True, exist_ok=True)
    _check_no_symlink(path)
    dir_fd = os.open("/", os.O_RDONLY | os.O_DIRECTORY | os.O_CLOEXEC)
    try:
        for part in path.parts[1:-1]:
            next_fd = os.open(part, os.O_RDONLY | os.O_DIRECTORY | os.O_NOFOLLOW | os.O_CLOEXEC,
                              dir_fd=dir_fd)
            os.close(dir_fd)
            dir_fd = next_fd
        temporary = ".identity-discovery-" + secrets.token_hex(16) + ".tmp"
        fd = os.open(temporary, os.O_WRONLY | os.O_CREAT | os.O_EXCL | os.O_NOFOLLOW | os.O_CLOEXEC,
                     0o600, dir_fd=dir_fd)
        try:
            with os.fdopen(fd, "wb") as handle:
                handle.write(raw)
                handle.flush()
                os.fsync(handle.fileno())
            _check_no_symlink(path)
            os.replace(temporary, path.name, src_dir_fd=dir_fd, dst_dir_fd=dir_fd)
            os.fsync(dir_fd)
        finally:
            try:
                os.unlink(temporary, dir_fd=dir_fd)
            except FileNotFoundError:
                pass
    finally:
        os.close(dir_fd)


def capture_state(identities: dict[str, Any]) -> dict[str, Any]:
    """Host-private observations; use public_state for all model/archive exports."""
    hunter_root = str(Path(__file__).resolve().parents[1] / "mcp-servers" / "mcp-hunter")
    if hunter_root not in sys.path:
        sys.path.insert(0, hunter_root)
    from cco_hunter_core.request_context import capture_state as core_capture_state
    return core_capture_state(identities)


def public_state(states: dict[str, Any]) -> dict[str, Any]:
    hunter_root = str(Path(__file__).resolve().parents[1] / "mcp-servers" / "mcp-hunter")
    if hunter_root not in sys.path:
        sys.path.insert(0, hunter_root)
    from cco_hunter_core.request_context import public_discovery_state
    return public_discovery_state(states)


def public_export(value: Any) -> Any:
    """Use the same idempotent whole-report boundary at production and archives."""
    hunter_root = str(Path(__file__).resolve().parents[1] / "mcp-servers" / "mcp-hunter")
    if hunter_root not in sys.path:
        sys.path.insert(0, hunter_root)
    from cco_hunter_core.request_context import public_discovery_report
    return public_discovery_report(value)


def _digest(value: Any) -> str:
    return hashlib.sha256(canonical_bytes(value)).hexdigest()


def _reference(path: Path) -> dict[str, Any]:
    raw = _read_bounded(path)
    return {"path": str(path), "bytes": len(raw), "sha256": hashlib.sha256(raw).hexdigest()}


def _signed_reference(ref: Any, purpose: str) -> dict[str, Any]:
    envelope = _read_reference(ref)
    payload = envelope.get("payload")
    if not isinstance(payload, dict) or not verify(canonical_bytes(payload), envelope, purpose):
        raise ValueError("private identity discovery signature changed")
    if payload.get("schema") != purpose + "/1":
        raise ValueError("private identity discovery envelope invalid")
    return payload


def publish_discovery(states: dict[str, Any], report: dict[str, Any], *,
                      operational_report: dict[str, Any] | None = None) -> None:
    """Producer handoff outside tool JSON; no public path or private data export."""
    context = os.environ.get(CONTEXT_ENV)
    if not context:
        return
    expected = json.loads(context)
    path = Path(expected["result_path"])
    if not path.is_absolute() or str(path) != expected.get("result_path"):
        raise ValueError("private identity discovery invocation changed")
    if public_state(states) != report.get("identity_discovery_state", {}):
        raise ValueError("private identity discovery public projection changed")
    operational_report = operational_report if operational_report is not None else {**report, "identity_discovery_state": states}
    if canonical_bytes(public_export(operational_report)) != canonical_bytes(report):
        raise ValueError("private identity discovery report projection changed")
    payload = {"schema": OBSERVATION_PURPOSE + "/1", "invocation": expected["invocation"],
               "task_spec_sha256": expected["task_spec_sha256"],
               "arguments_sha256": expected["arguments_sha256"],
                "public_output_sha256": _digest(report), "produced_at": time.time(), "states": states,
                "operational_report": operational_report}
    _write_bounded(path, canonical_bytes(attest(payload, OBSERVATION_PURPOSE)))


def seal_discovery(broker: Any, spec: Any, args: dict[str, Any], report: dict[str, Any],
                   receipt_path: Path, expected: dict[str, Any]) -> None:
    """Bind the producer blob to this invocation's exact measured host receipt."""
    path = Path(expected["result_path"])
    if not path.exists():
        if report.get("identity_discovery_state"):
            raise ValueError("private identity discovery result missing")
        return
    producer_ref = _reference(path)
    observation = _signed_reference(producer_ref, OBSERVATION_PURPOSE)
    receipt_ref = _reference(receipt_path)
    receipt = _read_reference(receipt_ref)
    _check_execution(receipt, spec.id, args, report)
    if (str(path) != expected.get("result_path") or path.parent != Path(broker.private)
            or observation.get("invocation") != expected.get("invocation")
            or observation.get("task_spec_sha256") != _digest(spec.to_dict())
            or observation.get("arguments_sha256") != _digest(args)
            or expected.get("task_spec_sha256") != _digest(spec.to_dict())
            or expected.get("arguments_sha256") != _digest(args)):
        raise ValueError("private identity discovery task invocation changed")
    _check_observation(observation, report)
    payload = {"schema": SOURCE_PURPOSE + "/1", "producer_reference": producer_ref,
               "execution_reference": receipt_ref, "invocation": observation["invocation"],
               "task_spec_sha256": _digest(spec.to_dict()), "arguments_sha256": _digest(args),
               "public_output_sha256": _digest(report)}
    seal_path = path.with_name(path.stem + "-receipt.json")
    _write_bounded(seal_path, canonical_bytes(attest(payload, SOURCE_PURPOSE)))
    broker.private_discovery_sources[str(receipt_path)] = _reference(seal_path)
    _write_bounded(Path(broker.private) / "private-discovery-receipts.json",
                   canonical_bytes(broker.private_discovery_sources))


def _check_execution(receipt: dict[str, Any], task_id: str, args: dict[str, Any],
                     report: dict[str, Any]) -> None:
    execution = receipt.get("execution")
    if (receipt.get("task_spec_id") != task_id or receipt.get("origin") != "solver"
            or receipt.get("tool") != "hunter_run_web_loop" or receipt.get("error")
            or not isinstance(execution, dict) or execution.get("execution_failed")
            or type(execution.get("actual_request_cost")) is not int or execution["actual_request_cost"] < 0
            or canonical_bytes(receipt.get("arguments")) != canonical_bytes(args)):
        raise ValueError("identity discovery source task provenance changed")
    result = execution.get("result")
    output = result.get("output") if isinstance(result, dict) else None
    if isinstance(output, str):
        output = json.loads(output)
    if canonical_bytes(output) != canonical_bytes(report):
        raise ValueError("identity discovery source changed")


def _check_observation(observation: dict[str, Any], report: dict[str, Any]) -> None:
    states = observation.get("states")
    produced_at = observation.get("produced_at")
    now = time.time()
    if (isinstance(produced_at, bool) or not isinstance(produced_at, (int, float))
            or not math.isfinite(produced_at) or produced_at > now or now - produced_at >= TTL_SECONDS):
        raise ValueError("private identity discovery observation expired or invalid")
    if (not isinstance(states, dict) or observation.get("public_output_sha256") != _digest(report)
            or canonical_bytes(public_state(states)) != canonical_bytes(report.get("identity_discovery_state", {}))):
        raise ValueError("private identity discovery public output changed")
    operational = observation.get("operational_report")
    if (not isinstance(operational, dict) or canonical_bytes(public_export(operational)) != canonical_bytes(report)
            or canonical_bytes(operational.get("identity_discovery_state", {})) != canonical_bytes(states)):
        raise ValueError("private identity discovery operational output changed")


def _source_observation(source: dict[str, Any], task_spec: dict[str, Any],
                        report: dict[str, Any], receipt: dict[str, Any]) -> dict[str, Any]:
    seal = _signed_reference(source.get("private_reference"), SOURCE_PURPOSE)
    observation = _signed_reference(seal.get("producer_reference"), OBSERVATION_PURPOSE)
    args = receipt.get("arguments")
    if not isinstance(args, dict):
        raise ValueError("private identity discovery receipt arguments invalid")
    if (seal.get("execution_reference") != source.get("execution_reference")
            or seal.get("public_output_sha256") != _digest(report)
            or seal.get("task_spec_sha256") != _digest(task_spec)
            or seal.get("arguments_sha256") != _digest(args)
            or observation.get("task_spec_sha256") != seal.get("task_spec_sha256")
            or observation.get("arguments_sha256") != seal.get("arguments_sha256")
            or not isinstance(seal.get("invocation"), str) or not seal["invocation"]
            or observation.get("invocation") != seal["invocation"]):
        raise ValueError("private identity discovery receipt context changed")
    _check_execution(receipt, task_spec["id"], args, report)
    _check_observation(observation, report)
    return observation


def _private_observations(source: dict[str, Any], task_spec: dict[str, Any],
                          report: dict[str, Any], receipt: dict[str, Any]) -> dict[str, Any]:
    return _source_observation(source, task_spec, report, receipt)["states"]


def checkpoint_evidence(broker: Any, sources: dict[str, Any]) -> set[Path]:
    """Bind the entire private producer/seal/executor chain, not just its map.

    This inventories immutable references without renewing their age or requiring
    old observations to be usable merely to save an otherwise valid checkpoint.
    Fresh-broker restoration performs the current-context/TTL checks separately.
    """
    paths: set[Path] = set()
    if not isinstance(sources, dict):
        raise ValueError("checkpoint private discovery map invalid")
    for execution_path, private_ref in sources.items():
        if not isinstance(execution_path, str):
            raise ValueError("checkpoint private discovery execution invalid")
        seal = _signed_reference(private_ref, SOURCE_PURPOSE)
        producer_ref, execution_ref = seal.get("producer_reference"), seal.get("execution_reference")
        if not isinstance(producer_ref, dict) or not isinstance(execution_ref, dict):
            raise ValueError("checkpoint private discovery references invalid")
        _signed_reference(producer_ref, OBSERVATION_PURPOSE)
        _read_reference(execution_ref)
        if (execution_ref["path"] != execution_path
                or Path(private_ref["path"]).parent != Path(broker.private)
                or Path(producer_ref["path"]).parent != Path(broker.private)
                or not any(row.get("artifact") == execution_path and row.get("origin") == "solver"
                           and row.get("tool") == "hunter_run_web_loop" for row in broker.tools)):
            raise ValueError("checkpoint private discovery provenance changed")
        paths.update(Path(ref["path"]) for ref in (private_ref, producer_ref, execution_ref))
    return paths


def checkpoint_context() -> dict[str, str]:
    validator_root = str(Path(__file__).resolve().parents[1] / "mcp-servers" / "mcp-validator")
    if validator_root not in sys.path:
        sys.path.insert(0, validator_root)
    from cco_validator_core.evidence import current_scope_revision, current_policy_hash
    return {"scope_revision": current_scope_revision(), "policy_hash": current_policy_hash()}


def restore_checkpoint_sources(broker: Any, sources: dict[str, Any], context: dict[str, str],
                               evidence_paths: set[Path]) -> dict[str, Any]:
    """Revalidate before installing any private refs; no hydration/model dispatch.

    Checkpoint signature/hash verification happens in WorkflowCheckpoint.read.
    The producer and source signatures still bind the original TaskSpec, measured
    arguments, invocation, projection and ages. Neither budget nor TTL is reset.
    """
    if not isinstance(sources, dict):
        raise ValueError("checkpoint private discovery map invalid")
    if sources and (context != checkpoint_context()
                    or not checkpoint_evidence(broker, sources) <= evidence_paths):
        raise ValueError("checkpoint private discovery context or evidence changed")
    specs = {spec.id: spec for spec in broker.tasks.specs}
    now = time.time()
    for execution_path, private_ref in sources.items():
        seal = _signed_reference(private_ref, SOURCE_PURPOSE)
        execution_ref = seal["execution_reference"]
        receipt = _read_reference(execution_ref)
        spec = specs.get(receipt.get("task_spec_id"))
        if spec is None:
            raise ValueError("checkpoint private discovery TaskSpec missing")
        output = ((receipt.get("execution") or {}).get("result") or {}).get("output")
        if isinstance(output, str):
            output = json.loads(output)
        if not isinstance(output, dict):
            raise ValueError("checkpoint private discovery output invalid")
        source = {"execution_reference": execution_ref, "private_reference": private_ref}
        observation = _source_observation(source, spec.to_dict(), output, receipt)
        from cco_validator_core.evidence import artifact_is_current, load_validation
        for item in observation["operational_report"].get("validations", []):
            if not isinstance(item, dict) or not item.get("validation_id"):
                raise ValueError("checkpoint private discovery validation invalid")
            record = load_validation(item["validation_id"])
            if (not record or not artifact_is_current(record, expected_target=spec.target)
                    or record.get("target") != item.get("url")):
                raise ValueError("checkpoint private discovery validation no longer current")
        if not any(row.get("spec_id") == spec.id and row.get("tool") == "hunter_run_web_loop"
                   and canonical_bytes(row.get("arguments")) == canonical_bytes(receipt.get("arguments"))
                   and canonical_bytes(broker.read_reference(row["content_ref"])) == canonical_bytes(output)
                   for row in broker.results):
            raise ValueError("checkpoint private discovery public receipt missing")
        for state in observation["states"].values():
            if not isinstance(state, dict):
                raise ValueError("checkpoint private discovery state invalid")
            observed_at = state.get("observed_at")
            binding = state.get("request_binding")
            if (isinstance(observed_at, bool) or not isinstance(observed_at, (int, float))
                    or not math.isfinite(observed_at) or observed_at > now or now - observed_at >= TTL_SECONDS):
                raise ValueError("checkpoint private discovery observation expired or invalid")
            if (not isinstance(binding, dict) or any(binding.get(key) != value for key, value in context.items())):
                raise ValueError("checkpoint private discovery scope or policy changed")
    # Independent structure: failed checks cannot leave partially restored refs.
    return json.loads(canonical_bytes(sources))


def queue_key(item: dict[str, Any]) -> tuple[Any, ...]:
    return tuple(item.get(name) for name in
                 ("url", "method", "vuln_class", "operation_id", "resource_owner", "identity"))


def _read_reference(ref: Any) -> dict[str, Any]:
    if (not isinstance(ref, dict) or not isinstance(ref.get("path"), str)
            or not Path(ref["path"]).is_absolute() or type(ref.get("bytes")) is not int):
        raise ValueError("identity discovery source reference invalid")
    raw = _read_bounded(Path(ref["path"]))
    if len(raw) != ref["bytes"] or hashlib.sha256(raw).hexdigest() != ref.get("sha256"):
        raise ValueError("identity discovery source changed")
    try:
        value = json.loads(raw)
    except (UnicodeDecodeError, ValueError) as exc:
        raise ValueError("identity discovery source invalid") from exc
    if not isinstance(value, dict):
        raise ValueError("identity discovery source invalid")
    return value


def _source_binding(source: dict[str, Any]) -> str:
    return hashlib.sha256(canonical_bytes([
        source.get("reference"), source.get("execution_reference"), source.get("private_reference"),
        source.get("state_names")])).hexdigest()


def _completed_queue(report: dict[str, Any], bindings: set[str]) -> dict[tuple[Any, ...], dict[str, Any]]:
    """A source pair requires exactly its whole, unambiguous directed queue."""
    queue, validations = report.get("validation_queue"), report.get("validations")
    if (len(bindings) != 2 or not isinstance(queue, list) or not queue
            or not isinstance(validations, list) or not validations
            or any(not isinstance(item, dict) for item in [*queue, *validations])):
        raise ValueError("identity discovery controls are no longer current")
    try:
        completed = {queue_key(item): item for item in validations}
        ids = [item.get("validation_id") for item in validations]
        if (len(completed) != len(validations) or len(set(ids)) != len(ids)
                or any(not isinstance(ident, str) or not ident for ident in ids)
                or len({queue_key(item) for item in queue}) != len(queue)
                or {queue_key(item) for item in queue} != set(completed)
                or {item.get("resource_owner") for item in queue} != bindings
                or any({item.get("resource_owner"), item.get("identity")} != bindings for item in queue)):
            raise ValueError("identity discovery controls are no longer current")
    except TypeError as exc:
        raise ValueError("identity discovery controls are no longer current") from exc
    return completed


def prepare_invocation(broker: Any, spec: Any, args: dict[str, Any]) -> dict[str, Any]:
    """Arm host-private operational report capture for one Hunter invocation."""
    _check_no_symlink(Path(broker.private))
    invocation = secrets.token_hex(32)
    result_path = Path(broker.private) / f"python-private-discovery-{invocation}.json"
    expected = {
        "invocation": invocation,
        "task_spec_sha256": hashlib.sha256(canonical_bytes(spec.to_dict())).hexdigest(),
        "arguments_sha256": hashlib.sha256(canonical_bytes(args)).hexdigest(),
        "source_references": [],
        "result_path": str(result_path),
    }
    os.environ[CONTEXT_ENV] = canonical_bytes(expected).decode()
    return expected


def prepare_discovery(broker: Any, spec: Any, args: dict[str, Any]) -> Path:
    """Publish only whole completed queues from this exact task's host receipts."""
    validator_root = str(Path(__file__).resolve().parents[1] / "mcp-servers" / "mcp-validator")
    if validator_root not in sys.path:
        sys.path.insert(0, validator_root)
    from cco_validator_core.evidence import current_scope_revision, current_policy_hash
    _check_no_symlink(Path(broker.private))
    trusted = {item["record"]["validation_id"]: item["record"] for item in broker.validation_attempts(spec)}
    measured: dict[bytes, dict[str, Any]] = {}
    for execution in broker.tools:
        if (execution.get("origin") != "solver" or execution.get("task_spec_id") != spec.id
                or execution.get("tool") != "hunter_run_web_loop"):
            continue
        receipt_raw = _read_bounded(Path(execution["artifact"]))
        receipt = json.loads(receipt_raw)
        result = receipt.get("execution")
        if (receipt.get("error") or not isinstance(result, dict) or result.get("execution_failed")
                or type(result.get("actual_request_cost")) is not int or result["actual_request_cost"] < 0):
            continue
        output = result.get("result", {}).get("output")
        if isinstance(output, str):
            try:
                output = json.loads(output)
            except ValueError:
                continue
        if isinstance(output, dict):
            measured[canonical_bytes([execution["task_spec_id"], execution["tool"], receipt.get("arguments"), output])] = {
                "path": str(execution["artifact"]), "bytes": len(receipt_raw),
                "sha256": hashlib.sha256(receipt_raw).hexdigest(),
            }
    try:
        current_bindings = set(json.loads(args.get("session_bindings", "{}")))
    except (ValueError, TypeError):
        current_bindings = set()
    states: dict[str, Any] = {}
    sources_by_name: dict[str, dict[str, Any]] = {}
    for row in broker.results:
        if row["spec_id"] != spec.id or row["tool"] != "hunter_run_web_loop":
            continue
        previous = row["arguments"]
        if previous.get("target") != spec.target or previous.get("live") is not True or previous.get("blind_discovery") is not True:
            continue
        report = broker.read_reference(row["content_ref"])
        if not isinstance(report, dict):
            continue
        execution_ref = measured.get(canonical_bytes([spec.id, row["tool"], previous, report]))
        if execution_ref is None:
            continue
        discovery = report.get("identity_discovery", {})
        if (not report.get("ok") or discovery.get("status") != "ready" or discovery.get("reasons")
                or discovery.get("budget_limited") or discovery.get("truncated_responses")
                or report.get("errors") or report.get("stopped")):
            continue
        source_entry = {
            "reference": {**row["content_ref"], "path": str(broker.workdir / row["content_ref"]["path"])},
            "execution_reference": execution_ref,
            "private_reference": getattr(broker, "private_discovery_sources", {}).get(execution_ref["path"]),
        }
        try:
            observation = _source_observation(source_entry, spec.to_dict(), report, _read_reference(execution_ref))
            operational = observation["operational_report"]
            bindings = json.loads(previous.get("session_bindings", "{}"))
            if not isinstance(bindings, dict):
                continue
            completed = _completed_queue(operational, set(bindings))
        except (ValueError, OSError, TypeError, KeyError):
            continue
        if any(item["validation_id"] not in trusted
               or trusted[item["validation_id"]]["target"] != item.get("url")
               or queue_key(trusted[item["validation_id"]].get("execution_context", {})) != key
               for key, item in completed.items()):
            continue
        source_entry.update(bindings=sorted(bindings),
                            validation_ids=sorted(item["validation_id"] for item in completed.values()))
        queue = operational["validation_queue"]
        observed = observation["states"]
        for name, state in observed.items():
            if name not in current_bindings:
                continue
            owned = [item for item in queue if item.get("resource_owner") == name]
            if (name not in bindings or not isinstance(state, dict) or not state.get("objects")
                    or any(obj.get("url") not in {item["url"] for item in owned} for obj in state["objects"])):
                continue
            # Keep original observation age when an earlier state was reused.
            states[name] = state
            sources_by_name[name] = source_entry
    sources_by_path: dict[str, dict[str, Any]] = {}
    for name, entry in sources_by_name.items():
        path_key = entry["reference"]["path"]
        selected = sources_by_path.setdefault(path_key, {**entry, "state_names": []})
        selected["state_names"].append(name)
    sources = list(sources_by_path.values())
    invocation = secrets.token_hex(32)
    target_path = Path(broker.private) / f"python-identity-discovery-{invocation}.json"
    result_path = Path(broker.private) / f"python-private-discovery-{invocation}.json"
    payload = {"schema": PURPOSE + "/1", "task_spec": spec.to_dict(), "target": spec.target,
               "arguments": args, "prepared_at": time.time(), "states": states, "sources": sources,
               "invocation": invocation,
               "scope_revision": current_scope_revision(), "policy_hash": current_policy_hash()}
    raw = canonical_bytes(attest(payload, PURPOSE))
    _write_bounded(target_path, raw)
    os.environ[STATE_ENV] = str(target_path)
    # Host expectation travels independently of the producer-signed envelope.
    # Keep it in the existing scoped environment so broker restoration also
    # preserves an earlier invocation's exact TaskSpec/arguments contract.
    os.environ[CONTEXT_ENV] = canonical_bytes({
        "invocation": invocation,
        "task_spec_sha256": hashlib.sha256(canonical_bytes(payload["task_spec"])).hexdigest(),
        "arguments_sha256": hashlib.sha256(canonical_bytes(args)).hexdigest(),
        "source_references": sorted(_source_binding(source) for source in sources),
        "result_path": str(result_path),
    }).decode()
    return target_path


def load_discovery(target: str, identities: dict[str, Any], max_requests: int) -> dict[str, Any]:
    """Recheck signatures/provenance/current controls; return observation metadata."""
    expected_invocation = os.environ.get(CONTEXT_ENV)
    if not expected_invocation:
        return {}
    path = state_path()
    if not path.is_absolute():
        raise ValueError("invalid identity discovery state path")
    _check_no_symlink(path)
    if not path.exists():
        return {}
    try:
        envelope = json.loads(_read_bounded(path))
    except (UnicodeDecodeError, json.JSONDecodeError, TypeError) as exc:
        raise ValueError("invalid identity discovery cache") from exc
    if not isinstance(envelope, dict) or not isinstance(envelope.get("payload"), dict):
        raise ValueError("invalid identity discovery envelope")
    payload = envelope["payload"]
    if not verify(canonical_bytes(payload), envelope, PURPOSE):
        raise ValueError("identity discovery signature changed")
    if payload.get("schema") != PURPOSE + "/1":
        raise ValueError("identity discovery schema invalid")
    try:
        expected = json.loads(expected_invocation)
    except ValueError as exc:
        raise ValueError("identity discovery invocation changed") from exc
    if not isinstance(expected, dict) or payload.get("invocation") != expected.get("invocation"):
        raise ValueError("identity discovery invocation changed")
    task_spec = payload.get("task_spec")
    if (not isinstance(task_spec, dict) or not isinstance(task_spec.get("id"), str) or not task_spec["id"]
            or task_spec.get("target") != payload.get("target")
            or hashlib.sha256(canonical_bytes(task_spec)).hexdigest() != expected.get("task_spec_sha256")
            or hashlib.sha256(canonical_bytes(payload.get("arguments"))).hexdigest() != expected.get("arguments_sha256")):
        raise ValueError("identity discovery task contract changed")
    hunter_root = str(Path(__file__).resolve().parents[1] / "mcp-servers" / "mcp-hunter")
    if hunter_root not in sys.path:
        sys.path.insert(0, hunter_root)
    validator_root = str(Path(__file__).resolve().parents[1] / "mcp-servers" / "mcp-validator")
    if validator_root not in sys.path:
        sys.path.insert(0, validator_root)
    from cco_hunter_core.request_context import request_binding
    from cco_validator_core.evidence import (artifact_is_current, load_validation,
                                             current_scope_revision, current_policy_hash)
    from python_candidate_runtime import authorization_controls_complete
    if payload.get("scope_revision") != current_scope_revision() or payload.get("policy_hash") != current_policy_hash():
        raise ValueError("identity discovery context is no longer current")
    now = time.time()
    prepared_at = payload.get("prepared_at")
    if isinstance(prepared_at, bool) or not isinstance(prepared_at, (int, float)) or not math.isfinite(prepared_at) or prepared_at > now:
        raise ValueError("identity discovery timestamp invalid")
    if now - prepared_at >= TTL_SECONDS:
        _unlink_if_regular(path)
        return {}
    args = payload.get("arguments")
    if not isinstance(args, dict):
        raise ValueError("identity discovery arguments invalid")
    try:
        bound_names = set(json.loads(args.get("session_bindings", "{}")))
    except (ValueError, TypeError) as exc:
        raise ValueError("identity discovery bindings invalid") from exc
    if (payload.get("target") != target or args.get("target") != target or args.get("live") is not True
            or args.get("blind_discovery") is not True or args.get("blind_max_requests", 24) != max_requests
            or bound_names != set(identities)):
        _unlink_if_regular(path)
        return {}
    sources = payload.get("sources")
    raw_states = payload.get("states")
    if not isinstance(sources, list) or not isinstance(raw_states, dict) or not set(raw_states) <= set(identities):
        raise ValueError("identity discovery structure invalid")
    if raw_states and (not sources or any(not isinstance(s, dict) or not s.get("validation_ids") for s in sources)):
        raise ValueError("identity discovery sources missing")
    expected_sources = expected.get("source_references")
    if not isinstance(expected_sources, list):
        raise ValueError("identity discovery source provenance missing")
    covered_states: set[str] = set()
    source_bindings_seen: list[str] = []
    for source in sources:
        if not isinstance(source, dict):
            raise ValueError("identity discovery source invalid")
        source_bindings = source.get("bindings")
        if (not isinstance(source_bindings, list) or not source_bindings
                or any(not isinstance(name, str) or not name for name in source_bindings)):
            raise ValueError("identity discovery source bindings invalid")
        allowed_bindings = set(source_bindings)
        if not (allowed_bindings & set(raw_states)):
            raise ValueError("identity discovery source unused")
        source_binding = _source_binding(source)
        if source_binding not in expected_sources:
            raise ValueError("identity discovery source changed")
        source_bindings_seen.append(source_binding)
        report = _read_reference(source.get("reference"))
        receipt = _read_reference(source.get("execution_reference"))
        execution = receipt.get("execution")
        if (receipt.get("task_spec_id") != task_spec["id"] or receipt.get("origin") != "solver"
                or receipt.get("tool") != "hunter_run_web_loop" or receipt.get("error")
                or not isinstance(execution, dict) or execution.get("execution_failed")
                or type(execution.get("actual_request_cost")) is not int or execution["actual_request_cost"] < 0):
            raise ValueError("identity discovery source task provenance changed")
        result = execution.get("result")
        output = result.get("output") if isinstance(result, dict) else None
        if isinstance(output, str):
            try:
                output = json.loads(output)
            except ValueError as exc:
                raise ValueError("identity discovery source invalid") from exc
        if canonical_bytes(output) != canonical_bytes(report):
            raise ValueError("identity discovery source changed")
        discovery = report.get("identity_discovery")
        if (not report.get("ok") or not isinstance(discovery, dict) or discovery.get("status") != "ready"
                or discovery.get("reasons") or discovery.get("budget_limited") or discovery.get("truncated_responses")
                or report.get("errors") or report.get("stopped")):
            raise ValueError("identity discovery source incomplete")
        previous = receipt.get("arguments")
        try:
            bindings = json.loads(previous.get("session_bindings", "{}")) if isinstance(previous, dict) else None
        except (ValueError, TypeError) as exc:
            raise ValueError("identity discovery source bindings invalid") from exc
        if (not isinstance(previous, dict) or previous.get("target") != target
                or previous.get("live") is not True or previous.get("blind_discovery") is not True
                or not isinstance(bindings, dict) or allowed_bindings != set(bindings)
                or len(source_bindings) != len(allowed_bindings)):
            raise ValueError("identity discovery controls are no longer current")
        observation = _source_observation(source, task_spec, report, receipt)
        completed = _completed_queue(observation["operational_report"], allowed_bindings)
        validation_ids = source.get("validation_ids")
        if (not isinstance(validation_ids, list)
                or canonical_bytes(sorted(item["validation_id"] for item in completed.values()))
                != canonical_bytes(sorted(validation_ids, key=str))):
            raise ValueError("identity discovery controls are no longer current")
        for key, item in completed.items():
            ident = item["validation_id"]
            record = load_validation(ident)
            context = record.get("execution_context", {}) if isinstance(record, dict) else {}
            owner = context.get("resource_owner")
            actor = context.get("identity")
            if (not record or not artifact_is_current(record) or record.get("verdict") not in {"CONFIRMED", "UNCONFIRMED"}
                    or owner not in allowed_bindings or actor not in allowed_bindings or owner == actor
                    or record.get("target") != item.get("url") or queue_key(context) != key
                    or not authorization_controls_complete(record)):
                raise ValueError("identity discovery controls are no longer current")
        observed = observation["states"]
        # Match only the identities selected from this source. Other states in
        # an overlapping pair may come from a later receipt with a different age.
        selected_names = source.get("state_names")
        if (not isinstance(selected_names, list) or not selected_names
                or any(not isinstance(name, str) for name in selected_names)
                or len(set(selected_names)) != len(selected_names)
                or not set(selected_names) <= allowed_bindings & set(raw_states)
                or any(not isinstance(observed.get(name), dict)
                       or canonical_bytes(observed[name]) != canonical_bytes(raw_states[name])
                       for name in selected_names)):
            raise ValueError("identity discovery sources missing")
        covered_states.update(selected_names)
    if sorted(source_bindings_seen) != expected_sources:
        raise ValueError("identity discovery source changed")
    if set(raw_states) - covered_states:
        raise ValueError("identity discovery sources missing")
    states: dict[str, Any] = {}
    for name, actor in identities.items():
        state = raw_states.get(name)
        if state is None:
            continue
        if not isinstance(state, dict):
            raise ValueError("identity discovery state invalid")
        observed_at = state.get("observed_at")
        if isinstance(observed_at, bool) or not isinstance(observed_at, (int, float)) or not math.isfinite(observed_at) or observed_at > now:
            raise ValueError("identity discovery observation timestamp invalid")
        if now - observed_at >= TTL_SECONDS:
            continue
        if (state.get("request_binding") != request_binding(actor.get("headers", {}))
                or state.get("role") != actor.get("role")
                or state.get("owned_objects_private") is not actor.get("owned_objects_private")):
            raise ValueError("identity discovery session context changed")
        states[name] = state
    _unlink_if_regular(path)
    return states
