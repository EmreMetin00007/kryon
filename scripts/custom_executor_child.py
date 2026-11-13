#!/usr/bin/env python3
"""Minimal child-only loader for contract-bound custom worker executors."""

from __future__ import annotations

import argparse
import asyncio
import base64
import contextlib
import importlib
import inspect
import json
import os
import sys

from executor_isolation import ExecutorContract, apply_process_resource_limits


CHILD_RESULT_PREFIX = "__CCO_WORKER_RESULT__:"


def _emit(response: dict, max_bytes: int) -> None:
    try:
        serialized = json.dumps(response, ensure_ascii=False, allow_nan=False, default=str).encode("utf-8")
    except Exception:
        serialized = json.dumps({
            "ok": False,
            "error_type": "ResultSerializationError",
            "executor_pid": os.getpid(),
        }, separators=(",", ":")).encode("utf-8")
    if len(serialized) > max_bytes:
        serialized = json.dumps({
            "ok": False,
            "error_type": "OutputLimitExceeded",
            "executor_pid": os.getpid(),
        }, separators=(",", ":")).encode("utf-8")
    print(f"{CHILD_RESULT_PREFIX}{base64.urlsafe_b64encode(serialized).decode('ascii')}", flush=True)


def _read_payload(max_bytes: int) -> dict:
    raw = sys.stdin.buffer.read(max_bytes + 1)
    if len(raw) > max_bytes:
        raise ValueError("executor input exceeds contract limit")
    payload = json.loads(raw.decode("utf-8") or "{}")
    if not isinstance(payload, dict):
        raise ValueError("executor input must be an object")
    return payload


def execute(contract_path: str) -> int:
    max_output = 1024 * 1024
    try:
        contract = ExecutorContract.load(contract_path)
        max_output = contract.max_output_bytes
        payload = _read_payload(contract.max_input_bytes)
        if payload.get("contract_sha256") != contract.digest:
            raise ValueError("executor contract changed after validation")
        if payload.get("executor_code_sha256") != contract.code_sha256:
            raise ValueError("executor source changed after validation")
        task = payload.get("task")
        if not isinstance(task, dict):
            raise ValueError("custom executor task must be an object")
        rlimits = apply_process_resource_limits(contract.limits)
        if str(contract.code_path.parent) not in sys.path:
            sys.path.insert(0, str(contract.code_path.parent))
        module_name, function_name = contract.executor.split(":", 1)
        with open(os.devnull, "w", encoding="utf-8") as sink:
            with contextlib.redirect_stdout(sink), contextlib.redirect_stderr(sink):
                module = importlib.import_module(module_name)
                executor = getattr(module, function_name, None)
                if not callable(executor):
                    raise ValueError("custom executor is not callable")
                output = executor(task)
                if inspect.isawaitable(output):
                    output = asyncio.run(output)
        if not isinstance(output, dict):
            raise ValueError("custom executor must return an object")
        json.dumps(output, ensure_ascii=False, allow_nan=False)
        response = {
            "ok": True,
            "output": output,
            "executor_pid": os.getpid(),
            "rlimits": rlimits,
        }
        exit_code = 0
    except BaseException as exc:
        response = {"ok": False, "error_type": type(exc).__name__, "executor_pid": os.getpid()}
        exit_code = 1
    _emit(response, max_output)
    return exit_code


def main(argv: list[str] | None = None) -> int:
    parser = argparse.ArgumentParser(description="CCO isolated custom executor child")
    parser.add_argument("--contract", required=True)
    args = parser.parse_args(argv)
    return execute(args.contract)


if __name__ == "__main__":
    raise SystemExit(main())
