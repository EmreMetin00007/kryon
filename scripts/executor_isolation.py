#!/usr/bin/env python3
"""Fail-closed isolation contracts for campaign worker executors."""

from __future__ import annotations

import hashlib
import json
import os
import re
import resource
import shutil
import stat
import uuid
from dataclasses import dataclass
from pathlib import Path
from typing import Any


CONTRACT_SCHEMA = "cco-executor-contract/1"
SAFE_PATH = "/usr/local/sbin:/usr/local/bin:/usr/sbin:/usr/bin:/sbin:/bin"
EXECUTOR_RE = re.compile(
    r"^[A-Za-z_][A-Za-z0-9_]*(?:\.[A-Za-z_][A-Za-z0-9_]*)*:[A-Za-z_][A-Za-z0-9_]*$"
)
ENV_NAME_RE = re.compile(r"^[A-Z_][A-Z0-9_]*$")
SENSITIVE_ENV_RE = re.compile(
    r"(?i)(api[_-]?key|authorization|bearer|cookie|credential|password|secret|session|token)"
)
PINNED_IMAGE_RE = re.compile(r"^.+@sha256:[0-9a-fA-F]{64}$")


def _reject_unknown(mapping: dict, allowed: set[str], field: str) -> None:
    unknown = sorted(set(mapping) - allowed)
    if unknown:
        raise ValueError(f"{field} contains unsupported fields: {', '.join(unknown)}")


def _require_fields(mapping: dict, required: set[str], field: str) -> None:
    missing = sorted(required - set(mapping))
    if missing:
        raise ValueError(f"{field} missing required fields: {', '.join(missing)}")


def _bounded_int(value: Any, field: str, minimum: int, maximum: int) -> int:
    if isinstance(value, bool) or not isinstance(value, int):
        raise ValueError(f"{field} must be an integer")
    if not minimum <= value <= maximum:
        raise ValueError(f"{field} must be between {minimum} and {maximum}")
    return value


def _bounded_float(value: Any, field: str, minimum: float, maximum: float) -> float:
    if isinstance(value, bool) or not isinstance(value, (int, float)):
        raise ValueError(f"{field} must be a number")
    parsed = float(value)
    if not minimum <= parsed <= maximum:
        raise ValueError(f"{field} must be between {minimum:g} and {maximum:g}")
    return parsed


@dataclass(frozen=True)
class ResourceLimits:
    cpu_seconds: int
    cpu_cores: float
    memory_mb: int
    pids: int
    network: str = "inherit"
    cgroup_mode: str = "best_effort"

    @classmethod
    def from_mapping(cls, data: dict, *, backend: str) -> "ResourceLimits":
        required = {"cpu_seconds", "cpu_cores", "memory_mb", "pids", "network", "cgroup_mode"}
        _require_fields(data, required, "isolation")
        network = str(data.get("network") or "")
        if network not in {"deny", "inherit"}:
            raise ValueError("isolation.network must be deny or inherit")
        cgroup_mode = str(data.get("cgroup_mode") or "")
        expected_modes = {"required", "best_effort"} if backend == "process" else {"container"}
        if cgroup_mode not in expected_modes:
            choices = ", ".join(sorted(expected_modes))
            raise ValueError(f"isolation.cgroup_mode must be one of: {choices}")
        return cls(
            cpu_seconds=_bounded_int(data.get("cpu_seconds"), "isolation.cpu_seconds", 1, 86400),
            cpu_cores=_bounded_float(data.get("cpu_cores"), "isolation.cpu_cores", 0.1, 128.0),
            memory_mb=_bounded_int(data.get("memory_mb"), "isolation.memory_mb", 64, 1048576),
            pids=_bounded_int(data.get("pids"), "isolation.pids", 1, 4096),
            network=network,
            cgroup_mode=cgroup_mode,
        )

    def child_payload(self) -> dict[str, int | float | str]:
        return {
            "cpu_seconds": self.cpu_seconds,
            "cpu_cores": self.cpu_cores,
            "memory_mb": self.memory_mb,
            "pids": self.pids,
            "network": self.network,
            "cgroup_mode": self.cgroup_mode,
        }


@dataclass(frozen=True)
class ExecutorContract:
    path: Path
    digest: str
    executor: str
    code_path: Path
    code_sha256: str
    backend: str
    limits: ResourceLimits
    env_allow: tuple[str, ...]
    max_input_bytes: int
    max_output_bytes: int
    container_image: str = ""
    container_runtime: str = ""

    @classmethod
    def load(cls, path: str | Path) -> "ExecutorContract":
        supplied = Path(path).expanduser()
        if supplied.is_symlink():
            raise ValueError("executor contract must not be a symlink")
        try:
            resolved = supplied.resolve(strict=True)
        except OSError as exc:
            raise ValueError("executor contract does not exist") from exc
        info = resolved.stat()
        if not stat.S_ISREG(info.st_mode):
            raise ValueError("executor contract must be a regular file")
        if info.st_mode & 0o022:
            raise ValueError("executor contract must not be group/world writable")
        raw = resolved.read_bytes()
        try:
            data = json.loads(raw.decode("utf-8"))
        except Exception as exc:
            raise ValueError("executor contract must be valid UTF-8 JSON") from exc
        if not isinstance(data, dict):
            raise ValueError("executor contract must be a JSON object")
        _reject_unknown(data, {"schema", "executor", "code", "isolation", "environment", "io"}, "contract")
        _require_fields(data, {"schema", "executor", "code", "isolation"}, "contract")
        if data.get("schema") != CONTRACT_SCHEMA:
            raise ValueError(f"executor contract schema must be {CONTRACT_SCHEMA}")
        executor = str(data.get("executor") or "")
        if not EXECUTOR_RE.fullmatch(executor):
            raise ValueError("executor must use module:function syntax")
        module_name = executor.split(":", 1)[0]
        if "." in module_name:
            raise ValueError("executor module must be a single hash-bound Python file")
        code = data.get("code")
        if not isinstance(code, dict):
            raise ValueError("code must be a JSON object")
        _reject_unknown(code, {"path", "sha256"}, "code")
        _require_fields(code, {"path", "sha256"}, "code")
        code_relative = Path(str(code.get("path") or ""))
        if code_relative.is_absolute() or len(code_relative.parts) != 1 or code_relative.name != f"{module_name}.py":
            raise ValueError("code.path must be the executor module filename beside the contract")
        supplied_code = resolved.parent / code_relative
        if supplied_code.is_symlink():
            raise ValueError("executor source must not be a symlink")
        try:
            code_path = supplied_code.resolve(strict=True)
        except OSError as exc:
            raise ValueError("executor source does not exist") from exc
        code_info = code_path.stat()
        if not stat.S_ISREG(code_info.st_mode) or code_info.st_mode & 0o022:
            raise ValueError("executor source must be a non-writable regular file")
        code_sha256 = str(code.get("sha256") or "").lower()
        if not re.fullmatch(r"[0-9a-f]{64}", code_sha256):
            raise ValueError("code.sha256 must be 64 lowercase hex characters")
        if hashlib.sha256(code_path.read_bytes()).hexdigest() != code_sha256:
            raise ValueError("executor source SHA-256 mismatch")

        isolation = data.get("isolation")
        if not isinstance(isolation, dict):
            raise ValueError("isolation must be a JSON object")
        allowed_isolation = {
            "backend", "network", "cpu_seconds", "cpu_cores", "memory_mb", "pids",
            "cgroup_mode", "image", "runtime",
        }
        _reject_unknown(isolation, allowed_isolation, "isolation")
        backend = str(isolation.get("backend") or "")
        if backend not in {"process", "container"}:
            raise ValueError("isolation.backend must be process or container")
        limits = ResourceLimits.from_mapping(isolation, backend=backend)

        image = ""
        runtime = ""
        if backend == "process":
            if "image" in isolation or "runtime" in isolation:
                raise ValueError("process isolation does not accept image or runtime")
        else:
            _require_fields(isolation, {"image", "runtime"}, "isolation")
            image = str(isolation.get("image") or "")
            if not PINNED_IMAGE_RE.fullmatch(image):
                raise ValueError("container image must be pinned with @sha256:<64 hex>")
            runtime = str(isolation.get("runtime") or "")
            if runtime not in {"auto", "docker", "podman"}:
                raise ValueError("isolation.runtime must be auto, docker, or podman")

        environment = data.get("environment") or {}
        if not isinstance(environment, dict):
            raise ValueError("environment must be a JSON object")
        _reject_unknown(environment, {"allow"}, "environment")
        env_allow = environment.get("allow") or []
        if not isinstance(env_allow, list) or any(not isinstance(item, str) for item in env_allow):
            raise ValueError("environment.allow must be a list of environment variable names")
        normalized_env = []
        for name in env_allow:
            if not ENV_NAME_RE.fullmatch(name):
                raise ValueError(f"invalid environment variable name: {name}")
            if SENSITIVE_ENV_RE.search(name):
                raise ValueError(f"sensitive environment variable cannot be delegated: {name}")
            if name not in normalized_env:
                normalized_env.append(name)

        io_limits = data.get("io") or {}
        if not isinstance(io_limits, dict):
            raise ValueError("io must be a JSON object")
        _reject_unknown(io_limits, {"max_input_bytes", "max_output_bytes"}, "io")
        max_input = _bounded_int(
            io_limits.get("max_input_bytes", 1024 * 1024), "io.max_input_bytes", 1024, 16 * 1024 * 1024
        )
        max_output = _bounded_int(
            io_limits.get("max_output_bytes", 1024 * 1024), "io.max_output_bytes", 1024, 16 * 1024 * 1024
        )
        return cls(
            path=resolved,
            digest=hashlib.sha256(raw).hexdigest(),
            executor=executor,
            code_path=code_path,
            code_sha256=code_sha256,
            backend=backend,
            limits=limits,
            env_allow=tuple(normalized_env),
            max_input_bytes=max_input,
            max_output_bytes=max_output,
            container_image=image,
            container_runtime=runtime,
        )

    def environment(self, runner_dir: Path) -> dict[str, str]:
        python_path = os.pathsep.join((str(self.path.parent), str(runner_dir)))
        env = {
            "PATH": SAFE_PATH,
            "HOME": "/tmp",
            "LANG": os.environ.get("LANG", "C.UTF-8"),
            "LC_ALL": os.environ.get("LC_ALL", "C.UTF-8"),
            "PYTHONPATH": python_path,
            "PYTHONUNBUFFERED": "1",
        }
        for name in self.env_allow:
            if name in os.environ:
                env[name] = os.environ[name]
        return env

    def process_command(self, command: list[str]) -> list[str]:
        if self.limits.network != "deny":
            return list(command)
        unshare = shutil.which("unshare")
        if not unshare:
            raise RuntimeError("network-denied process isolation requires unshare")
        return [unshare, "--net", "--", *command]

    def resolve_container_runtime(self) -> str:
        candidates = ("docker", "podman") if self.container_runtime == "auto" else (self.container_runtime,)
        for candidate in candidates:
            resolved = shutil.which(candidate)
            if resolved:
                return resolved
        raise RuntimeError("requested container runtime is unavailable")

    def container_command(self, runner_script: Path, isolation_module: Path) -> tuple[list[str], str, str]:
        runtime = self.resolve_container_runtime()
        name = f"cco-worker-{os.getpid()}-{uuid.uuid4().hex[:12]}"
        network = "none" if self.limits.network == "deny" else "bridge"
        contract_target = f"/contract/{self.path.name}"
        command = [
            runtime, "run", "--rm", "--interactive", "--name", name,
            "--network", network,
            "--cpus", f"{self.limits.cpu_cores:g}",
            "--ulimit", f"cpu={self.limits.cpu_seconds}:{self.limits.cpu_seconds + 1}",
            "--memory", f"{self.limits.memory_mb}m",
            "--pids-limit", str(self.limits.pids),
            "--read-only", "--cap-drop", "ALL",
            "--security-opt", "no-new-privileges",
            "--user", f"{os.getuid()}:{os.getgid()}",
            "--tmpfs", "/tmp:rw,noexec,nosuid,size=64m",
            "--volume", f"{runner_script}:/runner/custom_executor_child.py:ro",
            "--volume", f"{isolation_module}:/runner/executor_isolation.py:ro",
            "--volume", f"{self.path}:{contract_target}:ro",
            "--volume", f"{self.code_path}:/contract/{self.code_path.name}:ro",
            "--workdir", "/contract",
            "--env", "HOME=/tmp",
            "--env", "PYTHONPATH=/contract:/runner",
            "--env", "PYTHONUNBUFFERED=1",
        ]
        for env_name in self.env_allow:
            if env_name in os.environ:
                command.extend(("--env", env_name))
        command.extend((
            self.container_image,
            "python3", "/runner/custom_executor_child.py", "--contract", contract_target,
        ))
        return command, name, runtime


def apply_process_resource_limits(limits: ResourceLimits) -> dict[str, int]:
    """Apply irreversible child-process rlimits before importing executor code."""

    def cap(resource_id: int, requested: int) -> int:
        _soft, hard = resource.getrlimit(resource_id)
        if hard == resource.RLIM_INFINITY:
            return requested
        return min(requested, int(hard))

    cpu_soft = cap(resource.RLIMIT_CPU, limits.cpu_seconds)
    _old_soft, cpu_hard_current = resource.getrlimit(resource.RLIMIT_CPU)
    cpu_hard = cpu_soft + 1
    if cpu_hard_current != resource.RLIM_INFINITY:
        cpu_hard = min(cpu_hard, int(cpu_hard_current))
    cpu_hard = max(cpu_soft, cpu_hard)
    resource.setrlimit(resource.RLIMIT_CPU, (cpu_soft, cpu_hard))

    memory_bytes = cap(resource.RLIMIT_AS, limits.memory_mb * 1024 * 1024)
    resource.setrlimit(resource.RLIMIT_AS, (memory_bytes, memory_bytes))

    process_limit = cap(resource.RLIMIT_NPROC, limits.pids)
    resource.setrlimit(resource.RLIMIT_NPROC, (process_limit, process_limit))
    resource.setrlimit(resource.RLIMIT_CORE, (0, 0))

    nofile = cap(resource.RLIMIT_NOFILE, 1024)
    resource.setrlimit(resource.RLIMIT_NOFILE, (nofile, nofile))
    return {
        "cpu_seconds": cpu_soft,
        "memory_bytes": memory_bytes,
        "pids": process_limit,
        "open_files": nofile,
    }


class CgroupV2:
    """Small cgroup-v2 lifecycle helper for a single executor process."""

    def __init__(self, root: str | Path | None = None):
        self.root = Path(root or os.environ.get("CCO_CGROUP_ROOT", "/sys/fs/cgroup"))
        self.path: Path | None = None

    def attach(self, pid: int, limits: ResourceLimits) -> dict[str, Any]:
        if not (self.root / "cgroup.controllers").exists():
            raise RuntimeError("cgroup v2 is unavailable or not delegated")
        path = self.root / f"cco-worker-{pid}-{uuid.uuid4().hex[:10]}"
        path.mkdir(mode=0o700)
        try:
            period = 100000
            quota = max(1000, int(limits.cpu_cores * period))
            (path / "cpu.max").write_text(f"{quota} {period}\n", encoding="ascii")
            (path / "memory.max").write_text(f"{limits.memory_mb * 1024 * 1024}\n", encoding="ascii")
            (path / "pids.max").write_text(f"{limits.pids}\n", encoding="ascii")
            (path / "cgroup.procs").write_text(f"{pid}\n", encoding="ascii")
        except Exception:
            try:
                path.rmdir()
            except OSError:
                pass
            raise
        self.path = path
        return {
            "applied": True,
            "mode": limits.cgroup_mode,
            "cpu_cores": limits.cpu_cores,
            "memory_mb": limits.memory_mb,
            "pids": limits.pids,
        }

    def cleanup(self) -> None:
        if self.path is None:
            return
        try:
            self.path.rmdir()
        except OSError:
            pass
        self.path = None

    def kill(self) -> None:
        if self.path is None:
            return
        kill_file = self.path / "cgroup.kill"
        try:
            kill_file.write_text("1\n", encoding="ascii")
            return
        except OSError:
            pass
        try:
            pids = (self.path / "cgroup.procs").read_text(encoding="ascii").split()
        except OSError:
            return
        for raw_pid in pids:
            try:
                os.kill(int(raw_pid), 9)
            except (OSError, ValueError):
                pass


def attach_cgroup(pid: int, limits: ResourceLimits, root: str | Path | None = None) -> tuple[CgroupV2 | None, dict]:
    if limits.cgroup_mode == "container":
        return None, {"applied": True, "mode": "container"}
    cgroup = CgroupV2(root)
    try:
        report = cgroup.attach(pid, limits)
        return cgroup, report
    except Exception as exc:
        if limits.cgroup_mode == "required":
            raise RuntimeError(f"required cgroup isolation failed: {type(exc).__name__}") from exc
        return None, {
            "applied": False,
            "mode": "best_effort",
            "reason": type(exc).__name__,
        }
