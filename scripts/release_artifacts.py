#!/usr/bin/env python3
"""Build, inventory, sign, and verify reproducible CCO release artifacts."""

from __future__ import annotations

import argparse
import base64
import gzip
import hashlib
import io
import json
import os
import re
import shutil
import stat
import subprocess
import sys
import tarfile
import tempfile
import tomllib
import zipfile
from datetime import datetime, timezone
from pathlib import Path
from typing import Any

from cryptography.exceptions import InvalidSignature
from cryptography.hazmat.primitives import serialization
from cryptography.hazmat.primitives.asymmetric.ed25519 import Ed25519PrivateKey, Ed25519PublicKey


SOURCE_ROOT = Path(__file__).resolve().parents[1]
INSTALL_DATA_ROOT = Path(sys.prefix) / "share" / "hackagent"
if (SOURCE_ROOT / "pyproject.toml").is_file():
    REPO_ROOT = SOURCE_ROOT
elif (Path.cwd() / "pyproject.toml").is_file():
    REPO_ROOT = Path.cwd().resolve()
else:
    REPO_ROOT = INSTALL_DATA_ROOT
LOCK_FILE = REPO_ROOT / "requirements.lock"
MANIFEST_SCHEMA = "cco-release-manifest/1"
SIGNATURE_SCHEMA = "cco-release-signature/1"
SPDX_VERSION = "SPDX-2.3"
REQUIREMENT_RE = re.compile(r"^([A-Za-z0-9_.-]+)==([^\s;]+)\s+(.+)$")
NAME_RE = re.compile(r"^([A-Za-z0-9_.-]+)")
HASH_RE = re.compile(r"--hash=sha256:([0-9a-f]{64})")


def _canonical_name(name: str) -> str:
    return re.sub(r"[-_.]+", "-", name).lower()


def _sha256_bytes(data: bytes) -> str:
    return hashlib.sha256(data).hexdigest()


def _sha256_file(path: Path) -> str:
    digest = hashlib.sha256()
    with path.open("rb") as handle:
        for chunk in iter(lambda: handle.read(1024 * 1024), b""):
            digest.update(chunk)
    return digest.hexdigest()


def _json_bytes(data: dict) -> bytes:
    return (json.dumps(data, indent=2, sort_keys=True, ensure_ascii=True) + "\n").encode("utf-8")


def _write_json(path: Path, data: dict) -> bytes:
    rendered = _json_bytes(data)
    path.write_bytes(rendered)
    return rendered


def _project_metadata() -> tuple[str, str, set[str]]:
    data = tomllib.loads((REPO_ROOT / "pyproject.toml").read_text(encoding="utf-8"))
    project = data["project"]
    groups = _dependency_groups(data)
    return str(project["name"]), str(project["version"]), set().union(*groups.values())


def _dependency_groups(data: dict | None = None) -> dict[str, set[str]]:
    data = data or tomllib.loads((REPO_ROOT / "pyproject.toml").read_text(encoding="utf-8"))
    project = data["project"]
    raw_groups = {
        "runtime": project.get("dependencies", []),
        "development": project.get("optional-dependencies", {}).get("dev", []),
        "build": data.get("build-system", {}).get("requires", []),
    }
    groups: dict[str, set[str]] = {}
    for group, requirements in raw_groups.items():
        names = set()
        for requirement in requirements:
            match = NAME_RE.match(requirement)
            if not match:
                raise ValueError(f"invalid {group} dependency: {requirement}")
            names.add(_canonical_name(match.group(1)))
        groups[group] = names
    return groups


def parse_lock_file(path: str | Path = LOCK_FILE) -> list[dict[str, Any]]:
    lock_path = Path(path)
    if not lock_path.is_file():
        raise ValueError(f"lock file missing: {lock_path}")
    logical_lines: list[str] = []
    current = ""
    for raw_line in lock_path.read_text(encoding="utf-8").splitlines():
        stripped = raw_line.strip()
        if not stripped or stripped.startswith("#"):
            continue
        continued = stripped.endswith("\\")
        piece = stripped[:-1].strip() if continued else stripped
        current = f"{current} {piece}".strip()
        if not continued:
            logical_lines.append(current)
            current = ""
    if current:
        raise ValueError("lock file ends with an incomplete continuation")

    packages = []
    seen = set()
    for line in logical_lines:
        if " @ " in line or line.startswith(("-e ", "--editable")):
            raise ValueError("lock file contains a URL or editable dependency")
        match = REQUIREMENT_RE.fullmatch(line)
        if not match:
            raise ValueError(f"lock entry is not an exact pin: {line.split()[0]}")
        name, version, options = match.groups()
        canonical = _canonical_name(name)
        if canonical in seen:
            raise ValueError(f"duplicate lock entry: {canonical}")
        hashes = sorted(set(HASH_RE.findall(options)))
        if not hashes:
            raise ValueError(f"lock entry has no SHA-256 hashes: {canonical}")
        unsupported = HASH_RE.sub("", options).strip()
        if unsupported:
            raise ValueError(f"lock entry has unsupported options: {canonical}")
        seen.add(canonical)
        packages.append({"name": canonical, "version": version, "hashes": hashes})
    if not packages:
        raise ValueError("lock file has no packages")
    return sorted(packages, key=lambda item: item["name"])


def check_lock_file(path: str | Path = LOCK_FILE) -> dict:
    packages = parse_lock_file(path)
    _project, _version, direct = _project_metadata()
    locked = {package["name"] for package in packages}
    missing = sorted(direct - locked)
    if missing:
        raise ValueError(f"dev dependencies missing from lock: {', '.join(missing)}")
    return {
        "valid": True,
        "packages": len(packages),
        "direct_dependencies": len(direct),
        "sha256": _sha256_file(Path(path)),
    }


def _source_date_epoch(value: int | None = None) -> int:
    if value is not None:
        parsed = int(value)
    elif os.environ.get("SOURCE_DATE_EPOCH"):
        parsed = int(os.environ["SOURCE_DATE_EPOCH"])
    else:
        result = subprocess.run(
            ["git", "log", "-1", "--format=%ct"],
            cwd=REPO_ROOT,
            text=True,
            capture_output=True,
            check=False,
        )
        parsed = int(result.stdout.strip()) if result.returncode == 0 and result.stdout.strip() else 0
    if not 0 <= parsed <= 4294967295:
        raise ValueError("SOURCE_DATE_EPOCH must fit an unsigned 32-bit timestamp")
    return parsed


def _spdx_timestamp(epoch: int) -> str:
    return datetime.fromtimestamp(epoch, timezone.utc).replace(microsecond=0).isoformat().replace("+00:00", "Z")


def _spdx_id(prefix: str, value: str) -> str:
    safe = re.sub(r"[^A-Za-z0-9.-]+", "-", value).strip("-")
    return f"SPDXRef-{prefix}-{safe}"


def build_spdx_sbom(lock_packages: list[dict], artifacts: list[Path], *,
                    project: str, version: str, epoch: int, lock_sha256: str) -> dict:
    project_id = _spdx_id("Package", project)
    packages = [{
        "SPDXID": project_id,
        "name": project,
        "versionInfo": version,
        "downloadLocation": "NOASSERTION",
        "filesAnalyzed": False,
        "licenseConcluded": "NOASSERTION",
        "licenseDeclared": "NOASSERTION",
        "copyrightText": "NOASSERTION",
        "externalRefs": [{
            "referenceCategory": "PACKAGE-MANAGER",
            "referenceType": "purl",
            "referenceLocator": f"pkg:pypi/{project}@{version}",
        }],
    }]
    relationships = []
    dependency_groups = _dependency_groups()
    for dependency in lock_packages:
        dependency_id = _spdx_id("Package", dependency["name"])
        packages.append({
            "SPDXID": dependency_id,
            "name": dependency["name"],
            "versionInfo": dependency["version"],
            "downloadLocation": "NOASSERTION",
            "filesAnalyzed": False,
            "licenseConcluded": "NOASSERTION",
            "licenseDeclared": "NOASSERTION",
            "copyrightText": "NOASSERTION",
            "checksums": [{"algorithm": "SHA256", "checksumValue": value}
                          for value in dependency["hashes"]],
            "externalRefs": [{
                "referenceCategory": "PACKAGE-MANAGER",
                "referenceType": "purl",
                "referenceLocator": f"pkg:pypi/{dependency['name']}@{dependency['version']}",
            }],
        })
        if dependency["name"] in dependency_groups["runtime"]:
            relationships.append({
                "spdxElementId": project_id,
                "relationshipType": "DEPENDS_ON",
                "relatedSpdxElement": dependency_id,
            })
        elif dependency["name"] in dependency_groups["build"]:
            relationships.append({
                "spdxElementId": dependency_id,
                "relationshipType": "BUILD_DEPENDENCY_OF",
                "relatedSpdxElement": project_id,
            })
        elif dependency["name"] in dependency_groups["development"]:
            relationships.append({
                "spdxElementId": dependency_id,
                "relationshipType": "DEV_DEPENDENCY_OF",
                "relatedSpdxElement": project_id,
            })

    files = []
    for artifact in sorted(artifacts, key=lambda item: item.name):
        file_id = _spdx_id("File", artifact.name)
        files.append({
            "SPDXID": file_id,
            "fileName": f"./{artifact.name}",
            "checksums": [{"algorithm": "SHA256", "checksumValue": _sha256_file(artifact)}],
            "licenseConcluded": "NOASSERTION",
            "copyrightText": "NOASSERTION",
        })
        relationships.append({
            "spdxElementId": project_id,
            "relationshipType": "CONTAINS",
            "relatedSpdxElement": file_id,
        })
    relationships.append({
        "spdxElementId": "SPDXRef-DOCUMENT",
        "relationshipType": "DESCRIBES",
        "relatedSpdxElement": project_id,
    })
    return {
        "spdxVersion": SPDX_VERSION,
        "dataLicense": "CC0-1.0",
        "SPDXID": "SPDXRef-DOCUMENT",
        "name": f"{project}-{version}",
        "documentNamespace": f"https://spdx.org/spdxdocs/{project}-{version}-{lock_sha256[:16]}",
        "creationInfo": {
            "created": _spdx_timestamp(epoch),
            "creators": ["Tool: cco-release-artifacts/1"],
        },
        "packages": packages,
        "files": files,
        "relationships": sorted(
            relationships,
            key=lambda item: (item["spdxElementId"], item["relationshipType"], item["relatedSpdxElement"]),
        ),
    }


def _public_key_material(private_key: Ed25519PrivateKey) -> tuple[bytes, str]:
    public_key = private_key.public_key()
    raw = public_key.public_bytes(serialization.Encoding.Raw, serialization.PublicFormat.Raw)
    pem = public_key.public_bytes(serialization.Encoding.PEM, serialization.PublicFormat.SubjectPublicKeyInfo)
    return pem, f"sha256:{_sha256_bytes(raw)}"


def _load_private_key_bytes(raw: bytes) -> Ed25519PrivateKey:
    candidates = [raw]
    try:
        decoded = base64.b64decode(raw, validate=True)
        if decoded != raw:
            candidates.append(decoded)
    except Exception:
        pass
    for candidate in candidates:
        if len(candidate) == 32:
            return Ed25519PrivateKey.from_private_bytes(candidate)
        try:
            key = serialization.load_pem_private_key(candidate, password=None)
        except Exception:
            continue
        if isinstance(key, Ed25519PrivateKey):
            return key
    raise ValueError("release private key must be an unencrypted Ed25519 PEM or 32-byte base64 key")


def load_private_key(path: str | Path | None = None, env_name: str = "CCO_RELEASE_PRIVATE_KEY") -> Ed25519PrivateKey:
    if path:
        supplied = Path(path).expanduser()
        if supplied.is_symlink():
            raise ValueError("release private key must not be a symlink")
        resolved = supplied.resolve(strict=True)
        if resolved.is_relative_to(REPO_ROOT):
            raise ValueError("release private key must be stored outside the repository")
        info = resolved.stat()
        if not stat.S_ISREG(info.st_mode) or info.st_mode & 0o077:
            raise ValueError("release private key must be a regular owner-only file")
        return _load_private_key_bytes(resolved.read_bytes())
    value = os.environ.get(env_name, "")
    if not value:
        raise ValueError(f"release signing key missing; provide --private-key or {env_name}")
    return _load_private_key_bytes(value.encode("utf-8"))


def _load_public_key(path: str | Path) -> Ed25519PublicKey:
    key = serialization.load_pem_public_key(Path(path).read_bytes())
    if not isinstance(key, Ed25519PublicKey):
        raise ValueError("release public key must be Ed25519")
    return key


def _artifact_paths(output_dir: Path) -> list[Path]:
    artifacts = sorted([*output_dir.glob("*.whl"), *output_dir.glob("*.tar.gz")], key=lambda item: item.name)
    if len(artifacts) != 2 or not any(path.suffix == ".whl" for path in artifacts) \
            or not any(path.name.endswith(".tar.gz") for path in artifacts):
        raise ValueError("release requires exactly one wheel and one source archive")
    return artifacts


def _stage_release_source(staging: Path) -> None:
    staging.mkdir(parents=True, exist_ok=True)
    for name in ("LICENSE", "README.md", "pyproject.toml", "requirements.lock", "MANIFEST.in"):
        source = REPO_ROOT / name
        if source.is_symlink() or not source.is_file():
            raise ValueError(f"release source file missing: {name}")
        shutil.copy2(source, staging / name)
    config_files = {"llm.example.json", "bounty-program-policy.json", "run.example.json"}
    for relative in (Path("scripts"), Path("kryon_core"), Path("config")):
        source_root = REPO_ROOT / relative
        if source_root.is_symlink() or not source_root.is_dir():
            raise ValueError(f"release source directory missing: {relative}")
        destination_root = staging / relative
        for source in sorted(source_root.rglob("*")):
            if source.is_symlink():
                raise ValueError(f"release source symlink is forbidden: {source.relative_to(REPO_ROOT)}")
            if not source.is_file() or "__pycache__" in source.parts:
                continue
            if relative == Path("scripts") and source.suffix not in {".py", ".sh"}:
                continue
            if relative == Path("kryon_core") and source.suffix != ".py":
                continue
            if relative == Path("config") and source.relative_to(source_root).as_posix() not in config_files:
                continue
            destination = destination_root / source.relative_to(source_root)
            destination.parent.mkdir(parents=True, exist_ok=True)
            shutil.copy2(source, destination)


def audit_release_archives(artifacts: list[Path]) -> dict:
    wheel = next(path for path in artifacts if path.suffix == ".whl")
    source_archive = next(path for path in artifacts if path.name.endswith(".tar.gz"))
    project, version, _direct = _project_metadata()
    distribution = project.replace("-", "_")
    with zipfile.ZipFile(wheel) as wheel_archive:
        wheel_names = wheel_archive.namelist()
    with tarfile.open(source_archive, "r:gz") as tar_archive:
        source_names = tar_archive.getnames()

    def safe_parts(name: str) -> tuple[str, ...]:
        normalized = name.replace("\\", "/")
        parts = tuple(part for part in normalized.split("/") if part)
        if not parts or normalized.startswith("/") or ".." in parts:
            raise ValueError(f"release archive contains an unsafe path: {name}")
        return parts

    wheel_roots = {
        "scripts",
        "kryon_core",
        f"{distribution}-{version}.dist-info",
        f"{distribution}-{version}.data",
    }
    for name in wheel_names:
        parts = safe_parts(name)
        if parts[0] not in wheel_roots:
            raise ValueError(f"wheel contains a non-allowlisted path: {name}")
    allowed_source_roots = {
        "LICENSE", "README.md", "pyproject.toml", "requirements.lock", "MANIFEST.in",
        "PKG-INFO", "setup.cfg", "scripts", "kryon_core", "config", "hackagent.egg-info",
    }
    for name in source_names:
        parts = safe_parts(name)
        if len(parts) == 1:
            continue
        if parts[1] not in allowed_source_roots:
            raise ValueError(f"source archive contains a non-allowlisted path: {name}")
    forbidden_tokens = {
        ".env", ".git", "hepsiburada", "loot", "secret", "session_state",
    }
    for name in [*wheel_names, *source_names]:
        lowered = name.lower()
        if any(token in lowered for token in forbidden_tokens):
            raise ValueError(f"release archive contains forbidden content: {name}")
    return {"wheel_files": len(wheel_names), "source_files": len(source_names), "allowlist_passed": True}


def _normalize_source_archive(path: Path, epoch: int) -> None:
    members: list[tuple[tarfile.TarInfo, bytes | None]] = []
    with tarfile.open(path, "r:gz") as source:
        for member in source.getmembers():
            extracted = source.extractfile(member) if member.isfile() else None
            payload = extracted.read() if extracted is not None else None
            members.append((member, payload))
    temporary = path.with_name(path.name + ".tmp")
    with temporary.open("wb") as raw_output:
        with gzip.GzipFile(filename="", mode="wb", fileobj=raw_output, mtime=epoch, compresslevel=9) as compressed:
            with tarfile.open(fileobj=compressed, mode="w", format=tarfile.PAX_FORMAT) as archive:
                for original, payload in sorted(members, key=lambda item: item[0].name):
                    normalized = tarfile.TarInfo(original.name)
                    normalized.type = original.type
                    normalized.linkname = original.linkname
                    normalized.size = len(payload) if payload is not None else 0
                    normalized.mode = original.mode
                    normalized.mtime = epoch
                    normalized.uid = 0
                    normalized.gid = 0
                    normalized.uname = ""
                    normalized.gname = ""
                    normalized.devmajor = original.devmajor
                    normalized.devminor = original.devminor
                    normalized.pax_headers = {}
                    archive.addfile(normalized, io.BytesIO(payload) if payload is not None else None)
    os.replace(temporary, path)


def _build_packages(output_dir: Path, epoch: int) -> list[Path]:
    env = os.environ.copy()
    env.update({"SOURCE_DATE_EPOCH": str(epoch), "PYTHONHASHSEED": "0"})
    with tempfile.TemporaryDirectory(prefix="cco-release-source-") as temp_dir:
        staging = Path(temp_dir) / "source"
        _stage_release_source(staging)
        result = subprocess.run(
            [sys.executable, "-m", "build", "--no-isolation", "--sdist", "--wheel", "--outdir", str(output_dir)],
            cwd=staging,
            env=env,
            text=True,
            capture_output=True,
            check=False,
        )
    if result.returncode != 0:
        detail = (result.stderr or result.stdout or "package build failed")[-2000:]
        raise RuntimeError(detail.strip())
    artifacts = _artifact_paths(output_dir)
    _normalize_source_archive(next(path for path in artifacts if path.name.endswith(".tar.gz")), epoch)
    audit_release_archives(artifacts)
    return artifacts


def _verify_reproducible_build(artifacts: list[Path], epoch: int) -> None:
    expected = {path.name: _sha256_file(path) for path in artifacts}
    with tempfile.TemporaryDirectory(prefix="cco-repro-build-") as temp_dir:
        rebuilt = _build_packages(Path(temp_dir), epoch)
        actual = {path.name: _sha256_file(path) for path in rebuilt}
    if actual != expected:
        mismatched = sorted(
            name for name in set(actual) | set(expected) if actual.get(name) != expected.get(name)
        )
        raise RuntimeError(f"release build is not reproducible: {', '.join(mismatched)}")


def _source_is_clean() -> bool:
    result = subprocess.run(
        ["git", "status", "--porcelain", "--untracked-files=all"],
        cwd=REPO_ROOT,
        text=True,
        capture_output=True,
        check=False,
    )
    return result.returncode == 0 and not result.stdout.strip()


def assemble_release(output_dir: str | Path, private_key: Ed25519PrivateKey, *,
                     epoch: int, lock_file: str | Path = LOCK_FILE,
                     source_clean: bool = True) -> dict:
    output = Path(output_dir).resolve()
    artifacts = _artifact_paths(output)
    archive_audit = audit_release_archives(artifacts)
    project, version, _direct = _project_metadata()
    lock_packages = parse_lock_file(lock_file)
    lock_source = Path(lock_file)
    bundled_lock = output / "requirements.lock"
    if bundled_lock.exists():
        raise ValueError("release output already contains requirements.lock")
    bundled_lock.write_bytes(lock_source.read_bytes())
    lock_sha = _sha256_file(bundled_lock)

    sbom = build_spdx_sbom(
        lock_packages,
        artifacts,
        project=project,
        version=version,
        epoch=epoch,
        lock_sha256=lock_sha,
    )
    sbom_path = output / "sbom.spdx.json"
    _write_json(sbom_path, sbom)

    public_pem, key_id = _public_key_material(private_key)
    public_path = output / "release-public-key.pem"
    public_path.write_bytes(public_pem)
    artifact_entries = [{
        "name": path.name,
        "sha256": _sha256_file(path),
        "size": path.stat().st_size,
    } for path in artifacts]
    manifest = {
        "schema": MANIFEST_SCHEMA,
        "project": project,
        "version": version,
        "source_date_epoch": epoch,
        "source": {"clean": bool(source_clean)},
        "artifacts": artifact_entries,
        "archive_audit": archive_audit,
        "lockfile": {
            "name": bundled_lock.name,
            "sha256": lock_sha,
            "packages": len(lock_packages),
        },
        "sbom": {"name": sbom_path.name, "sha256": _sha256_file(sbom_path), "format": SPDX_VERSION},
        "signing": {
            "algorithm": "Ed25519",
            "key_id": key_id,
            "public_key": public_path.name,
            "public_key_sha256": _sha256_file(public_path),
        },
    }
    manifest_path = output / "release-manifest.json"
    manifest_bytes = _write_json(manifest_path, manifest)
    signature = private_key.sign(manifest_bytes)
    signature_envelope = {
        "schema": SIGNATURE_SCHEMA,
        "algorithm": "Ed25519",
        "key_id": key_id,
        "manifest": manifest_path.name,
        "manifest_sha256": _sha256_bytes(manifest_bytes),
        "signature": base64.b64encode(signature).decode("ascii"),
    }
    signature_path = output / "release-manifest.sig"
    _write_json(signature_path, signature_envelope)
    return verify_release(output, public_path)


def build_release(output_dir: str | Path, private_key: Ed25519PrivateKey, *,
                  source_date_epoch: int | None = None, verify_reproducible: bool = True,
                  require_clean: bool = True) -> dict:
    output = Path(output_dir).expanduser().resolve()
    output.mkdir(parents=True, exist_ok=True)
    if any(output.iterdir()):
        raise ValueError("release output directory must be empty")
    epoch = _source_date_epoch(source_date_epoch)
    source_clean = _source_is_clean()
    if require_clean and not source_clean:
        raise ValueError("production release requires a clean tracked Git worktree")
    check_lock_file()
    artifacts = _build_packages(output, epoch)
    if verify_reproducible:
        _verify_reproducible_build(artifacts, epoch)
    return assemble_release(output, private_key, epoch=epoch, source_clean=source_clean)


def verify_release(release_dir: str | Path, public_key_path: str | Path) -> dict:
    release = Path(release_dir).expanduser().resolve()
    manifest_path = release / "release-manifest.json"
    signature_path = release / "release-manifest.sig"
    if not manifest_path.is_file() or not signature_path.is_file():
        raise ValueError("release manifest or detached signature is missing")
    manifest_bytes = manifest_path.read_bytes()
    manifest = json.loads(manifest_bytes)
    signature = json.loads(signature_path.read_text(encoding="utf-8"))
    if manifest.get("schema") != MANIFEST_SCHEMA or signature.get("schema") != SIGNATURE_SCHEMA:
        raise ValueError("unsupported release manifest or signature schema")
    if signature.get("algorithm") != "Ed25519" or manifest.get("signing", {}).get("algorithm") != "Ed25519":
        raise ValueError("release signature algorithm must be Ed25519")
    if signature.get("manifest") != manifest_path.name:
        raise ValueError("signature references an unexpected manifest")
    if signature.get("manifest_sha256") != _sha256_bytes(manifest_bytes):
        raise ValueError("release manifest checksum mismatch")
    public_key = _load_public_key(public_key_path)
    raw_public = public_key.public_bytes(serialization.Encoding.Raw, serialization.PublicFormat.Raw)
    key_id = f"sha256:{_sha256_bytes(raw_public)}"
    if signature.get("key_id") != key_id or manifest.get("signing", {}).get("key_id") != key_id:
        raise ValueError("release signing key identity mismatch")
    try:
        public_key.verify(base64.b64decode(signature["signature"], validate=True), manifest_bytes)
    except (InvalidSignature, ValueError, KeyError) as exc:
        raise ValueError("release manifest signature is invalid") from exc

    project, version, _direct = _project_metadata()
    if manifest.get("project") != project or manifest.get("version") != version:
        raise ValueError("release manifest project metadata mismatch")
    expected_files = {"release-manifest.json", "release-manifest.sig"}
    for entry in manifest.get("artifacts", []):
        name = str(entry.get("name") or "")
        if not name or Path(name).name != name:
            raise ValueError("release artifact name is unsafe")
        path = release / name
        if not path.is_file() or path.stat().st_size != int(entry.get("size", -1)) \
                or _sha256_file(path) != entry.get("sha256"):
            raise ValueError(f"release artifact integrity mismatch: {name}")
        expected_files.add(name)
    artifacts = [release / entry["name"] for entry in manifest.get("artifacts", [])]
    if audit_release_archives(artifacts) != manifest.get("archive_audit"):
        raise ValueError("release archive allowlist audit mismatch")
    for section in ("lockfile", "sbom"):
        entry = manifest.get(section) or {}
        name = str(entry.get("name") or "")
        path = release / name
        if not name or Path(name).name != name or not path.is_file() or _sha256_file(path) != entry.get("sha256"):
            raise ValueError(f"release {section} integrity mismatch")
        expected_files.add(name)
    public_name = str(manifest.get("signing", {}).get("public_key") or "")
    bundled_public = release / public_name
    if not public_name or Path(public_name).name != public_name or not bundled_public.is_file() \
            or _sha256_file(bundled_public) != manifest["signing"].get("public_key_sha256"):
        raise ValueError("bundled release public key integrity mismatch")
    expected_files.add(public_name)

    lock_packages = parse_lock_file(release / manifest["lockfile"]["name"])
    if len(lock_packages) != int(manifest["lockfile"].get("packages", -1)):
        raise ValueError("release lock package count mismatch")
    sbom = json.loads((release / manifest["sbom"]["name"]).read_text(encoding="utf-8"))
    if sbom.get("spdxVersion") != SPDX_VERSION or sbom.get("name") != f"{project}-{version}":
        raise ValueError("release SBOM metadata mismatch")
    package_entries = sbom.get("packages") or []
    package_by_name = {entry.get("name"): entry for entry in package_entries if isinstance(entry, dict)}
    if len(package_by_name) != len(package_entries) or set(package_by_name) != {project, *[item["name"] for item in lock_packages]}:
        raise ValueError("release SBOM package inventory mismatch")
    project_package = package_by_name[project]
    if project_package.get("versionInfo") != version:
        raise ValueError("release SBOM project version mismatch")
    for package in lock_packages:
        sbom_package = package_by_name[package["name"]]
        checksums = {
            item.get("checksumValue") for item in sbom_package.get("checksums", [])
            if item.get("algorithm") == "SHA256"
        }
        if sbom_package.get("versionInfo") != package["version"] or checksums != set(package["hashes"]):
            raise ValueError(f"release SBOM dependency mismatch: {package['name']}")
    artifact_hashes = {entry["name"]: entry["sha256"] for entry in manifest.get("artifacts", [])}
    sbom_files = {
        str(entry.get("fileName", "")).removeprefix("./"): {
            item.get("checksumValue") for item in entry.get("checksums", [])
            if item.get("algorithm") == "SHA256"
        }
        for entry in sbom.get("files", []) if isinstance(entry, dict)
    }
    if set(sbom_files) != set(artifact_hashes) or any(
        sbom_files[name] != {digest} for name, digest in artifact_hashes.items()
    ):
        raise ValueError("release SBOM artifact checksum mismatch")
    project_id = _spdx_id("Package", project)
    dependency_groups = _dependency_groups()
    relationships = {
        (item.get("spdxElementId"), item.get("relationshipType"), item.get("relatedSpdxElement"))
        for item in sbom.get("relationships", []) if isinstance(item, dict)
    }
    expected_runtime = {
        (project_id, "DEPENDS_ON", _spdx_id("Package", name))
        for name in dependency_groups["runtime"]
    }
    actual_runtime = {item for item in relationships if item[1] == "DEPENDS_ON"}
    if actual_runtime != expected_runtime:
        raise ValueError("release SBOM runtime dependency scope mismatch")
    nested_entries = list(release.rglob("*"))
    unsafe_entries = sorted(
        path.relative_to(release).as_posix()
        for path in nested_entries
        if path.is_symlink() or path.is_dir()
    )
    if unsafe_entries:
        raise ValueError(f"release directory contains unsigned nested entries: {', '.join(unsafe_entries)}")
    actual_files = {path.relative_to(release).as_posix() for path in nested_entries if path.is_file()}
    extras = sorted(actual_files - expected_files)
    if extras:
        raise ValueError(f"release directory contains unsigned files: {', '.join(extras)}")
    return {
        "verified": True,
        "project": project,
        "version": version,
        "key_id": key_id,
        "artifacts": len(manifest.get("artifacts", [])),
        "lock_packages": len(lock_packages),
        "sbom_packages": len(sbom.get("packages", [])),
    }


def main(argv: list[str] | None = None) -> int:
    parser = argparse.ArgumentParser(description="Build and verify signed CCO release artifacts")
    sub = parser.add_subparsers(dest="command", required=True)

    check_lock = sub.add_parser("check-lock", help="validate exact pins and hashes")
    check_lock.add_argument("--lock-file", default=str(LOCK_FILE))

    build = sub.add_parser("build", help="build reproducibly and sign a release bundle")
    build.add_argument("--output-dir", default="dist/release")
    build.add_argument("--private-key", default="")
    build.add_argument("--private-key-env", default="CCO_RELEASE_PRIVATE_KEY")
    build.add_argument("--source-date-epoch", type=int)
    build.add_argument("--verify-reproducible", action=argparse.BooleanOptionalAction, default=True)
    build.add_argument("--ephemeral-key", action="store_true", help="smoke tests only; never use for a production release")
    build.add_argument("--allow-dirty", action="store_true", help="development smoke only; marks the signed manifest dirty")

    verify = sub.add_parser("verify", help="verify a signed release bundle")
    verify.add_argument("--release-dir", required=True)
    verify.add_argument("--public-key", required=True)
    args = parser.parse_args(argv)

    try:
        if args.command == "check-lock":
            report = check_lock_file(args.lock_file)
        elif args.command == "verify":
            report = verify_release(args.release_dir, args.public_key)
        else:
            if args.ephemeral_key and (args.private_key or os.environ.get(args.private_key_env)):
                raise ValueError("ephemeral key cannot be combined with a production signing key")
            private_key = Ed25519PrivateKey.generate() if args.ephemeral_key else load_private_key(
                args.private_key or None, args.private_key_env
            )
            report = build_release(
                args.output_dir,
                private_key,
                source_date_epoch=args.source_date_epoch,
                verify_reproducible=args.verify_reproducible,
                require_clean=not args.allow_dirty,
            )
    except (ValueError, RuntimeError, OSError, subprocess.CalledProcessError) as exc:
        print(json.dumps({"ok": False, "error": type(exc).__name__, "message": str(exc)}), file=sys.stderr)
        return 1
    print(json.dumps(report, indent=2, sort_keys=True))
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
