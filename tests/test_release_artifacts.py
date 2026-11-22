import importlib.util
import io
import json
import os
import sys
import tarfile
import zipfile

import pytest
from cryptography.hazmat.primitives import serialization


REPO_ROOT = os.path.dirname(os.path.dirname(os.path.abspath(__file__)))


def _load_release_artifacts():
    path = os.path.join(REPO_ROOT, "scripts", "release_artifacts.py")
    spec = importlib.util.spec_from_file_location("release_artifacts_test", path)
    module = importlib.util.module_from_spec(spec)
    sys.modules[spec.name] = module
    spec.loader.exec_module(module)
    return module


def _dummy_artifacts(output):
    output.mkdir()
    wheel = output / "hackagent-0.1.0-py3-none-any.whl"
    with zipfile.ZipFile(wheel, "w") as archive:
        archive.writestr("scripts/__init__.py", "")
        archive.writestr("hackagent-0.1.0.dist-info/METADATA", "Name: hackagent\n")
    source = output / "hackagent-0.1.0.tar.gz"
    with tarfile.open(source, "w:gz") as archive:
        root = tarfile.TarInfo("hackagent-0.1.0")
        root.type = tarfile.DIRTYPE
        archive.addfile(root)
        payload = b"[project]\nname='hackagent'\n"
        info = tarfile.TarInfo("hackagent-0.1.0/pyproject.toml")
        info.size = len(payload)
        archive.addfile(info, io.BytesIO(payload))


def test_hash_pinned_lock_covers_project_dev_dependencies():
    mod = _load_release_artifacts()

    report = mod.check_lock_file()
    packages = mod.parse_lock_file()

    assert report["valid"] is True
    assert report["packages"] == len(packages)
    assert report["direct_dependencies"] >= 10
    assert {"build", "chromadb", "cryptography", "kuzu", "mcp", "pytest", "setuptools", "wheel"}.issubset(
        {package["name"] for package in packages}
    )
    assert all(package["hashes"] for package in packages)


def test_release_bundle_has_spdx_sbom_and_valid_detached_signature(tmp_path):
    mod = _load_release_artifacts()
    output = tmp_path / "release"
    _dummy_artifacts(output)
    private_key = mod.Ed25519PrivateKey.generate()

    assembled = mod.assemble_release(output, private_key, epoch=1700000000)
    verified = mod.verify_release(output, output / "release-public-key.pem")
    manifest = json.loads((output / "release-manifest.json").read_text(encoding="utf-8"))
    signature = json.loads((output / "release-manifest.sig").read_text(encoding="utf-8"))
    sbom = json.loads((output / "sbom.spdx.json").read_text(encoding="utf-8"))

    assert assembled == verified
    assert verified["verified"] is True
    assert manifest["schema"] == "cco-release-manifest/1"
    assert manifest["archive_audit"]["allowlist_passed"] is True
    assert manifest["signing"]["algorithm"] == "Ed25519"
    assert signature["schema"] == "cco-release-signature/1"
    assert signature["signature"]
    assert sbom["spdxVersion"] == "SPDX-2.3"
    assert sbom["creationInfo"]["created"] == "2023-11-14T22:13:20Z"
    assert verified["sbom_packages"] == verified["lock_packages"] + 1


def test_release_verification_rejects_tampering_and_wrong_trust_root(tmp_path):
    mod = _load_release_artifacts()
    output = tmp_path / "release"
    _dummy_artifacts(output)
    private_key = mod.Ed25519PrivateKey.generate()
    mod.assemble_release(output, private_key, epoch=1700000000)

    wrong_public = tmp_path / "wrong-public.pem"
    wrong_public.write_bytes(
        mod.Ed25519PrivateKey.generate().public_key().public_bytes(
            serialization.Encoding.PEM,
            serialization.PublicFormat.SubjectPublicKeyInfo,
        )
    )
    with pytest.raises(ValueError, match="identity mismatch"):
        mod.verify_release(output, wrong_public)

    artifact = output / "hackagent-0.1.0-py3-none-any.whl"
    artifact.write_bytes(artifact.read_bytes() + b"tampered")
    with pytest.raises(ValueError, match="artifact integrity"):
        mod.verify_release(output, output / "release-public-key.pem")


def test_private_key_loader_requires_owner_only_external_file(tmp_path):
    mod = _load_release_artifacts()
    private = mod.Ed25519PrivateKey.generate()
    key_path = tmp_path / "release-key.pem"
    key_path.write_bytes(private.private_bytes(
        serialization.Encoding.PEM,
        serialization.PrivateFormat.PKCS8,
        serialization.NoEncryption(),
    ))
    key_path.chmod(0o644)

    with pytest.raises(ValueError, match="owner-only"):
        mod.load_private_key(key_path)

    key_path.chmod(0o600)
    loaded = mod.load_private_key(key_path)
    assert isinstance(loaded, mod.Ed25519PrivateKey)


def test_release_staging_excludes_repository_engagement_data(tmp_path):
    mod = _load_release_artifacts()
    staging = tmp_path / "staging"

    mod._stage_release_source(staging)

    names = {path.relative_to(staging).as_posix() for path in staging.rglob("*") if path.is_file()}
    assert "scripts/agentic_runner.py" in names
    assert "kryon_core/surface/extract.py" in names
    assert "config/llm.example.json" in names
    assert "config/bounty-program-policy.json" in names
    assert "requirements.lock" in names
    assert not any(
        name.startswith(("mcp-servers/", "hepsiburada-bb/", "memory/", ".codex/", ".git/"))
        for name in names
    )


def test_release_verification_rejects_unsigned_nested_files(tmp_path):
    mod = _load_release_artifacts()
    output = tmp_path / "release"
    _dummy_artifacts(output)
    private_key = mod.Ed25519PrivateKey.generate()
    mod.assemble_release(output, private_key, epoch=1700000000)
    nested = output / "unsigned"
    nested.mkdir()
    (nested / "payload.txt").write_text("not in manifest", encoding="utf-8")

    with pytest.raises(ValueError, match="unsigned nested"):
        mod.verify_release(output, output / "release-public-key.pem")
