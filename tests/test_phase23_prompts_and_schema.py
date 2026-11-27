"""Phase 2B + 3B tests: weak_credentials schema enum and concise QA coverage guidance."""
from __future__ import annotations

import json
from pathlib import Path
import sys

REPO_ROOT = Path(__file__).resolve().parent.parent
SCRIPTS_DIR = REPO_ROOT / "scripts"
if str(SCRIPTS_DIR) not in sys.path:
    sys.path.insert(0, str(SCRIPTS_DIR))

from agentic_context import build_system_prompt, build_worker_system_prompt  # noqa: E402
from agentic_sharding import (  # noqa: E402
    SubsystemCluster,
    build_cross_shard_synthesis_prompts,
    build_shard_prompts,
)
from agentic_tools import RECORD_FINDING_CLASS_ENUM, TOOL_SCHEMAS  # noqa: E402


def test_tool_schemas_closed_11_and_weak_credentials_enum() -> None:
    assert len(TOOL_SCHEMAS) == 12
    assert "weak_credentials" in RECORD_FINDING_CLASS_ENUM

    rf_tool = next(t["function"] for t in TOOL_SCHEMAS if t["function"]["name"] == "record_finding")
    class_enum = rf_tool["parameters"]["properties"]["class_type"]["enum"]
    assert "weak_credentials" in class_enum
    assert class_enum == RECORD_FINDING_CLASS_ENUM

    serialized = json.dumps(TOOL_SCHEMAS, ensure_ascii=False, separators=(",", ":")).encode("utf-8")
    assert len(serialized) <= 16_384


def test_context_prompts_include_concise_qa_guidance_and_stay_compact() -> None:
    sys_prompt = build_system_prompt(
        base_url="http://127.0.0.1:8080/",
        allowed_methods=["GET", "POST", "PUT", "PATCH", "DELETE"],
        actor_summaries=[{"alias": "anon", "role": "anonymous", "tenant": ""}],
        discovery_hints=["/"],
        http_budget=100,
    )
    worker_prompt = build_worker_system_prompt(
        base_url="http://127.0.0.1:8080/",
        allowed_methods=["GET", "POST", "PUT", "PATCH", "DELETE"],
        http_budget_remaining=50,
        micro_budget=8,
    )

    # Compactness bounds (prevent prompt bloat)
    assert len(sys_prompt) < 6200
    assert len(worker_prompt) < 3800

    for label, prompt in (("system", sys_prompt), ("worker", worker_prompt)):
        for token in (
            "member1",
            "member2",
            "weak_credentials",
            ".svg",
            "image/svg+xml",
            "Content-Type",
            "..%252F",
            "SubDir%2Ffile.ini",
            "/reboot",
            "/restart",
            "/shutdown",
            "/logout",
            "4 probes",
        ):
            assert token in prompt, f"{label} prompt missing {token!r}"


def test_sharding_and_synthesis_prompts_include_qa_reminders_and_stay_compact() -> None:
    cluster = SubsystemCluster(
        shard_id="shard-1",
        name="files",
        families=["files"],
        routes=["/files", "/files/upload", "/auth/login"],
        write_ops=["POST /files/upload", "POST /auth/login"],
        objects=[],
        params={"/files": ["path"]},
    )
    shard_sys, _ = build_shard_prompts(cluster, base_system_prompt="BASE SYSTEM PROMPT")
    assert len(shard_sys) < 1500
    for token in (
        "5 turns",
        "/reboot",
        "/restart",
        "/shutdown",
        "weak_credentials",
        ".svg",
        "Content-Type",
        "%252F",
        "%2F",
    ):
        assert token in shard_sys, f"shard prompt missing {token!r}"

    synth_sys, _ = build_cross_shard_synthesis_prompts(
        base_system_prompt="BASE SYSTEM PROMPT",
        synthesis_context={
            "findings": [],
            "internal_urls": [],
            "extracted_values": [],
            "auth_capabilities": [],
            "blockers": [],
            "untested_writes_and_blocked": [],
        },
        actor_summaries=[{"alias": "alice", "role": "member", "tenant": "t1"}],
        http_budget_remaining=40,
    )
    assert len(synth_sys) < 1800
    for token in (
        "5 turns",
        "/reboot",
        "/restart",
        "/shutdown",
        "weak_credentials",
        ".svg",
        "Content-Type",
        "%252F",
        "%2F",
    ):
        assert token in synth_sys, f"synthesis prompt missing {token!r}"
