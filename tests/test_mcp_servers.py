"""
CCO MCP Server Smoke / Regresyon Testleri
=========================================
Her MCP server için: import + list_tools + beklenen tool sayısı + metadata.
Ayrıca seçili pure-function'lar için offline temel çağrı testleri.

Çalıştırma:
    pip install pytest
    pytest -q                      # tüm suite
    pytest -q -k tool_count        # sadece tool sayısı regresyonu

Tüm testler OFFLINE'dır (network gerektirmez). Yeni tool eklerken
EXPECTED_TOOL_COUNTS güncellenmeli — aksi halde test kırılır (kasıtlı guard).
"""
import json

import pytest

from conftest import load_server, list_tool_names

# Beklenen tool sayıları — regresyon guard'ı (tool eklerken bilerek güncelle)
EXPECTED_TOOL_COUNTS = {
    "kali-tools": 93,
    "web-advanced": 30,
    "ctf-platform": 14,
    "validator": 28,
    "ad-tools": 12,
    "memory-server": 15,
    "container-tools": 10,
    "osint-tools": 9,
    "telemetry": 10,
    "browser": 20,
    "reasoning": 20,
    "rag-engine": 7,
    "hunter": 16,
    "llm-security": 6,
    "agent-browse": 2,
    "otp": 1,
}

ALL_SERVERS = sorted(EXPECTED_TOOL_COUNTS.keys())
TOTAL_EXPECTED = sum(EXPECTED_TOOL_COUNTS.values())


@pytest.mark.parametrize("server", ALL_SERVERS)
def test_server_imports(server):
    """Her server.py import edilebilmeli (bağımlılık/syntax kontrolü)."""
    mod = load_server(server)
    assert hasattr(mod, "mcp"), f"{server}: FastMCP 'mcp' nesnesi yok"


@pytest.mark.parametrize("server", ALL_SERVERS)
def test_tool_count(server):
    """Her server beklenen sayıda tool sunmalı (regresyon guard)."""
    mod = load_server(server)
    names = list_tool_names(mod)
    expected = EXPECTED_TOOL_COUNTS[server]
    assert len(names) == expected, (
        f"{server}: {len(names)} tool bulundu, {expected} bekleniyordu. "
        f"Tool eklediysen EXPECTED_TOOL_COUNTS'u güncelle."
    )


@pytest.mark.parametrize("server", ALL_SERVERS)
def test_tools_have_metadata(server):
    """Her tool'un boş olmayan adı ve açıklaması olmalı (LLM keşfi için kritik)."""
    import asyncio
    mod = load_server(server)
    tools = asyncio.run(mod.mcp.list_tools())
    for t in tools:
        assert t.name and t.name.strip(), f"{server}: adsız tool"
        assert t.description and len(t.description.strip()) >= 10, (
            f"{server}.{t.name}: açıklama eksik/çok kısa"
        )


def test_total_tool_count():
    """Toplam tool sayısı (16 server) regresyon kontrolü."""
    total = 0
    for server in ALL_SERVERS:
        total += len(list_tool_names(load_server(server)))
    assert total == TOTAL_EXPECTED, f"Toplam {total} tool, {TOTAL_EXPECTED} bekleniyordu"


def test_no_duplicate_tool_names_within_server():
    """Bir server içinde tool adları benzersiz olmalı."""
    for server in ALL_SERVERS:
        names = list_tool_names(load_server(server))
        assert len(names) == len(set(names)), f"{server}: tekrarlanan tool adı"


# ─────────────── Offline pure-function temel çağrı testleri ───────────────

def test_llm_security_payload_generator():
    """generate_injection_payloads geçerli JSON ve dolu payload döndürür."""
    mod = load_server("llm-security")
    out = json.loads(mod.generate_injection_payloads(goal="leak system prompt", technique="all"))
    assert "payloads" in out and out["payloads"], "payload üretilmedi"
    assert "roleplay" in out["payloads"]


def test_llm_security_owasp_checklist():
    """llm_owasp_top10_checklist 10 OWASP LLM kategorisi döndürür."""
    mod = load_server("llm-security")
    out = json.loads(mod.llm_owasp_top10_checklist())
    assert len(out["checklist"]) == 10


def test_browser_security_headers_handles_runtime_env():
    """Browser server her iki runtime'da da kontrollü davranır."""
    mod = load_server("browser")
    if not mod.HAS_PLAYWRIGHT:
        res = mod.browser_security_headers("https://example.com")
        assert isinstance(res, str) and "playwright" in res.lower()
    else:
        res = mod.browser_security_headers("ftp://bad")
        assert "HATA" in res


def test_browser_rejects_invalid_url():
    """browser tool'ları http/https olmayan URL'i reddeder."""
    mod = load_server("browser")
    res = mod.browser_security_headers("ftp://bad")
    if mod.HAS_PLAYWRIGHT:
        assert "HATA" in res
    else:
        assert isinstance(res, str) and "playwright" in res.lower()


def test_browser_tool_survives_running_asyncio_loop():
    """FastMCP tool'ları asyncio loop içinde çağrılır; sync_playwright orada patlar."""
    import asyncio

    mod = load_server("browser")

    async def call():
        return mod.browser_security_headers("ftp://bad")

    res = asyncio.run(call())
    assert "asyncio loop" not in res.lower()
    if mod.HAS_PLAYWRIGHT:
        assert "HATA" in res
    else:
        assert "playwright" in res.lower()
