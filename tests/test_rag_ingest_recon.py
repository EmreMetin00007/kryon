"""Converter tests for scripts/rag_ingest_recon.py (staging only, no ChromaDB)."""
import json
import sys
from pathlib import Path

sys.path.insert(0, str(Path(__file__).resolve().parent.parent / "scripts"))

from rag_ingest_recon import convert_json, flatten_item, stage


def test_flatten_item_httpx_shape():
    item = {"url": "https://x.example.com", "status-code": 200,
            "title": "Login", "technologies": ["Nginx", "React"], "ip": "1.2.3.4"}
    line = flatten_item(item)
    assert "https://x.example.com" in line
    assert "status=200" in line
    assert "title=Login" in line
    assert "Nginx" in line


def test_flatten_item_string_and_scalar():
    assert flatten_item("https://a.b") == "https://a.b"
    assert "k=v" in flatten_item({"host": "h", "k": "v"})


def test_convert_json_bad_file(tmp_path):
    bad = tmp_path / "bad.json"
    bad.write_text("{not json", encoding="utf-8")
    assert "OKUMA HATASI" in convert_json(bad)


def test_convert_json_caps_size(tmp_path):
    big = tmp_path / "big.json"
    big.write_text(json.dumps([{"url": f"https://h{i}.x", "blob": "y" * 500}
                               for i in range(3000)]))
    txt = convert_json(big)
    assert len(txt.encode("utf-8")) <= 200_000 + 200
    assert "KAYIT SAYISI: 3000" in txt


def test_stage_writes_manifest(tmp_path):
    src = tmp_path / "prog"
    src.mkdir()
    (src / "a.json").write_text(json.dumps([{"host": "h1"}]))
    out = tmp_path / "staging"
    assert stage(src, out) == 1
    assert (out / "a.txt").exists()
    assert (out / "_MANIFEST.txt").exists()
