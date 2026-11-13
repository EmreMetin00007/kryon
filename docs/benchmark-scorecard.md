# Benchmark ve Doğrulama Kartı

Tekrarlanabilir loopback doğrulama ve regresyon kontrolleri. Gerçek hedeflere
dokunulmaz; hedef yalnızca `127.0.0.1` üzerindeki kasıtlı-zafiyetli lab'dır
(`scripts/lab/vuln_lab.py`).

## Son doğrulanmış koşu özeti

| Alan | Değer |
|---|---|
| Tarih | 2026-11-13 |
| Birim test paketi | `python3 -m pytest tests -q -m 'not integration' --ignore=tests/test_full_agent_e6_benchmark.py` → **3365 passed, 37 skipped, 34 deselected** |
| Lab doğrulaması | `python3 scripts/lab-validate.py --skip-rag --quiet --json` → **48/48 passed** |
| Negatif kontrol | `python3 scripts/negative-control.py --rounds 1 --json` → **6/6 passed (`fp_rate: 0.0`)** |
| MCP kapsamı | `python3 scripts/tool_counts.py` → **16 MCP server, 292 tool** |
| Bağımlılık kilidi | `python3 scripts/release_artifacts.py check-lock` → **103 paket doğrulandı** |

## Kapsanan kontroller (özet)

- Hunter zinciri: RAG enrichment, `predict_vulnerabilities`, coverage kör nokta
- Authz: `build_authz_matrix` → canlı → `analyze_authz_result` (BOLA + unauth admin)
- Business logic: `generate_abuse_cases` + canlı negatif-fiyat
- Variant: `auto_fanout_variants(live=True)` (XSS + SQLi triage)
- Validator oracle'ları: SQLi, XSS, SSRF, IDOR, auth bypass, open redirect
  (confirmed + safe-unconfirmed çiftleri)

## Negatif kontrol (false-positive)

`scripts/negative-control.py`, lab'in sertleştirilmiş `/safe/*` ikizlerine
6 kontrol koşar (SQLi, XSS, IDOR, auth bypass, open redirect, BOLA oracle).
CONFIRMED = false-positive sayılır; tüm kontroller UNCONFIRMED dönmelidir.

## Tekrar üretme

```bash
python3 -m pytest tests/test_python_engine.py tests/test_full_agent_python_solver.py -q
python3 -m pytest tests/test_p9_integration.py tests/test_module_boundaries.py -q
python3 scripts/lab-validate.py --skip-rag --quiet --json
python3 scripts/negative-control.py --rounds 1 --json
python3 scripts/tool_counts.py
python3 scripts/release_check.py --list
python3 scripts/check_repo_layout.py
```

> Not: Bu kart lab/loopback ve yerel birim testi kanıtıdır; gerçek program kabulü
> veya harici saha başarısı iddiası taşımaz.
