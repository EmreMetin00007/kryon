# Benchmark Skor Kartı

Tekrarlanabilir loopback doğrulama sonuçları. Gerçek hedefe dokunulmaz;
hedef yalnızca `127.0.0.1` üzerindeki kasıtlı-zafiyetli lab'dır
(`scripts/lab/vuln_lab.py`).

## Son koşu

| Alan | Değer |
|---|---|
| Tarih (UTC) | 2026-10-17T14:33Z |
| Commit | `fbdbd4b` + mimari faz düzeltmeleri (çalışma ağacı) |
| Komut | `python3 scripts/lab-validate.py --skip-rag --quiet --json` |
| Sonuç | **48/48 passed** (`all_passed: true`) |
| Birim testler | `python3 -m pytest tests -q` → **653 passed** |
| Negatif kontrol | `python3 scripts/negative-control.py` → **fp_rate 0.0 (0/6)** |
| Kapsam | 16 MCP server / 275 tool (`python3 scripts/tool_counts.py`) |
| Ortam | `CCO_GRAPH_BACKEND=networkx` (CI ile aynı) |

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
CONFIRMED = false-positive sayılır. Son koşu: **0/6 FP, fp_rate 0.0**
(tüm kontroller UNCONFIRMED; ERROR yokluğu testte ayrıca doğrulanır).
CI'da her koşuda tekrarlanır.

## Tekrar üretme

```bash
CCO_GRAPH_BACKEND=networkx python3 -m pytest tests -q
python3 scripts/lab-validate.py --skip-rag --quiet --json
python3 scripts/negative-control.py --rounds 1 --json
python3 scripts/tool_counts.py
```

> Not: Bu kart lab/loopback kanıtıdır; gerçek program kabulü veya saha
> başarısı iddiası taşımaz. XBOW tarzi harici benchmark koşusu ayrı iştir.
