#!/usr/bin/env python3
"""blind-01 kor test derslerini reasoning hafizasina eker (idempotent).

Kullanim: python3 scripts/seed_blind01_lessons.py [--verify-only]
5 iskalama -> 5 kalici ders (worked=False paterni + duzeltici aksiyon).
Etiket: blind-01. recall_lessons ile planlamaya otomatik karisir.
"""
import sqlite3
import sys
from pathlib import Path

REPO = Path(__file__).resolve().parent.parent
sys.path.insert(0, str(REPO / "mcp-servers" / "mcp-reasoning"))

LESSONS = [
    dict(context="JWT guvenlik karari, cok-uclu API",
         technique="jwt_confusion",
         action="Tek saglam uctan 401 alip tum sistemi guvenli ilan etme",
         outcome="FALSE NEGATIVE: acik kardes uc test edilmeden kacirildi. Kural: hukum UC BASINADIR; her kardes uc ayri kanit ister.",
         worked=False, target_tech="JWT/RS256 API", tags="blind-01,verdict-discipline"),
    dict(context="BOLA/IDOR, UUID'li kaynaklar",
         technique="idor",
         action="Sayisal fuzz (1/2/3) ile yetinip seed ID bulunamadi diye birakma",
         outcome="FALSE NEGATIVE: UUID'li BOLA kacirildi. Kural: once harvest_identifiers ile yanitlardan UUID topla, sonra capraz-kimlik testi.",
         worked=False, target_tech="REST API", tags="blind-01,identifier-harvest"),
    dict(context="Sayisal IDOR, fatura/siparis kaynaklari",
         technique="idor",
         action="1/2/3 + gozlemlenen hesap no ile sinirli tarama",
         outcome="FALSE NEGATIVE: 1001 serisi kacirildi. Kural: idor_id_candidates kurumsal araliklarini (100/1000/5000/10000 serileri) tara.",
         worked=False, target_tech="REST API", tags="blind-01,id-ranges"),
    dict(context="Yansiyan XSS, naif WAF filtresi (403)",
         technique="xss_reflected",
         action="Standart payload 403 alinca vektor PARKED",
         outcome="FALSE NEGATIVE: double-URL-decode arkasi XSS kacirildi. Kural: 403 = evolve_payload cagrisi (double_url_encode/html_entity/hex_char zinciri), PARK degil.",
         worked=False, target_tech="WAF + web app", tags="blind-01,encode-chain"),
    dict(context="OAuth authorize, bilinmeyen client_id",
         technique="oauth_redirect",
         action="Ezbere jenerik client_id denemesi (web/app/storefront)",
         outcome="PARKED: gercek client kesfedilemedi. Kural: oauth_discovery_checklist sirasi — well-known, JS bundle madenciligi, hata mesaji; jenerik liste SON care.",
         worked=False, target_tech="OAuth2/OIDC", tags="blind-01,oauth-discovery"),
]


def main() -> int:
    import server as rs
    verify_only = "--verify-only" in sys.argv
    conn = sqlite3.connect(rs.LESSONS_DB)
    have = conn.execute("SELECT COUNT(*) FROM lessons WHERE tags LIKE '%blind-01%'").fetchone()[0] \
        if "lessons" in [r[0] for r in conn.execute(
            "SELECT name FROM sqlite_master WHERE type='table'")] else 0
    conn.close()
    if verify_only or have >= len(LESSONS):
        print(f"blind-01 dersleri mevcut: {have} kayit (ekleme yapilmadi)")
    else:
        for les in LESSONS:
            print(rs.record_lesson(**les))
    print("--- recall dogrulama ---")
    print(rs.recall_lessons(context="BOLA IDOR UUID", technique="idor", k=3))
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
