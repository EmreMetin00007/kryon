"""Taksonomi-bagimsiz hipotez uretimi: bulgu SINIFINDAN degil, yuzey
SEKILINDEN (metot + id-benzeri parametre + yol akrabaligi) turetilir.

Soru kaliplari:
  H1 karsilikli-kimlik okuma: A'nin nesnesi B ile okunursa ne degisir?
  H2 yaz-sonra-oku: POST ile yazilan deger GET yuzeyinde kimi etkiler?
  H3 tek-kullanim tekrari: ayni kupon/OTP/davet iki kez uygulanirsa
     gozlemcide cift etki olur mu? (idempotency kirigi / double-spend)
  H4 sayisal yuzey: negatif/sifir fiyat-miktar yazimi toplami dusurur mu?
     (korunum ihlali)
  H5 durum gecisi: ara adimi atlayip son yazma dogrudan cagrilirsa
     durum beklenmeyen degere gecer mi? (workflow bypass)
  H6 kayit istismari: ayni kimlikle tekrar kayit, asiri uzun e-posta
     kesilmesi ve rol alani enjeksiyonu ayricalik uretir mi?
Her hipotez calistirilabilir adimlar + onerilen oracle ile doner.
"""
from __future__ import annotations

import json
import re

ID_PARAM_RE = re.compile(
    r"(^|_)(id|uid|user|account|order|invoice|doc|file|pid|oid|ref|number)($|_)", re.I)
# Tek kullanımlık değer taşıyan parametreler (kupon / davet / OTP).
# csrf benzeri anti-CSRF alanları bilerek dışlanır (eşleşme adayı değil).
SINGLE_USE_RE = re.compile(
    r"(^|_)(coupon|promo|voucher|gift|referral|credit|redeem|invite|otp|pin|mfa|totp|captcha)(_|$)",
    re.I,
)
_CSRF_NAMES = frozenset({"csrf", "csrftoken", "csrf_token", "_csrf", "authenticity_token"})
NUMERIC_PARAM_RE = re.compile(
    r"(^|_)(price|amount|total|cost|fee|sum|balance|subtotal|qty|quantity|count|discount|credit)($|_)",
    re.I,
)
STATE_PARAM_RE = re.compile(
    r"(^|_)(step|stage|state|status|phase|next|wizard|current_step|stage_id)($|_)",
    re.I,
)
REGISTER_PATH_RE = re.compile(r"(register|signup|sign-up|join|onboard)", re.I)
_REGISTER_IDENTITY = ("username", "user", "login", "email", "mail", "password", "pass")


def _is_register_surface(rec: dict) -> bool:
    """Kayit yuzeyi: yol register benzeri + kimlik parametreleri birlikte."""
    if str(rec.get("method") or "").upper() not in {"POST", "PUT"}:
        return False
    path = _path(rec)
    names = {p.strip().lower() for p in _params(rec)}
    has_user = any(n in names for n in ("username", "user", "login"))
    has_mail = any(n in names for n in ("email", "mail"))
    has_pass = any(n in names for n in ("password", "pass"))
    return bool(REGISTER_PATH_RE.search(path)) and has_user and has_mail and has_pass


def _is_single_use_param(name: str) -> bool:
    low = (name or "").strip().lower()
    return bool(low) and low not in _CSRF_NAMES and bool(SINGLE_USE_RE.search(low))


def _params(rec: dict) -> list[str]:
    raw = rec.get("params_json") or rec.get("params") or "[]"
    if isinstance(raw, list):
        return [str(p) for p in raw]
    try:
        data = json.loads(raw)
    except (TypeError, json.JSONDecodeError):
        return []
    if isinstance(data, list):
        return [str(p.get("name", p)) if isinstance(p, dict) else str(p) for p in data]
    return [str(k) for k in data] if isinstance(data, dict) else []


def _path(rec: dict) -> str:
    return (rec.get("path") or rec.get("url") or "").split("?")[0]


def generate_hypotheses(records: list[dict], identities: tuple[str, ...] = ("A", "B")) -> list[dict]:
    """records: attack_surface satirlari (url/path/method/params_json)."""
    recs = [r for r in records or [] if isinstance(r, dict)]
    out: list[dict] = []
    gets = [r for r in recs if (r.get("method") or "GET").upper() == "GET"]
    writes = [r for r in recs if (r.get("method") or "").upper() in {"POST", "PUT", "PATCH"}]

    id_gets = []
    for r in gets:
        ids = [p for p in _params(r) if ID_PARAM_RE.search(p)]
        if ids or re.search(r"/\d+(/|$)", _path(r)):
            id_gets.append((r, ids or ["<path-id>"]))
    for r, ids in id_gets[:12]:
        out.append({
            "kind": "cross_identity_read",
            "question": f"{identities[0]}'nin nesnesi {identities[1]} kimligiyle okunursa ne degisir?",
            "surface": _path(r), "id_params": ids,
            "steps": [
                {"actor": identities[0], "action": "GET", "url": _path(r), "note": "sahip okuma (baseline)"},
                {"actor": identities[1], "action": "GET", "url": _path(r), "note": "yabanci kimlik ayni nesne"},
            ],
            "oracle": "validate_idor",
            "decision": "B 200 + A'ya ozel icerik gorurse CONFIRMED; 403/404/referans-yoksa UNCONFIRMED",
        })

    for w in writes[:8]:
        wp = _path(w)
        readers = [g for g in gets if _path(g) and (_path(g).startswith(wp.rsplit("/", 1)[0])
                                                    or wp.startswith(_path(g).rsplit("/", 1)[0]))]
        for g in readers[:2]:
            out.append({
                "kind": "write_then_read",
                "question": "POST ile yazilan deger okuma yuzeyinde kimi, nasil etkiler?",
                "write_surface": wp, "read_surface": _path(g),
                "steps": [
                    {"actor": identities[0], "action": (w.get("method") or "POST").upper(),
                     "url": wp, "note": "benzersiz canary yaz"},
                    {"actor": identities[1], "action": "GET", "url": _path(g),
                     "note": "baska kimlik canary'yi ham goruyor mu?"},
                ],
                "oracle": "validate_stored_reflection",
                "decision": "canary B'nin okumasinda ham -> stored primitif; encode/yok -> UNCONFIRMED",
            })

    _single_use_writes = [
        r for r in writes
        if any(_is_single_use_param(p) for p in _params(r))
    ]
    for w in _single_use_writes[:6]:
        wp = _path(w)
        sus = [p for p in _params(w) if _is_single_use_param(p)]
        obs = _nearest_reader(wp, gets) or wp
        out.append({
            "kind": "single_use_replay",
            "question": "Ayni tek-kullanimlik deger iki kez uygulanirsa gozlemcide cift etki olur mu?",
            "write_surface": wp, "single_use_params": sus[:4], "read_surface": obs,
            "steps": [
                {"actor": identities[0], "action": "GET", "url": obs,
                 "note": "etki oncesi sayac oku"},
                {"actor": identities[0], "action": (w.get("method") or "POST").upper(),
                 "url": wp, "note": "tek-kullanimlik degeri ilk uygula"},
                {"actor": identities[0], "action": "GET", "url": obs,
                 "note": "tek etkiyi kaydet (ara okuma)"},
                {"actor": identities[0], "action": (w.get("method") or "POST").upper(),
                 "url": wp, "note": "AYNI degeri ikinci kez uygula (replay)"},
                {"actor": identities[0], "action": "GET", "url": obs,
                 "note": "ikinci etki var mi?"},
            ],
            "oracle": "state_invariant",
            "decision": "ikinci uygulamada gozlemcide ek etki -> replay/double-spend CONFIRMED; etki tek -> UNCONFIRMED",
        })

    for w in writes[:6]:
        wp = _path(w)
        nums = [p for p in _params(w) if NUMERIC_PARAM_RE.search(p)]
        if not nums:
            continue
        obs = _nearest_reader(wp, gets) or wp
        out.append({
            "kind": "numeric_surface",
            "question": "Negatif/sifir sayisal yazim toplami dusurur mu?",
            "write_surface": wp, "numeric_params": nums[:3], "read_surface": obs,
            "steps": [
                {"actor": identities[0], "action": "GET", "url": obs,
                 "note": "toplam oku (once)"},
                {"actor": identities[0], "action": (w.get("method") or "POST").upper(),
                 "url": wp, "note": f"negatif deger yaz ({nums[0]}=-1)"},
                {"actor": identities[0], "action": "GET", "url": obs,
                 "note": "toplam dustu mu?"},
            ],
            "oracle": "state_invariant",
            "decision": "toplam azaldi/negatife dondu -> korunum ihlali CONFIRMED; degismedi -> UNCONFIRMED",
        })

    for w in writes[:4]:
        wp = _path(w)
        states = [p for p in _params(w) if STATE_PARAM_RE.search(p)]
        if not states:
            continue
        out.append({
            "kind": "state_transition",
            "question": "Ara adim atlanip son yazma dogrudan cagrilirsa durum beklenmeyen degere gecer mi?",
            "write_surface": wp, "state_params": states[:3],
            "steps": [
                {"actor": identities[0], "action": "GET", "url": wp,
                 "note": "mevcut durumu oku (once)"},
                {"actor": identities[0], "action": (w.get("method") or "POST").upper(),
                 "url": wp, "note": "onkoşul adimlari atla, son yazmayi dogrudan cagir"},
                {"actor": identities[0], "action": "GET", "url": wp,
                 "note": "durum izinsiz gecti mi?"},
            ],
            "oracle": "state_invariant",
            "decision": "durum onkoşulsuz degisti -> workflow bypass CONFIRMED; reddedildi -> UNCONFIRMED",
        })

    for w in writes[:4]:
        if not _is_register_surface(w):
            continue
        wp = _path(w)
        out.append({
            "kind": "registration_abuse",
            "question": "Tekrar kayit / asiri uzun e-posta / rol alani ayricalik uretir mi?",
            "write_surface": wp,
            "steps": [
                {"actor": identities[0], "action": (w.get("method") or "POST").upper(),
                 "url": wp, "note": "mevcut kullanici adiyla tekrar kayit dene (devralma?)"},
                {"actor": identities[0], "action": (w.get("method") or "POST").upper(),
                 "url": wp, "note": "300+ karakter e-posta: saklanan deger gonderilenle ayni mi? (kesilme)"},
                {"actor": identities[0], "action": (w.get("method") or "POST").upper(),
                 "url": wp, "note": "govdeye role/admin/is_admin ekle (yetki enjeksiyonu?)"},
            ],
            "oracle": "state_invariant",
            "decision": "tekrar kayit sifreyi degistirdi / kesilmis e-posta domain kurali gecti / rol alani saklandi -> CONFIRMED; hepsi reddedildi -> UNCONFIRMED",
        })
    return out


def _nearest_reader(write_path: str, gets: list[dict]) -> str:
    """Yazma yüzeyine yol akrabalığı en yakın GET gözlemcisi."""
    prefix = write_path.rsplit("/", 1)[0] if "/" in write_path else write_path
    for g in gets:
        gp = _path(g)
        if gp and (gp.startswith(prefix) or write_path.startswith(gp.rsplit("/", 1)[0])):
            return gp
    return ""
