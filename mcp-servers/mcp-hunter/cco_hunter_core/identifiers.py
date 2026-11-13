"""Kimlik cikarma (blind-01 kural 2: BOLA UUID tuzagi).

HTTP yanit govdelerinden test edilebilir kimlikleri toplar: UUID, sayisal ID,
hesap kodu, e-posta, JWT-benzeri token. Saf fonksiyon — ag cagrisi yok.
"""
import re

_UUID_RE = re.compile(
    r"\b[0-9a-fA-F]{8}-[0-9a-fA-F]{4}-[0-9a-fA-F]{4}-[0-9a-fA-F]{4}-[0-9a-fA-F]{12}\b"
)
_ACCT_RE = re.compile(r"\b[A-Z]{2,6}-[A-Z0-9]{2,6}(?:-[A-Z0-9]{2,8})?\b")
_EMAIL_RE = re.compile(r"\b[A-Za-z0-9._%+-]+@[A-Za-z0-9.-]+\.[A-Za-z]{2,}\b")
_JWT_RE = re.compile(r"\beyJ[A-Za-z0-9_-]{10,}\.[A-Za-z0-9_-]{10,}(?:\.[A-Za-z0-9_-]{10,})?\b")
_NUMID_RE = re.compile(r'"(?:id|user_id|account_id|order_id|invoice_id|tenant_id)"\s*:\s*"?(\d{2,12})"?')
_URL_RE = re.compile(r"https?://[^\s\"'<>]+")
_CLIENT_ID_RE = re.compile(
    r"(?:client_id|clientId|CLIENT_ID|data-client-id)\s*[:=]\s*[\"']([^\"']{1,80})[\"']"
)
_API_PATH_RE = re.compile(
    r"[\"'`](/(?:api|oauth|auth|graphql|v\d+)(?:/[A-Za-z0-9_\-{}.]+)+)[\"'`]?"
)
_SECRET_HINT_RE = re.compile(
    r"(?:api[_-]?key|apikey|client[_-]?secret|MAPS_API_KEY)\s*[:=]\s*[\"']([^\"']{4,100})[\"']",
    re.IGNORECASE,
)

_MASS_NOISE = {"00000000-0000-0000-0000-000000000000"}


def extract_identifiers(text):
    """Metinden kimlik adaylarini cikar; sinifli dict doner.

    Args:
        text: Ham yanit govdesi / log parcasi (str; None/boş kabul edilir).

    Returns:
        dict: {uuids, numeric_ids, account_ids, emails, jwt_like, urls,
        client_ids, api_paths, secret_hints} — her biri sirali unique liste.
        Bos girdi -> bos listeler.
    """
    empty = {"uuids": [], "numeric_ids": [], "account_ids": [],
             "emails": [], "jwt_like": [], "urls": [],
             "client_ids": [], "api_paths": [], "secret_hints": []}
    if not text or not isinstance(text, str):
        return empty
    uuids = sorted({u for u in _UUID_RE.findall(text) if u not in _MASS_NOISE})
    return {
        "uuids": uuids,
        "numeric_ids": sorted(set(_NUMID_RE.findall(text))),
        "account_ids": sorted(set(_ACCT_RE.findall(text))),
        "emails": sorted(set(_EMAIL_RE.findall(text))),
        "jwt_like": sorted(set(_JWT_RE.findall(text))),
        "urls": sorted(set(_URL_RE.findall(text)))[:50],
        "client_ids": sorted(set(_CLIENT_ID_RE.findall(text))),
        "api_paths": sorted(set(_API_PATH_RE.findall(text)))[:50],
        "secret_hints": sorted(set(_SECRET_HINT_RE.findall(text)))[:20],
    }
