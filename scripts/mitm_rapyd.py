"""mitmproxy eklentisi: Rapyd merchants-portal trafiğini kaydet + route envanteri çıkar.

Çalıştırma:
  mitmdump -s scripts/mitm_rapyd.py --listen-port 8080 -q

Çıktılar (repo DIŞI, secret sızmasın):
  /root/.cco/rapyd-traffic.jsonl   — ham istek/yanıt özeti
  /root/.cco/rapyd-routes-live.json — gözlenen route envanteri
"""
import json
from pathlib import Path

CCO = Path("/root/.cco")
TRAFFIC = CCO / "rapyd-traffic.jsonl"
ROUTES = CCO / "rapyd-routes-live.json"

WATCH_HOSTS = ("dashboard.rapyd.net", "m.dashboard.rapyd.net")

_redact = {"token", "fingerprint", "authorization", "cookie", "set-cookie"}


def _clean(headers) -> dict:
    return {k: ("<redacted>" if k.lower() in _redact else v)
            for k, v in headers.items()}


def load_routes() -> dict:
    if ROUTES.exists():
        try:
            return json.loads(ROUTES.read_text())
        except ValueError:
            pass
    return {}


def save_routes(routes: dict) -> None:
    ROUTES.write_text(json.dumps(routes, indent=1, sort_keys=True))


class RapydLogger:
    def __init__(self) -> None:
        self.routes = load_routes()

    def response(self, flow) -> None:  # noqa: ANN001
        host = flow.request.host
        if host not in WATCH_HOSTS:
            return
        if "/merchants-portal/" not in flow.request.path:
            return
        key = f"{flow.request.method} {flow.request.path.split('?')[0]}"
        entry = self.routes.get(key, {"count": 0, "statuses": {}})
        entry["count"] += 1
        st = str(flow.response.status_code)
        entry["statuses"][st] = entry["statuses"].get(st, 0) + 1
        if "?" in flow.request.path:
            entry["sample_query"] = flow.request.path.split("?", 1)[1][:300]
        self.routes[key] = entry
        save_routes(self.routes)
        rec = {"method": flow.request.method, "url": flow.request.pretty_url,
               "status": flow.response.status_code,
               "req_headers": _clean(flow.request.headers),
               "req_body": flow.request.text[:2000] if flow.request.text else "",
               "resp_body": flow.response.text[:2000] if flow.response.text else ""}
        with TRAFFIC.open("a") as f:
            f.write(json.dumps(rec) + "\n")


addons = [RapydLogger()]
