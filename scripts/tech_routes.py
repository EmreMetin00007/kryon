"""Teknoloji-bilincli mini route kesif listesi (50-100 rota).

Link-takibi kor kalan rotalari (orn. nginx alias /files) kucuk ve hizli
bir wordlist ile yoklar. Prod-guvenli: varsayilan butce 50 istek
(CCO_FUZZ_BUDGET), lab'da yukseltilebilir.
"""
from __future__ import annotations

import os

# Siklik sirali taban liste (~40). Prod butcesi (50) icine sigar.
BASE_ROUTES = [
    "robots.txt", "sitemap.xml", ".git/HEAD", ".env",
    "admin", "login", "api", "static", "assets", "files",
    "uploads", "media", "images", "js", "css", "config",
    "backup", "test", "dev", "docs", "dashboard",
    "server-status", "v1", "v2", "health", "status",
    "graphql", "search", "user", "users", "account",
    "profile", "settings", "public", "data", "downloads",
    "includes", "tmp", "old", "console", "debug",
]

# Teknolojiye ozel ekler (~8-12'ser). Alias-somurulebilir rotalar dahil.
TECH_ROUTES = {
    "nginx": ["files", "data", "download", "export", "static",
              "media", "uploads", "backup", "stub_status", "nginx_status"],
    "apache": ["icons", "manual", "server-status", "server-info",
               "cgi-bin", "phpmyadmin", "webdav", "uploads"],
    "iis": ["aspnet_client", "iisstart", "trace.axd", "elmah.axd",
            "web.config", "admin", "exchange", "owa"],
    "php": ["phpinfo.php", "phpmyadmin", "adminer.php", "info.php",
            "test.php", "config.php", "wp-admin", "wp-login.php",
            "xmlrpc.php", "laravel.log"],
    "wordpress": ["wp-admin", "wp-login.php", "wp-content", "wp-json",
                  "xmlrpc.php", "readme.html", "license.txt"],
    "node": ["api", "graphql", "status", "health", "metrics",
             "debug", "console", ".env", "package.json"],
    "django": ["admin", "static", "media", ".env", "debug",
               "api", "graphql", "sitemap.xml"],
    "spring": ["actuator", "actuator/health", "actuator/env",
               "manager/html", "jmx-console", "api", "health"],
    "rails": ["rails/info", "admin", "api", "health", "status"],
    "dotnet": ["elmah.axd", "trace.axd", "web.config", "api",
               "swagger", "swagger.json", "health"],
    "go": ["debug/pprof", "metrics", "health", "api", "status"],
}

# Server/X-Powered-By alt-string -> teknoloji
SERVER_FINGERPRINTS = {
    "nginx": ["nginx"],
    "apache": ["apache"],
    "iis": ["iis", "microsoft-httpapi"],
    "php": ["php"],
    "node": ["express", "node"],
    "django": ["django", "gunicorn", "wsgi"],
    "spring": ["tomcat", "jetty", "spring"],
    "rails": ["rails", "phusion", "puma"],
    "dotnet": ["asp.net", "kestrel"],
    "go": ["go-http"],
}

# Body isaretleri -> teknoloji
BODY_FINGERPRINTS = {
    "wordpress": ["wp-content", "wp-includes", "wp-json"],
    "django": ["csrfmiddlewaretoken", "django"],
    "rails": ["csrf-param", "rails"],
    "spring": ["_csrf", "jsessionid"],
    "php": [".php", "laravel", "symfony"],
}

MAX_ROUTES = 100


def default_budget() -> int:
    try:
        return max(1, int(os.environ.get("CCO_FUZZ_BUDGET", "50")))
    except ValueError:
        return 50


def detect_tech(server: str = "", powered_by: str = "", body: str = "") -> list[str]:
    found: list[str] = []
    blob = f"{server}\n{powered_by}".lower()
    for tech, markers in SERVER_FINGERPRINTS.items():
        if any(m in blob for m in markers) and tech not in found:
            found.append(tech)
    bl = (body or "")[:20000].lower()
    for tech, markers in BODY_FINGERPRINTS.items():
        if any(m in bl for m in markers) and tech not in found:
            found.append(tech)
    return found


def build_wordlist(server: str = "", powered_by: str = "", body: str = "",
                   budget: int | None = None) -> tuple[list[str], list[str]]:
    """(wordlist, tespit_edilen_teknolojiler). Butceye gore kirpilir."""
    techs = detect_tech(server, powered_by, body)
    words: list[str] = list(BASE_ROUTES)
    for t in techs:
        for w in TECH_ROUTES.get(t, []):
            if w not in words:
                words.append(w)
    words = words[:MAX_ROUTES]
    cap = budget if budget is not None else default_budget()
    return words[:max(1, cap)], techs
