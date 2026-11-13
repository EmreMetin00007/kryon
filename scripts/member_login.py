"""Bounded ordinary-member demo login with encrypted, reference-only sessions."""
from __future__ import annotations

from dataclasses import dataclass, field
import fcntl
from html.parser import HTMLParser
import json
import os
from pathlib import Path
import re
import tempfile
import time
from urllib.parse import parse_qsl, unquote, urlencode, urljoin, urlsplit, urlunsplit

import requests

from policy_engine import PolicyEngine, ScopeResolver

TOOL = "kali-tools_member_login"
_PRIVILEGED = re.compile(r"\b(?:admin|administrator|root|superuser)\b", re.I)
_MUTATING = re.compile(r"/(?:logout|signout|delete|remove|destroy|reset|revoke|update|create|register)(?:/|$)", re.I)
_ACCOUNT_FIELDS = {"user", "username", "identity", "account", "role", "as", "persona", "actor", "who", "user_id"}


class LoginStopped(Exception):
    pass


def _origin(url):
    p = urlsplit(url)
    if p.scheme not in {"http", "https"} or not p.hostname or p.username is not None:
        raise LoginStopped("invalid_origin")
    return p.scheme, p.hostname.lower(), p.port or (443 if p.scheme == "https" else 80)


def _normal(value):
    return re.sub(r"[^a-z0-9]", "", str(value).lower())


def _readonly(url, target):
    if _origin(url) != _origin(target):
        raise LoginStopped("cross_origin_redirect")
    p = urlsplit(url)
    path = p.path
    for _ in range(5):
        path = unquote(path)
    if (p.query or p.fragment or _MUTATING.search(path)
            or re.search(r"/(?:admin|administrator|superuser)(?:/|$)", path, re.I)
            or re.search(r"[%;\r\n\x00]", path)):
        raise LoginStopped("unsafe_profile_url")
    return url


def _pace(home):
    """Share the 2 rps ceiling across concurrent member tool calls."""
    path = Path(home) / "member-wire-clock"
    path.parent.mkdir(parents=True, exist_ok=True)
    fd = os.open(path, os.O_CREAT | os.O_RDWR | os.O_NOFOLLOW, 0o600)
    with os.fdopen(fd, "r+") as handle:
        fcntl.flock(handle, fcntl.LOCK_EX)
        raw = handle.read()
        previous = float(raw) if raw else 0.0
        current = time.monotonic()
        if previous > current + 5 or previous < 0:
            previous = 0.0
        time.sleep(max(0.0, min(0.5, previous + 0.5 - current)))
        handle.seek(0)
        handle.truncate()
        handle.write(str(time.monotonic()))
        handle.flush()


@dataclass
class _Form:
    action: str
    method: str
    inputs: list = field(default_factory=list)
    options: list = field(default_factory=list)


class _AuthHTML(HTMLParser):
    def __init__(self, text):
        super().__init__(convert_charrefs=True)
        self.forms, self.links = [], []
        self.form = self.select = self.option = self.link = self.button = None
        self.roles = []
        self.feed(text)
        self.close()

    def handle_starttag(self, tag, attrs):
        attrs = dict(attrs)
        if tag == "form":
            self.form = _Form(attrs.get("action", ""), attrs.get("method", "GET").upper())
        elif tag == "input" and self.form is not None:
            self.form.inputs.append(attrs)
        elif tag == "button" and self.form is not None and attrs.get("name"):
            self.button = {**attrs, "text": ""}
        elif tag == "select" and self.form is not None:
            self.select = attrs.get("name", "")
        elif tag == "option" and self.form is not None and self.select:
            self.option = {**attrs, "name": self.select, "text": ""}
        elif tag == "a" and attrs.get("href"):
            self.link = {**attrs, "text": ""}
        elif tag == "meta" and attrs.get("name", "").lower() in {"user-role", "current-role", "account-role"}:
            self.roles.append(attrs.get("content", ""))

    def handle_data(self, data):
        if self.option is not None:
            self.option["text"] += data
        if self.link is not None:
            self.link["text"] += data
        if self.button is not None:
            self.button["text"] += data

    def handle_endtag(self, tag):
        if tag == "option" and self.option is not None and self.form is not None:
            self.form.options.append(self.option)
            self.option = None
        elif tag == "select":
            self.select = self.option = None
        elif tag == "form" and self.form is not None:
            self.forms.append(self.form)
            self.form = self.select = self.option = None
        elif tag == "button" and self.button is not None and self.form is not None:
            self.form.inputs.append(self.button)
            self.button = None
        elif tag == "a" and self.link is not None:
            self.links.append(self.link)
            self.link = None


def published_flow(text, page_url, login_url, identity):
    """Select an exact published account; never synthesize credentials or roles."""
    document = _AuthHTML(text)
    wanted = _normal(identity)
    flows, password_form = [], False
    for form in document.forms:
        if urljoin(page_url, form.action) != login_url or form.method not in {"GET", "POST"}:
            continue
        if any(item.get("type", "").lower() == "password" for item in form.inputs):
            password_form = True
            continue
        selected = []
        for item in [*form.options, *form.inputs]:
            value, label = item.get("value", ""), item.get("text", "").strip()
            if wanted not in {_normal(value), _normal(label)}:
                continue
            if _PRIVILEGED.search(" ".join(str(item.get(k, "")) for k in ["value", "text", "data-role"])):
                continue
            name = item.get("name", "")
            if (re.fullmatch(r"[A-Za-z][A-Za-z0-9_.-]{0,63}", name)
                    and isinstance(value, str) and 0 < len(value) <= 256):
                selected.append((name, value, [value, label, identity]))
        unique = {(name, value) for name, value, _ in selected}
        if len(unique) != 1:
            continue
        name, value, markers = selected[0]
        data = {name: value}
        for item in form.inputs:
            key = item.get("name", "")
            if (item.get("type", "").lower() == "hidden" and key != name
                    and re.search(r"csrf|nonce|token", key, re.I)
                    and re.fullmatch(r"[A-Za-z][A-Za-z0-9_.-]{0,63}", key)):
                hidden = item.get("value", "")
                if len(hidden) > 4096:
                    raise LoginStopped("invalid_login_form")
                data[key] = hidden
        if len(data) > 9 or sum(len(value) for value in data.values()) > 8192:
            raise LoginStopped("invalid_login_form")
        flows.append((form.method, login_url, data, markers))
    for link in document.links:
        href = urljoin(page_url, link["href"])
        parsed = urlsplit(href)
        base = urlunsplit((parsed.scheme, parsed.netloc, parsed.path, "", ""))
        if base != login_url or parsed.fragment:
            continue
        pairs = parse_qsl(parsed.query, keep_blank_values=True)
        if len(pairs) != 1 or pairs[0][0].lower() not in _ACCOUNT_FIELDS:
            continue
        value, label = pairs[0][1], link.get("text", "").strip()
        if (len(value) > 256 or wanted not in {_normal(value), _normal(label)}
                or _PRIVILEGED.search(" ".join([value, label, link.get("data-role", "")]))):
            continue
        flows.append(("GET", href, {}, [value, label, identity]))
    unique = {(method, url, json.dumps(data, sort_keys=True)): (method, url, data, markers)
              for method, url, data, markers in flows}
    if len(unique) == 1:
        return next(iter(unique.values()))
    if len(unique) > 1:
        raise LoginStopped("ambiguous_member_login")
    if password_form:
        raise LoginStopped("credentials_required")
    raise LoginStopped("published_member_login_missing")


def _privileged_profile(text):
    roles = list(_AuthHTML(text).roles)
    try:
        document = json.loads(text)
        if isinstance(document, dict):
            roles.append(document.get("role", ""))
            if isinstance(document.get("user"), dict):
                roles.append(document["user"].get("role", ""))
    except ValueError:
        pass
    return any(isinstance(role, str) and _PRIVILEGED.search(role) for role in roles)


class _Wire:
    def __init__(self, engine, target):
        self.engine, self.target = engine, target
        self.auth, self.anon = requests.Session(), requests.Session()
        self.count = 0
        self.headers = {"User-Agent": "CCO-Member-Login/1.0", **engine.program_policy.get("required_request_headers", {})}

    def request(self, method, url, *, data=None, headers=None, anonymous=False):
        if self.count >= 8:
            raise LoginStopped("request_budget_exhausted")
        if _origin(url) != _origin(self.target):
            raise LoginStopped("cross_origin_request")
        client = self.anon if anonymous else self.auth
        prepared = client.prepare_request(requests.Request(method, url, data=data, headers={**self.headers, **(headers or {})}))
        if _origin(prepared.url) != _origin(self.target):
            raise LoginStopped("cross_origin_prepared_request")
        decision = self.engine.validate_wire_invocation(TOOL, {
            "target": prepared.url, "url": prepared.url, "method": method,
            "headers": dict(prepared.headers),
        })
        if not decision.get("allowed"):
            raise LoginStopped("policy:" + decision.get("reason", "denied"))
        _pace(self.engine.cco_home)
        self.count += 1
        response = client.send(prepared, timeout=15, allow_redirects=False, stream=True)
        try:
            if response.status_code == 429 or response.status_code >= 500:
                raise LoginStopped("service_stop_http_" + str(response.status_code))
            chunks, length = [], 0
            for chunk in response.iter_content(16384):
                length += len(chunk)
                if length > 524288:
                    raise LoginStopped("response_budget_exhausted")
                chunks.append(chunk)
            body = b"".join(chunks).decode(response.encoding or "utf-8", errors="replace")
            return response.status_code, body, dict(response.headers)
        finally:
            response.close()

    def close(self):
        self.auth.close()
        self.anon.close()


def _claim_login(home, target, identity):
    path = Path(home) / "member-login-attempts.json"
    path.parent.mkdir(parents=True, exist_ok=True)
    descriptor = os.open(path.with_suffix(".lock"), os.O_CREAT | os.O_RDWR | os.O_NOFOLLOW, 0o600)
    temporary = None
    try:
        fcntl.flock(descriptor, fcntl.LOCK_EX)
        state = json.loads(path.read_text()) if path.exists() else {}
        key = target + "::" + identity
        if state.get(key):
            raise LoginStopped("login_attempt_budget_exhausted")
        state[key] = True
        with tempfile.NamedTemporaryFile(mode="w", dir=path.parent, delete=False) as handle:
            temporary = Path(handle.name)
            os.fchmod(handle.fileno(), 0o600)
            json.dump(state, handle)
            handle.flush()
            os.fsync(handle.fileno())
        os.replace(temporary, path)
    finally:
        if temporary is not None:
            temporary.unlink(missing_ok=True)
        os.close(descriptor)


def login_member(target, identity):
    wire = None
    try:
        engine = PolicyEngine()
        rule = engine.program_policy.get("member_login") or {}
        if rule.get("test_data_only") is not True or identity not in rule.get("accounts", []):
            raise LoginStopped("member_login_not_enabled_for_identity")
        parsed = urlsplit(target)
        login_url = rule["login_url"]
        if (parsed.path not in {"", "/"} or parsed.query or parsed.fragment
                or _origin(target) != _origin(login_url) or not ScopeResolver().permits_url(target)):
            raise LoginStopped("invalid_member_login_target")
        if _PRIVILEGED.search(identity):
            raise LoginStopped("privileged_identity_denied")
        surface_path = Path(__file__).resolve().parents[1] / "mcp-servers/mcp-memory-server"
        import sys
        if str(surface_path) not in sys.path:
            sys.path.insert(0, str(surface_path))
        from cco_surface_core import session_store
        wire = _Wire(engine, target)
        existing = session_store.get_session(target, identity)
        check_stop = None
        def check(url, headers, cookies):
            nonlocal check_stop
            _readonly(url, target)
            headers = dict(headers)
            if cookies:
                headers["Cookie"] = "; ".join(f"{key}={value}" for key, value in cookies.items())
            status, body, _ = wire.request("GET", url, headers=headers)
            if _privileged_profile(body):
                check_stop = "privileged_session_denied"
                raise LoginStopped(check_stop)
            return status, body
        if existing:
            refreshed = session_store.refresh_status(target, identity, check)
            if check_stop:
                raise LoginStopped(check_stop)
            if refreshed.get("status") == "fresh":
                return {"ok": True, "status": "fresh", "identity": identity,
                        "session": refreshed, "actual_requests": wire.count, "security_finding": False}
        status, root_body, _ = wire.request("GET", target.rstrip("/") + "/")
        if status != 200:
            raise LoginStopped("public_root_unavailable")
        page_url = target.rstrip("/") + "/"
        try:
            method, url, data, markers = published_flow(root_body, page_url, login_url, identity)
        except LoginStopped as missing:
            if missing.args[0] != "published_member_login_missing":
                raise
            if not any(urljoin(page_url, link["href"]) == login_url for link in _AuthHTML(root_body).links):
                raise
            status, login_body, _ = wire.request("GET", login_url)
            if status != 200:
                raise LoginStopped("published_login_page_unavailable")
            method, url, data, markers = published_flow(login_body, login_url, login_url, identity)
        _claim_login(engine.cco_home, target, identity)
        if method == "GET" and data:
            url += "?" + urlencode(data)
        status, body, response_headers = wire.request(method, url, data=data if method == "POST" else None)
        if status in {301, 302, 303, 307, 308}:
            profile = _readonly(urljoin(url, response_headers.get("Location", "")), target)
            if profile == login_url:
                raise LoginStopped("login_rejected")
        elif status == 200:
            candidates = [urljoin(url, link["href"]) for link in _AuthHTML(body).links
                          if re.search(r"/(?:dashboard|profile|me)$", urlsplit(urljoin(url, link["href"])).path)]
            if len(set(candidates)) != 1:
                raise LoginStopped("private_profile_link_missing")
            profile = _readonly(candidates[0], target)
        else:
            raise LoginStopped("login_http_" + str(status))
        status, profile_body, _ = wire.request("GET", profile)
        if status != 200:
            raise LoginStopped("profile_not_authenticated")
        if _privileged_profile(profile_body):
            raise LoginStopped("privileged_session_denied")
        marker = next((value for value in markers if len(value) >= 3 and value in profile_body), None)
        if not marker:
            raise LoginStopped("account_marker_missing")
        anonymous_status, anonymous_body, _ = wire.request("GET", profile, anonymous=True)
        if anonymous_status == 200 and marker in anonymous_body:
            raise LoginStopped("profile_check_not_private")
        prepared = wire.auth.prepare_request(requests.Request("GET", profile))
        cookie = prepared.headers.get("Cookie", "")
        if not cookie:
            raise LoginStopped("login_cookie_missing")
        session_store.put_session(target, identity, headers={"Cookie": cookie}, check_url=profile, marker=marker)
        checked = session_store.refresh_status(target, identity, check)
        if check_stop:
            raise LoginStopped(check_stop)
        return {"ok": checked.get("status") == "fresh", "status": checked.get("status"),
                "identity": identity, "login_method": method, "login_path": urlsplit(login_url).path,
                "check_path": urlsplit(profile).path, "session": checked,
                "actual_requests": wire.count, "security_finding": False}
    except LoginStopped as stop:
        return {"ok": False, "status": "incomplete", "reason": stop.args[0],
                "actual_requests": wire.count if wire else 0, "security_finding": False}
    except requests.RequestException:
        return {"ok": False, "status": "incomplete", "reason": "transport_failed",
                "actual_requests": wire.count if wire else 0, "security_finding": False}
    except (ValueError, OSError, KeyError):
        return {"ok": False, "status": "incomplete", "reason": "member_login_state_unavailable",
                "actual_requests": wire.count if wire else 0, "security_finding": False}
    finally:
        if wire is not None:
            wire.close()
