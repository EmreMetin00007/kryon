"""Request-level policy for disposable, read-only Playwright contexts."""
from __future__ import annotations

import json
import re
import time
from inspect import isawaitable
from urllib.parse import unquote, urljoin, urlsplit

_LOGIN_PATH = re.compile(r"/(?:login|signin|sign-in|sso|auth/login)\b", re.I)


def _login_path(url):
    path = urlsplit(url).path
    for _ in range(4):
        decoded = unquote(path)
        if decoded == path:
            break
        path = decoded
    return bool(_LOGIN_PATH.search(path))


class _RedirectGate:
    """Chromium bypasses Playwright routes on automatic redirect hops.

    Pause redirect responses before Chromium can follow Location. This avoids
    competing with Playwright's request-stage interception. Admit and charge
    the next hop before releasing its redirect response. Owned targets cover
    the context's pages, frames and popups; user contexts are not intercepted.
    """
    def __init__(self, context, admit, stop, observe=None):
        self.context, self.admit, self.stop = context, admit, stop
        self.observe = observe
        self.root = context.browser.new_browser_cdp_session()
        self.context_id = None
        self.sessions, self.targets, self.pending = {}, {}, {}
        self.ready, self.watched, self.after_ready = set(), set(), {}
        self.attaching = set()
        self.failed = False
        self.closed = False
        self.probe = None
        self.sequence = 0
        self.root.on("Target.receivedMessageFromTarget", self._message)
        self.root.on("Target.detachedFromTarget", self._detached)
        self.root.on("Target.attachedToTarget", self._attached)

    def prepare_page(self, page):
        if self.context_id is None:
            self.probe = self.context.new_cdp_session(page)
            self.context_id = self.probe.send("Target.getTargetInfo")["targetInfo"]["browserContextId"]
        self._prepare_targets()
        deadline = time.monotonic() + 5
        while set(self.targets) - self.ready:
            if self.failed or time.monotonic() >= deadline:
                raise RuntimeError("Chromium redirect interception did not initialize")
            page.wait_for_timeout(5)

    def prepare(self, request):
        if self.context_id is None:
            self.prepare_page(request.frame.page)
        else:
            self._prepare_targets()

    def _prepare_targets(self):
        infos = self.root.send("Target.getTargets")["targetInfos"]
        for info in infos:
            if info.get("browserContextId") == self.context_id and info.get("type") in {"page", "iframe"}:
                self._attach(info["targetId"])

    def _send(self, session_id, method, params=None, callback=None):
        self.sequence += 1
        self.pending[self.sequence] = (session_id, callback)
        self.root.send("Target.sendMessageToTarget", {"sessionId": session_id,
            "message": json.dumps({"id": self.sequence, "method": method, "params": params or {}})})

    def _attach(self, target, callback=None):
        if callback:
            if target in self.ready:
                callback()
            else:
                self.after_ready.setdefault(target, []).append(callback)
        if target in self.targets or target in self.attaching:
            return
        self.attaching.add(target)
        try:
            raw = self.root.send("Target.attachToTarget", {"targetId": target, "flatten": False})["sessionId"]
            self.sessions[raw], self.targets[target] = target, raw
            self._send(raw, "Fetch.enable", {"patterns": [{"urlPattern": "*", "requestStage": "Response"}]},
                       callback=lambda: self._mark_ready(target))
        finally:
            self.attaching.discard(target)

    def _mark_ready(self, target):
        self.ready.add(target)
        for callback in self.after_ready.pop(target, []):
            callback()
        if target not in self.watched:
            self.watched.add(target)
            self.root.send("Target.autoAttachRelated", {"targetId": target, "waitForDebuggerOnStart": True,
                "filter": [{"type": "page", "exclude": False}, {"type": "iframe", "exclude": False},
                           {"exclude": True}]})

    def _attached(self, event):
        info, flat = event["targetInfo"], event["sessionId"]
        if info.get("browserContextId") != self.context_id:
            self.root.send("Target.detachFromTarget", {"sessionId": flat})
            return
        target = info["targetId"]
        def resume():
            self._send(self.targets[target], "Runtime.runIfWaitingForDebugger")
            self.root.send("Target.detachFromTarget", {"sessionId": flat})
        try:
            self._attach(target, resume if event.get("waitingForDebugger") else None)
        except Exception:
            self.failed = True
            self.stop("interception_unavailable")

    def _detached(self, event):
        session_id = event["sessionId"]
        target = self.sessions.pop(session_id, None)
        if target is not None:
            self.targets.pop(target, None)
            self.ready.discard(target)
            self.after_ready.pop(target, None)
        self.pending = {key: value for key, value in self.pending.items() if value[0] != session_id}

    def _message(self, event):
        session_id = event["sessionId"]
        if session_id not in self.sessions:
            return
        try:
            message = json.loads(event["message"])
            if "id" in message:
                command = self.pending.pop(message["id"], None)
                if "error" in message:
                    self.failed = True
                    self.stop("interception_unavailable")
                elif command and command[1]:
                    command[1]()
            elif message.get("method") == "Fetch.requestPaused":
                self._paused(session_id, message["params"])
        except Exception:
            self.failed = True
            self.stop("interception_unavailable")

    def _paused(self, session_id, event):
        request_id = event["requestId"]
        try:
            request = event["request"]
            status = event.get("responseStatusCode")
            headers = {h["name"].lower(): h["value"] for h in event.get("responseHeaders") or []}
            location = headers.get("location") or ""
            if self.observe:
                self.observe(request['url'], status, location)
            elif status in {401, 429}:
                self.stop(f"http_{status}")
            if status not in {301, 302, 303, 307, 308} or not location:
                self._send(session_id, "Fetch.continueResponse", {"requestId": request_id})
                return
            url = urljoin(request["url"], location)
            if _login_path(url):
                if not self.observe:
                    self.stop("login_redirect")
                headers = None
            else:
                headers = self.admit(url, request["method"], request.get("headers") or {})
            if headers is None:
                self._send(session_id, "Fetch.failRequest", {"requestId": request_id, "errorReason": "BlockedByClient"})
            else:
                self._send(session_id, "Fetch.continueResponse", {"requestId": request_id})
        except Exception:
            self.stop("interception_unavailable")
            try:
                self._send(session_id, "Fetch.failRequest", {"requestId": request_id, "errorReason": "BlockedByClient"})
            except Exception:
                pass  # A closed target cannot send another request.

    def close(self):
        if self.closed:
            return
        self.closed = True
        for session in (self.probe, self.root):
            if session is not None:
                try:
                    session.detach()
                except Exception:
                    pass  # The owning browser/context may already be closed.


def install_readonly_request_gate(context, engine, tool_name, header_provider=None, request_filter=None,
                                  on_stop=None, wire_gate=None, stop_on_denial=False, auth_boundary=None) -> dict:
    """Abort denied requests before they leave the browser context.

    Service workers must be disabled by the caller. WebSockets are blocked
    here because they do not use the HTTP wire-gate contract.
    """
    state = {"stopped": False, "reason": ""}

    def deny(reason):
        if stop_on_denial:
            stop(reason)
        return None

    def admit(url, method, headers):
        try:
            method = str(method or "").upper()
            if state["stopped"] or (auth_boundary and auth_boundary.pending) or method not in {"GET", "HEAD", "OPTIONS"}:
                return deny("request_method_denied")
            url = str(url or "")
            if request_filter and not request_filter(url, headers):
                return deny("request_origin_denied")
            current_tool = tool_name() if callable(tool_name) else tool_name
            if not isinstance(current_tool, str) or not current_tool.strip():
                return deny("tool_unavailable")
            extra_headers = header_provider(url) if header_provider else {}
            if not isinstance(extra_headers, dict):
                return deny("headers_unavailable")
            merged = dict(headers)
            for key, value in extra_headers.items():
                if not any(str(existing).lower() == str(key).lower() for existing in merged):
                    merged[str(key)] = str(value)
            if wire_gate is not None:
                # The inherited gate owns scope, grants, freshness and budget.
                # Calling consume_request again would charge each request twice.
                allowed, reason = wire_gate(method, url, merged)
            else:
                decision = engine.validate_wire_invocation(current_tool, {
                    "target": url, "url": url, "method": method, "headers": merged})
                if not decision.get("allowed"):
                    return deny("policy_denied")
                from wire_budget import consume_request
                allowed, reason = consume_request(engine)
            if not allowed:
                stop(reason)
                return None
        except Exception:
            return deny("policy_unavailable")
        return merged

    def on_request(route):
        try:
            request = route.request
            redirects.prepare(request)
            headers = admit(request.url, request.method, request.all_headers())
            if headers is None:
                route.abort("blockedbyclient")
                return
        except Exception:
            stop("interception_unavailable")
            route.abort("blockedbyclient")
            return
        if header_provider:
            route.continue_(headers=headers)
        else:
            route.continue_()

    async def on_websocket(socket):
        # Playwright dispatches WebSocket routes on its asyncio loop, including
        # the Sync API. Await the route coroutine without reentering its sync bridge.
        if stop_on_denial:
            stop("websocket_denied")
        route = getattr(socket, "_impl_obj", socket)
        closing = route.close(code=1008, reason="browser policy: websocket disabled")
        if isawaitable(closing):
            await closing

    def stop(reason):
        if state["stopped"]:
            return
        state["stopped"] = True
        state["reason"] = reason
        if on_stop:
            try:
                on_stop(reason)
            except Exception:
                # The local session store must never weaken the request gate.
                pass

    def on_response(response):
        try:
            status = int(response.status)
            headers = response.headers or {}
            location = headers.get("location") or headers.get("Location") or ""
            if auth_boundary:
                observe(response.url, status, location)
            elif status in {401, 429}:
                stop(f"http_{status}")
            elif status in {301, 302, 303, 307, 308} and location and _login_path(urljoin(response.url, location)):
                stop("login_redirect")
        except Exception:
            stop("response_unavailable")

    def observe(url, status, location):
        reason = auth_boundary.observe(url, status, location)
        if reason:
            stop(reason)

    # Missing interception support must fail before navigation starts.
    if not callable(getattr(context, "new_cdp_session", None)):
        raise AttributeError("Chromium CDP redirect interception is required")
    redirects = _RedirectGate(context, admit, stop, observe if auth_boundary else None)

    create_page = context.new_page
    def new_page(*args, **kwargs):
        page = create_page(*args, **kwargs)
        try:
            redirects.prepare_page(page)
        except Exception:
            stop("interception_unavailable")
            raise
        return page

    # The page event is asynchronous relative to new_page's return. Prepare
    # interception before callers can navigate the returned owned page.
    context.new_page = new_page

    close_context = context.close
    def close(*args, **kwargs):
        try:
            return close_context(*args, **kwargs)
        finally:
            redirects.close()

    # Cleanup runs after the Sync API close call returns, outside the context
    # close event's asyncio callback and before the owning driver stops.
    context.close = close
    for page in context.pages:
        redirects.prepare_page(page)
    context.on("response", on_response)
    context.route_web_socket("**/*", on_websocket)
    context.route("**/*", on_request)
    return state
