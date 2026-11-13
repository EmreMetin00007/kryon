"""Small LLM discovery loop over the existing security core.

Flow: observation -> LLM-chosen request -> tool result -> next decision.
Scope, budgets and evidence accounting are host-side; test order and
candidates are chosen by the model. The model carries an explicit
research state (facts, identity-object relations, open hypotheses,
tried controls, next discriminating experiment) that the host persists
verbatim and re-injects each turn. A no-progress brake and a closing
reserve guarantee a partial report instead of a silent budget death.
"""
from __future__ import annotations

import hashlib
import json
import os
import sys
import time
import urllib.error
import urllib.request
from pathlib import Path

sys.path.insert(0, str(Path(__file__).resolve().parent))

from discovery_executor import LabExecutor  # noqa: E402
from full_agent_budget import BudgetError, FRAMING_TOKENS, SharedBudget, prompt_bound  # noqa: E402

TOOLS = [
    {"type": "function", "name": "fetch_route",
     "description": "Fetch a route on the local web service. Use method POST with a JSON body when the route requires it. Pass the session value in the session field after signing in.",
     "parameters": {"type": "object", "properties": {
         "path": {"type": "string", "description": "Path and query string starting with /"},
         "method": {"type": "string", "enum": ["GET", "POST"]},
         "session": {"type": "string", "description": "Session value obtained from the sign-in flow, if any"},
         "body": {"type": "object", "additionalProperties": True, "description": "JSON object body for POST requests"}},
        "required": ["path"], "additionalProperties": False}},
    {"type": "function", "name": "update_research_state",
     "description": "Record your current research state. The host stores it verbatim and returns it to you next turn. Keep it current: observed facts, which identities own which objects, open hypotheses, controls already tried, and the next experiment that would discriminate between hypotheses.",
     "parameters": {"type": "object", "properties": {
         "observed_facts": {"type": "array", "items": {"type": "string"}},
         "identity_object_map": {"type": "object", "additionalProperties": True},
         "open_hypotheses": {"type": "array", "items": {"type": "string"}},
         "tried_controls": {"type": "array", "items": {"type": "string"}},
         "next_experiment": {"type": "string"}},
        "required": [], "additionalProperties": False}},
    {"type": "function", "name": "submit_analysis_summary",
     "description": "Submit the final summary when the assessment is complete.",
     "parameters": {"type": "object", "properties": {
         "detected_differences": {"type": "array", "items": {"type": "object", "properties": {
             "endpoint": {"type": "string"},
             "family": {"type": "string", "enum": ["access_control", "query_handling", "template_eval", "file_path", "xss", "csrf", "ssrf", "auth_bypass", "open_redirect", "business_logic", "other"]},
             "observation": {"type": "string"}}, "required": ["endpoint", "family", "observation"]}},
         "confirmed_matches": {"type": "array", "items": {"type": "string"}}},
        "required": ["detected_differences", "confirmed_matches"], "additionalProperties": False}},
]

INSTRUCTIONS = (
    "You are an autonomous security assessment assistant working on an authorized local test service. "
    "Start by calling fetch_route on / to discover the service surface, including any linked assets. "
    "Assess the discovered routes for security weaknesses, using the methods, inputs and any test accounts "
    "or session flow the service provides, as you judge appropriate. Keep your research state updated with "
    "update_research_state: observed facts, which identities own which objects, open hypotheses, controls "
    "already tried, and the next discriminating experiment. Distinguish behavior that looks vulnerable from "
    "behavior that looks correctly defended, and gather concrete evidence for each claim. When you have "
    "covered the discovered surface, call submit_analysis_summary with your findings."
)

CLOSURE_INSTRUCTIONS = (
    "The discovery phase is over. Submit your final assessment now with submit_analysis_summary. "
    "Use the recorded research notes and selected request/response evidence below. Research notes are "
    "not independent proof; confirm claims only with concrete evidence. Treat omitted or truncated "
    "evidence and untried experiments as coverage limits. Put ordinary behavioral comparisons under "
    "family other and keep unsupported hypotheses unconfirmed. Be concise. No further requests or "
    "research-state updates are permitted in this closing call."
)


def responses_transport(api_key: str, model: str, base_url: str = "https://agentrouter.org/v1/responses"):
    """Real provider transport (Responses API). Returns a callable."""
    def call(body: dict) -> dict:
        headers = {"Authorization": f"Bearer {api_key}", "Content-Type": "application/json",
                   "Originator": "codex_cli_rs", "Version": "0.101.0", "User-Agent": "codex_cli_rs/0.101.0"}
        req = urllib.request.Request(base_url, data=json.dumps(body).encode(), headers=headers, method="POST")
        with urllib.request.urlopen(req, timeout=180) as resp:
            payload = json.loads(resp.read().decode())
        texts, calls = [], []
        for item in payload.get("output", []):
            if item.get("type") == "message":
                for c in item.get("content", []):
                    if c.get("type") in ("output_text", "text"):
                        texts.append(c.get("text", ""))
            elif item.get("type") == "function_call":
                calls.append({"call_id": item.get("call_id"), "name": item.get("name"),
                              "arguments": item.get("arguments")})
        return {"usage": payload.get("usage", {}), "text": "\n".join(texts).strip(), "function_calls": calls,
                "response_id": payload.get("id"), "response_model": payload.get("model"),
                "response_status": payload.get("status"), "incomplete_details": payload.get("incomplete_details")}
    return call


def call_with_retry(transport, body, label="call", attempts=5):
    delays = (5, 20, 45, 75, 75)
    for attempt in range(attempts):
        try:
            return transport(body)
        except urllib.error.HTTPError as exc:
            exc.read()
            if exc.code not in (429, 500, 502, 503, 504) or attempt == attempts - 1:
                raise
        except Exception:
            if attempt == attempts - 1:
                raise
        time.sleep(delays[attempt])


class DiscoveryLoop:
    def __init__(self, lab_base: str, transport, *, model: str = "gpt-6.1-sol",
                 http_budget: int = 120, token_budget: int = 120_000, max_turns: int = 18,
                 brake_window: int = 4, output_limit: int = 1500, brake_mode: str = "novelty",
                 closure_prompt_limit: int = 12_000, closure_output_tokens: int = 8192,
                 closure_reasoning_effort: str | None = "low"):
        if brake_mode not in ("novelty", "hypothesis"):
            raise ValueError(f"unknown brake_mode: {brake_mode}")
        if type(closure_prompt_limit) is not int or closure_prompt_limit <= 0:
            raise ValueError("closure_prompt_limit must be a positive byte limit")
        if type(closure_output_tokens) is not int or closure_output_tokens < 16:
            raise ValueError("closure_output_tokens must be at least 16")
        if type(max_turns) is not int or max_turns <= 0:
            raise ValueError("max_turns must be a positive integer")
        if closure_reasoning_effort not in (None, "low", "medium", "high"):
            raise ValueError("unsupported closure_reasoning_effort")
        self.lab_base = lab_base.rstrip("/")
        self.transport = transport
        self.model = model
        self.budget = SharedBudget(http=http_budget, tokens=token_budget, seconds=1800)
        self.executor = LabExecutor(self.lab_base, self.budget)
        self.max_turns = max_turns
        self.brake_window = brake_window
        self.brake_mode = brake_mode
        self.output_limit = output_limit
        self.closure_prompt_limit = closure_prompt_limit
        self.closure_output_tokens = closure_output_tokens
        self.closure_reasoning_effort = closure_reasoning_effort
        # prompt_bound never exceeds wire bytes + framing. Protect this
        # worst-case compact prompt and bounded output before discovery starts.
        self.closure_reserve_tokens = closure_prompt_limit + FRAMING_TOKENS + closure_output_tokens
        self.closure_request: dict | None = None
        self.closure_error: dict | None = None
        self.settings = {"model": model, "http_budget": http_budget, "token_budget": token_budget,
                         "max_turns": max_turns, "brake_window": brake_window, "brake_mode": brake_mode,
                         "closure_mode": "compact_forced_reserved",
                         "closure_prompt_limit": closure_prompt_limit,
                         "closure_output_tokens": closure_output_tokens,
                         "closure_reasoning_effort": closure_reasoning_effort,
                         "closure_reserve_tokens": self.closure_reserve_tokens,
                         "closure_instructions_sha256": hashlib.sha256(CLOSURE_INSTRUCTIONS.encode()).hexdigest()[:16],
                         "hypothesis_signature": "method_path_body_sha256_observed_identity",
                         "hypothesis_identity_source": "successful_session_user_response",
                         "instructions_sha256": hashlib.sha256(INSTRUCTIONS.encode()).hexdigest()[:16]}
        self.state: dict = {}
        self.history: list[dict] = []
        self.turns: list[dict] = []
        self.seen_evidence: set[str] = set()
        self.signatures: set[str] = set()
        self._session_identities: dict[str, str] = {}
        self.stale_turns = 0
        self._controls_len = 0

    # -- tool execution -------------------------------------------------
    def _execute_fetch(self, args: dict) -> dict:
        return self.executor.fetch(str(args.get("method") or "GET"), str(args.get("path", "/")),
                                   body=args.get("body") if isinstance(args.get("body"), dict) else {},
                                   session=str(args["session"]) if args.get("session") else None)

    def _request_identity(self, args: dict) -> str:
        session = str(args["session"]) if args.get("session") else None
        if session is None:
            return "anonymous"
        key = hashlib.sha256(session.encode()).hexdigest()
        # Invented session values must not keep a repeated template alive.
        return self._session_identities.get(key, "unbound_session")

    def _observe_session_identity(self, payload: dict) -> None:
        """Bind only observed successful session/user receipts, not model notes."""
        status, reply = payload.get("status"), payload.get("body")
        if type(status) is not int or not 200 <= status < 300 or not isinstance(reply, dict):
            return
        session, user = reply.get("session"), reply.get("user")
        if not isinstance(session, str) or not session or not isinstance(user, str) or not user:
            return
        key = hashlib.sha256(session.encode()).hexdigest()
        # Session rotation retains the same logical actor. Neither raw token
        # nor user value is written into the progress signature.
        self._session_identities[key] = f"authenticated:{user}"

    @staticmethod
    def _signature(method: str, path: str, body: dict | None = None, *,
                   identity: str | None = None) -> str:
        parts = []
        for seg in path.split("?")[0].split("/"):
            if len(seg) >= 16 and all(c in "0123456789abcdef-" for c in seg.lower()):
                parts.append("{id}")
            else:
                parts.append(seg)
        keys = sorted(k.split("=")[0] for k in path.split("?", 1)[1].split("&")) if "?" in path else []
        signature = f"{method.upper()} {'/'.join(parts)}?{','.join(keys)}"
        if method.upper() == "POST":
            body = body or {}
            # Compare values as well as field names: invalid and valid login
            # controls often have identical keys. Do not put plaintext values
            # (including passwords) in the signature.
            encoded = json.dumps(body, sort_keys=True, ensure_ascii=False, default=str).encode()
            signature += f" {{{','.join(sorted(body))}}}:{hashlib.sha256(encoded).hexdigest()}"
        if identity is not None:
            signature += f" actor:{hashlib.sha256(identity.encode()).hexdigest()}"
        return signature

    def _evidence_key(self, payload: dict) -> str:
        blob = json.dumps(payload.get("body"), sort_keys=True, default=str)[:400]
        return hashlib.sha256(f"{payload.get('method')}|{payload.get('path')}|{payload.get('status')}|{blob}".encode()).hexdigest()

    def _partial_report(self, reason: str, final=None) -> dict:
        return {"status": "partial", "reason": reason,
                "submitted_findings": (final or {}).get("detected_differences", []),
                "research_state": self.state,
                "turns": len(self.turns), "evidence_keys": len(self.seen_evidence)}

    def _state_summary(self) -> dict:
        """Preserve recorded observations without promoting them to findings.

        Research-state prose has no structured evidence bindings. A host-only
        fallback therefore keeps facts as 'other' observations and leaves
        confirmations empty; open hypotheses remain in research_state.
        """
        return {"detected_differences": [
                    {"endpoint": "", "family": "other", "observation": fact}
                    for fact in (self.state.get("observed_facts") or []) if isinstance(fact, str)],
                "confirmed_matches": []}

    def _request_body(self, step: int) -> dict:
        state_blob = json.dumps(self.state, ensure_ascii=False)[:2000] if self.state else "(empty)"
        user = (f"Begin the assessment of the local service at {self.lab_base}. Start at /."
                if step == 1 else "Continue the assessment.")
        items = [{"role": "user", "content": user},
                 {"role": "user", "content": f"RESEARCH STATE (yours; keep it updated): {state_blob}"}]
        for h in self.history:
            items.append({"type": "function_call", "call_id": h["call_id"], "name": h["name"], "arguments": h["arguments"]})
            out = h["output"]
            items.append({"type": "function_call_output", "call_id": h["call_id"],
                          "output": out[: self.output_limit] + ("...[truncated]" if len(out) > self.output_limit else "")})
        return {"model": self.model, "instructions": INSTRUCTIONS, "input": items, "tools": TOOLS}

    @staticmethod
    def _closure_view(value, *, text_limit=400, item_limit=8, depth=0):
        """Bound notes/evidence and redact auth material in the closing view."""
        if isinstance(value, str):
            return value if len(value) <= text_limit else value[:text_limit] + "...[truncated]"
        if isinstance(value, dict):
            if depth >= 6:
                return "[nested data omitted]"
            return {k: DiscoveryLoop._closure_view(v, text_limit=text_limit, item_limit=item_limit, depth=depth + 1)
                    for k, v in list(value.items())[:item_limit]
                    if k.lower() not in {"password", "session", "csrf_token", "credentials", "authorization"}}
        if isinstance(value, list):
            if depth >= 6:
                return "[nested data omitted]"
            return [DiscoveryLoop._closure_view(v, text_limit=text_limit, item_limit=item_limit, depth=depth + 1)
                    for v in value[-item_limit:]]
        return value

    def _closure_evidence(self) -> list[dict]:
        """Select already observed evidence; never invent requests or use lab truth."""
        rows, sessions = [], {}
        for h in self.history:
            if h["name"] != "fetch_route":
                continue
            try:
                args, payload = json.loads(h["arguments"]), json.loads(h["output"])
            except (ValueError, TypeError):
                continue
            if not isinstance(args, dict) or not isinstance(payload, dict):
                continue
            reply = payload.get("body")
            if isinstance(reply, dict) and isinstance(reply.get("session"), str) and isinstance(reply.get("user"), str):
                sessions[reply["session"]] = (reply["user"], h["call_id"])
            identity = sessions.get(args.get("session"))
            request = {"method": payload.get("method", args.get("method", "GET")),
                       "path": payload.get("path", args.get("path", "/")),
                       "actor": identity[0] if identity else None,
                       "actor_source_call_id": identity[1] if identity else None}
            if isinstance(args.get("body"), dict):
                request["body_fields"] = sorted(args["body"])
                request["body"] = self._closure_view(args["body"])
            view = self._closure_view(reply, text_limit=800)
            rows.append({"source_call_id": h["call_id"], "request_index": len(rows) + 1,
                         "request": request, "response": {"status": payload.get("status"), "body": view},
                         "response_view_truncated": view != reply})
        path_ids = {seg for r in rows for seg in str(r["request"]["path"]).split("?", 1)[0].split("/")
                    if len(seg) >= 16}

        def priority(row):
            reply = row["response"]["body"]
            owner = reply.get("owner") if isinstance(reply, dict) else None
            actor = row["request"]["actor"]
            if actor and owner and actor != owner:
                return 100
            if actor and row["response"]["status"] == 403:
                return 80
            if not owner and any(oid in json.dumps(reply) for oid in path_ids):
                return 60
            if owner:
                return 40
            if row["response"]["status"] in (401, 403):
                return 20
            return 10

        unique = {}
        for r in rows:
            key = json.dumps({"request": r["request"], "response": r["response"]}, sort_keys=True)
            unique[key] = r
        return sorted(unique.values(), key=lambda r: (priority(r), r["request_index"]), reverse=True)

    def _closure_body(self) -> dict:
        tool = json.loads(json.dumps(TOOLS[-1]))
        tool["strict"] = True
        tool["parameters"]["properties"]["detected_differences"]["items"]["additionalProperties"] = False
        context = {"research_state": {}, "research_state_truncated": bool(self.state),
                   "selected_request_response_evidence": [], "omitted_evidence_count": 0,
                   "observed_request_count": sum(h["name"] == "fetch_route" for h in self.history)}

        def body():
            request = {"model": self.model, "instructions": CLOSURE_INSTRUCTIONS,
                    "input": [{"role": "user", "content": json.dumps(context, ensure_ascii=False, separators=(",", ":"))}],
                    # A required call with one available function and no
                    # parallel calls forces that function. AgentRouter's
                    # response decoder rejects the object tool_choice form.
                    "tools": [tool], "tool_choice": "required",
                    "parallel_tool_calls": False, "max_output_tokens": self.closure_output_tokens}
            if self.closure_reasoning_effort is not None:
                request["reasoning"] = {"effort": self.closure_reasoning_effort}
            return request

        def size():
            return len(json.dumps(body()).encode())

        if size() > self.closure_prompt_limit:
            raise BudgetError("compact closure scaffold exceeds prompt limit")
        # Keep notes bounded so raw request/response evidence has room too.
        for text_limit, item_limit in ((400, 8), (200, 4), (100, 2)):
            view = self._closure_view(self.state, text_limit=text_limit, item_limit=item_limit)
            if len(json.dumps(view)) <= self.closure_prompt_limit // 3:
                context["research_state"] = view
                context["research_state_truncated"] = view != self.state
                if size() <= self.closure_prompt_limit:
                    break
                context["research_state"] = {}
                context["research_state_truncated"] = bool(self.state)
        evidence = self._closure_evidence()
        context["omitted_evidence_count"] = context["observed_request_count"]
        for row in evidence:
            context["selected_request_response_evidence"].append(row)
            context["omitted_evidence_count"] -= 1
            if size() > self.closure_prompt_limit:
                context["selected_request_response_evidence"].pop()
                context["omitted_evidence_count"] += 1
        context["selected_request_response_evidence"].sort(key=lambda r: r["request_index"])
        request = body()
        assert len(json.dumps(request).encode()) <= self.closure_prompt_limit
        return request

    @staticmethod
    def _valid_summary(args) -> bool:
        if not isinstance(args, dict) or set(args) != {"detected_differences", "confirmed_matches"}:
            return False
        differences, matches = args["detected_differences"], args["confirmed_matches"]
        families = TOOLS[-1]["parameters"]["properties"]["detected_differences"]["items"]["properties"]["family"]["enum"]
        return (isinstance(differences, list) and isinstance(matches, list)
                and all(isinstance(x, str) for x in matches)
                and all(isinstance(d, dict) and set(d) == {"endpoint", "family", "observation"}
                        and all(isinstance(d[k], str) for k in d) and d["family"] in families for d in differences))

    def _close(self, step: int, reason: str, ticket: str | None):
        """Spend the protected reserve on one summary call, with a safe fallback."""
        try:
            body = self._closure_body()
            self.closure_request = body
            bound, profile = prompt_bound(json.dumps(body).encode())
            estimated = bound + self.closure_output_tokens
            available = self.budget.available("tokens") + (self.closure_reserve_tokens if ticket else 0)
            if self.budget.blocked or not self.budget.remaining_seconds():
                raise BudgetError("closure blocked by budget or deadline")
            if ticket is None:
                ticket = self.budget.reserve("tokens", estimated)
                reserved = estimated
            else:
                reserved = self.closure_reserve_tokens
                if estimated > reserved:
                    raise BudgetError("compact closure exceeds protected reserve")
        except BudgetError as exc:
            if ticket:
                self.budget.settle(ticket, 0, phase="closure", executed=False)
            self.closure_error = {"type": "budget", "message": str(exc)}
            return self._state_summary(), "host_research_state"
        try:
            response = call_with_retry(self.transport, body, "closure", attempts=3)
        except Exception as exc:
            self.budget.settle(ticket, reserved, phase="closure", executed=True, measured=False)
            self.closure_error = {"type": type(exc).__name__, "http_status": getattr(exc, "code", None)}
            return self._state_summary(), "host_research_state"
        usage = (response.get("usage") or {}).get("total_tokens")
        try:
            self.budget.settle(ticket, usage if type(usage) is int else reserved,
                               phase="closure", executed=True, measured=type(usage) is int)
        except BudgetError:
            self.closure_error = {"type": "invalid_usage"}
        calls = response.get("function_calls") or []
        if not isinstance(calls, list) or any(not isinstance(c, dict) for c in calls):
            self.closure_error = {"type": "invalid_tool_calls"}
            calls = []
        if response.get("response_status") not in (None, "completed"):
            self.closure_error = {"type": "incomplete_response", "status": response.get("response_status")}
        self.turns.append({"turn": step, "phase": "closure", "tokens": usage if type(usage) is int else None,
                           "calls": [{"name": c.get("name"), "arguments": c.get("arguments")} for c in calls],
                           "text": response.get("text", ""), "closure_injected": True, "closure_reason": reason,
                           "available_tokens_before": available, "prompt_bound": bound,
                           "reserve_tokens": reserved, "estimated_request_tokens": estimated,
                           "usage_reservation_ratio": usage / reserved if type(usage) is int else None,
                           "bound_profile": profile, "state_after": json.loads(json.dumps(self.state)),
                           "response_id": response.get("response_id"), "response_model": response.get("response_model"),
                           "response_status": response.get("response_status"),
                           "incomplete_details": response.get("incomplete_details")})
        if self.closure_error is None and len(calls) == 1 and calls[0].get("name") == "submit_analysis_summary":
            try:
                args = json.loads(calls[0].get("arguments") or "{}")
            except (ValueError, TypeError):
                args = None
            if self._valid_summary(args):
                return args, "model"
        self.closure_error = self.closure_error or {"type": "invalid_summary_or_tool_choice"}
        # Unexpected closing tools are never executed and never change state.
        return self._state_summary(), "host_research_state"

    # -- main loop --------------------------------------------------------
    def run(self) -> dict:
        final = None
        summary_origin = None
        closure_reason = None
        stop_reason = "turn_cap"
        try:
            closure_ticket = self.budget.reserve("tokens", self.closure_reserve_tokens)
        except BudgetError:
            closure_ticket = None
            closure_reason = "insufficient_closure_reserve"
            stop_reason = "token_budget"
        steps = range(1, self.max_turns + 1) if closure_ticket else ()
        for step in steps:
            body = self._request_body(step)
            bound, profile = prompt_bound(json.dumps(body).encode())
            reserve_tokens = bound + 4096
            # available() excludes the held closing ticket. Do not spend it
            # on discovery; only one compact closing call needs a final turn.
            available = self.budget.available("tokens")
            if available < reserve_tokens or step == self.max_turns:
                closure_reason = "remaining_budget" if available < reserve_tokens else "remaining_turns"
                stop_reason = "token_budget" if available < reserve_tokens else "turn_cap"
                break
            try:
                ticket = self.budget.reserve("tokens", reserve_tokens)
            except BudgetError:
                stop_reason = "token_budget"
                break
            try:
                resp = call_with_retry(self.transport, body, f"step {step}")
            except Exception as exc:
                self.budget.settle(ticket, reserve_tokens, phase="discovery", executed=True, measured=False)
                stop_reason = f"provider_error:{type(exc).__name__}"
                break
            usage = (resp.get("usage") or {}).get("total_tokens")
            try:
                self.budget.settle(ticket, usage if type(usage) is int else reserve_tokens,
                                   phase="discovery", executed=True, measured=type(usage) is int)
            except BudgetError:
                stop_reason = "token_budget_invalid_usage"
                # settle() already charged the reservation and blocked the budget
            calls = resp.get("function_calls", [])
            self.turns.append({"turn": step, "phase": "discovery", "tokens": usage if type(usage) is int else None,
                               "calls": [{"name": c["name"], "arguments": c["arguments"]} for c in calls],
                               "text": resp.get("text", ""), "closure_injected": False,
                               "closure_reason": None, "available_tokens_before": available,
                               "available_total_tokens_before": available + self.closure_reserve_tokens,
                               "closure_reserve_tokens": self.closure_reserve_tokens,
                               "prompt_bound": bound, "reserve_tokens": reserve_tokens,
                               "usage_reservation_ratio": usage / reserve_tokens if type(usage) is int else None,
                               "bound_profile": profile,
                               "response_id": resp.get("response_id"), "response_model": resp.get("response_model"),
                               "response_status": resp.get("response_status"),
                               "incomplete_details": resp.get("incomplete_details"),
                               "state_after": json.loads(json.dumps(self.state))})
            if stop_reason.startswith("token_budget"):
                break
            if not calls:
                stop_reason = "no_tool_call"
                break
            novel = False
            new_signature = False
            for c in calls:
                try:
                    args = json.loads(c["arguments"] or "{}")
                except ValueError:
                    args = {}
                if not isinstance(args, dict):
                    args = {}
                if c["name"] == "submit_analysis_summary":
                    if self._valid_summary(args):
                        final = args
                        summary_origin = "model"
                        out = json.dumps({"status": "summary_accepted"})
                        novel = True
                    else:
                        out = json.dumps({"error": "invalid summary schema"})
                elif c["name"] == "update_research_state":
                    self.state = {k: args.get(k) for k in
                                  ("observed_facts", "identity_object_map", "open_hypotheses",
                                   "tried_controls", "next_experiment") if args.get(k) is not None}
                    out = json.dumps({"status": "state_saved"})
                    novel = True
                elif c["name"] == "fetch_route":
                    identity = self._request_identity(args)
                    try:
                        payload = self._execute_fetch(args)
                    except BudgetError:
                        stop_reason = "http_budget"
                        payload = {"path": args.get("path", "/"), "status": 0, "body": {"error": "http budget exhausted"}}
                    self._observe_session_identity(payload)
                    key = self._evidence_key(payload)
                    if key not in self.seen_evidence:
                        self.seen_evidence.add(key)
                        novel = True
                    sig = self._signature(payload.get("method", "GET"), payload.get("path", "/"),
                                          args.get("body") if isinstance(args.get("body"), dict) else None,
                                          identity=identity)
                    if sig not in self.signatures:
                        self.signatures.add(sig)
                        new_signature = True
                    out = json.dumps(payload)
                else:
                    out = json.dumps({"error": "unknown tool"})
                self.history.append({"call_id": c["call_id"], "name": c["name"],
                                     "arguments": c["arguments"], "output": out, "origin": "llm"})
            self.turns[-1]["state_after"] = json.loads(json.dumps(self.state))
            if final is not None:
                stop_reason = "submitted"
                break
            if stop_reason == "http_budget":
                break
            if self.brake_mode == "hypothesis":
                # Re-trying the same request template with fresh ids is not
                # progress for the same actor. First controls for another
                # observed identity must still advance the assessment.
                controls = self.state.get("tried_controls") or []
                controls_grew = len(controls) > self._controls_len
                self._controls_len = len(controls)
                progressed = new_signature or controls_grew
            else:
                progressed = novel
            self.stale_turns = 0 if progressed else self.stale_turns + 1
            if self.brake_mode == "hypothesis":
                self.turns[-1]["hypothesis_progress"] = {
                    "new_signature": new_signature, "controls_grew": controls_grew,
                    "progressed": progressed, "stale_turns": self.stale_turns}
            if self.stale_turns >= self.brake_window:
                stop_reason = f"progress_brake:{self.brake_mode}"
                break
            time.sleep(0.5)
        if final is None:
            closure_reason = closure_reason or stop_reason
            final, summary_origin = self._close(len(self.turns) + 1, closure_reason, closure_ticket)
            if summary_origin == "model":
                stop_reason = "submitted"
        elif closure_ticket:
            self.budget.settle(closure_ticket, 0, phase="closure", executed=False)
        snap = self.budget.snapshot()
        token_events = [e for e in snap["events"] if e["kind"] == "tokens"]
        reserved_tokens = sum(e["reserved"] for e in token_events if e.get("executed", True))
        return {"executor": "llm_discovery_loop", "stop_reason": stop_reason,
                "settings": self.settings,
                "closure_trigger": {"reason": stop_reason,
                                    "closing_injected": any(t.get("closure_injected") for t in self.turns),
                                    "trigger": closure_reason,
                                    "submitted": summary_origin == "model",
                                    "summary_origin": summary_origin,
                                    "report_completed": final is not None,
                                    "protected_reserve_tokens": self.closure_reserve_tokens,
                                    "error": self.closure_error},
                "closure_request": self.closure_request,
                "turns": len(self.turns), "llm_tokens": snap["used"]["tokens"],
                "phase_turns": {p: sum(t["phase"] == p for t in self.turns) for p in ("discovery", "closure")},
                "token_accounting": {"reserved_total": reserved_tokens,
                                     "charged_total": snap["used"]["tokens"],
                                     "charged_reservation_ratio": snap["used"]["tokens"] / reserved_tokens if reserved_tokens else None,
                                     "events": token_events},
                "http_requests": snap["used"]["http"],
                "final_report": final,
                "partial_report": None if summary_origin == "model" else self._partial_report(stop_reason, final),
                "research_state": self.state,
                "turn_log": self.turns,
                "candidate_origins": {"llm": sum(1 for h in self.history if h["name"] == "fetch_route"),
                                      "host": 0}}


def transport_from_env(model: str | None = None):
    key = os.environ.get("DISCOVERY_API_KEY") or os.environ.get("AR_KEY") or ""
    if not key:
        return None
    return responses_transport(key, model or os.environ.get("DISCOVERY_MODEL", "gpt-6.1-sol"))
