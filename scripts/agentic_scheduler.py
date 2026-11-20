"""Programmatic Control Plane: Anti-Bias UCB Scheduler and Lazy Intervention Monitor."""
from __future__ import annotations

from collections import Counter
from dataclasses import dataclass, field
import math
from typing import Any, Mapping, Sequence

from agentic_bsag import (
    NODE_ARTIFACT,
    NODE_AUTH_CONTEXT,
    NODE_ENDPOINT,
    NODE_HYPOTHESIS,
    STATUS_REFUTED,
    STATUS_SUSPECT_DECOY,
    STATUS_UNEXPLORED,
    STATUS_VERIFIED,
    BeliefStateAttackGraph,
)

EVALUATION_CATEGORIES: tuple[str, ...] = (
    "surface_discovery",
    "auth_session",
    "access_control",
    "object_isolation",
    "input_validation",
    "state_mutation",
    "multi_step_workflow",
)
VALID_SCHEDULER_MODES = frozenset({"ucb", "round_robin", "prompt_only"})
VALID_INTERVENTION_MODES = frozenset({"lazy", "always_on", "off"})


def shannon_entropy(counts: Sequence[str] | Mapping[str, int]) -> float:
    """Compute Shannon entropy H(C) in bits over a sequence of category labels or count map."""
    if isinstance(counts, Mapping):
        freq = {str(k): int(v) for k, v in counts.items() if int(v) > 0}
    else:
        freq = dict(Counter(str(x) for x in counts if str(x)))
    total = sum(freq.values())
    if total <= 0:
        return 0.0
    entropy = 0.0
    for count in freq.values():
        p = count / total
        if p > 0.0:
            entropy -= p * math.log2(p)
    return round(entropy, 6)


@dataclass(frozen=True)
class ArmSelection:
    """Selected (endpoint_node_id, category) work item for an ephemeral worker."""

    node_id: str
    category: str
    score: float
    reason: str
    route_template: str = ""


@dataclass(frozen=True)
class InterventionDecision:
    """Deterministic decision emitted by LazyInterventionMonitor."""

    intervene: bool
    trigger: str = ""
    action: str = ""
    reason: str = ""
    details: dict[str, Any] = field(default_factory=dict)


class AntiBiasUCBScheduler:
    """Deterministic Anti-Bias UCB scheduler with Shannon category entropy cooldown."""

    def __init__(
        self,
        *,
        alpha: float = 1.2,
        beta: float = 1.5,
        mode: str = "ucb",
        cooldown_window: int = 8,
        cooldown_steps: int = 3,
        entropy_threshold: float = 0.85,
    ):
        norm_mode = str(mode or "ucb").strip().lower()
        if norm_mode not in VALID_SCHEDULER_MODES:
            raise ValueError(f"invalid scheduler mode: {mode!r}")
        self.alpha = float(alpha)
        self.beta = float(beta)
        self.mode = norm_mode
        self.cooldown_window = max(2, int(cooldown_window))
        self.cooldown_steps = max(1, int(cooldown_steps))
        self.entropy_threshold = float(entropy_threshold)

        self.arm_pulls: dict[tuple[str, str], int] = {}
        self.arm_rewards: dict[tuple[str, str], float] = {}
        self.total_pulls: int = 0
        self.recent_categories: list[str] = []
        self.all_category_counts: dict[str, int] = {}
        self.category_cooldowns: dict[str, int] = {}
        self._rr_cursor: int = 0

    def _non_anon_auth_count(self, bsag: BeliefStateAttackGraph) -> int:
        return sum(
            1
            for n in bsag.nodes.values()
            if n.node_type == NODE_AUTH_CONTEXT
            and n.attributes.get("alias") != "anon"
            and bool(n.attributes.get("authenticated"))
        )

    def _auth_context_count(self, bsag: BeliefStateAttackGraph) -> int:
        return sum(1 for n in bsag.nodes.values() if n.node_type == NODE_AUTH_CONTEXT)

    def _open_multihop_endpoints(self, bsag: BeliefStateAttackGraph) -> set[str]:
        out: set[str] = set()
        for n in bsag.nodes.values():
            if (
                n.node_type == NODE_HYPOTHESIS
                and n.attributes.get("multi_hop")
                and n.status not in {STATUS_VERIFIED, STATUS_REFUTED}
            ):
                ep_id = str(n.attributes.get("endpoint_node_id") or "")
                if ep_id:
                    out.add(ep_id)
        return out

    def _arm_hypothesis_status(
        self, bsag: BeliefStateAttackGraph, node_id: str, category: str
    ) -> tuple[bool, bool]:
        """Return (has_verified, all_refuted) for hypotheses on (node_id, category)."""
        matching = [
            n
            for n in bsag.nodes.values()
            if n.node_type == NODE_HYPOTHESIS
            and n.attributes.get("endpoint_node_id") == node_id
            and n.attributes.get("category") == category
        ]
        if not matching:
            return False, False
        has_verified = any(n.status == STATUS_VERIFIED for n in matching)
        all_refuted = all(n.status == STATUS_REFUTED for n in matching)
        return has_verified, all_refuted

    def candidate_arms(self, bsag: BeliefStateAttackGraph) -> list[tuple[str, str]]:
        """Enumerate valid (endpoint_node_id, category) arms from current BSAG state."""
        non_anon_auths = self._non_anon_auth_count(bsag)
        total_auths = self._auth_context_count(bsag)
        write_allowed = bool(bsag.allowed_methods & {"POST", "PUT", "PATCH", "DELETE"})
        has_artifacts = any(n.node_type == NODE_ARTIFACT for n in bsag.nodes.values())
        open_multihop = self._open_multihop_endpoints(bsag)

        endpoints = sorted(
            (n for n in bsag.nodes.values() if n.node_type == NODE_ENDPOINT),
            key=lambda x: (x.discovered_at_step, x.node_id),
        )
        arms: list[tuple[str, str]] = []
        for ep in endpoints:
            attrs = ep.attributes
            tmpl = str(attrs.get("route_template") or ep.label)
            is_auth_util = bool(attrs.get("is_auth_utility"))
            methods = set(attrs.get("methods") or ())
            declared_writes = set(attrs.get("declared_write_methods") or ())
            q_params = list(attrs.get("query_params") or ())
            b_fields = list(attrs.get("body_fields") or ())
            actors_2xx = list(attrs.get("actors_2xx") or ())
            actors_denied = list(attrs.get("actors_denied") or ())
            actors_tested = list(attrs.get("actors_tested") or ())
            statuses = set(str(s) for s in (attrs.get("statuses") or ()))
            is_only_404 = bool(statuses) and statuses.issubset({"404", "410"})
            if is_only_404 or ep.status == STATUS_VERIFIED:
                continue

            is_logout = any(tok in tmpl for tok in ("logout", "sign-out", "signout"))
            if is_logout:
                continue

            needs_auth_fetch = bool(actors_denied) and not bool(actors_2xx) and non_anon_auths > 0

            # 1. surface_discovery
            if not is_auth_util and (
                ep.visit_count == 0
                or ep.status == STATUS_UNEXPLORED
                or needs_auth_fetch
                or (tmpl in {"/", "/openapi.json"} and not actors_2xx)
            ):
                arms.append((ep.node_id, "surface_discovery"))

            # 2. auth_session
            if (is_auth_util and non_anon_auths == 0) or (
                non_anon_auths == 0
                and (tmpl == "/" or "auth" in tmpl or "sign" in tmpl or "login" in tmpl or "register" in tmpl)
            ):
                arms.append((ep.node_id, "auth_session"))

            # 3. access_control
            if not is_auth_util and (
                total_auths > 1
                or tmpl.startswith("/api/")
                or "/admin" in tmpl
                or (actors_2xx and "anon" not in actors_tested)
            ):
                arms.append((ep.node_id, "access_control"))

            # 4. object_isolation
            if "{id}" in tmpl and (total_auths >= 2):
                arms.append((ep.node_id, "object_isolation"))

            # 5. input_validation (including query/form params on auth endpoints like redirect/continue)
            if q_params or b_fields or (
                not is_auth_util
                and ("search" in tmpl or "redirect" in tmpl or "continue" in tmpl or "report" in tmpl or "query" in tmpl)
            ):
                arms.append((ep.node_id, "input_validation"))
            elif not is_auth_util and ep.visit_count == 0 and "GET" in methods:
                arms.append((ep.node_id, "input_validation"))

            # 6. state_mutation
            if write_allowed and not is_auth_util and (
                bool(declared_writes & set(bsag.allowed_methods))
                or ("{id}" in tmpl and bool(bsag.allowed_methods & {"PUT", "PATCH"}))
                or bool(methods & {"POST", "PUT", "PATCH", "DELETE"})
            ):
                arms.append((ep.node_id, "state_mutation"))

            # 7. multi_step_workflow
            if ep.node_id in open_multihop or (
                not is_auth_util and has_artifacts and (bool(declared_writes) or (ep.visit_count > 0 and bool(actors_2xx)))
            ):
                arms.append((ep.node_id, "multi_step_workflow"))

            # Guarantee at least surface_discovery if non-utility endpoint had no specialized arms yet.
            if not is_auth_util and not any(nid == ep.node_id for nid, _ in arms):
                arms.append((ep.node_id, "surface_discovery"))
        return arms

    def score_arm(self, bsag: BeliefStateAttackGraph, node_id: str, category: str) -> float:
        """Compute Priority(s, c) = mu_hat(s, c) + alpha*sqrt(ln(N+1)/(n+1)) - beta*D(s) + bonus."""
        node = bsag.nodes[node_id]
        n_pulls = self.arm_pulls.get((node_id, category), 0)
        if n_pulls > 0:
            raw_mu = self.arm_rewards.get((node_id, category), 0.0) / n_pulls
            mu_hat = raw_mu / (1.0 + 2.0 * n_pulls)
        else:
            mu_hat = float(node.information_gain_ema)

        explore = self.alpha * math.sqrt(math.log(self.total_pulls + 1.0 + 1e-9) / (n_pulls + 1.0))
        decoy_penalty = self.beta * float(node.decoy_suspicion_score)

        attrs = node.attributes
        tmpl = str(attrs.get("route_template") or node.label)
        declared_writes = set(attrs.get("declared_write_methods") or ()) & set(bsag.allowed_methods)
        actors_2xx = set(attrs.get("actors_2xx") or ())
        actors_denied = set(attrs.get("actors_denied") or ())
        actors_tested = set(attrs.get("actors_tested") or ())
        q_params = list(attrs.get("query_params") or ())
        non_anon_auths = self._non_anon_auth_count(bsag)
        open_multihop = self._open_multihop_endpoints(bsag)
        has_verified, all_refuted = self._arm_hypothesis_status(bsag, node_id, category)
        needs_auth_fetch = bool(actors_denied) and not bool(actors_2xx) and non_anon_auths > 0

        bonus = 1.2 if n_pulls == 0 else (-1.8 * n_pulls)
        if node.status == STATUS_UNEXPLORED and n_pulls == 0:
            bonus += 0.8
        if category == "surface_discovery" and needs_auth_fetch and n_pulls == 0:
            bonus += 1.4
        elif category == "surface_discovery" and node.visit_count == 0:
            bonus += 0.7
        if category == "auth_session" and non_anon_auths == 0:
            bonus += 1.25
        if category == "state_mutation" and declared_writes and n_pulls == 0:
            bonus += 1.0
        if category == "object_isolation" and "{id}" in tmpl and n_pulls == 0:
            bonus += 0.95
        if category == "input_validation" and q_params and n_pulls == 0:
            bonus += 0.9
        if category == "access_control" and actors_2xx and "anon" not in actors_tested and n_pulls == 0:
            bonus += 0.85
        if category == "multi_step_workflow" and node_id in open_multihop:
            bonus += 0.85
        if node.status == STATUS_VERIFIED or has_verified:
            bonus -= 2.5
        elif all_refuted:
            bonus -= 1.0
        if node.status == STATUS_SUSPECT_DECOY:
            bonus -= 2.5

        return round(mu_hat + explore - decoy_penalty + bonus, 6)

    def apply_entropy_cooldown(self) -> str | None:
        """Check recent category entropy H(C) and cool down dominant category if H(C) < threshold."""
        if len(self.recent_categories) < 4:
            return None
        window = self.recent_categories[-self.cooldown_window :]
        h_val = shannon_entropy(window)
        if h_val < self.entropy_threshold:
            dominant, _ = Counter(window).most_common(1)[0]
            self.category_cooldowns[dominant] = max(
                self.category_cooldowns.get(dominant, 0),
                self.cooldown_steps,
            )
            return dominant
        return None

    def _tick_cooldowns(self) -> None:
        expired = []
        for cat, rem in self.category_cooldowns.items():
            if rem <= 1:
                expired.append(cat)
            else:
                self.category_cooldowns[cat] = rem - 1
        for cat in expired:
            self.category_cooldowns.pop(cat, None)

    def select_arm(self, bsag: BeliefStateAttackGraph) -> ArmSelection | None:
        """Select the next (node_id, category) arm according to the active scheduler mode."""
        arms = self.candidate_arms(bsag)
        if not arms:
            return None

        if self.mode == "round_robin":
            # Prefer least-pulled arms in deterministic round-robin order.
            min_pulls = min(self.arm_pulls.get(a, 0) for a in arms)
            least_pulled = [a for a in arms if self.arm_pulls.get(a, 0) == min_pulls]
            chosen = least_pulled[self._rr_cursor % len(least_pulled)]
            self._rr_cursor += 1
            node = bsag.nodes[chosen[0]]
            return ArmSelection(
                node_id=chosen[0],
                category=chosen[1],
                score=float(-min_pulls),
                reason="round_robin",
                route_template=str(node.attributes.get("route_template") or node.label),
            )

        if self.mode == "prompt_only":
            # Minimal unranked selection: pick first unvisited endpoint or least-visited arm.
            ranked = sorted(
                arms,
                key=lambda a: (
                    self.arm_pulls.get(a, 0),
                    bsag.nodes[a[0]].visit_count,
                    a[0],
                    a[1],
                ),
            )
            chosen = ranked[0]
            node = bsag.nodes[chosen[0]]
            return ArmSelection(
                node_id=chosen[0],
                category=chosen[1],
                score=0.0,
                reason="prompt_only",
                route_template=str(node.attributes.get("route_template") or node.label),
            )

        # Default: Anti-Bias UCB with Shannon entropy cooldown
        self._tick_cooldowns()
        cooled_cat = self.apply_entropy_cooldown()
        non_cooled = [a for a in arms if a[1] not in self.category_cooldowns]
        pool = non_cooled if non_cooled else arms

        best_arm = max(pool, key=lambda a: (self.score_arm(bsag, a[0], a[1]), -self.arm_pulls.get(a, 0), a[0]))
        best_score = self.score_arm(bsag, best_arm[0], best_arm[1])
        node = bsag.nodes[best_arm[0]]
        reason = "ucb_priority"
        if cooled_cat and non_cooled:
            reason = f"ucb_priority(entropy_cooldown:{cooled_cat})"
        return ArmSelection(
            node_id=best_arm[0],
            category=best_arm[1],
            score=best_score,
            reason=reason,
            route_template=str(node.attributes.get("route_template") or node.label),
        )

    def record_selection(self, node_id: str, category: str) -> None:
        """Record that an arm was dispatched to a worker."""
        key = (node_id, category)
        self.arm_pulls[key] = self.arm_pulls.get(key, 0) + 1
        self.total_pulls += 1
        self.recent_categories.append(category)
        if len(self.recent_categories) > max(self.cooldown_window * 2, 16):
            self.recent_categories = self.recent_categories[-self.cooldown_window :]
        self.all_category_counts[category] = self.all_category_counts.get(category, 0) + 1

    def record_outcome(self, node_id: str, category: str, reward: float) -> None:
        """Update empirical reward estimate mu_hat(s, c) after worker execution."""
        key = (node_id, category)
        self.arm_rewards[key] = self.arm_rewards.get(key, 0.0) + float(reward)

    def has_unexplored_priority_arms(self, bsag: BeliefStateAttackGraph) -> bool:
        """Return True if non-decoy unexplored endpoints or untested write/isolation arms remain."""
        for nid, cat in self.candidate_arms(bsag):
            node = bsag.nodes.get(nid)
            if node is None or node.status == STATUS_SUSPECT_DECOY:
                continue
            if self.arm_pulls.get((nid, cat), 0) == 0 and (
                node.status == STATUS_UNEXPLORED
                or cat in {"state_mutation", "object_isolation", "access_control", "auth_session"}
            ):
                return True
        return False

    def current_entropy(self) -> float:
        return shannon_entropy(self.all_category_counts)

    def to_dict(self) -> dict[str, Any]:
        return {
            "mode": self.mode,
            "total_pulls": self.total_pulls,
            "arm_pulls": [[k[0], k[1], v] for k, v in sorted(self.arm_pulls.items())],
            "arm_rewards": [[k[0], k[1], v] for k, v in sorted(self.arm_rewards.items())],
            "recent_categories": list(self.recent_categories),
            "all_category_counts": dict(self.all_category_counts),
            "category_cooldowns": dict(self.category_cooldowns),
            "rr_cursor": self._rr_cursor,
        }

    def load_dict(self, data: dict[str, Any]) -> None:
        if not isinstance(data, dict):
            return
        self.total_pulls = int(data.get("total_pulls") or 0)
        self.arm_pulls = {
            (str(x[0]), str(x[1])): int(x[2])
            for x in (data.get("arm_pulls") or [])
            if isinstance(x, list) and len(x) == 3
        }
        self.arm_rewards = {
            (str(x[0]), str(x[1])): float(x[2])
            for x in (data.get("arm_rewards") or [])
            if isinstance(x, list) and len(x) == 3
        }
        self.recent_categories = [str(x) for x in (data.get("recent_categories") or [])]
        self.all_category_counts = {
            str(k): int(v) for k, v in (data.get("all_category_counts") or {}).items()
        }
        self.category_cooldowns = {
            str(k): int(v) for k, v in (data.get("category_cooldowns") or {}).items()
        }
        self._rr_cursor = int(data.get("rr_cursor") or 0)


class LazyInterventionMonitor:
    """Monitor that stays passive while graph grows and intervenes on measurable triggers."""

    def __init__(
        self,
        *,
        mode: str = "lazy",
        stagnation_k: int = 5,
        entropy_window_w: int = 8,
        entropy_threshold: float = 0.85,
        micro_budget: int = 14,
        early_stop_budget_pct: float = 0.25,
    ):
        norm_mode = str(mode or "lazy").strip().lower()
        if norm_mode not in VALID_INTERVENTION_MODES:
            raise ValueError(f"invalid intervention mode: {mode!r}")
        self.mode = norm_mode
        self.stagnation_k = max(1, int(stagnation_k))
        self.entropy_window_w = max(2, int(entropy_window_w))
        self.entropy_threshold = float(entropy_threshold)
        self.micro_budget = max(1, int(micro_budget))
        self.early_stop_budget_pct = float(early_stop_budget_pct)
        self.consecutive_zero_delta: int = 0

    def reset_worker_window(self) -> None:
        self.consecutive_zero_delta = 0

    def evaluate_step(
        self,
        *,
        delta_v: int,
        delta_e: int,
        worker_steps: int,
        scheduler: AntiBiasUCBScheduler,
        claim_submitted: bool = False,
        finish_requested: bool = False,
        bsag: BeliefStateAttackGraph | None = None,
        http_remaining_ratio: float = 1.0,
    ) -> InterventionDecision:
        """Evaluate whether control plane should intervene after a worker step."""
        # 1. Claim routing always routes to Layer 4 Oracle.
        if claim_submitted:
            return InterventionDecision(
                intervene=True,
                trigger="claim_submitted",
                action="route_to_oracle",
                reason="Claimed hypothesis routed to verification gate.",
            )

        # 2. Premature campaign finish guard
        if finish_requested and self.mode != "off":
            if (
                http_remaining_ratio > self.early_stop_budget_pct
                and bsag is not None
                and scheduler.has_unexplored_priority_arms(bsag)
            ):
                return InterventionDecision(
                    intervene=True,
                    trigger="early_finish",
                    action="block_early_finish",
                    reason=(
                        f"HTTP budget remaining ({round(http_remaining_ratio * 100, 1)}%) exceeds threshold "
                        "and unexplored high-priority BSAG arms remain."
                    ),
                    details={"http_remaining_ratio": round(http_remaining_ratio, 3)},
                )

        # 3. Micro-budget cap on individual ephemeral worker
        if worker_steps >= self.micro_budget:
            return InterventionDecision(
                intervene=True,
                trigger="micro_budget",
                action="rotate_worker",
                reason=f"Worker reached micro-budget limit ({worker_steps}/{self.micro_budget}).",
                details={"worker_steps": worker_steps, "micro_budget": self.micro_budget},
            )

        # 4. In lazy mode, remain passive while BSAG is gaining new nodes or edges.
        has_progress = (delta_v > 0) or (delta_e > 0)
        if has_progress:
            self.consecutive_zero_delta = 0
            if self.mode == "lazy":
                return InterventionDecision(intervene=False, reason="graph_progress")
        else:
            self.consecutive_zero_delta += 1

        if self.mode == "off":
            return InterventionDecision(intervene=False, reason="intervention_off")

        eff_k = self.stagnation_k if self.mode == "lazy" else max(1, self.stagnation_k // 2)
        if self.consecutive_zero_delta >= eff_k:
            return InterventionDecision(
                intervene=True,
                trigger="stagnation",
                action="switch_arm",
                reason=f"No new BSAG nodes or edges for {self.consecutive_zero_delta} consecutive steps.",
                details={"consecutive_zero_delta": self.consecutive_zero_delta, "threshold": eff_k},
            )

        recent = scheduler.recent_categories[-self.entropy_window_w :]
        if len(recent) >= 4:
            h_val = shannon_entropy(recent)
            if h_val < self.entropy_threshold:
                cooled = scheduler.apply_entropy_cooldown()
                return InterventionDecision(
                    intervene=True,
                    trigger="low_entropy",
                    action="cooldown_category",
                    reason=f"Category entropy H(C)={h_val:.3f} < {self.entropy_threshold}; cooled down {cooled}.",
                    details={"entropy": h_val, "cooled_category": cooled},
                )

        if self.mode == "always_on":
            return InterventionDecision(
                intervene=True,
                trigger="always_on",
                action="steer_next_priority",
                reason="Always-on control mode active.",
            )

        return InterventionDecision(intervene=False, reason="passive_ok")
