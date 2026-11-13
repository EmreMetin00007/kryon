#!/usr/bin/env python3
"""Durable campaign/task runtime for autonomous bug bounty workflows."""

from __future__ import annotations

import argparse
import base64
import hashlib
import hmac
import json
import math
import os
import re
import secrets
import sqlite3
import sys
import time
from datetime import datetime, timedelta, timezone
from pathlib import Path
from urllib.parse import urlsplit


SCRIPT_DIR = Path(__file__).resolve().parent
if str(SCRIPT_DIR) not in sys.path:
    sys.path.insert(0, str(SCRIPT_DIR))

from policy_engine import PolicyEngine


TASK_SECRET_FIELDS = {"lease_token", "execution_permit_id", "worker_fencing_token"}
_HUNTER_ARGUMENTS = {"target", "live", "crawl", "zap", "cookie", "headers", "fuzz_limit",
                     "max_validations", "sleep_s", "identities", "blind_discovery", "blind_differential",
                     "blind_max_requests", "session_bindings", "gap_ref"}
_SESSION_LABEL = re.compile(r"[A-Za-z][A-Za-z0-9_.-]{0,63}\Z")
_SECRET_HEADER = re.compile(r"auth|cookie|token|session|credential|api[-_]?key|csrf|xsrf|secret|password", re.I)


def _queue_origin(value):
    try:
        parsed = urlsplit(value)
        if (parsed.scheme not in {"http", "https"} or not parsed.hostname or parsed.username is not None
                or parsed.query or parsed.fragment):
            return None
        port = parsed.port if parsed.port is not None else (443 if parsed.scheme == "https" else 80)
        return (parsed.scheme, parsed.hostname.lower(), port) if port > 0 else None
    except (TypeError, ValueError):
        return None


def _validate_hunter_queue_args(args):
    """Reject credential-bearing Hunter arguments before they reach SQLite."""
    if set(args) - _HUNTER_ARGUMENTS or not isinstance(args.get("live", False), bool):
        raise ValueError("invalid Hunter campaign arguments")
    origin = _queue_origin(args.get("target"))
    if not origin or args.get("cookie") or args.get("identities"):
        raise ValueError("Hunter tasks require a query-free target and session references, not credentials")
    for name in ("crawl", "zap", "blind_discovery", "blind_differential"):
        if name in args and not isinstance(args[name], bool):
            raise ValueError("invalid Hunter campaign options")
    for name in ("fuzz_limit", "max_validations", "blind_max_requests"):
        if name in args and (not isinstance(args[name], int) or isinstance(args[name], bool)):
            raise ValueError("invalid Hunter campaign limits")
    if "sleep_s" in args and (not isinstance(args["sleep_s"], (int, float)) or isinstance(args["sleep_s"], bool)):
        raise ValueError("invalid Hunter campaign pacing")
    headers = args.get("headers") or ""
    if headers:
        try:
            parsed = json.loads(headers) if isinstance(headers, str) else None
        except (TypeError, ValueError):
            parsed = None
        if (not isinstance(parsed, dict) or any(not isinstance(k, str) or not isinstance(v, str)
                or _SECRET_HEADER.search(k) or any(c in v for c in "\r\n\x00") for k, v in parsed.items())):
            raise ValueError("Hunter campaign headers must be non-credential JSON headers")
    bindings = args.get("session_bindings") or ""
    gap_ref = args.get("gap_ref") or ""
    if gap_ref and (not isinstance(gap_ref, str) or not re.fullmatch(r"[a-f0-9]{64}", gap_ref)
                    or args.get("crawl") or args.get("zap") or args.get("blind_discovery")):
        raise ValueError("invalid targeted coverage task")
    if bindings:
        try:
            parsed = json.loads(bindings) if isinstance(bindings, str) else None
        except (TypeError, ValueError):
            parsed = None
        if (not isinstance(parsed, dict)
                or not (2 if args.get("blind_discovery") else 1) <= len(parsed) <= 8):
            raise ValueError("invalid Hunter session references")
        for label, spec in parsed.items():
            if (not isinstance(label, str) or not _SESSION_LABEL.fullmatch(label) or not isinstance(spec, dict)
                    or set(spec) - {"target", "role", "test_data_only", "owned_objects_private"}
                    or _queue_origin(spec.get("target")) != origin or spec.get("test_data_only") is not True
                    or ("owned_objects_private" in spec and not isinstance(spec["owned_objects_private"], bool))
                    or ("role" in spec and (not isinstance(spec["role"], str)
                                           or not _SESSION_LABEL.fullmatch(spec["role"])) )):
                raise ValueError("invalid Hunter session references")


class TaskTransitionError(ValueError):
    pass


def _utc_now() -> str:
    return datetime.now(timezone.utc).isoformat()


class CampaignRuntime:
    def __init__(self, cco_home: str | None = None):
        self.cco_home = Path(cco_home or os.environ.get("CCO_HOME", "~/.cco")).expanduser()
        self.cco_home.mkdir(parents=True, exist_ok=True)
        self.db_path = self.cco_home / "campaigns.db"
        self.sqlite_timeout_seconds = max(1.0, float(os.environ.get("CCO_SQLITE_TIMEOUT_SECONDS", "30")))
        self._init_db()

    def _connect(self):
        conn = sqlite3.connect(self.db_path, timeout=self.sqlite_timeout_seconds)
        conn.row_factory = sqlite3.Row
        conn.execute("PRAGMA foreign_keys=ON")
        conn.execute(f"PRAGMA busy_timeout={int(self.sqlite_timeout_seconds * 1000)}")
        return conn

    def _init_db(self):
        conn = self._connect()
        conn.execute("PRAGMA journal_mode=WAL")
        conn.execute("PRAGMA synchronous=NORMAL")
        conn.executescript(
            """
            CREATE TABLE IF NOT EXISTS campaigns (
                id INTEGER PRIMARY KEY AUTOINCREMENT,
                name TEXT NOT NULL,
                scope_file TEXT DEFAULT '',
                status TEXT NOT NULL DEFAULT 'active',
                budget_requests INTEGER DEFAULT 0,
                budget_usd REAL DEFAULT 0,
                budget_usd_micros INTEGER DEFAULT 0,
                requests_reserved INTEGER DEFAULT 0,
                usd_reserved_micros INTEGER DEFAULT 0,
                requests_used INTEGER DEFAULT 0,
                usd_used_micros INTEGER DEFAULT 0,
                checkpoint_json TEXT DEFAULT '{}',
                notes TEXT DEFAULT '',
                created_at TEXT NOT NULL,
                updated_at TEXT NOT NULL
            );

            CREATE TABLE IF NOT EXISTS tasks (
                id INTEGER PRIMARY KEY AUTOINCREMENT,
                campaign_id INTEGER NOT NULL,
                parent_id INTEGER,
                kind TEXT NOT NULL,
                tool_name TEXT DEFAULT '',
                args_json TEXT DEFAULT '{}',
                status TEXT NOT NULL DEFAULT 'pending',
                attempts INTEGER NOT NULL DEFAULT 0,
                max_attempts INTEGER NOT NULL DEFAULT 3,
                scheduled_at TEXT NOT NULL,
                claimed_by TEXT DEFAULT '',
                lease_token TEXT DEFAULT '',
                claim_expires_at TEXT DEFAULT '',
                last_error TEXT DEFAULT '',
                result_json TEXT DEFAULT '{}',
                checkpoint_json TEXT DEFAULT '{}',
                request_cost INTEGER NOT NULL DEFAULT 1,
                usd_cost_micros INTEGER NOT NULL DEFAULT 0,
                reserved_request_cost INTEGER NOT NULL DEFAULT 0,
                reserved_usd_micros INTEGER NOT NULL DEFAULT 0,
                idempotency_key TEXT DEFAULT '',
                execution_permit_id TEXT DEFAULT '',
                worker_fencing_token TEXT DEFAULT '',
                created_at TEXT NOT NULL,
                updated_at TEXT NOT NULL,
                FOREIGN KEY(campaign_id) REFERENCES campaigns(id),
                FOREIGN KEY(parent_id) REFERENCES tasks(id)
            );

            CREATE TABLE IF NOT EXISTS task_events (
                id INTEGER PRIMARY KEY AUTOINCREMENT,
                task_id INTEGER NOT NULL,
                event_type TEXT NOT NULL,
                payload_json TEXT DEFAULT '{}',
                created_at TEXT NOT NULL,
                FOREIGN KEY(task_id) REFERENCES tasks(id)
            );

            CREATE TABLE IF NOT EXISTS coverage_resume_cursors (
                filter_key TEXT PRIMARY KEY, last_task_id INTEGER NOT NULL
            );

            CREATE INDEX IF NOT EXISTS idx_tasks_sched ON tasks(status, scheduled_at);
            CREATE INDEX IF NOT EXISTS idx_tasks_campaign ON tasks(campaign_id, status);
            CREATE INDEX IF NOT EXISTS idx_task_events_task ON task_events(task_id, created_at);
            """
        )
        for statement in (
            "ALTER TABLE campaigns ADD COLUMN budget_usd_micros INTEGER DEFAULT 0",
            "ALTER TABLE campaigns ADD COLUMN requests_reserved INTEGER DEFAULT 0",
            "ALTER TABLE campaigns ADD COLUMN usd_reserved_micros INTEGER DEFAULT 0",
            "ALTER TABLE campaigns ADD COLUMN requests_used INTEGER DEFAULT 0",
            "ALTER TABLE campaigns ADD COLUMN usd_used_micros INTEGER DEFAULT 0",
            "ALTER TABLE tasks ADD COLUMN lease_token TEXT DEFAULT ''",
            "ALTER TABLE tasks ADD COLUMN request_cost INTEGER NOT NULL DEFAULT 1",
            "ALTER TABLE tasks ADD COLUMN usd_cost_micros INTEGER NOT NULL DEFAULT 0",
            "ALTER TABLE tasks ADD COLUMN reserved_request_cost INTEGER NOT NULL DEFAULT 0",
            "ALTER TABLE tasks ADD COLUMN reserved_usd_micros INTEGER NOT NULL DEFAULT 0",
            "ALTER TABLE tasks ADD COLUMN idempotency_key TEXT DEFAULT ''",
            "ALTER TABLE tasks ADD COLUMN execution_permit_id TEXT DEFAULT ''",
            "ALTER TABLE tasks ADD COLUMN worker_fencing_token TEXT DEFAULT ''",
        ):
            try:
                conn.execute(statement)
            except sqlite3.OperationalError:
                pass
        try:
            conn.execute(
                "CREATE UNIQUE INDEX IF NOT EXISTS idx_tasks_idempotency ON tasks(campaign_id, idempotency_key) WHERE idempotency_key != ''"
            )
        except sqlite3.OperationalError:
            pass
        task_columns = {row[1] for row in conn.execute("PRAGMA table_info(tasks)")}
        if "references_json" not in task_columns:
            conn.execute("ALTER TABLE tasks ADD COLUMN references_json TEXT NOT NULL DEFAULT '{}'")
        conn.commit()
        conn.close()

    @staticmethod
    def _non_negative_int(value: int | str, field: str) -> int:
        try:
            parsed = int(value)
        except Exception as exc:
            raise ValueError(f"{field} non-negative integer olmalı") from exc
        if parsed < 0:
            raise ValueError(f"{field} negatif olamaz")
        return parsed

    @staticmethod
    def _usd_to_micros(value: float | int, field: str = "usd_cost") -> int:
        try:
            parsed = float(value or 0.0)
        except Exception as exc:
            raise ValueError(f"{field} finite non-negative number olmalı") from exc
        if not math.isfinite(parsed) or parsed < 0:
            raise ValueError(f"{field} finite non-negative number olmalı")
        return int(round(parsed * 1_000_000))

    @staticmethod
    def _parse_json_object(raw: str, field: str) -> dict:
        try:
            value = json.loads(raw or "{}")
        except Exception as exc:
            raise ValueError(f"{field} geçerli JSON object olmalı") from exc
        if not isinstance(value, dict):
            raise ValueError(f"{field} JSON object olmalı")
        return value

    def _permit_secret(self) -> bytes:
        path = self.cco_home / "campaign_worker_signing.key"
        encoded = base64.urlsafe_b64encode(secrets.token_bytes(32))
        try:
            fd = os.open(path, os.O_WRONLY | os.O_CREAT | os.O_EXCL, 0o600)
        except FileExistsError:
            pass
        else:
            with os.fdopen(fd, "wb") as handle:
                handle.write(encoded)
                handle.flush()
                os.fsync(handle.fileno())
        try:
            return base64.urlsafe_b64decode(path.read_text().strip().encode())
        except Exception as exc:
            raise ValueError("campaign worker signing key okunamadı") from exc

    @staticmethod
    def _b64encode(raw: bytes) -> str:
        return base64.urlsafe_b64encode(raw).decode().rstrip("=")

    @staticmethod
    def _b64decode(raw: str) -> bytes:
        padding = "=" * (-len(raw) % 4)
        return base64.urlsafe_b64decode((raw + padding).encode())

    def _sign_execution_permit(self, payload: dict) -> str:
        encoded_payload = json.dumps(payload, sort_keys=True, separators=(",", ":"), allow_nan=False).encode()
        signature = hmac.new(self._permit_secret(), encoded_payload, hashlib.sha256).digest()
        return f"{self._b64encode(encoded_payload)}.{self._b64encode(signature)}"

    def _verify_execution_permit(self, permit: str, allow_expired: bool = False) -> dict:
        try:
            encoded_payload, encoded_signature = permit.split(".", 1)
            payload_bytes = self._b64decode(encoded_payload)
            expected = hmac.new(self._permit_secret(), payload_bytes, hashlib.sha256).digest()
            supplied = self._b64decode(encoded_signature)
        except Exception as exc:
            raise ValueError("execution permit geçersiz") from exc
        if not hmac.compare_digest(expected, supplied):
            raise ValueError("execution permit imzası geçersiz")
        try:
            payload = json.loads(payload_bytes.decode())
        except Exception as exc:
            raise ValueError("execution permit payload geçersiz") from exc
        if payload.get("version") != 1:
            raise ValueError("execution permit versiyonu desteklenmiyor")
        expires_at = str(payload.get("expires_at", ""))
        if not allow_expired and (not expires_at or expires_at < _utc_now()):
            raise ValueError("execution permit süresi doldu")
        return payload

    def _make_execution_permit(self, *, task_id: int, campaign_id: int, worker_id: str,
                               permit_id: str, fencing_token: str, expires_at: str,
                               idempotency_key: str = "") -> str:
        return self._sign_execution_permit({
            "version": 1,
            "task_id": int(task_id),
            "campaign_id": int(campaign_id),
            "worker_id": worker_id,
            "permit_id": permit_id,
            "fencing_token": fencing_token,
            "expires_at": expires_at,
            "idempotency_key": idempotency_key or "",
            "issued_at": _utc_now(),
        })

    @staticmethod
    def _sanitize_task(row: dict) -> dict:
        sanitized = dict(row)
        for field in TASK_SECRET_FIELDS:
            if field in sanitized:
                sanitized[field] = ""
        return sanitized

    def _policy_engine(self, scope_file: str | None = None) -> PolicyEngine:
        return PolicyEngine(
            cco_home=str(self.cco_home),
            repo_root=str(SCRIPT_DIR.parent),
            scope_file=scope_file or None,
        )

    def _record_event(self, conn, task_id: int, event_type: str, payload: dict | None = None):
        conn.execute(
            "INSERT INTO task_events (task_id, event_type, payload_json, created_at) VALUES (?, ?, ?, ?)",
            (task_id, event_type, json.dumps(payload or {}, allow_nan=False), _utc_now()),
        )

    def create_campaign(self, name: str, scope_file: str = "", budget_requests: int = 0,
                        budget_usd: float = 0.0, notes: str = "") -> int:
        now = _utc_now()
        budget_requests = self._non_negative_int(budget_requests, "budget_requests")
        budget_usd_micros = self._usd_to_micros(budget_usd, "budget_usd")
        budget_usd_float = budget_usd_micros / 1_000_000
        conn = self._connect()
        cur = conn.execute(
            "INSERT INTO campaigns (name, scope_file, budget_requests, budget_usd, budget_usd_micros, notes, created_at, updated_at) VALUES (?, ?, ?, ?, ?, ?, ?, ?)",
            (name, scope_file, budget_requests, budget_usd_float, budget_usd_micros, notes, now, now),
        )
        campaign_id = cur.lastrowid
        conn.commit()
        conn.close()
        return campaign_id

    def set_campaign_status(self, campaign_id: int, status: str):
        if status in {"cancelled", "killed"}:
            self.kill_campaign(campaign_id, f"campaign {status}")
            return
        conn = self._connect()
        conn.execute(
            "UPDATE campaigns SET status=?, updated_at=? WHERE id=?",
            (status, _utc_now(), campaign_id),
        )
        conn.commit()
        conn.close()

    def kill_campaign(self, campaign_id: int, reason: str = "killed") -> int:
        conn = self._connect()
        conn.execute("BEGIN IMMEDIATE")
        try:
            conn.execute(
                "UPDATE campaigns SET status='cancelled', updated_at=? WHERE id=?",
                (_utc_now(), campaign_id),
            )
            rows = conn.execute(
                "SELECT * FROM tasks WHERE campaign_id=? AND status IN ('pending', 'running', 'waiting_approval', 'rate_limited')",
                (campaign_id,),
            ).fetchall()
            for row in rows:
                if row["status"] == "running":
                    if self._is_live_hunter_task(row):
                        self._settle_budget_locked(conn, row, None, None)
                    else:
                        self._release_budget_reservation_locked(conn, row)
                conn.execute(
                    """
                    UPDATE tasks
                    SET status='blocked', claimed_by='', lease_token='', execution_permit_id='',
                        worker_fencing_token='', claim_expires_at='', reserved_request_cost=0,
                        reserved_usd_micros=0, last_error=?, updated_at=?
                    WHERE id=?
                    """,
                    (reason[:1000], _utc_now(), row["id"]),
                )
                self._record_event(conn, row["id"], "blocked", {"reason": reason})
            conn.commit()
            return len(rows)
        except Exception:
            conn.rollback()
            raise
        finally:
            conn.close()

    def store_campaign_checkpoint(self, campaign_id: int, checkpoint: dict):
        conn = self._connect()
        conn.execute(
            "UPDATE campaigns SET checkpoint_json=?, updated_at=? WHERE id=?",
            (json.dumps(checkpoint, allow_nan=False), _utc_now(), campaign_id),
        )
        conn.commit()
        conn.close()

    def bind_solver_checkpoint(self, campaign_id: int, workdir):
        """Bind the canonical signed file; never enqueue completed solver phases.

        SQLite retains a run pointer, not a second replayable phase queue. Every
        consumer rechecks the signature and artifact hashes from checkpoint.json.
        """
        from workflow_checkpoint import WorkflowCheckpoint
        checkpoint = WorkflowCheckpoint(workdir)
        payload = checkpoint.read()
        conn = self._connect()
        try:
            conn.execute('BEGIN IMMEDIATE')
            row = conn.execute('SELECT scope_file FROM campaigns WHERE id=?', (campaign_id,)).fetchone()
            if not row:
                raise ValueError('campaign not found')
            if row['scope_file'] and str(Path(row['scope_file']).expanduser().resolve()) not in payload['context']['policy_hashes']:
                raise ValueError('campaign scope does not match solver checkpoint')
            control = self._read_checkpoint_locked(conn, campaign_id)
            control['solver_checkpoint'] = {
                'schema': 'campaign-solver-checkpoint/1', 'run_id': payload['run_id'],
                'workdir': str(checkpoint.workdir)}
            conn.execute('UPDATE campaigns SET checkpoint_json=?, updated_at=? WHERE id=?',
                         (json.dumps(control, allow_nan=False), _utc_now(), campaign_id))
            conn.commit()
        except BaseException:
            conn.rollback()
            raise
        finally:
            conn.close()
        return payload

    def read_solver_checkpoint(self, campaign_id: int):
        from workflow_checkpoint import WorkflowCheckpoint
        conn = self._connect()
        try:
            control = self._read_checkpoint_locked(conn, campaign_id)
            pointer = control.get('solver_checkpoint', control)
        finally:
            conn.close()
        if pointer.get('schema') != 'campaign-solver-checkpoint/1':
            raise ValueError('campaign has no solver checkpoint')
        payload = WorkflowCheckpoint(pointer['workdir']).read()
        if payload['run_id'] != pointer['run_id']:
            raise ValueError('campaign checkpoint run identity changed')
        return payload

    def _read_checkpoint_locked(self, conn, campaign_id: int) -> dict:
        row = conn.execute(
            "SELECT checkpoint_json FROM campaigns WHERE id=?", (campaign_id,)
        ).fetchone()
        if not row:
            raise ValueError(f"campaign bulunamadı: {campaign_id}")
        try:
            checkpoint = json.loads(row["checkpoint_json"] or "{}")
        except (ValueError, TypeError):
            checkpoint = {}
        return checkpoint if isinstance(checkpoint, dict) else {}

    @staticmethod
    def _normalize_goal(goal: dict) -> dict:
        if not isinstance(goal, dict):
            raise ValueError("goal dict olmalı")
        endpoint = str(goal.get("endpoint") or "").strip()
        if not endpoint:
            raise ValueError("goal.endpoint zorunlu")
        requires = goal.get("requires") or []
        if not isinstance(requires, list):
            raise ValueError("goal.requires liste olmalı")
        normalized_requires = []
        for req in requires:
            if not isinstance(req, dict):
                raise ValueError("requirement dict olmalı")
            req_id = str(req.get("id") or "").strip()
            if not req_id:
                raise ValueError("requirement.id zorunlu")
            status = str(req.get("status") or "unmet").strip()
            if status not in ("unmet", "met", "blocked"):
                raise ValueError("requirement.status unmet/met/blocked olmalı")
            normalized_requires.append({
                "id": req_id,
                "description": str(req.get("description") or ""),
                "status": status,
                "evidence": str(req.get("evidence") or ""),
            })
        status = str(goal.get("status") or "active").strip()
        if status not in ("active", "achieved", "abandoned"):
            raise ValueError("goal.status active/achieved/abandoned olmalı")
        return {
            "endpoint": endpoint,
            "objective": str(goal.get("objective") or ""),
            "requires": normalized_requires,
            "status": status,
            "updated_at": _utc_now(),
        }

    def set_goal(self, campaign_id: int, goal: dict) -> dict:
        normalized = self._normalize_goal(goal)
        conn = self._connect()
        checkpoint = self._read_checkpoint_locked(conn, campaign_id)
        checkpoint["goal"] = normalized
        conn.execute(
            "UPDATE campaigns SET checkpoint_json=?, updated_at=? WHERE id=?",
            (json.dumps(checkpoint, allow_nan=False), _utc_now(), campaign_id),
        )
        conn.commit()
        conn.close()
        return normalized

    def get_goal(self, campaign_id: int) -> dict | None:
        conn = self._connect()
        try:
            checkpoint = self._read_checkpoint_locked(conn, campaign_id)
        finally:
            conn.close()
        goal = checkpoint.get("goal")
        return goal if isinstance(goal, dict) else None

    def update_requirement(self, campaign_id: int, req_id: str, status: str, evidence: str = "") -> dict:
        status = str(status or "").strip()
        if status not in ("unmet", "met", "blocked"):
            raise ValueError("status unmet/met/blocked olmalı")
        conn = self._connect()
        checkpoint = self._read_checkpoint_locked(conn, campaign_id)
        goal = checkpoint.get("goal")
        if not isinstance(goal, dict):
            conn.close()
            raise ValueError("önce set_goal ile hedef tanımlanmalı")
        for req in goal.get("requires", []):
            if req.get("id") == req_id:
                req["status"] = status
                if evidence:
                    req["evidence"] = str(evidence)
                break
        else:
            conn.close()
            raise ValueError(f"requirement bulunamadı: {req_id}")
        goal["updated_at"] = _utc_now()
        conn.execute(
            "UPDATE campaigns SET checkpoint_json=?, updated_at=? WHERE id=?",
            (json.dumps(checkpoint, allow_nan=False), _utc_now(), campaign_id),
        )
        conn.commit()
        conn.close()
        return goal

    def untested_routes(self, campaign_id: int, target_like: str = "") -> dict:
        """Envanterdeki endpoint'lerden kampanya task'larında hiç geçmeyenler.

        Kapsam körlüğü kapısı: rapor-final öncesi boş olmalı; boş değilse kalan
        rota ya test edilir ya written justification ile kapatılır.
        """
        memory_db = self.cco_home / "agent_memory.db"
        if not memory_db.exists():
            return {"untested": [], "tested": [], "total": 0, "note": "envanter yok"}
        scope_hosts: list[str] = []
        if not target_like:
            try:
                conn_c = self._connect()
                crow = conn_c.execute("SELECT scope_file FROM campaigns WHERE id=?", (campaign_id,)).fetchone()
                conn_c.close()
                sfile = str(crow["scope_file"] or "").strip() if crow else ""
                if sfile and Path(sfile).is_file():
                    sdata = json.loads(Path(sfile).read_text(encoding="utf-8"))
                    for item in sdata.get("in_scope") or []:
                        asset = str(item.get("asset") if isinstance(item, dict) else item or "").strip()
                        if asset:
                            from urllib.parse import urlparse
                            h = urlparse(asset if "://" in asset else f"http://{asset}").hostname or asset
                            if h and h not in scope_hosts:
                                scope_hosts.append(h)
            except Exception:
                pass
        surface_tested_urls: set[str] = set()
        try:
            mem = sqlite3.connect(memory_db)
            if target_like:
                rows = mem.execute(
                    "SELECT url_or_port FROM endpoints WHERE target LIKE ?",
                    (f"%{target_like}%",),
                ).fetchall()
            else:
                rows = mem.execute("SELECT url_or_port, target FROM endpoints").fetchall()
                if scope_hosts:
                    filtered = [r for r in rows if any(h in str(r[1] or "") or h in str(r[0] or "") for h in scope_hosts)]
                    if filtered:
                        rows = filtered
            try:
                scols = {r[1] for r in mem.execute("PRAGMA table_info(attack_surface)").fetchall()}
                if "url" in scols and "target" in scols:
                    has_tc = "tested_classes" in scols
                    has_t = "tested" in scols
                    select_cols = ["url", "target"]
                    if has_tc:
                        select_cols.append("tested_classes")
                    if has_t:
                        select_cols.append("tested")
                    srows = mem.execute(f"SELECT {', '.join(select_cols)} FROM attack_surface").fetchall()
                    for srow in srows:
                        u = str(srow[0] or "").strip()
                        starget = str(srow[1] or "")
                        if not u:
                            continue
                        if target_like and target_like not in starget and target_like not in u:
                            continue
                        if scope_hosts and not target_like and not any(h in starget or h in u for h in scope_hosts):
                            continue
                        idx = 2
                        is_tested = False
                        if has_tc:
                            raw_tc = srow[idx]
                            idx += 1
                            try:
                                parsed_tc = json.loads(raw_tc or "[]")
                                if isinstance(parsed_tc, list) and len(parsed_tc) > 0:
                                    is_tested = True
                            except Exception:
                                if raw_tc and str(raw_tc).strip() not in ("", "[]", "0"):
                                    is_tested = True
                        if has_t and srow[idx]:
                            is_tested = True
                        if is_tested:
                            surface_tested_urls.add(u)
            except sqlite3.OperationalError:
                pass
            mem.close()
        except Exception:
            return {"untested": [], "tested": [], "total": 0, "note": "envanter okunamadı"}
        inventory = []
        for row in rows:
            value = str(row[0] or "").strip()
            if value and value not in inventory:
                inventory.append(value)
        conn = self._connect()
        task_rows = conn.execute(
            "SELECT args_json, result_json FROM tasks WHERE campaign_id=?",
            (campaign_id,),
        ).fetchall()
        conn.close()
        corpus = "\n".join(
            f"{row[0] or ''}\n{row[1] or ''}" for row in task_rows
        )
        tested = [
            route for route in inventory
            if route and (route in corpus or route in surface_tested_urls)
        ]
        untested = [route for route in inventory if route not in tested]
        return {"untested": untested, "tested": tested, "total": len(inventory), "note": ""}

    def check_stall_all(self, window: int = 3, cooldown_seconds: int = 1800,
                        max_brainstorms: int = 5, enqueue: bool = False) -> dict:
        """Tüm aktif kampanyalarda stall tara (cron girişi)."""
        checked = []
        actives = [c for c in self.list_campaigns(limit=200) if c.get("status") == "active"]
        for campaign in actives:
            if enqueue:
                result = self.maybe_enqueue_brainstorm(
                    campaign["id"], window, cooldown_seconds, max_brainstorms)
            else:
                stall = self.detect_stall(campaign["id"], window)
                result = {"enqueued": False, "reason": "dry-run", "stall": stall}
            checked.append({"campaign_id": campaign["id"], "name": campaign["name"],
                            **result})
        return {"checked": checked,
                "enqueued_total": sum(1 for c in checked if c.get("enqueued"))}

    def record_verdict(self, campaign_id: int, topic: str, file_path: str,
                       summary: str = "") -> dict:
        """Beyin/fırtına hükmünü kampanyaya bağla (görünürlük + kapı girdisi)."""
        import re as _re
        import shutil as _shutil

        slug = _re.sub(r"[^a-zA-Z0-9_-]+", "-", (topic or "").strip().lower())[:48]
        if not slug:
            raise ValueError("topic gerekli")
        source = Path(file_path or "")
        if not source.is_file():
            raise ValueError(f"hüküm dosyası yok: {file_path}")
        vault = self.cco_home / "brain_verdicts"
        vault.mkdir(parents=True, exist_ok=True)
        dest = vault / f"{campaign_id}_{slug}.md"
        _shutil.copyfile(source, dest)
        conn = self._connect()
        checkpoint = self._read_checkpoint_locked(conn, campaign_id)
        verdicts = checkpoint.get("verdicts")
        if not isinstance(verdicts, list):
            verdicts = []
        entry = {"topic": topic, "path": str(dest), "summary": str(summary or ""),
                 "recorded_at": _utc_now()}
        verdicts.append(entry)
        checkpoint["verdicts"] = verdicts
        conn.execute(
            "UPDATE campaigns SET checkpoint_json=?, updated_at=? WHERE id=?",
            (json.dumps(checkpoint, allow_nan=False), _utc_now(), campaign_id),
        )
        conn.commit()
        conn.close()
        return {"recorded": True, "campaign_id": campaign_id, "verdict": entry,
                "verdict_count": len(verdicts)}

    def check_close_out(self, campaign_id: int, require_brain_review: bool = False,
                        waive_untested: str = "") -> dict:
        """Kapanış önkoşullarını salt-okunur denetle (mutasyonsuz)."""
        conn = self._connect()
        row = conn.execute(
            "SELECT id, status FROM campaigns WHERE id=?", (campaign_id,)).fetchone()
        conn.close()
        if row is None:
            return {"ok": False, "reason": f"kampanya yok: {campaign_id}"}
        conn = self._connect()
        checkpoint = self._read_checkpoint_locked(conn, campaign_id)
        conn.close()
        if row["status"] == "closed" and checkpoint.get("close_out"):
            return {"ok": True, "untested": [],
                    "verdict_count": len(checkpoint.get("verdicts") or []),
                    "closed": True}
        coverage = self.untested_routes(campaign_id)
        if coverage["untested"] and not (waive_untested or "").strip():
            return {"ok": False, "reason": "untested-routes",
                    "untested": coverage["untested"],
                    "hint": "test et veya --waive-untested ile yazılı gerekçe bırak"}
        conn = self._connect()
        checkpoint = self._read_checkpoint_locked(conn, campaign_id)
        conn.close()
        verdicts = checkpoint.get("verdicts") or []
        if require_brain_review and not verdicts:
            return {"ok": False, "reason": "brain-review-missing",
                    "hint": "fırtına çalıştırıp 'campaign verdict' ile kaydet"}
        from tui_snapshot import campaign_snapshot
        integration = campaign_snapshot(self.cco_home, campaign_id)
        if integration['remaining'] and not (waive_untested or '').strip():
            return {'ok': False, 'reason': 'incomplete-operation-coverage',
                    'remaining': integration['remaining']}
        return {"ok": True, "untested": coverage["untested"],
                "verdict_count": len(verdicts)}

    def close_out(self, campaign_id: int, require_brain_review: bool = False,
                  waive_untested: str = "") -> dict:
        """Rapor-final kapısı: kapsama + beyin hükmü sağlanmadan kapanmaz."""
        check = self.check_close_out(campaign_id, require_brain_review, waive_untested)
        if not check.get("ok"):
            out = {"closed": False}
            out.update({k: v for k, v in check.items() if k != "ok"})
            return out
        conn = self._connect()
        checkpoint = self._read_checkpoint_locked(conn, campaign_id)
        from tui_snapshot import campaign_snapshot
        integration = campaign_snapshot(self.cco_home, campaign_id)
        checkpoint["close_out"] = {
            "integration": integration,
            "at": _utc_now(), "require_brain_review": bool(require_brain_review),
            "waive_untested": str(waive_untested or ""),
            "untested_at_close": check.get("untested", []),
            "verdict_count": check.get("verdict_count", 0),
        }
        conn.execute(
            "UPDATE campaigns SET checkpoint_json=?, status='closed', updated_at=? WHERE id=?",
            (json.dumps(checkpoint, allow_nan=False), _utc_now(), campaign_id),
        )
        conn.commit()
        conn.close()
        return {"closed": True, "campaign_id": campaign_id,
                "close_out": checkpoint["close_out"]}

    def enqueue_task(self, campaign_id: int, kind: str, tool_name: str = "", args: dict | None = None,
                      parent_id: int | None = None, max_attempts: int = 3, scheduled_in: int = 0,
                      request_cost: int = 1, usd_cost: float = 0.0, idempotency_key: str = "",
                      references: dict | None = None) -> int:
        now = datetime.now(timezone.utc)
        scheduled = (now + timedelta(seconds=max(0, scheduled_in))).isoformat()
        args = args or {}
        if not isinstance(args, dict):
            raise ValueError("args dict olmalı")
        if tool_name == "hunter_run_web_loop":
            _validate_hunter_queue_args(args)
            if args.get("gap_ref"):
                canonical_key = "coverage-gap-" + args["gap_ref"]
                if idempotency_key and idempotency_key != canonical_key:
                    raise ValueError("coverage dimension requires its canonical idempotency key")
                idempotency_key = canonical_key
                if isinstance(max_attempts, bool) or not isinstance(max_attempts, int) or not 1 <= max_attempts <= 3:
                    raise ValueError("coverage tasks permit one to three attempts")
        from agent_integration import validate_references
        references = references or {}
        if tool_name == "hunter_run_web_loop" and args.get("gap_ref"):
            try:
                bound_refs = self._coverage_module().task_references(self, args)
            except ValueError:
                # Legacy queue rows may precede observation admission. They
                # remain non-runnable until the existing claim gate admits them.
                if references:
                    raise
                bound_refs = {}
            if references and references != bound_refs:
                raise ValueError("operation/hypothesis references differ from admitted request")
            references = bound_refs
        errors = validate_references(references)
        if errors:
            raise ValueError("schema_validation_failed: " + "; ".join(errors))
        references_json = json.dumps(references, sort_keys=True, allow_nan=False)
        request_cost = self._non_negative_int(request_cost, "request_cost")
        usd_cost_micros = self._usd_to_micros(usd_cost, "usd_cost")
        max_attempts = max(1, int(max_attempts))
        args_json = json.dumps(args, allow_nan=False)
        idempotency_key = str(idempotency_key or "")
        conn = self._connect()
        # Serialize lookup and insertion; a unique index alone would make a
        # concurrent caller fail after both callers miss the initial lookup.
        conn.execute("BEGIN IMMEDIATE")
        campaign = conn.execute(
            "SELECT id FROM campaigns WHERE id=?",
            (campaign_id,),
        ).fetchone()
        if not campaign:
            conn.close()
            raise ValueError(f"campaign bulunamadı: {campaign_id}")
        if tool_name == "hunter_run_web_loop" and args.get("gap_ref"):
            other = conn.execute("SELECT campaign_id FROM tasks WHERE tool_name=? AND idempotency_key=? AND campaign_id!=?",
                                 (tool_name, idempotency_key, campaign_id)).fetchone()
            if other:
                conn.close()
                raise ValueError("coverage dimension already belongs to another campaign")
        if parent_id is not None:
            parent = conn.execute(
                "SELECT id FROM tasks WHERE id=? AND campaign_id=?",
                (parent_id, campaign_id),
            ).fetchone()
            if not parent:
                conn.close()
                raise ValueError("parent_id aynı campaign içinde mevcut olmalı")
        if idempotency_key:
            existing = conn.execute(
                "SELECT * FROM tasks WHERE campaign_id=? AND idempotency_key=?",
                (campaign_id, idempotency_key),
            ).fetchone()
            if existing:
                try:
                    same_args = (json.dumps(json.loads(existing["args_json"] or "{}"), sort_keys=True, allow_nan=False)
                                 == json.dumps(args, sort_keys=True, allow_nan=False))
                except (TypeError, ValueError):
                    same_args = False
                same_task = (same_args and json.loads(existing["references_json"]) == references and existing["kind"] == kind and existing["tool_name"] == tool_name
                             and existing["parent_id"] == parent_id and existing["request_cost"] == request_cost
                             and int(existing["usd_cost_micros"] or 0) == usd_cost_micros
                             and existing["max_attempts"] == max_attempts)
                conn.close()
                if not same_task:
                    raise ValueError("idempotency key already belongs to a different task")
                return int(existing["id"])
        cur = conn.execute(
            """
            INSERT INTO tasks (
                campaign_id, parent_id, kind, tool_name, args_json, status,
                max_attempts, scheduled_at, request_cost, usd_cost_micros, idempotency_key, created_at, updated_at
            ) VALUES (?, ?, ?, ?, ?, 'pending', ?, ?, ?, ?, ?, ?, ?)
            """,
            (
                campaign_id,
                parent_id,
                kind,
                tool_name,
                args_json,
                max_attempts,
                scheduled,
                request_cost,
                usd_cost_micros,
                idempotency_key,
                now.isoformat(),
                now.isoformat(),
            ),
        )
        task_id = cur.lastrowid
        conn.execute("UPDATE tasks SET references_json=? WHERE id=?", (references_json, task_id))
        self._record_event(conn, task_id, "enqueued", {"kind": kind, "tool_name": tool_name})
        conn.commit()
        conn.close()
        return task_id

    def schedule_coverage_gaps(self, campaign_id: int, target: str, **options) -> dict:
        return self._coverage_module().schedule_gaps(self, campaign_id, target, **options)

    def _plan_observed_coverage_gaps(self, target, scope, *, run_id="", limit=100):
        return self._coverage_module().plan_observed_requests(
            str(self.cco_home / "agent_memory.db"), self.cco_home, target, scope,
            run_id=run_id, limit=limit)

    @staticmethod
    def _coverage_module():
        from runtime_paths import runtime_root
        hunter_path = str(runtime_root() / "mcp-servers" / "mcp-hunter")
        if hunter_path not in sys.path:
            sys.path.insert(0, hunter_path)
        from cco_hunter_core import campaign_gaps
        return campaign_gaps

    @staticmethod
    def _coverage_digest(value) -> str:
        raw = json.dumps(value, sort_keys=True, separators=(",", ":"), allow_nan=False).encode()
        return hashlib.sha256(raw).hexdigest()

    def _capture_coverage_attempt_locked(self, conn, row, args):
        if row["tool_name"] != "hunter_run_web_loop" or not args.get("gap_ref") or not args.get("session_bindings"):
            return
        module = self._coverage_module()
        try:
            checks = module.capture_checks(self.cco_home, args["session_bindings"])
        except (ValueError, KeyError, TypeError, OSError):
            return  # An unreadable index must not prevent the worker from blocking safely.
        context, revision, policy = module.versions()
        receipt = self._sign_execution_permit({
            "version": 1, "purpose": "coverage-attempt/1", "task_id": row["id"], "campaign_id": row["campaign_id"],
            "attempt": int(row["attempts"]) + 1, "max_attempts": row["max_attempts"],
            "args_sha256": self._coverage_digest(args), "gap_ref": args["gap_ref"],
            "request_allowance": row["request_cost"], "checks": checks,
            "context_key": context, "scope_revision": revision, "policy_hash": policy,
        })
        self._record_event(conn, row["id"], "coverage_attempt", {"receipt": receipt})

    def _coverage_receipt_locked(self, conn, task_id, event_type, purpose):
        row = conn.execute("SELECT payload_json FROM task_events WHERE task_id=? AND event_type=? ORDER BY id DESC LIMIT 1",
                           (task_id, event_type)).fetchone()
        if not row:
            raise ValueError("verified session block record unavailable")
        receipt = json.loads(row["payload_json"])["receipt"]
        payload = self._verify_execution_permit(receipt, allow_expired=True)
        if payload.get("purpose") != purpose or payload.get("task_id") != task_id:
            raise ValueError("verified session block record unavailable")
        return payload

    def _record_coverage_session_block_locked(self, conn, row, result, checkpoint, reason, actual_request_cost):
        if row["tool_name"] != "hunter_run_web_loop" or not isinstance(result, dict):
            return
        replan, gap = result.get("replan"), result.get("coverage_gap")
        if not isinstance(replan, dict) or not isinstance(gap, dict):
            return
        actions = replan.get("actions")
        if not isinstance(actions, list) or any(not isinstance(action, dict) for action in actions):
            return
        categories = {action.get("category") for action in actions}
        if (replan.get("status") != "blocked" or replan.get("automatic_retry") is not False
                or not categories.intersection({"session", "identity"})
                or categories - {"session", "identity", "unavailable"}
                or gap.get("status") not in {"not_tested", "inconclusive"}
                or isinstance(actual_request_cost, bool) or not isinstance(actual_request_cost, int)
                or not 0 <= actual_request_cost < row["request_cost"]):
            return
        try:
            source = self._coverage_receipt_locked(conn, row["id"], "coverage_attempt", "coverage-attempt/1")
            args = json.loads(row["args_json"])
            if "identity" in categories:
                packet = self._coverage_module().load_request(str(self.cco_home / "agent_memory.db"), self.cco_home,
                                                             args["target"], args["gap_ref"])
                if not packet["item"].get("test_resource"):
                    return  # Only saved explicit access rules can enter this continuation path.
            if (source["campaign_id"] != row["campaign_id"] or source["attempt"] != row["attempts"]
                    or source["max_attempts"] != row["max_attempts"] or source["request_allowance"] != row["request_cost"]
                    or source["args_sha256"] != self._coverage_digest(args)
                    or source["gap_ref"] != gap.get("fingerprint") or not source["checks"]):
                return
            descriptor = {**source, "purpose": "coverage-session-block/1",
                          "checks": self._coverage_module().capture_checks(self.cco_home, args["session_bindings"]),
                          "blocked_at_ns": time.time_ns(),
                          "remaining_request_cost": row["request_cost"] - actual_request_cost,
                          "result_sha256": self._coverage_digest(result),
                          "checkpoint_sha256": self._coverage_digest(checkpoint or {}),
                          "reason_sha256": self._coverage_digest(str(reason or "incomplete result")[:1000])}
            self._record_event(conn, row["id"], "coverage_session_block", {
                "receipt": self._sign_execution_permit(descriptor)})
            self._coverage_module().hypothesis_task_state(self, args, "blocked", checks=descriptor["checks"])
        except (ValueError, KeyError, TypeError, OSError):
            return  # Legacy or unverified blocks remain explicitly blocked.

    def _resume_coverage_gaps_locked(self, conn, campaign_id=None, target="", run_id="", limit=100):
        query = ("SELECT t.* FROM tasks t WHERE t.status='blocked' AND t.tool_name='hunter_run_web_loop' "
                 "AND EXISTS (SELECT 1 FROM task_events e WHERE e.task_id=t.id AND e.event_type='coverage_session_block') ")
        params = []
        if campaign_id is not None:
            query += "AND t.campaign_id=? "
            params.append(campaign_id)
        filter_key = self._coverage_digest([campaign_id, target, run_id])
        cursor = conn.execute("SELECT last_task_id FROM coverage_resume_cursors WHERE filter_key=?", (filter_key,)).fetchone()
        last_id = cursor[0] if cursor else 0
        rows = conn.execute(query + "ORDER BY (t.id<=?), t.id LIMIT ?",
                            [*params, last_id, max(1, min(int(limit), 100))]).fetchall()
        if not rows:
            return {"resumed": [], "deferred": [], "requests_sent": 0}
        conn.execute("INSERT INTO coverage_resume_cursors VALUES (?, ?) ON CONFLICT(filter_key) "
                     "DO UPDATE SET last_task_id=excluded.last_task_id", (filter_key, rows[-1]["id"]))
        module = self._coverage_module()
        resumed, deferred = [], []
        for row in rows:
            try:
                args = json.loads(row["args_json"])
                if target and args.get("target") != target:
                    continue
                _validate_hunter_queue_args(args)
                descriptor = self._coverage_receipt_locked(conn, row["id"], "coverage_session_block", "coverage-session-block/1")
                if (descriptor["campaign_id"] != row["campaign_id"] or descriptor["attempt"] != row["attempts"]
                        or descriptor["max_attempts"] != row["max_attempts"]
                        or descriptor["request_allowance"] != row["request_cost"]
                        or descriptor["args_sha256"] != self._coverage_digest(args)
                        or descriptor["result_sha256"] != self._coverage_digest(json.loads(row["result_json"]))
                        or descriptor["checkpoint_sha256"] != self._coverage_digest(json.loads(row["checkpoint_json"]))
                        or descriptor["reason_sha256"] != self._coverage_digest(row["last_error"])
                        or descriptor["gap_ref"] != args.get("gap_ref")
                        or row["idempotency_key"] != "coverage-gap-" + args["gap_ref"]
                        or row["reserved_request_cost"] or row["reserved_usd_micros"] or row["usd_cost_micros"]):
                    raise ValueError("verified session block record unavailable")
                if row["attempts"] >= row["max_attempts"]:
                    raise ValueError("attempt limit exhausted")
                current = module.versions()
                if current != (descriptor["context_key"], descriptor["scope_revision"], descriptor["policy_hash"]):
                    raise ValueError("request context missing, expired or mismatched")
                packet = module.load_request(str(self.cco_home / "agent_memory.db"), self.cco_home,
                                             args["target"], args["gap_ref"])
                if run_id and packet["item"].get("run_id") != run_id:
                    continue
                with sqlite3.connect(self.cco_home / "agent_memory.db") as memory:
                    dimension = memory.execute("SELECT status FROM hunter_gap_queue WHERE fingerprint=?",
                                               (args["gap_ref"],)).fetchone()
                if dimension and dimension[0] in {"confirmed", "tested_clean"}:
                    raise ValueError("coverage dimension already complete")
                checks, expected = module.verified_checks(self.cco_home, args.get("session_bindings") or "")
                if (set(checks) != set(descriptor["checks"]) or not checks
                        or any(checks[label] == descriptor["checks"][label] for label in checks)
                        or any(entry.get("checked_at_ns", 0) <= descriptor["blocked_at_ns"] for _, _, entry in expected)):
                    raise ValueError("new session verification required for each bound account")
                campaign_row = conn.execute("SELECT * FROM campaigns WHERE id=?", (row["campaign_id"],)).fetchone()
                if not campaign_row or campaign_row["status"] != "active":
                    raise ValueError("active campaign required")
                remaining = descriptor["remaining_request_cost"]
                pending = conn.execute("SELECT COALESCE(SUM(request_cost),0) FROM tasks WHERE campaign_id=? "
                                       "AND status IN ('pending','waiting_approval','rate_limited')", (row["campaign_id"],)).fetchone()[0]
                if (remaining <= 0 or (campaign_row["budget_requests"] and campaign_row["requests_used"]
                        + campaign_row["requests_reserved"] + pending + remaining > campaign_row["budget_requests"])):
                    raise ValueError("campaign request budget exhausted")
                if row["parent_id"] is not None:
                    parent = conn.execute("SELECT status FROM tasks WHERE id=? AND campaign_id=?",
                                          (row["parent_id"], row["campaign_id"])).fetchone()
                    if not parent or parent[0] != "done":
                        raise ValueError("task dependency unavailable")
                module.admit_request(self, dict(campaign_row), args)
                if not module.checks_unchanged(self.cco_home, expected):
                    raise ValueError("session changed during admission")
                checkpoint = {"phase": "verified_session_resume", "previous_attempt": row["attempts"],
                              "previous_result_sha256": descriptor["result_sha256"], "remaining_request_cost": remaining}
                updated = conn.execute("UPDATE tasks SET status='pending', request_cost=?, scheduled_at=?, "
                                       "checkpoint_json=?, updated_at=? WHERE id=? AND status='blocked' AND attempts=?",
                                       (remaining, _utc_now(), json.dumps(checkpoint), _utc_now(), row["id"], row["attempts"]))
                if updated.rowcount == 1:
                    self._record_event(conn, row["id"], "coverage_session_resumed", checkpoint)
                    module.hypothesis_task_state(self, args, "ready", checks=checks, previous_checks=descriptor["checks"])
                    resumed.append({"task_id": row["id"], "gap_ref": args["gap_ref"], "remaining_request_cost": remaining})
            except (ValueError, KeyError, TypeError, sqlite3.Error, OSError) as exc:
                deferred.append({"task_id": row["id"], "reason": module.prerequisite_reason(exc)})
        return {"resumed": resumed, "deferred": deferred, "requests_sent": 0}

    def resume_coverage_gaps(self, campaign_id: int, target: str, *, run_id: str = "", limit: int = 100) -> dict:
        with self._connect() as conn:
            conn.execute("BEGIN IMMEDIATE")
            return self._resume_coverage_gaps_locked(conn, campaign_id, target, run_id, limit)

    @staticmethod
    def _is_live_hunter_task(row) -> bool:
        if row["tool_name"] != "hunter_run_web_loop":
            return False
        try:
            args = json.loads(row["args_json"] or "{}")
            return isinstance(args, dict) and bool(args.get("live"))
        except (TypeError, ValueError):
            # A malformed running Hunter task cannot prove it sent no requests.
            return True

    def is_network_task(self, row) -> bool:
        from wire_budget import network_required
        try:
            args = json.loads(row["args_json"] or "{}")
            if not isinstance(args, dict):
                return True
            return network_required(row["tool_name"], args, self._policy_engine())
        except (ValueError, TypeError, OSError):
            return True  # Unknown wire use cannot authorize a fresh reservation.

    def _recover_stale_tasks_locked(self, conn) -> int:
        now = _utc_now()
        rows = conn.execute(
            "SELECT * FROM tasks WHERE status='running' AND claim_expires_at != '' AND claim_expires_at < ?",
            (now,),
        ).fetchall()
        recovered = 0
        for row in rows:
            if self.is_network_task(row):
                status = "blocked"
                self._settle_budget_locked(conn, row, None, None)
            else:
                status = "dead_letter" if int(row["attempts"]) >= int(row["max_attempts"]) else "pending"
                self._release_budget_reservation_locked(conn, row)
            scheduled_at = now if status == "pending" else conn.execute("SELECT scheduled_at FROM tasks WHERE id=?", (row["id"],)).fetchone()[0]
            conn.execute(
                """
                UPDATE tasks
                SET status=?, scheduled_at=?, claimed_by='', lease_token='', execution_permit_id='',
                    worker_fencing_token='', claim_expires_at='', reserved_request_cost=0,
                    reserved_usd_micros=0,
                    last_error=CASE WHEN ? IN ('dead_letter','blocked') THEN 'stale lease expired' ELSE last_error END,
                    updated_at=?
                WHERE id=?
                """,
                (status, scheduled_at, status, now, row["id"]),
            )
            event = "recovered_stale" if status == "pending" else status
            self._record_event(conn, row["id"], event, {"reason": "lease expired"})
            recovered += 1
        return recovered

    def recover_stale_tasks(self, claim_timeout_seconds: int = 300) -> int:
        del claim_timeout_seconds
        conn = self._connect()
        conn.execute("BEGIN IMMEDIATE")
        try:
            recovered = self._recover_stale_tasks_locked(conn)
            conn.commit()
        except Exception:
            conn.rollback()
            conn.close()
            raise
        conn.close()
        return recovered

    def _validate_task_policy(self, tool_name: str, args: dict, campaign_id: int, task_id: int,
                              scope_file: str = ""):
        if not tool_name:
            return {"allowed": True, "reason": "no-tool"}
        options = {}
        if tool_name == "hunter_run_web_loop" and args.get("gap_ref"):
            try:
                _validate_hunter_queue_args(args)
            except ValueError:
                return {"allowed": False, "reason": "blocked_invalid_hunter_arguments"}
            # A targeted validator has its own wire gate. Lifecycle checks
            # must not reserve the full web loop's batch multiplier each time.
            options["_wire_request"] = True
            headers = json.loads(args.get("headers") or "{}")
            try:
                headers = self._coverage_module().lifecycle_request_headers(self.cco_home, args)
            except (ValueError, KeyError, TypeError, OSError, sqlite3.Error):
                # Missing metadata is handled by the execution guard, which
                # can record a resumable prerequisite block after claiming.
                pass
            args = {**args, "method": "GET", "headers": headers}
        return self._policy_engine(scope_file).validate_tool_invocation(
            tool_name,
            args,
            extra_metadata={"source": "campaign-runtime", "campaign_id": campaign_id, "task_id": task_id},
            **options,
        )

    @staticmethod
    def _policy_status(reason: str) -> str:
        if reason == "blocked_approval_required":
            return "waiting_approval"
        if reason == "blocked_rate_limit":
            return "rate_limited"
        return "blocked"

    def _set_policy_state_locked(self, conn, row, decision: dict):
        status = self._policy_status(str(decision.get("reason", "")))
        scheduled_at = row["scheduled_at"]
        if status == "rate_limited":
            scheduled_at = (datetime.now(timezone.utc) + timedelta(seconds=60)).isoformat()
        conn.execute(
            """
            UPDATE tasks
            SET status=?, scheduled_at=?, claimed_by='', lease_token='', execution_permit_id='',
                worker_fencing_token='', claim_expires_at='', last_error=?, updated_at=?
            WHERE id=?
            """,
            (status, scheduled_at, f"policy gate: {decision.get('reason', 'blocked')}", _utc_now(), row["id"]),
        )
        self._record_event(conn, row["id"], status, decision)

    @staticmethod
    def _reserved_request_cost(row) -> int:
        return int(row["reserved_request_cost"] or row["request_cost"] or 0)

    @staticmethod
    def _reserved_usd_micros(row) -> int:
        return int(row["reserved_usd_micros"] or row["usd_cost_micros"] or 0)

    def _reserve_budget_locked(self, conn, row) -> bool:
        request_cost = int(row["request_cost"] or 0)
        usd_cost_micros = int(row["usd_cost_micros"] or 0)
        updated = conn.execute(
            """
            UPDATE campaigns
            SET requests_reserved=requests_reserved + ?,
                usd_reserved_micros=usd_reserved_micros + ?,
                updated_at=?
            WHERE id=? AND status='active'
              AND (budget_requests=0 OR requests_used + requests_reserved + ? <= budget_requests)
              AND (budget_usd_micros=0 OR usd_used_micros + usd_reserved_micros + ? <= budget_usd_micros)
            """,
            (request_cost, usd_cost_micros, _utc_now(), row["campaign_id"], request_cost, usd_cost_micros),
        )
        return updated.rowcount == 1

    def _release_budget_reservation_locked(self, conn, row):
        request_cost = self._reserved_request_cost(row)
        usd_cost_micros = self._reserved_usd_micros(row)
        conn.execute(
            """
            UPDATE campaigns
            SET requests_reserved=MAX(0, requests_reserved - ?),
                usd_reserved_micros=MAX(0, usd_reserved_micros - ?),
                updated_at=?
            WHERE id=?
            """,
            (request_cost, usd_cost_micros, _utc_now(), row["campaign_id"]),
        )

    def _settle_budget_locked(self, conn, row, actual_request_cost: int | None,
                              actual_usd_cost: float | int | None):
        if actual_request_cost is None:
            actual_request_cost = int(row["request_cost"] or 0)
        else:
            actual_request_cost = self._non_negative_int(actual_request_cost, "actual_request_cost")
        if actual_usd_cost is None:
            actual_usd_micros = int(row["usd_cost_micros"] or 0)
        else:
            actual_usd_micros = self._usd_to_micros(actual_usd_cost, "actual_usd_cost")
        request_cost = self._reserved_request_cost(row)
        usd_cost_micros = self._reserved_usd_micros(row)
        conn.execute(
            """
            UPDATE campaigns
            SET requests_reserved=MAX(0, requests_reserved - ?),
                usd_reserved_micros=MAX(0, usd_reserved_micros - ?),
                requests_used=requests_used + ?,
                usd_used_micros=usd_used_micros + ?,
                updated_at=?
            WHERE id=?
            """,
            (request_cost, usd_cost_micros, actual_request_cost, actual_usd_micros, _utc_now(), row["campaign_id"]),
        )

    def _refresh_waiting_tasks_locked(self, conn):
        now = _utc_now()
        rows = conn.execute(
            """
            SELECT t.*, c.scope_file FROM tasks t
            JOIN campaigns c ON c.id=t.campaign_id
            WHERE c.status='active'
              AND (
                t.status='waiting_approval'
                OR (t.status='rate_limited' AND t.scheduled_at<=?)
              )
            ORDER BY t.id
            """,
            (now,),
        ).fetchall()
        for row in rows:
            try:
                args = json.loads(row["args_json"] or "{}")
                if not isinstance(args, dict):
                    raise ValueError("task args_json JSON object olmalı")
            except Exception as exc:
                conn.execute(
                    "UPDATE tasks SET status='dead_letter', last_error=?, updated_at=? WHERE id=?",
                    (f"invalid task args: {exc}", _utc_now(), row["id"]),
                )
                self._record_event(conn, row["id"], "dead_letter", {"reason": "invalid args_json"})
                continue
            decision = self._validate_task_policy(row["tool_name"], args, row["campaign_id"], row["id"], row["scope_file"] or "")
            if decision["allowed"]:
                conn.execute(
                    "UPDATE tasks SET status='pending', last_error='', updated_at=? WHERE id=? AND status IN ('waiting_approval', 'rate_limited')",
                    (_utc_now(), row["id"]),
                )
                self._record_event(conn, row["id"], "requeued", {"reason": "policy now allowed"})
            else:
                self._set_policy_state_locked(conn, row, decision)

    def claim_next_task(self, worker_id: str, campaign_id: int | None = None,
                        claim_timeout_seconds: int = 300,
                        kinds: list[str] | None = None) -> dict | None:
        conn = self._connect()
        conn.execute("BEGIN IMMEDIATE")
        try:
            self._recover_stale_tasks_locked(conn)
            self._refresh_waiting_tasks_locked(conn)
            self._resume_coverage_gaps_locked(conn, campaign_id)
            deferred = conn.execute(
                "SELECT t.id FROM tasks t JOIN campaigns c ON c.id=t.campaign_id "
                "WHERE t.status='pending' AND c.status='active' AND t.last_error!='blocked_budget' "
                "AND ((c.budget_requests>0 AND c.requests_used+c.requests_reserved+t.request_cost>c.budget_requests) "
                "OR (c.budget_usd_micros>0 AND c.usd_used_micros+c.usd_reserved_micros+t.usd_cost_micros>c.budget_usd_micros)) "
                + ("AND t.campaign_id=?" if campaign_id is not None else ""),
                (campaign_id,) if campaign_id is not None else ()).fetchall()
            for pending in deferred:
                conn.execute("UPDATE tasks SET last_error='blocked_budget', updated_at=? WHERE id=?", (_utc_now(), pending['id']))
                self._record_event(conn, pending['id'], 'budget_deferred', {'reason_code': 'blocked_budget', 'coverage': 'not_tested'})
            while True:
                query = (
                    "SELECT t.*, c.status AS campaign_status, c.scope_file, c.budget_requests, c.requests_used, "
                    "c.requests_reserved, c.budget_usd_micros, c.usd_used_micros, c.usd_reserved_micros FROM tasks t "
                    "JOIN campaigns c ON c.id=t.campaign_id "
                    "WHERE t.status='pending' AND t.scheduled_at<=? AND t.attempts < t.max_attempts AND c.status='active' "
                    + ("AND t.campaign_id=? " if campaign_id is not None else "")
                    + ("AND t.kind IN (%s) " % ",".join("?" * len(kinds)) if kinds else "")
                    + "AND (t.parent_id IS NULL OR EXISTS (SELECT 1 FROM tasks p WHERE p.id=t.parent_id AND p.status='done')) "
                    "AND (c.budget_requests=0 OR c.requests_used + c.requests_reserved + t.request_cost <= c.budget_requests) "
                    "AND (c.budget_usd_micros=0 OR c.usd_used_micros + c.usd_reserved_micros + t.usd_cost_micros <= c.budget_usd_micros) "
                    "ORDER BY t.scheduled_at, t.id LIMIT 1"
                )
                params = [_utc_now()]
                if campaign_id is not None:
                    params.append(campaign_id)
                if kinds:
                    params.extend(list(kinds))
                row = conn.execute(query, params).fetchone()
                if not row:
                    conn.commit()
                    conn.close()
                    return None
                try:
                    args = json.loads(row["args_json"] or "{}")
                    if not isinstance(args, dict):
                        raise ValueError("task args_json JSON object olmalı")
                except Exception as exc:
                    conn.execute(
                        "UPDATE tasks SET status='dead_letter', last_error=?, updated_at=? WHERE id=? AND status='pending'",
                        (f"invalid task args: {exc}", _utc_now(), row["id"]),
                    )
                    self._record_event(conn, row["id"], "dead_letter", {"reason": "invalid args_json"})
                    continue
                decision = self._validate_task_policy(
                    row["tool_name"], args, row["campaign_id"], row["id"], row["scope_file"] or ""
                )
                if not decision["allowed"]:
                    self._set_policy_state_locked(conn, row, decision)
                    continue
                if row['tool_name'] == 'hunter_run_web_loop' and args.get('gap_ref'):
                    bound_refs = self._coverage_module().task_references(self, args)
                    old_refs = json.loads(row['references_json'] or '{}')
                    if old_refs and old_refs != bound_refs:
                        self._set_policy_state_locked(conn, row, {'allowed': False, 'reason': 'blocked_prerequisite: reference mismatch'})
                        continue
                    conn.execute('UPDATE tasks SET references_json=? WHERE id=?',
                                 (json.dumps(bound_refs, sort_keys=True), row['id']))
                if not self._reserve_budget_locked(conn, row):
                    if row['last_error'] != 'blocked_budget':
                        conn.execute("UPDATE tasks SET last_error='blocked_budget', updated_at=? WHERE id=?",
                                     (_utc_now(), row['id']))
                        self._record_event(conn, row['id'], 'budget_deferred',
                                           {'reason_code': 'blocked_budget', 'coverage': 'not_tested'})
                    conn.commit()
                    conn.close()
                    return None
                lease_token = secrets.token_urlsafe(24)
                execution_permit_id = secrets.token_urlsafe(18)
                worker_fencing_token = secrets.token_urlsafe(18)
                claim_expires = (datetime.now(timezone.utc) + timedelta(seconds=claim_timeout_seconds)).isoformat()
                updated = conn.execute(
                    """
                    UPDATE tasks
                    SET status='running', attempts=attempts+1, claimed_by=?, lease_token=?,
                        execution_permit_id=?, worker_fencing_token=?, claim_expires_at=?,
                        reserved_request_cost=?, reserved_usd_micros=?, updated_at=?
                    WHERE id=? AND status='pending'
                    """,
                    (
                        worker_id,
                        lease_token,
                        execution_permit_id,
                        worker_fencing_token,
                        claim_expires,
                        int(row["request_cost"] or 0),
                        int(row["usd_cost_micros"] or 0),
                        _utc_now(),
                        row["id"],
                    ),
                )
                if updated.rowcount != 1:
                    self._release_budget_reservation_locked(conn, row)
                    continue
                self._record_event(conn, row["id"], "claimed", {"worker_id": worker_id, "permit": "issued"})
                self._capture_coverage_attempt_locked(conn, row, args)
                if row["tool_name"] == "hunter_run_web_loop" and args.get("gap_ref"):
                    self._coverage_module().hypothesis_task_state(self, args, "running")
                conn.commit()
                task = dict(row)
                task["status"] = "running"
                task["claimed_by"] = worker_id
                task["claim_expires_at"] = claim_expires
                task["lease_token"] = lease_token
                task["execution_permit_id"] = ""
                task["worker_fencing_token"] = ""
                task["reserved_request_cost"] = int(row["request_cost"] or 0)
                task["reserved_usd_micros"] = int(row["usd_cost_micros"] or 0)
                task["attempts"] = int(row["attempts"]) + 1
                task["execution_permit"] = self._make_execution_permit(
                    task_id=row["id"],
                    campaign_id=row["campaign_id"],
                    worker_id=worker_id,
                    permit_id=execution_permit_id,
                    fencing_token=worker_fencing_token,
                    expires_at=claim_expires,
                    idempotency_key=row["idempotency_key"] or "",
                )
                conn.close()
                return task
        except Exception:
            conn.rollback()
            conn.close()
            raise

    def _get_running_task(self, conn, task_id: int, worker_id: str, lease_token: str,
                          allow_expired: bool = False):
        if allow_expired:
            row = conn.execute(
                "SELECT * FROM tasks WHERE id=? AND status='running' AND claimed_by=? AND lease_token=? AND claim_expires_at != ''",
                (task_id, worker_id, lease_token),
            ).fetchone()
        else:
            row = conn.execute(
                "SELECT * FROM tasks WHERE id=? AND status='running' AND claimed_by=? AND lease_token=? AND claim_expires_at != '' AND claim_expires_at >= ?",
                (task_id, worker_id, lease_token, _utc_now()),
            ).fetchone()
        if not row:
            raise ValueError("task aktif lease ile worker'a ait değil")
        return row

    def _get_running_task_by_permit(self, conn, permit: str,
                                    allow_expired: bool = False):
        payload = self._verify_execution_permit(permit, allow_expired=allow_expired)
        expiry_clause = "" if allow_expired else "AND claim_expires_at >= ?"
        params = [
            int(payload["task_id"]),
            int(payload["campaign_id"]),
            payload["worker_id"],
            payload["permit_id"],
            payload["fencing_token"],
        ]
        if not allow_expired:
            params.append(_utc_now())
        row = conn.execute(
            f"""
            SELECT * FROM tasks
            WHERE id=? AND campaign_id=? AND status='running' AND claimed_by=?
              AND execution_permit_id=? AND worker_fencing_token=?
              AND claim_expires_at != '' {expiry_clause}
            """,
            params,
        ).fetchone()
        if not row:
            raise ValueError("execution permit aktif worker fencing token ile eşleşmedi")
        return row, payload

    def _assert_worker_control_locked(self, conn, row):
        campaign = conn.execute("SELECT status FROM campaigns WHERE id=?", (row["campaign_id"],)).fetchone()
        status = campaign["status"] if campaign else "cancelled"
        if status == "active":
            return
        if status == "paused":
            raise ValueError("campaign paused")
        if self._is_live_hunter_task(row):
            self._settle_budget_locked(conn, row, None, None)
        else:
            self._release_budget_reservation_locked(conn, row)
        conn.execute(
            """
            UPDATE tasks
            SET status='blocked', claimed_by='', lease_token='', execution_permit_id='',
                worker_fencing_token='', claim_expires_at='', reserved_request_cost=0,
                reserved_usd_micros=0, last_error=?, updated_at=?
            WHERE id=? AND status='running'
            """,
            (f"campaign {status}", _utc_now(), row["id"]),
        )
        self._record_event(conn, row["id"], "blocked", {"reason": f"campaign {status}"})
        raise TaskTransitionError(f"campaign {status}")

    def _revalidate_running_policy_locked(self, conn, row, *, actual_request_cost=None, actual_usd_cost=None):
        campaign = conn.execute("SELECT scope_file FROM campaigns WHERE id=?", (row["campaign_id"],)).fetchone()
        try:
            args = json.loads(row["args_json"] or "{}")
            if not isinstance(args, dict):
                raise ValueError("task args_json JSON object olmalı")
        except Exception as exc:
            if self._is_live_hunter_task(row):
                self._settle_budget_locked(conn, row, actual_request_cost, actual_usd_cost)
            else:
                self._release_budget_reservation_locked(conn, row)
            conn.execute(
                """
                UPDATE tasks
                SET status='dead_letter', claimed_by='', lease_token='', execution_permit_id='',
                    worker_fencing_token='', claim_expires_at='', reserved_request_cost=0,
                    reserved_usd_micros=0, last_error=?, updated_at=?
                WHERE id=?
                """,
                (f"invalid task args: {exc}", _utc_now(), row["id"]),
            )
            self._record_event(conn, row["id"], "dead_letter", {"reason": "invalid args_json"})
            raise TaskTransitionError(f"invalid task args: {exc}") from exc
        decision = self._validate_task_policy(
            row["tool_name"], args, row["campaign_id"], row["id"], campaign["scope_file"] if campaign else ""
        )
        if decision["allowed"]:
            return
        if self._is_live_hunter_task(row):
            self._settle_budget_locked(conn, row, actual_request_cost, actual_usd_cost)
            decision = {**decision, "reason": "running live web policy changed: " + str(decision.get("reason") or "blocked")}
            conn.execute("UPDATE tasks SET status='blocked', claimed_by='', lease_token='', execution_permit_id='', "
                         "worker_fencing_token='', claim_expires_at='', last_error=?, updated_at=? WHERE id=?",
                         (decision["reason"][:1000], _utc_now(), row["id"]))
            self._record_event(conn, row["id"], "blocked", decision)
        else:
            self._release_budget_reservation_locked(conn, row)
            self._set_policy_state_locked(conn, row, decision)
        conn.execute(
            "UPDATE tasks SET reserved_request_cost=0, reserved_usd_micros=0 WHERE id=?",
            (row["id"],),
        )
        raise TaskTransitionError(f"policy gate: {decision['reason']}")

    def heartbeat_task(self, task_id: int, worker_id: str, lease_token: str,
                       checkpoint: dict | None = None, claim_timeout_seconds: int = 300,
                       fencing_token: str | None = None,
                       allow_expired_lease: bool = False) -> str | None:
        # allow_expired_lease: gecikmiş heartbeat, lease dolmuş ama fencing/lease
        # hâlâ aynıysa yenileyebilir (başkası devraldıysa tokenlar değişmiştir,
        # eşleşme yine başarısız olur). Yük altında sağlıklı işin ölmesini önler.
        claim_expires = (datetime.now(timezone.utc) + timedelta(seconds=claim_timeout_seconds)).isoformat()
        conn = self._connect()
        conn.execute("BEGIN IMMEDIATE")
        try:
            row = self._get_running_task(conn, task_id, worker_id, lease_token,
                                         allow_expired=allow_expired_lease)
            if fencing_token and row["worker_fencing_token"] != fencing_token:
                raise ValueError("heartbeat fencing token eşleşmedi")
            self._assert_worker_control_locked(conn, row)
            self._revalidate_running_policy_locked(conn, row)
            checkpoint_json = row["checkpoint_json"] if checkpoint is None else json.dumps(checkpoint, allow_nan=False)
            new_fencing_token = secrets.token_urlsafe(18) if fencing_token else row["worker_fencing_token"]
            updated = conn.execute(
                """
                UPDATE tasks
                SET checkpoint_json=?, worker_fencing_token=?, claim_expires_at=?, updated_at=?
                WHERE id=? AND status='running' AND claimed_by=? AND lease_token=?
                """,
                (checkpoint_json, new_fencing_token, claim_expires, _utc_now(), task_id, worker_id, lease_token),
            )
            if updated.rowcount != 1:
                raise ValueError("heartbeat güncellemesi başarısız")
            self._record_event(conn, task_id, "heartbeat", checkpoint if checkpoint is not None else {})
            conn.commit()
            if fencing_token:
                return self._make_execution_permit(
                    task_id=task_id,
                    campaign_id=row["campaign_id"],
                    worker_id=worker_id,
                    permit_id=row["execution_permit_id"],
                    fencing_token=new_fencing_token,
                    expires_at=claim_expires,
                    idempotency_key=row["idempotency_key"] or "",
                )
        except TaskTransitionError:
            conn.commit()
            conn.close()
            raise
        except Exception:
            conn.rollback()
            conn.close()
            raise
        conn.close()
        return None

    def heartbeat_task_with_permit(self, execution_permit: str, checkpoint: dict | None = None,
                                   claim_timeout_seconds: int = 300,
                                   allow_expired_lease: bool = False) -> str:
        conn = self._connect()
        try:
            row, payload = self._get_running_task_by_permit(
                conn, execution_permit, allow_expired=allow_expired_lease)
        finally:
            conn.close()
        refreshed = self.heartbeat_task(
            int(payload["task_id"]),
            payload["worker_id"],
            row["lease_token"],
            checkpoint,
            claim_timeout_seconds,
            payload["fencing_token"],
            allow_expired_lease=allow_expired_lease,
        )
        if not refreshed:
            raise ValueError("execution permit yenilenemedi")
        return refreshed

    def _with_outcome(self, row, result, status, actual_request_cost, reason=""):
        from agent_integration import normalize_outcome
        result = dict(result or {})
        # Missing usage is conservatively settled at the reservation, as before.
        measured = 0 if actual_request_cost is None else actual_request_cost
        if actual_request_cost is not None and (type(actual_request_cost) is not int or actual_request_cost < 0):
            raise ValueError('invalid actual_request_cost')
        result["outcome"] = normalize_outcome(dict(row), result, status=status,
                                               requests_sent=measured, reason=reason)
        result['outcome']['request_count_known'] = actual_request_cost is not None
        result['outcome']['requests_charged'] = (int(row['reserved_request_cost'] or row['request_cost'] or 0)
                                                if actual_request_cost is None else actual_request_cost)
        refs = result['outcome']['references']
        if refs:
            from agent_integration import current_hypothesis_result
            memory = self.cco_home / 'agent_memory.db'
            if memory.is_file():
                try:
                    with sqlite3.connect(f'file:{memory}?mode=ro', uri=True) as conn:
                        proof = conn.execute('SELECT status,validation_id FROM web_hypotheses WHERE fingerprint=?',
                                             (refs['hypothesis_ref'],)).fetchone()
                    if proof:
                        state = current_hypothesis_result(self.cco_home, refs['dimension'], *proof)
                        result['outcome']['test_result'] = {'confirmed': 'confirmed',
                            'tested_no_violation': 'tested_clean'}.get(state, 'inconclusive')
                except sqlite3.Error:
                    pass
        return result

    def enqueue_spec(self, campaign_id, spec, args, *, tool_name, request_cost=1):
        """Locally prevalidate a brain contract before queue admission."""
        from agent_integration import preflight
        checked = preflight(spec)
        if checked['status'] != 'ready':
            return {k: v for k, v in checked.items() if k != 'spec'}
        if tool_name not in spec.tools or args.get('target', args.get('url')) != spec.target:
            return {'status': 'blocked', 'reason_code': 'schema_validation_failed',
                    'errors': ['execution does not match task contract'], 'repair_attempts': 0}
        task_id = self.enqueue_task(campaign_id, 'web', tool_name, args,
                                   request_cost=request_cost, references=spec.references)
        return {'status': 'queued', 'task_id': task_id, 'references': spec.references}

    def complete_task(self, task_id: int, worker_id: str, lease_token: str,
                      result: dict | None = None, checkpoint: dict | None = None,
                      actual_request_cost: int | None = None,
                      actual_usd_cost: float | int | None = None):
        conn = self._connect()
        conn.execute("BEGIN IMMEDIATE")
        try:
            row = self._get_running_task(conn, task_id, worker_id, lease_token)
            self._assert_worker_control_locked(conn, row)
            self._revalidate_running_policy_locked(conn, row, actual_request_cost=actual_request_cost,
                                                   actual_usd_cost=actual_usd_cost)
            result = self._with_outcome(row, result, "done", actual_request_cost)
            checkpoint_json = row["checkpoint_json"] if checkpoint is None else json.dumps(checkpoint, allow_nan=False)
            self._settle_budget_locked(conn, row, actual_request_cost, actual_usd_cost)
            updated = conn.execute(
                """
                UPDATE tasks
                SET status='done', result_json=?, checkpoint_json=?, claimed_by='', lease_token='',
                    execution_permit_id='', worker_fencing_token='', claim_expires_at='',
                    reserved_request_cost=0, reserved_usd_micros=0, updated_at=?
                WHERE id=? AND status='running' AND claimed_by=? AND lease_token=?
                """,
                (json.dumps(result or {}, allow_nan=False), checkpoint_json, _utc_now(), task_id, worker_id, lease_token),
            )
            if updated.rowcount != 1:
                raise ValueError("complete güncellemesi başarısız")
            self._record_event(conn, task_id, "completed", result or {})
            if row["tool_name"] == "hunter_run_web_loop":
                self._coverage_module().hypothesis_task_state(self, json.loads(row["args_json"]), "inconclusive")
            conn.commit()
        except TaskTransitionError:
            conn.commit()
            conn.close()
            raise
        except Exception:
            conn.rollback()
            conn.close()
            raise
        conn.close()

    def complete_task_with_permit(self, execution_permit: str, result: dict | None = None,
                                  checkpoint: dict | None = None,
                                  actual_request_cost: int | None = None,
                                  actual_usd_cost: float | int | None = None):
        conn = self._connect()
        try:
            row, payload = self._get_running_task_by_permit(conn, execution_permit)
        finally:
            conn.close()
        return self.complete_task(
            int(payload["task_id"]),
            payload["worker_id"],
            row["lease_token"],
            result,
            checkpoint,
            actual_request_cost,
            actual_usd_cost,
        )

    def block_task_with_permit(self, execution_permit: str, reason: str, result: dict | None = None,
                               checkpoint: dict | None = None,
                               actual_request_cost: int | None = None,
                               actual_usd_cost: float | int | None = None):
        """Preserve an incomplete result without silently retrying or marking it done."""
        conn = self._connect()
        conn.execute("BEGIN IMMEDIATE")
        try:
            # An expired lease is acceptable only if the same fenced worker
            # still owns the row; a reclaimed task has a different token.
            row, payload = self._get_running_task_by_permit(conn, execution_permit, allow_expired=True)
            self._assert_worker_control_locked(conn, row)
            result = self._with_outcome(row, result, "blocked", actual_request_cost, reason)
            self._settle_budget_locked(conn, row, actual_request_cost, actual_usd_cost)
            updated = conn.execute(
                """UPDATE tasks SET status='blocked', result_json=?, checkpoint_json=?, last_error=?,
                   claimed_by='', lease_token='', execution_permit_id='', worker_fencing_token='',
                   claim_expires_at='', reserved_request_cost=0, reserved_usd_micros=0, updated_at=?
                   WHERE id=? AND status='running' AND worker_fencing_token=?""",
                (json.dumps(result or {}, allow_nan=False), json.dumps(checkpoint or {}, allow_nan=False),
                 str(reason or "incomplete result")[:1000], _utc_now(),
                 int(payload["task_id"]), payload["fencing_token"]))
            if updated.rowcount != 1:
                raise ValueError("block güncellemesi başarısız")
            self._record_coverage_session_block_locked(conn, row, result, checkpoint, reason, actual_request_cost)
            self._record_event(conn, int(payload["task_id"]), "blocked", {"reason": str(reason)[:1000]})
            conn.commit()
        except TaskTransitionError:
            conn.commit()
            raise
        except Exception:
            conn.rollback()
            raise
        finally:
            conn.close()

    def fail_task(self, task_id: int, worker_id: str, lease_token: str,
                  error: str, retry_in: int = 60, checkpoint: dict | None = None):
        conn = self._connect()
        conn.execute("BEGIN IMMEDIATE")
        try:
            row = self._get_running_task(conn, task_id, worker_id, lease_token)
            live_network = self.is_network_task(row)
            status = "blocked" if live_network else ("dead_letter" if int(row["attempts"]) >= int(row["max_attempts"]) else "pending")
            if live_network:
                # Generic failure carries no trusted wire count or session
                # classification. It must not open a fresh full allowance.
                error = "network execution failed; request count unavailable"
                self._settle_budget_locked(conn, row, None, None)
            else:
                self._release_budget_reservation_locked(conn, row)
            checkpoint_json = row["checkpoint_json"] if checkpoint is None else json.dumps(checkpoint, allow_nan=False)
            scheduled_at = row["scheduled_at"] if status != "pending" else (datetime.now(timezone.utc) + timedelta(seconds=max(0, retry_in))).isoformat()
            updated = conn.execute(
                """
                UPDATE tasks
                SET status=?, scheduled_at=?, last_error=?, checkpoint_json=?, claimed_by='',
                    lease_token='', execution_permit_id='', worker_fencing_token='',
                    claim_expires_at='', reserved_request_cost=0, reserved_usd_micros=0,
                    updated_at=?
                WHERE id=? AND status='running' AND claimed_by=? AND lease_token=?
                """,
                (status, scheduled_at, error[:1000], checkpoint_json, _utc_now(), task_id, worker_id, lease_token),
            )
            if updated.rowcount != 1:
                raise ValueError("fail güncellemesi başarısız")
            self._record_event(conn, task_id, "failed" if status == "pending" else status,
                               {"error": error, "retry_in": 0 if live_network else retry_in})
            conn.commit()
        except Exception:
            conn.rollback()
            conn.close()
            raise
        conn.close()

    def fail_task_with_permit(self, execution_permit: str, error: str, retry_in: int = 60,
                              checkpoint: dict | None = None):
        conn = self._connect()
        try:
            row, payload = self._get_running_task_by_permit(conn, execution_permit)
        finally:
            conn.close()
        return self.fail_task(
            int(payload["task_id"]),
            payload["worker_id"],
            row["lease_token"],
            error,
            retry_in,
            checkpoint,
        )

    def list_tasks(self, campaign_id: int | None = None, status: str | None = None,
                   include_secrets: bool = False) -> list[dict]:
        conn = self._connect()
        query = "SELECT * FROM tasks WHERE 1=1"
        params = []
        if campaign_id is not None:
            query += " AND campaign_id=?"
            params.append(campaign_id)
        if status:
            query += " AND status=?"
            params.append(status)
        query += " ORDER BY id"
        rows = conn.execute(query, params).fetchall()
        conn.close()
        tasks = [dict(row) for row in rows]
        if include_secrets:
            return tasks
        return [self._sanitize_task(task) for task in tasks]

    def show_campaign(self, campaign_id: int) -> dict | None:
        conn = self._connect()
        campaign = conn.execute("SELECT * FROM campaigns WHERE id=?", (campaign_id,)).fetchone()
        if not campaign:
            conn.close()
            return None
        tasks = conn.execute(
            "SELECT status, COUNT(*) AS count FROM tasks WHERE campaign_id=? GROUP BY status",
            (campaign_id,),
        ).fetchall()
        conn.close()
        data = dict(campaign)
        data["task_counts"] = {row["status"]: row["count"] for row in tasks}
        return data

    def list_campaigns(self, limit: int = 20, include_terminal: bool = True) -> list[dict]:
        limit = max(1, min(int(limit or 20), 200))
        conn = self._connect()
        query = "SELECT * FROM campaigns"
        params: list = []
        if not include_terminal:
            query += " WHERE status NOT IN ('completed', 'cancelled')"
        query += " ORDER BY updated_at DESC, id DESC LIMIT ?"
        params.append(limit)
        rows = [dict(row) for row in conn.execute(query, params).fetchall()]
        counts = conn.execute(
            "SELECT campaign_id, status, COUNT(*) AS count FROM tasks GROUP BY campaign_id, status"
        ).fetchall()
        conn.close()
        by_campaign: dict[int, dict[str, int]] = {}
        for row in counts:
            by_campaign.setdefault(int(row["campaign_id"]), {})[row["status"]] = int(row["count"])
        for row in rows:
            row["task_counts"] = by_campaign.get(int(row["id"]), {})
        return rows

    @staticmethod
    def _task_has_progress(result_raw: str) -> bool:
        try:
            result = json.loads(result_raw or "{}")
        except (ValueError, TypeError):
            return True
        if isinstance(result, str):
            return bool(result.strip())
        if not isinstance(result, dict) or not result:
            return False
        if result.get("no_progress") is True:
            return False
        # Host completion metadata records queue/accounting state, not newly
        # discovered security information. An empty tool result stays empty.
        return bool({key: value for key, value in result.items() if key != "outcome"})

    @staticmethod
    def _stall_target(args_list: list[dict]) -> str:
        for args in args_list:
            if not isinstance(args, dict):
                continue
            for key in ("target", "target_url", "url", "host", "hostname", "domain"):
                value = args.get(key)
                if isinstance(value, str) and value.strip():
                    return value.strip()
        return ""

    def detect_stall(self, campaign_id: int, window: int = 3) -> dict:
        window = max(1, int(window or 3))
        conn = self._connect()
        rows = conn.execute(
            "SELECT id, result_json FROM tasks"
            " WHERE campaign_id=? AND status='done' AND kind != 'brainstorm'"
            " ORDER BY updated_at DESC, id DESC LIMIT ?",
            (campaign_id, window),
        ).fetchall()
        conn.close()
        task_ids = [int(row["id"]) for row in rows]
        if len(task_ids) < window:
            return {"stalled": False, "reason": "yetersiz tamamlanmış task",
                    "window": window, "checked": len(task_ids), "task_ids": task_ids}
        stalled = all(not self._task_has_progress(row["result_json"]) for row in rows)
        return {"stalled": stalled, "window": window, "checked": len(task_ids), "task_ids": task_ids}

    def maybe_enqueue_brainstorm(self, campaign_id: int, window: int = 3,
                                 cooldown_seconds: int = 1800, max_brainstorms: int = 5) -> dict:
        stall = self.detect_stall(campaign_id, window)
        if not stall["stalled"]:
            return {"enqueued": False, "reason": "stall yok", "stall": stall}
        conn = self._connect()
        brainstorms = conn.execute(
            "SELECT id, created_at FROM tasks WHERE campaign_id=? AND kind='brainstorm'"
            " ORDER BY created_at DESC, id DESC",
            (campaign_id,),
        ).fetchall()
        conn.close()
        if len(brainstorms) >= max(1, int(max_brainstorms)):
            return {"enqueued": False, "reason": "brainstorm kotası doldu",
                    "stall": stall, "brainstorm_count": len(brainstorms)}
        if brainstorms:
            try:
                last = datetime.fromisoformat(brainstorms[0]["created_at"])
                if last.tzinfo is None:
                    last = last.replace(tzinfo=timezone.utc)
                elapsed = (datetime.now(timezone.utc) - last).total_seconds()
                if elapsed < max(0, int(cooldown_seconds)):
                    return {"enqueued": False, "reason": "cooldown sürüyor",
                            "stall": stall, "cooldown_remaining": int(max(0, int(cooldown_seconds)) - elapsed)}
            except (ValueError, TypeError):
                pass
        conn = self._connect()
        stalled_args = []
        for stalled_id in stall["task_ids"]:
            row = conn.execute(
                "SELECT args_json FROM tasks WHERE id=?", (stalled_id,)
            ).fetchone()
            if row:
                try:
                    stalled_args.append(json.loads(row["args_json"] or "{}"))
                except (ValueError, TypeError):
                    continue
        conn.close()
        target = self._stall_target(stalled_args)
        task_id = self.enqueue_task(
            campaign_id,
            "brainstorm",
            "reasoning_next_best_action",
            {"target": target},
            idempotency_key=f"brainstorm-stall-{stall['task_ids'][0]}",
        )
        return {"enqueued": True, "task_id": task_id, "stall": stall, "target": target}


def main(argv: list[str] | None = None) -> int:
    parser = argparse.ArgumentParser(description="CCO campaign runtime")
    sub = parser.add_subparsers(dest="command", required=True)

    create = sub.add_parser("create")
    create.add_argument("name")
    create.add_argument("--scope-file", default="")
    create.add_argument("--budget-requests", type=int, default=0)
    create.add_argument("--budget-usd", type=float, default=0.0)
    create.add_argument("--notes", default="")

    enqueue = sub.add_parser("enqueue")
    enqueue.add_argument("campaign_id", type=int)
    enqueue.add_argument("kind")
    enqueue.add_argument("--tool", default="")
    enqueue.add_argument("--args-json", default="{}")
    enqueue.add_argument("--parent-id", type=int)
    enqueue.add_argument("--max-attempts", type=int, default=3)
    enqueue.add_argument("--scheduled-in", type=int, default=0)
    enqueue.add_argument("--request-cost", type=int, default=1)
    enqueue.add_argument("--usd-cost", type=float, default=0.0)
    enqueue.add_argument("--idempotency-key", default="")

    gaps = sub.add_parser("schedule-gaps")
    gaps.add_argument("campaign_id", type=int)
    gaps.add_argument("target")
    gaps.add_argument("--session-bindings", default="")
    gaps.add_argument("--headers", default="")
    gaps.add_argument("--request-cost", type=int, default=12)
    gaps.add_argument("--limit", type=int, default=15)
    gaps.add_argument("--run-id", default="")
    gaps.add_argument("--max-attempts", type=int, default=3)

    resume_gaps = sub.add_parser("resume-gaps")
    resume_gaps.add_argument("campaign_id", type=int)
    resume_gaps.add_argument("target")
    resume_gaps.add_argument("--run-id", default="")
    resume_gaps.add_argument("--limit", type=int, default=100)

    claim = sub.add_parser("claim")
    claim.add_argument("worker_id")
    claim.add_argument("--campaign-id", type=int)

    heartbeat = sub.add_parser("heartbeat")
    heartbeat.add_argument("task_id", type=int)
    heartbeat.add_argument("worker_id")
    heartbeat.add_argument("lease_token")
    heartbeat.add_argument("--checkpoint-json", default="")

    heartbeat_permit = sub.add_parser("heartbeat-permit")
    heartbeat_permit.add_argument("execution_permit")
    heartbeat_permit.add_argument("--checkpoint-json", default="")

    complete = sub.add_parser("complete")
    complete.add_argument("task_id", type=int)
    complete.add_argument("worker_id")
    complete.add_argument("lease_token")
    complete.add_argument("--result-json", default="")
    complete.add_argument("--checkpoint-json", default="")
    complete.add_argument("--actual-request-cost", type=int)
    complete.add_argument("--actual-usd-cost", type=float)

    complete_permit = sub.add_parser("complete-permit")
    complete_permit.add_argument("execution_permit")
    complete_permit.add_argument("--result-json", default="")
    complete_permit.add_argument("--checkpoint-json", default="")
    complete_permit.add_argument("--actual-request-cost", type=int)
    complete_permit.add_argument("--actual-usd-cost", type=float)

    fail = sub.add_parser("fail")
    fail.add_argument("task_id", type=int)
    fail.add_argument("worker_id")
    fail.add_argument("lease_token")
    fail.add_argument("error")
    fail.add_argument("--retry-in", type=int, default=60)
    fail.add_argument("--checkpoint-json", default="")

    fail_permit = sub.add_parser("fail-permit")
    fail_permit.add_argument("execution_permit")
    fail_permit.add_argument("error")
    fail_permit.add_argument("--retry-in", type=int, default=60)
    fail_permit.add_argument("--checkpoint-json", default="")

    show = sub.add_parser("show")
    show.add_argument("campaign_id", type=int)

    tasks = sub.add_parser("tasks")
    tasks.add_argument("--campaign-id", type=int)
    tasks.add_argument("--status", default="")

    status_cmd = sub.add_parser("status")
    status_cmd.add_argument("campaign_id", type=int)
    status_cmd.add_argument("status", choices=["active", "paused", "completed", "cancelled", "killed"])

    kill = sub.add_parser("kill")
    kill.add_argument("campaign_id", type=int)
    kill.add_argument("--reason", default="killed")

    check_stall = sub.add_parser("check-stall")
    check_stall.add_argument("campaign_id", type=int)
    check_stall.add_argument("--window", type=int, default=3)
    check_stall.add_argument("--enqueue", action="store_true")
    check_stall.add_argument("--cooldown", type=int, default=1800)
    check_stall.add_argument("--max", type=int, default=5)

    goal_set = sub.add_parser("goal-set")
    goal_set.add_argument("campaign_id", type=int)
    goal_set.add_argument("--goal-json", required=True)

    goal_update = sub.add_parser("goal-update")
    goal_update.add_argument("campaign_id", type=int)
    goal_update.add_argument("req_id")
    goal_update.add_argument("status", choices=["unmet", "met", "blocked"])
    goal_update.add_argument("--evidence", default="")

    untested = sub.add_parser("untested-routes")
    untested.add_argument("campaign_id", type=int)
    untested.add_argument("--target-like", default="")

    stall_all = sub.add_parser("check-stall-all")
    stall_all.add_argument("--window", type=int, default=3)
    stall_all.add_argument("--enqueue", action="store_true")
    stall_all.add_argument("--cooldown", type=int, default=1800)
    stall_all.add_argument("--max", type=int, default=5)

    verdict = sub.add_parser("verdict")
    verdict.add_argument("campaign_id", type=int)
    verdict.add_argument("--topic", required=True)
    verdict.add_argument("--file", required=True)
    verdict.add_argument("--summary", default="")

    close = sub.add_parser("close-out")
    close.add_argument("campaign_id", type=int)
    close.add_argument("--require-brain-review", action="store_true")
    close.add_argument("--waive-untested", default="")

    args = parser.parse_args(argv)
    runtime = CampaignRuntime()

    if args.command == "create":
        cid = runtime.create_campaign(args.name, args.scope_file, args.budget_requests, args.budget_usd, args.notes)
        print(json.dumps({"campaign_id": cid}, indent=2))
        return 0
    if args.command == "enqueue":
        parsed_args = runtime._parse_json_object(args.args_json, "args-json")
        task_id = runtime.enqueue_task(
            args.campaign_id,
            args.kind,
            args.tool,
            parsed_args,
            args.parent_id,
            args.max_attempts,
            args.scheduled_in,
            args.request_cost,
            args.usd_cost,
            args.idempotency_key,
        )
        print(json.dumps({"task_id": task_id}, indent=2))
        return 0
    if args.command == "claim":
        print(json.dumps(runtime.claim_next_task(args.worker_id, args.campaign_id), indent=2))
        return 0
    if args.command == "schedule-gaps":
        print(json.dumps(runtime.schedule_coverage_gaps(
            args.campaign_id, args.target, session_bindings=args.session_bindings,
            headers=args.headers, request_cost=args.request_cost, limit=args.limit, run_id=args.run_id,
            max_attempts=args.max_attempts)))
        return 0
    if args.command == "resume-gaps":
        print(json.dumps(runtime.resume_coverage_gaps(args.campaign_id, args.target, run_id=args.run_id, limit=args.limit)))
        return 0
    if args.command == "heartbeat":
        runtime.heartbeat_task(
            args.task_id,
            args.worker_id,
            args.lease_token,
            runtime._parse_json_object(args.checkpoint_json, "checkpoint-json") if args.checkpoint_json else None,
        )
        return 0
    if args.command == "heartbeat-permit":
        refreshed = runtime.heartbeat_task_with_permit(
            args.execution_permit,
            runtime._parse_json_object(args.checkpoint_json, "checkpoint-json") if args.checkpoint_json else None,
        )
        print(json.dumps({"execution_permit": refreshed}, indent=2))
        return 0
    if args.command == "complete":
        runtime.complete_task(
            args.task_id,
            args.worker_id,
            args.lease_token,
            runtime._parse_json_object(args.result_json, "result-json") if args.result_json else None,
            runtime._parse_json_object(args.checkpoint_json, "checkpoint-json") if args.checkpoint_json else None,
            args.actual_request_cost,
            args.actual_usd_cost,
        )
        return 0
    if args.command == "complete-permit":
        runtime.complete_task_with_permit(
            args.execution_permit,
            runtime._parse_json_object(args.result_json, "result-json") if args.result_json else None,
            runtime._parse_json_object(args.checkpoint_json, "checkpoint-json") if args.checkpoint_json else None,
            args.actual_request_cost,
            args.actual_usd_cost,
        )
        return 0
    if args.command == "fail":
        runtime.fail_task(
            args.task_id,
            args.worker_id,
            args.lease_token,
            args.error,
            args.retry_in,
            runtime._parse_json_object(args.checkpoint_json, "checkpoint-json") if args.checkpoint_json else None,
        )
        return 0
    if args.command == "fail-permit":
        runtime.fail_task_with_permit(
            args.execution_permit,
            args.error,
            args.retry_in,
            runtime._parse_json_object(args.checkpoint_json, "checkpoint-json") if args.checkpoint_json else None,
        )
        return 0
    if args.command == "show":
        print(json.dumps(runtime.show_campaign(args.campaign_id), indent=2))
        return 0
    if args.command == "tasks":
        print(json.dumps(runtime.list_tasks(args.campaign_id, args.status or None), indent=2))
        return 0
    if args.command == "status":
        runtime.set_campaign_status(args.campaign_id, args.status)
        return 0
    if args.command == "kill":
        blocked = runtime.kill_campaign(args.campaign_id, args.reason)
        print(json.dumps({"blocked_tasks": blocked}, indent=2))
        return 0
    if args.command == "check-stall":
        if args.enqueue:
            result = runtime.maybe_enqueue_brainstorm(args.campaign_id, args.window, args.cooldown, args.max)
        else:
            result = runtime.detect_stall(args.campaign_id, args.window)
        print(json.dumps(result, indent=2, ensure_ascii=False))
        return 0
    if args.command == "goal-set":
        goal = runtime.set_goal(args.campaign_id, runtime._parse_json_object(args.goal_json, "goal-json"))
        print(json.dumps(goal, indent=2, ensure_ascii=False))
        return 0
    if args.command == "goal-update":
        goal = runtime.update_requirement(args.campaign_id, args.req_id, args.status, args.evidence)
        print(json.dumps(goal, indent=2, ensure_ascii=False))
        return 0
    if args.command == "untested-routes":
        print(json.dumps(runtime.untested_routes(args.campaign_id, args.target_like),
                         indent=2, ensure_ascii=False))
        return 0
    if args.command == "check-stall-all":
        print(json.dumps(runtime.check_stall_all(
            args.window, args.cooldown, args.max, enqueue=args.enqueue),
            indent=2, ensure_ascii=False))
        return 0
    if args.command == "verdict":
        try:
            out = runtime.record_verdict(
                args.campaign_id, args.topic, args.file, args.summary)
        except ValueError as exc:
            print(json.dumps({"recorded": False, "error": str(exc)}))
            return 1
        print(json.dumps(out, indent=2, ensure_ascii=False))
        return 0
    if args.command == "close-out":
        out = runtime.close_out(
            args.campaign_id, args.require_brain_review, args.waive_untested)
        print(json.dumps(out, indent=2, ensure_ascii=False))
        return 0 if out.get("closed") else 1
    return 1


if __name__ == "__main__":
    raise SystemExit(main())
