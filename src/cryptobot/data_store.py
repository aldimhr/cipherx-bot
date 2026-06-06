"""JSON-backed admin data store — stats, activity log, bans."""

from __future__ import annotations

import json
import os
import time
from datetime import datetime, timezone
from typing import Any

DATA_DIR = os.path.join(os.path.dirname(os.path.dirname(os.path.dirname(__file__))), "data")
STATS_FILE = os.path.join(DATA_DIR, "stats.json")
ACTIVITY_FILE = os.path.join(DATA_DIR, "activity.json")
BANS_FILE = os.path.join(DATA_DIR, "bans.json")
MAX_ACTIVITY = 500  # rotating log

os.makedirs(DATA_DIR, exist_ok=True)


def _read_json(path: str, default: Any) -> Any:
    try:
        if os.path.exists(path):
            with open(path, "r") as f:
                return json.load(f)
    except (json.JSONDecodeError, OSError):
        pass
    return default


def _write_json(path: str, data: Any) -> None:
    try:
        with open(path, "w") as f:
            json.dump(data, f, indent=2)
    except OSError:
        pass


def _today() -> str:
    return datetime.now(timezone.utc).strftime("%Y-%m-%d")


# ── Stats ─────────────────────────────────────────────────────────────────────

def get_stats() -> dict:
    return _read_json(STATS_FILE, {
        "total_operations": 0,
        "unique_users": [],
        "daily": {},
    })


def record_operation(user_id: int, operation: str, method: str, success: bool) -> None:
    stats = get_stats()
    day = _today()

    stats["total_operations"] += 1
    if user_id not in stats["unique_users"]:
        stats["unique_users"].append(user_id)

    if day not in stats["daily"]:
        stats["daily"][day] = {"operations": 0, "users": []}
    stats["daily"][day]["operations"] += 1
    if user_id not in stats["daily"][day]["users"]:
        stats["daily"][day]["users"].append(user_id)

    _write_json(STATS_FILE, stats)

    # Also log to activity
    log_activity(user_id, operation, method, success)


# ── Activity log ──────────────────────────────────────────────────────────────

def get_activity() -> list[dict]:
    return _read_json(ACTIVITY_FILE, [])


def log_activity(user_id: int, operation: str, method: str, success: bool) -> None:
    activity = get_activity()
    activity.insert(0, {
        "user_id": user_id,
        "op": operation,
        "method": method,
        "success": success,
        "ts": datetime.now(timezone.utc).isoformat(),
    })
    if len(activity) > MAX_ACTIVITY:
        activity = activity[:MAX_ACTIVITY]
    _write_json(ACTIVITY_FILE, activity)


# ── Bans ──────────────────────────────────────────────────────────────────────

def get_bans() -> list[int]:
    return _read_json(BANS_FILE, [])


def is_banned(user_id: int) -> bool:
    return user_id in get_bans()


def ban_user(user_id: int) -> bool:
    bans = get_bans()
    if user_id in bans:
        return False
    bans.append(user_id)
    _write_json(BANS_FILE, bans)
    return True


def unban_user(user_id: int) -> bool:
    bans = get_bans()
    if user_id not in bans:
        return False
    bans.remove(user_id)
    _write_json(BANS_FILE, bans)
    return True


# ── User registry (for /users command) ───────────────────────────────────────

USERS_FILE = os.path.join(DATA_DIR, "users.json")


def register_user(user_id: int, username: str | None, first_name: str | None) -> None:
    users = _read_json(USERS_FILE, {})
    uid = str(user_id)
    if uid not in users:
        users[uid] = {
            "username": username,
            "first_name": first_name,
            "first_seen": datetime.now(timezone.utc).isoformat(),
            "last_seen": datetime.now(timezone.utc).isoformat(),
            "operations": 1,
        }
    else:
        users[uid]["last_seen"] = datetime.now(timezone.utc).isoformat()
        users[uid]["operations"] = users[uid].get("operations", 0) + 1
        if username:
            users[uid]["username"] = username
        if first_name:
            users[uid]["first_name"] = first_name
    _write_json(USERS_FILE, users)


def get_users() -> dict:
    return _read_json(USERS_FILE, {})
