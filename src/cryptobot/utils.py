"""Utility helpers — formatting, session state, channel footer."""

from __future__ import annotations

import os
import tempfile
from dataclasses import dataclass, field
from typing import Any

CHANNEL_FOOTER = "\n\n📢 @x0projects"


def with_footer(text: str) -> str:
    return text + CHANNEL_FOOTER


def truncate(text: str, max_len: int = 3500) -> str:
    if len(text) <= max_len:
        return text
    return text[:max_len] + "…"


def code_block(text: str) -> str:
    """Wrap text in a Telegram code block."""
    return f"<code>{text}</code>"


def format_hash_result(algorithm: str, hex_digest: str) -> str:
    return (
        f"#️⃣ <b>{algorithm.upper()}</b>\n\n"
        f"<code>{hex_digest}</code>"
    )


# ── Temp file management ─────────────────────────────────────────────────────

TEMP_DIR = os.path.join(os.path.dirname(os.path.dirname(os.path.dirname(__file__))), "data")


def get_temp_dir() -> str:
    os.makedirs(TEMP_DIR, exist_ok=True)
    return TEMP_DIR


def temp_path(suffix: str = ".tmp") -> str:
    return os.path.join(get_temp_dir(), tempfile.mktemp(suffix=suffix))


def cleanup(path: str) -> None:
    try:
        if os.path.exists(path):
            os.remove(path)
    except OSError:
        pass


# ── Session state for multi-step flows ───────────────────────────────────────

@dataclass
class UserSession:
    action: str  # "encrypt_text", "decrypt_text", "hash_text", "hmac_text", "encrypt_file", "decrypt_file"
    method: str = ""  # "aes", "fernet", "base64", "rot13", "caesar", hash algo, etc.
    step: str = "method"  # "method" -> "input" -> "password" -> "done"
    shift: int = 3  # for Caesar
    temp_file: str = ""  # for file ops
    password: str = ""  # temporary, deleted after use
    data: dict[str, Any] = field(default_factory=dict)


_sessions: dict[int, UserSession] = {}


def get_session(user_id: int) -> UserSession | None:
    return _sessions.get(user_id)


def set_session(user_id: int, session: UserSession) -> None:
    _sessions[user_id] = session


def clear_session(user_id: int) -> None:
    sess = _sessions.pop(user_id, None)
    if sess and sess.temp_file:
        cleanup(sess.temp_file)
