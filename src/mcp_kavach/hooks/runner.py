"""Shared harness and filesystem helpers for hook handlers."""

from __future__ import annotations

import contextlib
import json
import os
import secrets
import sys
import time
import traceback
from collections.abc import Callable
from pathlib import Path

_MAX_STDIN = 8 * 1024 * 1024
_MAX_ERRLOG = 1024 * 1024


def data_dir() -> Path:
    base = os.environ.get("KAVACH_DATA_DIR")
    if base:
        path = Path(base)
    elif os.environ.get("XDG_DATA_HOME"):
        path = Path(os.environ["XDG_DATA_HOME"]) / "kavach"
    else:
        path = Path.home() / ".local" / "share" / "kavach"
    path.mkdir(parents=True, exist_ok=True)
    with contextlib.suppress(OSError):
        path.chmod(0o700)
    return path


def hmac_salt() -> bytes:
    """Persistent random salt so audit HMACs correlate across hook processes."""
    path = data_dir() / "salt"
    try:
        fd = os.open(path, os.O_WRONLY | os.O_CREAT | os.O_EXCL, 0o600)
    except FileExistsError:
        return path.read_bytes()
    try:
        salt = secrets.token_bytes(32)
        os.write(fd, salt)
        return salt
    finally:
        os.close(fd)


def log_error(message: str) -> None:
    path = data_dir() / "hook-errors.log"
    try:
        if path.exists() and path.stat().st_size > _MAX_ERRLOG:
            path.unlink()
        with path.open("a", encoding="utf-8") as f:
            f.write(f"[{time.strftime('%Y-%m-%dT%H:%M:%S%z')}]\n{message}\n")
    except OSError:
        pass


def run_hook(handler: Callable[[dict], dict | None]) -> int:
    """Run a handler over stdin/stdout. Always returns 0 (fail open)."""
    try:
        raw = sys.stdin.buffer.read(_MAX_STDIN)
        data = json.loads(raw.decode("utf-8", errors="replace") or "{}")
        if not isinstance(data, dict):
            data = {}
        out = handler(data)
        if out is not None:
            sys.stdout.write(json.dumps(out))
    except Exception:
        log_error(traceback.format_exc())
    return 0
