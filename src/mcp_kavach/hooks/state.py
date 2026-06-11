"""Pending-confirmation store for the confirm-by-resend flow.

A blocked prompt's hash is parked here; resending the identical prompt
within the window consumes the entry and lets it through.
"""

from __future__ import annotations

import json
import os
import time
from pathlib import Path

from mcp_kavach.hooks.runner import data_dir

_MAX_PENDING = 20
_STALE_FILE_SECONDS = 24 * 3600


def _path(session_id: str) -> Path:
    safe = "".join(ch for ch in session_id if ch.isalnum() or ch in "-_") or "global"
    return data_dir() / f"pending-{safe}.json"


def _load(path: Path) -> dict[str, float]:
    try:
        data = json.loads(path.read_text())
        return {str(k): float(v) for k, v in data.items()} if isinstance(data, dict) else {}
    except (OSError, ValueError):
        return {}


def _write(path: Path, entries: dict[str, float]) -> None:
    if not entries:
        path.unlink(missing_ok=True)
        return
    tmp = path.with_suffix(".tmp")
    tmp.write_text(json.dumps(entries))
    os.replace(tmp, path)


def _prune_stale_files() -> None:
    now = time.time()
    for p in data_dir().glob("pending-*.json"):
        try:
            if now - p.stat().st_mtime > _STALE_FILE_SECONDS:
                p.unlink()
        except OSError:
            pass


def consume(session_id: str, digest: str, window_seconds: int) -> bool:
    """True if this digest was pending and fresh; the entry is removed."""
    path = _path(session_id)
    now = time.time()
    entries = {k: v for k, v in _load(path).items() if now - v <= window_seconds}
    hit = entries.pop(digest, None) is not None
    _write(path, entries)
    return hit


def store(session_id: str, digest: str, window_seconds: int) -> None:
    _prune_stale_files()
    path = _path(session_id)
    now = time.time()
    entries = {k: v for k, v in _load(path).items() if now - v <= window_seconds}
    entries[digest] = now
    if len(entries) > _MAX_PENDING:
        for key in sorted(entries, key=entries.get)[: len(entries) - _MAX_PENDING]:
            del entries[key]
    _write(path, entries)
