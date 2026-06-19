"""Reversible tokenization vault: the coat check for PII.

The same value always yields the same stable token within a scope
([PERSON_NAME_1], [PHONE_2], ...), so referential integrity survives
masking — five rows about one person stay recognizably one person. The
original values are stored locally, encrypted at rest, and only
``rehydrate()`` (the trusted-sink path) ever turns tokens back into them.

Storage is a single SQLite file (stdlib ``sqlite3``) at
``$VIRELIA_DATA_DIR/vault.db``, mode 0600. Lookups never store plaintext
keys: values are located by a salted HMAC (same construction as
``audit.hmac_value``) with the salt derived from the vault key, and the
value itself is encrypted with Fernet (AES-128-CBC + HMAC, from the
``cryptography`` package — installed via ``virelia[vault]``). Fernet
was chosen over a hand-rolled stdlib cipher: the stdlib has no
authenticated encryption, and a security project should not improvise
one; the dependency stays behind an extra so the base install remains
stdlib + pydantic + pyyaml.
"""

from __future__ import annotations

import os
import re
import sqlite3
import threading
from datetime import datetime, timezone
from pathlib import Path

from virelia.audit import hmac_value

DEFAULT_SCOPE = "default"

# A token is [LABEL_N] where LABEL is the normalized entity type. Labels
# never contain digits, so the greedy match cannot eat the counter.
_TOKEN_RE = re.compile(r"\[([A-Z][A-Z_]*)_(\d+)\]")

_SCHEMA = """
CREATE TABLE IF NOT EXISTS vault (
    scope TEXT NOT NULL,
    entity_type TEXT NOT NULL,
    value_hmac TEXT NOT NULL,
    encrypted_value BLOB NOT NULL,
    token_id INTEGER NOT NULL,
    created_at TEXT NOT NULL,
    PRIMARY KEY (scope, entity_type, value_hmac),
    UNIQUE (scope, entity_type, token_id)
)
"""


class VaultError(RuntimeError):
    pass


def default_vault_path() -> Path:
    from virelia.hooks.runner import data_dir

    return data_dir() / "vault.db"


def _label(entity_type: str) -> str:
    """Normalize an entity type into a token label (A-Z and _ only)."""
    label = re.sub(r"[^A-Z_]+", "_", entity_type.upper()).strip("_")
    if not label:
        raise VaultError(f"cannot derive a token label from entity type {entity_type!r}")
    return label


def _create_private_file(path: Path, content: bytes | None = None) -> bool:
    """Create ``path`` with mode 0600 if missing. Returns True if created."""
    path.parent.mkdir(parents=True, exist_ok=True)
    try:
        fd = os.open(path, os.O_WRONLY | os.O_CREAT | os.O_EXCL, 0o600)
    except FileExistsError:
        return False
    try:
        if content is not None:
            os.write(fd, content)
    finally:
        os.close(fd)
    return True


class Vault:
    """Token store. One vault file can hold many scopes; a :class:`Vault`
    instance is bound to one scope (token counters and rehydration are
    per-scope, so two sessions never see each other's mappings)."""

    def __init__(self, path: str | Path | None = None, *, scope: str = DEFAULT_SCOPE) -> None:
        try:
            from cryptography.fernet import Fernet
        except ImportError as err:  # pragma: no cover - exercised only without the extra
            raise VaultError(
                "the tokenization vault requires the 'cryptography' package — "
                "install with: pip install 'virelia[vault]'"
            ) from err

        self.path = Path(path) if path is not None else default_vault_path()
        self.scope = scope
        key = self._load_or_create_key(self.path.with_suffix(".key"), Fernet)
        self._fernet = Fernet(key)
        # Salt for value lookups, derived from the key so it survives
        # restarts but is useless without the key file. Domain-separated
        # from Fernet's own use of the key material.
        import hashlib

        self._salt = hashlib.sha256(b"virelia.vault.hmac-salt:" + key).digest()
        _create_private_file(self.path)  # exists with 0600 before sqlite opens it
        self._conn = sqlite3.connect(self.path, check_same_thread=False)
        self._conn.execute(_SCHEMA)
        self._conn.commit()
        self._lock = threading.Lock()

    @staticmethod
    def _load_or_create_key(path: Path, fernet_cls: type) -> bytes:
        if not _create_private_file(path, key := fernet_cls.generate_key()):
            key = path.read_bytes().strip()
        return key

    # -- tokenize -------------------------------------------------------

    def token_for(self, entity_type: str, value: str) -> str:
        """Return the stable token for ``value``, minting one on first sight."""
        label = _label(entity_type)
        mac = hmac_value(self._salt, value)
        with self._lock:
            for _ in range(8):  # retry on counter races with other processes
                row = self._conn.execute(
                    "SELECT token_id FROM vault"
                    " WHERE scope = ? AND entity_type = ? AND value_hmac = ?",
                    (self.scope, label, mac),
                ).fetchone()
                if row is not None:
                    return f"[{label}_{row[0]}]"
                next_id = self._conn.execute(
                    "SELECT COALESCE(MAX(token_id), 0) + 1 FROM vault"
                    " WHERE scope = ? AND entity_type = ?",
                    (self.scope, label),
                ).fetchone()[0]
                try:
                    self._conn.execute(
                        "INSERT INTO vault VALUES (?, ?, ?, ?, ?, ?)",
                        (
                            self.scope,
                            label,
                            mac,
                            self._fernet.encrypt(value.encode("utf-8")),
                            next_id,
                            datetime.now(timezone.utc).isoformat(),
                        ),
                    )
                    self._conn.commit()
                    return f"[{label}_{next_id}]"
                except sqlite3.IntegrityError:
                    self._conn.rollback()  # another writer won; re-read
        raise VaultError("could not allocate a token after repeated conflicts")

    # -- rehydrate (trusted sink) ----------------------------------------

    def lookup(self, token: str) -> str | None:
        """Original value for one exact token, or None if unknown here."""
        m = _TOKEN_RE.fullmatch(token)
        if m is None:
            return None
        row = self._conn.execute(
            "SELECT encrypted_value FROM vault"
            " WHERE scope = ? AND entity_type = ? AND token_id = ?",
            (self.scope, m.group(1), int(m.group(2))),
        ).fetchone()
        if row is None:
            return None
        from cryptography.fernet import InvalidToken

        try:
            return self._fernet.decrypt(row[0]).decode("utf-8")
        except InvalidToken as err:
            raise VaultError(
                f"vault key at {self.path.with_suffix('.key')} cannot decrypt "
                f"{token} — was the key file replaced?"
            ) from err

    def rehydrate(self, payload: object) -> object:
        """Replace every known token in a payload (str/dict/list, nested)
        with its original value. Unknown tokens pass through unchanged."""
        if isinstance(payload, str):
            return _TOKEN_RE.sub(
                lambda m: self.lookup(m.group(0)) or m.group(0), payload
            )
        if isinstance(payload, dict):
            return {k: self.rehydrate(v) for k, v in payload.items()}
        if isinstance(payload, list):
            return [self.rehydrate(v) for v in payload]
        return payload

    # -- lifecycle --------------------------------------------------------

    def close(self) -> None:
        self._conn.close()

    def __enter__(self) -> Vault:
        return self

    def __exit__(self, *exc: object) -> None:
        self.close()


def rehydrate(
    payload: object, *, path: str | Path | None = None, scope: str = DEFAULT_SCOPE
) -> object:
    """One-shot trusted-sink helper: open the vault, restore originals, close."""
    with Vault(path, scope=scope) as vault:
        return vault.rehydrate(payload)
