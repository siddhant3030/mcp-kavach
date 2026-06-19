"""Reversible tokenization vault.

PII leaves as consistent, self-describing tokens ([PERSON_NAME_1],
[PHONE_2]) and the real values are restored only by ``rehydrate()`` at a
trusted sink that holds the vault key. See docs/vault.md.
"""

from virelia.vault.store import DEFAULT_SCOPE, Vault, VaultError, default_vault_path, rehydrate

__all__ = ["DEFAULT_SCOPE", "Vault", "VaultError", "default_vault_path", "rehydrate"]
