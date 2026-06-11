"""Reversible tokenization vault — future milestone.

Will hold the deterministic, HMAC-keyed token store that powers
"rehydration": PII leaves as consistent self-describing tokens
([PII:NAME:a1b2c3d4]) and real values are restored only at trusted sinks
that hold the vault key. Planned tiers: in-memory → Redis (TTL) → Postgres.
"""
