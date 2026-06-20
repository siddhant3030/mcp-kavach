"""virelia: privacy guardrail layer for MCP tool traffic."""

from virelia.audit import AuditSink, InMemorySink
from virelia.engine import Engine
from virelia.models import Action, AuditEvent, GuardrailResult, Span
from virelia.policy import Policy, PolicyError, load_policy, load_preset, parse_policy
from virelia.vault import Vault, VaultError

__version__ = "0.3.0"

__all__ = [
    "Action",
    "AuditEvent",
    "AuditSink",
    "Engine",
    "GuardrailResult",
    "InMemorySink",
    "Policy",
    "PolicyError",
    "Span",
    "Vault",
    "VaultError",
    "__version__",
    "load_policy",
    "load_preset",
    "parse_policy",
]
