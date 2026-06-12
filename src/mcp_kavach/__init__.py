"""mcp-kavach: privacy guardrail layer for MCP tool traffic."""

from mcp_kavach.audit import AuditSink, InMemorySink
from mcp_kavach.engine import Engine
from mcp_kavach.models import Action, AuditEvent, GuardrailResult, Span
from mcp_kavach.policy import Policy, PolicyError, load_policy, load_preset, parse_policy
from mcp_kavach.vault import Vault, VaultError

__version__ = "0.2.0"

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
