"""Masking MCP proxy: front upstream MCP servers you can't modify and scrub
every tool result through the virelia engine.

With a single upstream server, tools are mirrored 1:1 under their original
names. With multiple upstreams, fastmcp prefixes tools as
``{server}_{tool}`` — policy ``match.tool`` globs and hook allowlists must
account for that prefix.
"""

from __future__ import annotations

from typing import Any

from virelia.audit import AuditSink
from virelia.engine import Engine
from virelia.policy import Policy
from virelia.transform import TokenVault


def build_proxy(
    upstream: Any,
    policy: Policy,
    *,
    scan_arguments: bool = False,
    sink: AuditSink | None = None,
    hmac_salt: bytes | None = None,
    name: str = "virelia-proxy",
    vault: TokenVault | None = None,
):
    """upstream: an ``{"mcpServers": {...}}`` dict (Claude .mcp.json shape),
    a bare ``{name: spec}`` mapping, or a FastMCP instance (tests)."""
    try:
        from fastmcp.server import create_proxy
    except ImportError as err:
        raise ImportError(
            "virelia proxy requires fastmcp — install with: pip install 'virelia[proxy]'"
        ) from err
    from virelia.adapters.fastmcp_middleware import VireliaMiddleware

    target = upstream
    if isinstance(upstream, dict) and "mcpServers" not in upstream:
        target = {"mcpServers": upstream}
    proxy = create_proxy(target, name=name)
    engine = Engine(policy, sink=sink, hmac_salt=hmac_salt, vault=vault)
    proxy.add_middleware(VireliaMiddleware(engine, scan_arguments=scan_arguments))
    return proxy
