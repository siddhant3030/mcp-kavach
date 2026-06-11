"""Masking MCP proxy: front upstream MCP servers you can't modify and scrub
every tool result through the kavach engine.

With a single upstream server, tools are mirrored 1:1 under their original
names. With multiple upstreams, fastmcp prefixes tools as
``{server}_{tool}`` — policy ``match.tool`` globs and hook allowlists must
account for that prefix.
"""

from __future__ import annotations

from typing import Any

from mcp_kavach.audit import AuditSink
from mcp_kavach.engine import Engine
from mcp_kavach.policy import Policy


def build_proxy(
    upstream: Any,
    policy: Policy,
    *,
    scan_arguments: bool = False,
    sink: AuditSink | None = None,
    hmac_salt: bytes | None = None,
    name: str = "kavach-proxy",
):
    """upstream: an ``{"mcpServers": {...}}`` dict (Claude .mcp.json shape),
    a bare ``{name: spec}`` mapping, or a FastMCP instance (tests)."""
    try:
        from fastmcp.server import create_proxy
    except ImportError as err:
        raise ImportError(
            "kavach proxy requires fastmcp — install with: pip install 'mcp-kavach[proxy]'"
        ) from err
    from mcp_kavach.adapters.fastmcp_middleware import KavachMiddleware

    target = upstream
    if isinstance(upstream, dict) and "mcpServers" not in upstream:
        target = {"mcpServers": upstream}
    proxy = create_proxy(target, name=name)
    engine = Engine(policy, sink=sink, hmac_salt=hmac_salt)
    proxy.add_middleware(KavachMiddleware(engine, scan_arguments=scan_arguments))
    return proxy
