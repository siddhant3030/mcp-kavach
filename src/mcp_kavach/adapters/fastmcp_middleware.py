"""FastMCP middleware adapter — scrubs tool results (and optionally
arguments) through a kavach Engine.

Requires the [proxy] extra. The module imports without fastmcp installed;
accessing ``KavachMiddleware`` lazily builds the class (PEP 562) and raises
a clear ImportError if fastmcp is missing.
"""

from __future__ import annotations

import json
from typing import Any

from mcp_kavach.engine import Engine

_cached: type | None = None


def __getattr__(name: str):
    if name == "KavachMiddleware":
        global _cached
        if _cached is None:
            _cached = _build_middleware_class()
        return _cached
    raise AttributeError(f"module {__name__!r} has no attribute {name!r}")


def _build_middleware_class() -> type:
    try:
        from fastmcp.exceptions import ToolError
        from fastmcp.server.middleware import Middleware
        from fastmcp.tools.tool import ToolResult
        from mcp.types import TextContent
    except ImportError as err:
        raise ImportError(
            "KavachMiddleware requires fastmcp — install with: "
            "pip install 'mcp-kavach[proxy]'"
        ) from err

    class KavachMiddleware(Middleware):
        """Engine-backed guardrail for FastMCP servers and proxies.

        block_mode: "result" returns the engine's block payload as an error
        result (the model sees *why*); "error" raises ToolError instead.
        fail_open: if the engine itself fails, False (default) withholds the
        result — the right posture for a privacy gateway.
        """

        def __init__(
            self,
            engine: Engine,
            *,
            scan_arguments: bool = False,
            block_mode: str = "result",
            fail_open: bool = False,
        ) -> None:
            self.engine = engine
            self.scan_arguments = scan_arguments
            self.block_mode = block_mode
            self.fail_open = fail_open

        async def on_call_tool(self, context, call_next):
            tool = context.message.name
            if self.scan_arguments and context.message.arguments:
                request = self.engine.scan_request(tool, context.message.arguments)
                if request.blocked:
                    raise ToolError(request.block_reason or "blocked by mcp-kavach")
                if request.modified:
                    context = context.copy(
                        message=context.message.model_copy(
                            update={"arguments": request.payload}
                        )
                    )
            result = await call_next(context)
            try:
                return self._scrub(tool, result)
            except ToolError:
                raise
            except Exception:
                if self.fail_open:
                    return result
                return ToolResult(
                    content=[
                        TextContent(
                            type="text",
                            text="mcp-kavach failed to scan this result and is "
                            "withholding it (fail-closed).",
                        )
                    ],
                    is_error=True,
                )

        def _scrub(self, tool: str, result):
            blocked_payload: dict | None = None

            structured = getattr(result, "structured_content", None)
            if isinstance(structured, dict):
                scan = self.engine.scan_result(tool, structured)
                if scan.blocked:
                    blocked_payload = scan.payload
                else:
                    structured = scan.payload

            new_blocks = []
            for block in result.content:
                if blocked_payload is None and getattr(block, "type", None) == "text":
                    new_text, blocked_payload = self._scrub_text(tool, block.text)
                    if blocked_payload is None:
                        block = block.model_copy(update={"text": new_text})
                new_blocks.append(block)

            if blocked_payload is not None:
                if self.block_mode == "error":
                    raise ToolError(
                        str(blocked_payload.get("message", "blocked by mcp-kavach"))
                    )
                return ToolResult(
                    content=[
                        TextContent(type="text", text=json.dumps(blocked_payload))
                    ],
                    structured_content=blocked_payload,
                    is_error=True,
                )
            return ToolResult(
                content=new_blocks,
                structured_content=structured,
                meta=getattr(result, "meta", None),
                is_error=getattr(result, "is_error", False),
            )

        def _scrub_text(self, tool: str, text: str) -> tuple[str, dict | None]:
            """Scan one text block. JSON-looking text is parsed first so
            structural path rules apply; re-serialization may normalize
            whitespace, which is acceptable."""
            payload: Any = text
            is_json = False
            if text.lstrip()[:1] in ("{", "["):
                try:
                    payload = json.loads(text)
                    is_json = True
                except ValueError:
                    pass
            scan = self.engine.scan_result(tool, payload)
            if scan.blocked:
                return text, scan.payload
            if is_json:
                return json.dumps(scan.payload, ensure_ascii=False), None
            return scan.payload, None

    return KavachMiddleware
