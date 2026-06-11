"""Middleware + proxy tests. Skipped when fastmcp isn't installed (it's in
the dev dependency group; the base package doesn't require it)."""

import asyncio
import builtins
import json

import pytest
from conftest import VALID_AADHAAR

from mcp_kavach import Engine, load_preset

fastmcp = pytest.importorskip("fastmcp")


def make_upstream():
    server = fastmcp.FastMCP("upstream")

    @server.tool
    def get_user() -> dict:
        return {"name": "Lakshmi Devi", "email": "lakshmi@example.org", "aadhaar": VALID_AADHAAR}

    @server.tool
    def echo(text: str) -> str:
        return text

    @server.tool
    def leak_secret() -> dict:
        return {"token": "ghp_AbCdEfGhIjKlMnOpQrStUvWxYz0123456789"}

    return server


def call(server, tool, args=None):
    async def run():
        async with fastmcp.Client(server) as client:
            return await client.call_tool(tool, args or {}, raise_on_error=False)

    return asyncio.run(run())


def make_engine(preset="ngo-default"):
    return Engine(load_preset(preset), hmac_salt=b"test")


def with_middleware(server, engine, **kwargs):
    from mcp_kavach.adapters.fastmcp_middleware import KavachMiddleware

    server.add_middleware(KavachMiddleware(engine, **kwargs))
    return server


class TestMiddleware:
    def test_masks_tool_result(self):
        server = with_middleware(make_upstream(), make_engine())
        result = call(server, "get_user")
        dump = json.dumps([c.model_dump(mode="json") for c in result.content]) + json.dumps(
            result.structured_content or {}
        )
        assert "lakshmi@example.org" not in dump
        assert "Lakshmi Devi" not in dump
        assert VALID_AADHAAR not in dump
        assert "BLOCKED" in dump  # aadhaar field marker

    def test_result_scope_block_becomes_error(self):
        server = with_middleware(make_upstream(), make_engine("strict"))
        result = call(server, "leak_secret")
        assert result.is_error
        dump = json.dumps([c.model_dump(mode="json") for c in result.content])
        assert "ghp_" not in dump

    def test_scan_arguments_rewrites_input(self):
        server = with_middleware(make_upstream(), make_engine(), scan_arguments=True)
        result = call(server, "echo", {"text": "mail lakshmi@example.org"})
        dump = json.dumps([c.model_dump(mode="json") for c in result.content])
        assert "lakshmi@example.org" not in dump
        assert "l***@example.org" in dump

    def test_clean_result_untouched(self):
        server = with_middleware(make_upstream(), make_engine())
        result = call(server, "echo", {"text": "all good"})
        assert "all good" in json.dumps([c.model_dump(mode="json") for c in result.content])
        assert not result.is_error


class TestProxy:
    def test_proxy_mirrors_tools_and_masks(self):
        from mcp_kavach.adapters.proxy import build_proxy

        proxy = build_proxy(make_upstream(), load_preset("ngo-default"), hmac_salt=b"t")

        async def run():
            async with fastmcp.Client(proxy) as client:
                tools = {t.name for t in await client.list_tools()}
                result = await client.call_tool("get_user", {}, raise_on_error=False)
                return tools, result

        tools, result = asyncio.run(run())
        assert {"get_user", "echo", "leak_secret"} <= tools  # 1:1, no meta-tool
        dump = json.dumps([c.model_dump(mode="json") for c in result.content])
        assert "lakshmi@example.org" not in dump


class TestLazyImport:
    def test_missing_fastmcp_gives_actionable_error(self, monkeypatch):
        import mcp_kavach.adapters.fastmcp_middleware as mod

        monkeypatch.setattr(mod, "_cached", None)
        real_import = builtins.__import__

        def fake_import(name, *args, **kwargs):
            if name.startswith("fastmcp"):
                raise ImportError(name)
            return real_import(name, *args, **kwargs)

        monkeypatch.setattr(builtins, "__import__", fake_import)
        with pytest.raises(ImportError, match=r"mcp-kavach\[proxy\]"):
            _ = mod.KavachMiddleware
        monkeypatch.setattr(mod, "_cached", None)
