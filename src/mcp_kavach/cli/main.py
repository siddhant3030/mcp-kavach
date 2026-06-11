"""kavach CLI: hook handlers, dry-run scanning, and the masking MCP proxy."""

from __future__ import annotations

import argparse
import json
import sys
from pathlib import Path

import yaml


def main(argv: list[str] | None = None) -> int:
    parser = argparse.ArgumentParser(
        prog="kavach",
        description="Privacy guardrail for MCP tool traffic and Claude Code.",
    )
    sub = parser.add_subparsers(dest="command", required=True)

    hook_p = sub.add_parser(
        "hook", help="Claude Code hook handler (stdin JSON -> stdout JSON, always exit 0)"
    )
    hook_p.add_argument(
        "event", choices=["prompt-guard", "tool-input-guard", "tool-output-guard"]
    )

    scan_p = sub.add_parser("scan", help="dry-run a policy against text")
    scan_p.add_argument("text")
    scan_p.add_argument("--policy", default="personal", help="preset name or YAML path")

    proxy_p = sub.add_parser(
        "proxy", help="run a masking MCP proxy over upstream servers (stdio)"
    )
    proxy_p.add_argument(
        "--config", required=True, help="JSON/YAML file with an mcpServers mapping"
    )
    proxy_p.add_argument("--policy", default="personal", help="preset name or YAML path")
    proxy_p.add_argument(
        "--scan-arguments", action="store_true", help="also scrub tool arguments"
    )
    proxy_p.add_argument("--audit", help="append hash-only audit events to this JSONL file")
    proxy_p.add_argument("--name", default="kavach-proxy")

    sub.add_parser("version", help="print version")

    args = parser.parse_args(argv)
    if args.command == "hook":
        return _hook(args.event)
    if args.command == "scan":
        return _scan(args)
    if args.command == "proxy":
        return _proxy(args)
    from mcp_kavach import __version__

    print(f"mcp-kavach {__version__}")
    return 0


def _hook(event: str) -> int:
    from mcp_kavach.hooks import prompt_guard, tool_input, tool_output
    from mcp_kavach.hooks.runner import run_hook

    handlers = {
        "prompt-guard": prompt_guard.handle,
        "tool-input-guard": tool_input.handle,
        "tool-output-guard": tool_output.handle,
    }
    return run_hook(handlers[event])


def _scan(args: argparse.Namespace) -> int:
    from mcp_kavach.engine import Engine
    from mcp_kavach.hooks.config import resolve_policy

    engine = Engine(resolve_policy(args.policy), hmac_salt=b"kavach-scan-dry-run")
    result = engine.scan_request("scan", args.text)
    print(result.payload)
    if result.events:
        print()
        print(f"{'ENTITY':<16} {'ACTION':<13} {'RULE':<24} {'TIER':<4} CONF")
        for e in result.events:
            rule = e.rule_id or "(default)"
            row = f"{e.entity_type:<16} {e.action.value:<13} {rule:<24} {e.tier:<4}"
            print(f"{row} {e.confidence:.2f}")
    else:
        print("\nno PII detected", file=sys.stderr)
    return 0


def _proxy(args: argparse.Namespace) -> int:
    import logging

    # stdio mode: stdout is the MCP protocol channel — logs go to stderr.
    logging.basicConfig(stream=sys.stderr, level=logging.INFO)

    from mcp_kavach.adapters.proxy import build_proxy
    from mcp_kavach.audit import JsonlSink
    from mcp_kavach.hooks.config import resolve_policy
    from mcp_kavach.hooks.runner import hmac_salt

    path = Path(args.config)
    text = path.read_text()
    config = yaml.safe_load(text) if path.suffix in (".yaml", ".yml") else json.loads(text)
    proxy = build_proxy(
        config,
        resolve_policy(args.policy),
        scan_arguments=args.scan_arguments,
        sink=JsonlSink(args.audit) if args.audit else None,
        hmac_salt=hmac_salt(),
        name=args.name,
    )
    proxy.run()
    return 0


if __name__ == "__main__":
    sys.exit(main())
