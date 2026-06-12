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
    scan_p.add_argument(
        "--vault", nargs="?", const="", metavar="PATH",
        help="enable tokenize actions; optional vault path (default: "
        "$KAVACH_DATA_DIR/vault.db)",
    )
    scan_p.add_argument("--scope", default=None, help="vault scope (default: 'default')")

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
    proxy_p.add_argument(
        "--audit",
        help="write hash-only audit events here: a .jsonl path, "
        "a .db/.sqlite path, or a postgres:// URL",
    )
    proxy_p.add_argument("--name", default="kavach-proxy")
    proxy_p.add_argument(
        "--vault", nargs="?", const="", metavar="PATH",
        help="enable tokenize actions; optional vault path (default: "
        "$KAVACH_DATA_DIR/vault.db)",
    )
    proxy_p.add_argument("--scope", default=None, help="vault scope (default: 'default')")

    rehydrate_p = sub.add_parser(
        "rehydrate",
        help="trusted sink: replace [ENTITY_N] tokens with their original values",
    )
    rehydrate_p.add_argument(
        "file", nargs="?", help="file to rehydrate (default: read stdin)"
    )
    rehydrate_p.add_argument(
        "--vault", metavar="PATH",
        help="vault path (default: $KAVACH_DATA_DIR/vault.db)",
    )
    rehydrate_p.add_argument("--scope", default=None, help="vault scope (default: 'default')")

    audit_p = sub.add_parser("audit", help="inspect the hash-only audit log")
    audit_sub = audit_p.add_subparsers(dest="audit_command", required=True)
    source_help = (
        "audit source: a .jsonl path, a .db/.sqlite path, or a postgres:// URL "
        "(default: where the hooks write)"
    )
    report_p = audit_sub.add_parser(
        "report", help="per-entity / per-action / per-tool aggregates"
    )
    report_p.add_argument("--since", help="ISO date or datetime (naive = UTC)")
    report_p.add_argument("--until", help="ISO date or datetime (naive = UTC)")
    report_p.add_argument("--policy", help="only events recorded under this policy name")
    report_p.add_argument("--source", help=source_help)
    tail_p = audit_sub.add_parser("tail", help="stream new audit events as they land")
    tail_p.add_argument("--source", help=source_help)

    sub.add_parser("version", help="print version")

    args = parser.parse_args(argv)
    if args.command == "hook":
        return _hook(args.event)
    if args.command == "scan":
        return _scan(args)
    if args.command == "proxy":
        return _proxy(args)
    if args.command == "audit":
        return _audit(args)
    if args.command == "rehydrate":
        return _rehydrate(args)
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


def _open_vault(args: argparse.Namespace):
    """--vault with no value means 'use the default path'; absent means None."""
    if getattr(args, "vault", None) is None:
        return None
    from mcp_kavach.vault import DEFAULT_SCOPE, Vault

    return Vault(args.vault or None, scope=args.scope or DEFAULT_SCOPE)


def _scan(args: argparse.Namespace) -> int:
    from mcp_kavach.engine import Engine
    from mcp_kavach.hooks.config import resolve_policy

    engine = Engine(
        resolve_policy(args.policy), hmac_salt=b"kavach-scan-dry-run", vault=_open_vault(args)
    )
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


def _audit(args: argparse.Namespace) -> int:
    from mcp_kavach.cli.audit import run_report, run_tail

    if args.audit_command == "report":
        return run_report(args.source, args.since, args.until, args.policy)
    return run_tail(args.source)


def _proxy(args: argparse.Namespace) -> int:
    import logging

    # stdio mode: stdout is the MCP protocol channel — logs go to stderr.
    logging.basicConfig(stream=sys.stderr, level=logging.INFO)

    from mcp_kavach.adapters.proxy import build_proxy
    from mcp_kavach.audit import open_sink
    from mcp_kavach.hooks.config import resolve_policy
    from mcp_kavach.hooks.runner import hmac_salt

    path = Path(args.config)
    text = path.read_text()
    config = yaml.safe_load(text) if path.suffix in (".yaml", ".yml") else json.loads(text)
    proxy = build_proxy(
        config,
        resolve_policy(args.policy),
        scan_arguments=args.scan_arguments,
        sink=open_sink(args.audit) if args.audit else None,
        hmac_salt=hmac_salt(),
        name=args.name,
        vault=_open_vault(args),
    )
    proxy.run()
    return 0


def _rehydrate(args: argparse.Namespace) -> int:
    from mcp_kavach.vault import DEFAULT_SCOPE, Vault

    text = Path(args.file).read_text() if args.file else sys.stdin.read()
    with Vault(args.vault, scope=args.scope or DEFAULT_SCOPE) as vault:
        sys.stdout.write(vault.rehydrate(text))
    return 0


if __name__ == "__main__":
    sys.exit(main())
