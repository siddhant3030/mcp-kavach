"""Claude Code hook handlers.

Each handler reads one JSON object on stdin and writes one JSON object to
stdout. Handlers always exit 0 and never raise to the caller — a broken
guard must never break someone's session (fail open). Errors land in
``<data_dir>/hook-errors.log``.
"""
