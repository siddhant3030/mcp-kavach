#!/bin/sh
# SessionStart check: tell the user when the kavach engine is missing.
cat >/dev/null 2>&1
if command -v kavach >/dev/null 2>&1; then
  exit 0
fi
printf '%s' '{"systemMessage": "kavach plugin: the kavach CLI is not installed, so PII guards are OFF. Install it with: pip install mcp-kavach  (or: uv tool install mcp-kavach)"}'
exit 0
