#!/bin/sh
# SessionStart check: tell the user when the virelia engine is missing.
cat >/dev/null 2>&1
if command -v virelia >/dev/null 2>&1; then
  exit 0
fi
printf '%s' '{"systemMessage": "virelia plugin: the virelia CLI is not installed, so PII guards are OFF. Install it with: pip install virelia  (or: uv tool install virelia)"}'
exit 0
