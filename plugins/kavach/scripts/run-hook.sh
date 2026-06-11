#!/bin/sh
# kavach hook dispatcher. Fails OPEN: if the kavach CLI isn't installed,
# drain stdin and exit 0 silently so the plugin never breaks a session.
# Install the engine with: pip install mcp-kavach
if command -v kavach >/dev/null 2>&1; then
  exec kavach hook "$1"
fi
cat >/dev/null 2>&1
exit 0
