#!/bin/sh
# virelia hook dispatcher. Fails OPEN: if the virelia CLI isn't installed,
# drain stdin and exit 0 silently so the plugin never breaks a session.
# Install the engine with: pip install virelia
if command -v virelia >/dev/null 2>&1; then
  exec virelia hook "$1"
fi
cat >/dev/null 2>&1
exit 0
