# Recording the README demo GIF

Use [vhs](https://github.com/charmbracelet/vhs) (`brew install vhs`). Two
scenes; keep the total under 25 seconds — viewers decide in the first 10.

## Scene 1 — `kavach scan` (terminal)

`demo.tape`:

```tape
Output demo.gif
Set FontSize 18
Set Width 1100
Set Height 420
Set Theme "Catppuccin Mocha"

Type "kavach scan 'call Lakshmi at 9876543210, aadhaar 2345 6789 0124'"
Sleep 800ms
Enter
Sleep 4s
```

Money shot: the phone partial-masked, the Aadhaar `[BLOCKED:...]`, the
detection table with checksum confidence.

## Scene 2 — the Claude Code prompt block (screen recording)

1. Fresh Claude Code session with the plugin installed.
2. Type: `my email is sid@example.org, write me a signature` → show the
   block message with the masked copy.
3. Resend the same message → show the "confirmed by resend" banner.

Record with QuickTime/Kap, crop to the terminal, export GIF ≤ 5 MB.

Embed both at the top of README under the badges:

```markdown
<p align="center"><img src="docs/assets/demo.gif" width="700"></p>
```
