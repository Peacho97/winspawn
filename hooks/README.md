# hidden_spawn_guard.py

A Claude Code `PreToolUse` hook. It reads the tool-call JSON on stdin and checks
the content being written (`Write` `content`, `Edit` `new_string`) or run
(`Bash` / `PowerShell` `command`) for spawn forms that open a console window.
The patterns come from `winspawn.BANNED_PATTERNS`, so `winspawn` must be
importable (`pip install .`); a built-in copy is used if it is not.

Behaviour: remind once, not a gate. The first time a (pattern, target) pair
appears in a session the hook exits 2 and prints the safe replacement to
stderr, which Claude Code feeds back to the model. A retry of the same call
passes. Any malformed payload or exception exits 0 (fail open). Files named
`winspawn.py`, `hidden_spawn_guard.py` and anything under a `tests/` directory
are skipped.

Register it in `~/.claude/settings.json` (or a project `.claude/settings.json`):

```json
{
  "hooks": {
    "PreToolUse": [
      {
        "matcher": "Write|Edit|Bash|PowerShell",
        "hooks": [
          { "type": "command", "command": "python /path/to/hooks/hidden_spawn_guard.py" }
        ]
      }
    ]
  }
}
```

Payload shape consumed (fields not listed are ignored):

```json
{ "session_id": "abc", "tool_name": "Write",
  "tool_input": { "file_path": "run.py", "content": "..." } }
```

Reminder state is stored under `~/.claude/gate-state/<session_id>/`.

## Escape

Put `spawn-hidden-ok: <reason>` in a comment on the flagged line or the line
directly above it:

```python
flags = subprocess.CREATE_NEW_CONSOLE  # spawn-hidden-ok: interactive installer must show a window
```

Use `//` in JavaScript and `#` in Python and PowerShell. Both the hook and
`python -m winspawn --audit` skip the line.
