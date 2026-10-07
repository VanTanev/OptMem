# Windows support

OptMem now runs on native Windows (no WSL required).

## What changed
- `import fcntl` is guarded — falls back to `None` on platforms without it.
- `locked()` uses `msvcrt` advisory locking with spin/backoff when `fcntl`
  is unavailable, so parallel sessions (the documented multi-process case)
  queue instead of raising `Resource deadlock avoided`.
- The `.lock` file is opened in append mode (`"a"`) rather than `"w"`, which
  would truncate and break locks held by other processes on Windows.

## Test (Windows native, no WSL)
```bat
python memo init
set MEMORY_DIR=C:\path\to\mem
python memo note "first memory"
python memo note "second memory"
python memo wake
```
## Orders on stdin

`memo` prints the commands it gives an agent as a quoted POSIX heredoc
(`memo note - <<'MEMO'`), so nothing in a memory line can run in the shell.
Git Bash, which Claude Code uses on Windows, runs them as printed.
PowerShell cannot parse a heredoc, so there the order fails before anything
runs. In PowerShell, pass the line as one argument instead of `-`, in single
quotes so nothing in it expands:

```powershell
python memo note 'one memory line'
python memo nap 0-1 'one summary line'
```

Concurrency: 8 parallel `memo note` processes writing 1600 memories
resulted in 1600/1600 records persisted (lock verified).
