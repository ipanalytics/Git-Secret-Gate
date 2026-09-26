"""``python -m git_secret_gate`` — the form the git hooks call, so they never depend on PATH."""

from .cli import main

if __name__ == "__main__":
    raise SystemExit(main())
