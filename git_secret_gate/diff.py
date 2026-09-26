"""Read what a commit or a push would add, without trusting the working tree.

We look at the diff, not at the files: a file can be dirty in ways that never reach the index,
and a push can carry commits whose contents are long gone from the disk. Both cases are exactly
where credentials slip out.
"""

from __future__ import annotations

import subprocess
from dataclasses import dataclass

HEADER = ("+++ b/", "+++ ")
HUNK_PREFIX = "@@ "


@dataclass
class AddedLine:
    path: str
    number: int
    text: str


def git(*args: str) -> tuple[int, str]:
    """Run git and hand back whatever it said — a missing repository is a normal answer."""
    result = subprocess.run(["git", *args], capture_output=True, text=True, check=False, errors="replace")
    return result.returncode, result.stdout


def parse(diff_text: str) -> list[AddedLine]:
    """Every ``+`` line of a unified diff, with the file it belongs to and its real line number."""
    added: list[AddedLine] = []
    path = ""
    number = 0
    for raw in diff_text.splitlines():
        if raw.startswith("diff --git ") or raw.startswith("+++ ") or raw.startswith("--- "):
            if raw.startswith("+++ "):
                path = raw[4:].strip()
                if path == "/dev/null":
                    path = ""
                elif path.startswith("b/"):
                    path = path[2:]
            continue
        if raw.startswith(HUNK_PREFIX):
            try:
                target = raw.split("+", 1)[1].split(" ", 1)[0]
                number = int(target.split(",")[0])
            except (IndexError, ValueError):
                number = 0
            continue
        if raw.startswith("+"):
            if path:
                added.append(AddedLine(path, number, raw[1:]))
            number += 1
        elif raw.startswith("-") and not raw.startswith("---"):
            continue
        elif number:
            number += 1
    return added


def diff_lines(*extra_args: str, rev_range: str | None = None) -> list[AddedLine]:
    """``-U0`` so hunk headers give us exact line numbers and no context lines are scanned."""
    args = ["diff", "-U0", "--no-color", "--no-ext-diff"]
    if rev_range:
        args.append(rev_range)
    else:
        args.append("--cached")
    args.extend(extra_args)
    code, out = git(*args)
    if code not in (0, 1):
        return []
    return parse(out)


def last_commit() -> list[AddedLine]:
    return diff_lines(rev_range="HEAD~1..HEAD")


def files_in(*extra_args: str, rev_range: str | None = None) -> list[str]:
    args = ["diff", "--name-only", "-z"]
    args.append(rev_range if rev_range else "--cached")
    args.extend(extra_args)
    code, out = git(*args)
    if code not in (0, 1):
        return []
    return [name for name in out.split("\0") if name]


def repo_root() -> str | None:
    code, out = git("rev-parse", "--show-toplevel")
    if code != 0:
        return None
    return out.strip() or None
