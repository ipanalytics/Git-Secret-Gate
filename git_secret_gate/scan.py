"""Scan one added line, or one staged path, and describe what is wrong — never what it holds.

The report deliberately does not print the secret. A gate that echoes the credential into a CI
log turns a local mistake into a public one, so every match is masked down to a recognisable
prefix and its length.

Two things can silence a rule on purpose: the marker ``secret-gate: allow`` on the line itself
(for fixtures and examples), or an ``ignore_paths`` entry in the config.
"""

from __future__ import annotations

import math
import re
from dataclasses import dataclass

from . import patterns as rules

ALLOW_MARKER = "secret-gate: allow"
ENTROPY_MIN = 4.0
ENTROPY_RE = re.compile(r"[A-Za-z0-9+/=_\-]{24,}")
PATH_KINDS = (rules.POLICY,)


@dataclass
class Finding:
    rule: str
    severity: str
    kind: str
    path: str
    line: int
    masked: str
    hint: str

    @property
    def blocks(self) -> bool:
        return self.severity == rules.BLOCK


def mask(value: str) -> str:
    """Enough to recognise, not enough to use."""
    value = " ".join(value.strip().split())
    if len(value) <= 8:
        return "*" * len(value)
    return f"{value[:3]}…({len(value)} chars)"


def entropy(value: str) -> float:
    counts: dict = {}
    for char in value:
        counts[char] = counts.get(char, 0) + 1
    total = len(value)
    return -sum((count / total) * math.log2(count / total) for count in counts.values())


def looks_random(token: str) -> bool:
    """A long token with mixed case, digits and high entropy — the shape of a key, not of prose."""
    if len(token) < 24 or token.lower().startswith(("http", "www", "sha", "md5")):
        return False
    mixed = any(char.islower() for char in token) and any(char.isupper() for char in token)
    return mixed and any(char.isdigit() for char in token) and entropy(token) >= ENTROPY_MIN


def scan_text(path: str, line_no: int, text: str, *, kinds=None, extra=()) -> list[Finding]:
    """Rules that look at content: secrets, dangerous commands, private addresses."""
    if ALLOW_MARKER in text:
        return []
    found = []
    for rule in list(extra) + rules.ALL_RULES:
        if rule.where != "text":
            continue
        if kinds and rule.kind not in kinds:
            continue
        match = re.search(rule.pattern, text)
        if match:
            found.append(Finding(rule.id, rule.severity, rule.kind, path, line_no, mask(match.group(0)), rule.hint))
    for token in ENTROPY_RE.findall(text):
        if looks_random(token) and not any(item.rule == "high-entropy-string" for item in found):
            found.append(
                Finding(
                    "high-entropy-string",
                    rules.WARN,
                    rules.SECRET,
                    path,
                    line_no,
                    mask(token),
                    "a long random-looking literal: if it is a key, rotate it and read it from the environment; "
                    "if it is a checksum or fixture, add `secret-gate: allow` on the line.",
                )
            )
    return found


def scan_path(path: str, *, kinds=None, extra=()) -> list[Finding]:
    """Rules that look at the file name: key material, env files, credential stores."""
    found = []
    for rule in list(extra) + rules.ALL_RULES:
        if rule.where != "path":
            continue
        if kinds and rule.kind not in kinds:
            continue
        if re.search(rule.pattern, path):
            found.append(Finding(rule.id, rule.severity, rule.kind, path, 0, path, rule.hint))
    return found
