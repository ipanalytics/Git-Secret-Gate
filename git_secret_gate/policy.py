"""The gate's own policy: what to ignore, which rules to mute, and extra rules of your own.

The file is ``secret-gate.toml`` at the repository root (``secret-gate.json`` also works, for
machines that ship an older Python). Everything is optional; the defaults below are the ones we
run with, and they deliberately do **not** ignore markdown: documentation is where leaked
credentials most often sit. Examples in docs are silenced with the marker on the line instead.
"""

from __future__ import annotations

import json
import pathlib
import re
from dataclasses import dataclass

from . import patterns as rules

CONFIG_NAMES = ("secret-gate.toml", "secret-gate.json")
DEFAULTS: dict = {
    "kinds": [rules.SECRET, rules.COMMAND, rules.POLICY],
    "ignore_paths": [
        "tests/fixtures/**",
        "testdata/**",
        "*.lock",
        "package-lock.json",
        "node_modules/**",
        ".venv/**",
        "vendor/**",
    ],
    "ignore_rules": [],
    "extra_rules": [],
    "warn_as_error": False,
    "check_entropy": True,
}


class ConfigError(ValueError):
    """A configuration file we refuse to guess about."""


@dataclass
class Policy:
    config: dict
    path: pathlib.Path | None = None

    @property
    def kinds(self) -> list:
        return list(self.config.get("kinds") or [])

    @property
    def extra_rules(self):
        compiled = []
        for item in self.config.get("extra_rules") or []:
            missing = [key for key in ("id", "pattern", "hint") if not item.get(key)]
            if missing:
                raise ConfigError(f"extra rule {item.get('id') or item!r} is missing: {', '.join(missing)}")
            try:
                re.compile(item["pattern"])
            except re.error as exc:
                raise ConfigError(f"extra rule {item['id']} has a broken pattern: {exc}") from exc
            compiled.append(
                rules.Rule(
                    id=str(item["id"]),
                    kind=str(item.get("kind", rules.SECRET)),
                    severity=str(item.get("severity", rules.BLOCK)),
                    pattern=str(item["pattern"]),
                    hint=str(item["hint"]),
                    where=str(item.get("where", "text")),
                )
            )
        return compiled

    def ignored(self, path: str) -> bool:
        from fnmatch import fnmatch

        return any(fnmatch(path, pattern) for pattern in self.config.get("ignore_paths") or [])

    def muted(self, rule_id: str) -> bool:
        return rule_id in set(self.config.get("ignore_rules") or [])

    def failing_severities(self) -> set:
        severities = {rules.BLOCK}
        if self.config.get("warn_as_error"):
            severities.add(rules.WARN)
        return severities


def find(start: pathlib.Path) -> pathlib.Path | None:
    for directory in [start, *start.parents]:
        for name in CONFIG_NAMES:
            candidate = directory / name
            if candidate.is_file():
                return candidate
    return None


def load(path: pathlib.Path | None = None) -> Policy:
    if path is None:
        return Policy(dict(DEFAULTS))
    try:
        text = path.read_text(encoding="utf-8")
    except OSError as exc:
        raise ConfigError(f"cannot read {path}: {exc}") from exc
    if path.suffix == ".json":
        raw = json.loads(text)
    else:
        try:
            import tomllib
        except ModuleNotFoundError as exc:  # Python < 3.11
            raise ConfigError("secret-gate.toml needs Python 3.11+; use secret-gate.json on older machines") from exc
        raw = tomllib.loads(text)
    if not isinstance(raw, dict):
        raise ConfigError(f"{path} must contain a table of settings")
    unknown = sorted(set(raw) - set(DEFAULTS))
    if unknown:
        raise ConfigError(f"{path} has keys the gate does not know: {', '.join(unknown)}")
    return Policy({**DEFAULTS, **raw}, path)
