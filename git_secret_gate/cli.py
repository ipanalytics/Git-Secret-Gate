"""secret-gate — stop a credential before it leaves the machine.

    secret-gate check                  screen what a commit would add (the default)
    secret-gate check --range A..B     screen a range, which is what a push hook does
    secret-gate check --file notes.txt scan a file on disk, no git involved
    secret-gate install                write .git/hooks/pre-commit and pre-push
    secret-gate init                   write a starter secret-gate.toml
    secret-gate rules                  list every rule, its severity and what it means

All options are top level on purpose: a hook command is written once by a machine and read later
by a human, so `check --staged --quiet` must work in any order.
"""

from __future__ import annotations

import argparse
import pathlib
import stat
import sys

from . import diff as diff_mod
from . import patterns as rules
from . import policy as policy_mod
from . import report as report_mod
from . import scan
from .policy import ConfigError

EXIT_CLEAN, EXIT_FOUND, EXIT_USAGE = 0, 1, 2
HOOK_TEMPLATE = (
    "#!/bin/sh\n"
    "# written by git-secret-gate — delete this file to uninstall\n"
    'exec {python} -m git_secret_gate check {args} "$@"\n'
)
STARTER_CONFIG = """# secret-gate policy. Everything here is optional.
kinds = ["secret", "command", "policy"]
warn_as_error = false
check_entropy = true

# Paths the gate does not look at. Documentation is deliberately not here.
ignore_paths = ["tests/fixtures/**", "*.lock", "node_modules/**"]

# Rule ids to mute in this repository, e.g. ["private-ip"].
ignore_rules = []

# Your own patterns, in the same shape as the built-in ones.
# [[extra_rules]]
# id = "internal-hostname"
# pattern = "\\\\b[a-z0-9-]+\\\\.our\\\\.lan\\\\b"
# severity = "block"
# kind = "policy"
# hint = "an internal host name: keep it in a local config."
"""


def build_parser() -> argparse.ArgumentParser:
    parser = argparse.ArgumentParser(
        prog="secret-gate",
        description="Screen a commit or a push for credentials, key files and destructive commands.",
    )
    parser.add_argument("command", nargs="?", default="check", choices=["check", "install", "init", "rules"])
    parser.add_argument("--config", help="path to secret-gate.toml (default: the nearest one up the tree)")
    parser.add_argument("--json", action="store_true", help="print the record instead of the lines")
    parser.add_argument("--quiet", action="store_true", help="print nothing, only set the exit code")
    parser.add_argument("--warn-as-error", action="store_true", help="treat warnings as blocking")
    parser.add_argument("--no-entropy", action="store_true", help="skip the random-looking-string check")
    parser.add_argument("--limit", type=int, default=0, help="print at most this many findings")
    parser.add_argument("--staged", action="store_true", help="what a commit would add (the default)")
    parser.add_argument("--range", dest="rev_range", help="a git range, e.g. origin/main..HEAD")
    parser.add_argument("--last", action="store_true", help="only the last commit")
    parser.add_argument("--file", action="append", default=[], help="scan a file on disk, ignoring git")
    parser.add_argument("--stdin", action="store_true", help="scan text from standard input")
    return parser


def load_policy(args):
    if args.config:
        return policy_mod.load(pathlib.Path(args.config).expanduser())
    root = diff_mod.repo_root()
    found = policy_mod.find(pathlib.Path(root)) if root else None
    return policy_mod.load(found)


def collect(args, policy) -> list:
    """Everything the gate would complain about, deduplicated and muted rules dropped."""
    kinds = policy.kinds
    extra = policy.extra_rules
    sources: list = []
    findings: list = []
    if args.stdin:
        text = sys.stdin.read()
        sources = [("<stdin>", number, line) for number, line in enumerate(text.splitlines(), 1)]
    elif args.file:
        for name in args.file:
            path = pathlib.Path(name).expanduser()
            try:
                text = path.read_text(encoding="utf-8", errors="replace")
            except OSError as exc:
                print(f"secret-gate: cannot read {path}: {exc}", file=sys.stderr)
                continue
            sources.extend((str(path), number, line) for number, line in enumerate(text.splitlines(), 1))
            findings.extend(scan.scan_path(str(path), kinds=kinds, extra=extra))
    else:
        added = diff_mod.diff_lines(rev_range=args.rev_range)
        if args.last or (args.rev_range and not added):
            added = diff_mod.last_commit()
        for line in added:
            if not policy.ignored(line.path):
                sources.append((line.path, line.number, line.text))
        for path in {line.path for line in added}:
            if not policy.ignored(path):
                findings.extend(scan.scan_path(path, kinds=kinds, extra=extra))
    for path, number, text in sources:
        if not policy.ignored(path):
            findings.extend(scan.scan_text(path, number, text, kinds=kinds, extra=extra))
    if args.no_entropy or not policy.config.get("check_entropy", True):
        findings = [item for item in findings if item.rule != "high-entropy-string"]
    seen, unique = set(), []
    for finding in findings:
        if policy.muted(finding.rule):
            continue
        key = (finding.rule, finding.path, finding.line)
        if key not in seen:
            seen.add(key)
            unique.append(finding)
    return unique


def run_check(args) -> int:
    policy = load_policy(args)
    findings = collect(args, policy)
    failed = any(item.severity in policy.failing_severities() for item in findings)
    if not args.quiet:
        if args.json:
            print(report_mod.as_json(findings, warn_as_error=policy.config["warn_as_error"], failed=failed))
        else:
            text = report_mod.human(findings, warn_as_error=policy.config["warn_as_error"], limit=args.limit)
            if text:
                print(text)
    return EXIT_FOUND if failed else EXIT_CLEAN


def run_install(args) -> int:
    root = diff_mod.repo_root()
    if not root:
        print("secret-gate: not inside a git repository", file=sys.stderr)
        return EXIT_USAGE
    hooks = pathlib.Path(root) / ".git" / "hooks"
    hooks.mkdir(parents=True, exist_ok=True)
    python = sys.executable or "python3"
    written = []
    for name, arguments in (("pre-commit", "--staged"), ("pre-push", "--range @{upstream}..HEAD")):
        hook = hooks / name
        hook.write_text(HOOK_TEMPLATE.format(python=python, args=arguments), encoding="utf-8")
        hook.chmod(hook.stat().st_mode | stat.S_IXUSR | stat.S_IXGRP | stat.S_IXOTH)
        written.append(f".git/hooks/{name}")
    print("installed: " + ", ".join(written))
    return EXIT_CLEAN


def run_init(args) -> int:
    target = pathlib.Path("secret-gate.toml")
    if target.exists():
        print(f"secret-gate: {target} already exists, nothing written", file=sys.stderr)
        return EXIT_USAGE
    target.write_text(STARTER_CONFIG, encoding="utf-8")
    print(f"wrote {target}: set ignore_paths to what your project ignores")
    return EXIT_CLEAN


def run_rules(args) -> int:
    policy = load_policy(args)
    for rule in list(policy.extra_rules) + rules.ALL_RULES:
        print(f"{rule.severity:5} {rule.kind:7} {rule.id:24} {rule.hint}")
    return EXIT_CLEAN


def main(argv=None) -> int:
    args = build_parser().parse_args(argv)
    try:
        if args.command == "install":
            return run_install(args)
        if args.command == "init":
            return run_init(args)
        if args.command == "rules":
            return run_rules(args)
        return run_check(args)
    except ConfigError as exc:
        print(f"secret-gate: {exc}", file=sys.stderr)
        return EXIT_USAGE


if __name__ == "__main__":
    raise SystemExit(main())
