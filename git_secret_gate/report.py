"""Two outputs: lines a human reads at 23:40, and a record a script can keep.

The human output answers three questions in order — what is wrong, where, and what to do — and
never repeats the credential itself.
"""

from __future__ import annotations

import json

from . import patterns as rules


def counts(findings) -> dict:
    by_severity = {rules.BLOCK: 0, rules.WARN: 0}
    for finding in findings:
        by_severity[finding.severity] = by_severity.get(finding.severity, 0) + 1
    return {
        "findings": len(findings),
        "blocking": by_severity.get(rules.BLOCK, 0),
        "warnings": by_severity.get(rules.WARN, 0),
        "files": len({finding.path for finding in findings}),
        "by_severity": by_severity,
    }


def human(findings, *, warn_as_error: bool = False, limit: int = 0) -> str:
    if not findings:
        return ""
    rows = sorted(findings, key=lambda item: (item.path, item.line, item.rule))
    shown = rows[:limit] if limit else rows
    summary = counts(findings)
    head = (
        f"secret-gate: {summary['findings']} finding(s) in {summary['files']} file(s) "
        f"({summary['blocking']} blocking, {summary['warnings']} warning)"
    )
    lines = [head, ""]
    for finding in shown:
        where = f"{finding.path}:{finding.line}" if finding.line else finding.path
        lines.append(f"{where}  [{finding.severity}] {finding.rule}  {finding.masked}")
        lines.append(f"    {finding.hint}")
    if limit and len(rows) > limit:
        lines.append(f"… and {len(rows) - limit} more")
    lines.append("")
    if summary["blocking"] or warn_as_error:
        lines.append(
            "the commit was stopped. Judge each line, then either fix it, or add "
            "`secret-gate: allow` on the line itself, or list the path in secret-gate.toml."
        )
    else:
        lines.append("nothing blocking; the warnings above are yours to judge.")
    return "\n".join(lines)


def payload(findings, *, warn_as_error: bool = False, failed: bool = False) -> dict:
    return {
        "summary": {**counts(findings), "failed": failed, "warn_as_error": warn_as_error},
        "findings": [
            {
                "rule": finding.rule,
                "severity": finding.severity,
                "kind": finding.kind,
                "path": finding.path,
                "line": finding.line,
                "masked": finding.masked,
                "hint": finding.hint,
            }
            for finding in sorted(findings, key=lambda item: (item.path, item.line, item.rule))
        ],
    }


def as_json(findings, **kwargs) -> str:
    return json.dumps(payload(findings, **kwargs), ensure_ascii=False, indent=2)
