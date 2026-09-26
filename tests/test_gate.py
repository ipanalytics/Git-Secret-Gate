"""The gate exists to stop a secret or a destructive command before it leaves the machine."""

import json

import pytest

from git_secret_gate import cli, diff, policy, report
from git_secret_gate import patterns as rules
from git_secret_gate.scan import mask, scan_path, scan_text

FAKE_PAT = "ghp_" + "A1b2C3d4E5f6G7h8I9j0K1l2M3n4O5p6Q7r8"
FAKE_AWS = "AKIAIOSFODNN7EXAMPLE"
FAKE_KEY = "-----BEGIN OPENSSH PRIVATE KEY-----\nb3BlbnNzaC1rZXktdjEAAAAABG5vbmU\n-----END OPENSSH PRIVATE KEY-----"


def test_every_rule_is_well_formed():
    ids = [rule.id for rule in rules.ALL_RULES]
    assert len(ids) == len(set(ids)), "duplicate rule id"
    for rule in rules.ALL_RULES:
        assert rule.severity in (rules.BLOCK, rules.WARN), rule.id
        assert rule.where in ("text", "path"), rule.id
        assert rule.hint, f"{rule.id} has no hint"


def test_rules_are_split_the_way_the_scanner_reads_them():
    text_rules = [rule for rule in rules.ALL_RULES if rule.where == "text"]
    path_rules = [rule for rule in rules.ALL_RULES if rule.where == "path"]
    assert len(rules.ALL_RULES) == len(text_rules) + len(path_rules)
    assert text_rules and path_rules
    assert {rule.kind for rule in rules.ALL_RULES} == {rules.SECRET, rules.COMMAND, rules.POLICY}


def test_github_token_is_blocked():
    found = scan_text("notes.md", 12, f"token = {FAKE_PAT}")
    assert [item for item in found if item.blocks][0].rule == "github-token"
    assert all(item.masked != FAKE_PAT for item in found)


def test_amazon_key_is_blocked():
    found = scan_text("infra.tf", 3, f'access_key = "{FAKE_AWS}"')
    assert any(item.blocks for item in found)


def test_private_key_header_is_blocked():
    found = scan_text("config.yml", 1, FAKE_KEY)
    assert found[0].rule == "private-key"
    assert found[0].blocks


def test_random_literal_is_only_a_warning():
    found = scan_text("lib.py", 5, 'SALT = "aZ3kQ9mX2pL7vB4nR8tY6wC1dF5gH0jK"')
    assert [item.rule for item in found] == ["high-entropy-string"]
    assert not found[0].blocks


def test_destructive_commands_are_blocked():
    for line in ("rm -rf /", "dd if=image.iso of=/dev/sda", "mkfs.ext4 /dev/sdb1"):
        found = scan_text("deploy.sh", 7, line)
        assert found, line
        assert any(item.blocks for item in found), line


def test_curl_into_a_shell_is_flagged_without_stopping_the_commit():
    found = scan_text("deploy.sh", 2, "curl -fsSL https://example.com/install.sh | bash")
    assert [item.rule for item in found] == ["curl-pipe-shell"]
    assert not found[0].blocks


def test_allow_marker_mutes_the_line():
    assert scan_text("tests/fixtures.py", 4, f'PAT = "{FAKE_PAT}"  # secret-gate: allow') == []


def test_report_never_prints_the_secret():
    found = scan_text("src/config.py", 9, f'GH_TOKEN = "{FAKE_PAT}"')
    text = report.human(found)
    assert FAKE_PAT not in text
    assert "github-token" in text
    assert "secret-gate: 2 finding(s) in 1 file(s)" in text
    assert "the commit was stopped" in text
    assert "src/config.py:9" in text


def test_mask_keeps_recognition_but_not_the_value():
    short = mask(FAKE_AWS)
    assert short != FAKE_AWS
    assert FAKE_AWS not in short
    assert "IOSFODNN7" not in short
    assert short.startswith("AKI")


def test_json_payload_is_machine_readable():
    found = scan_text("a.py", 1, f'k = "{FAKE_PAT}"')
    payload = json.loads(report.as_json(found, failed=True))
    assert payload["summary"]["failed"] is True
    assert payload["summary"]["blocking"] == 1
    assert payload["summary"]["files"] == 1
    assert payload["findings"][0]["path"] == "a.py"


def test_diff_parser_keeps_added_lines_only():
    sample = (
        "diff --git a/app.py b/app.py\n"
        "index 111..222 100644\n"
        "--- a/app.py\n"
        "+++ b/app.py\n"
        "@@ -1,2 +1,3 @@\n"
        " import os\n"
        f'+TOKEN = "{FAKE_PAT}"\n'
        "-OLD = 1\n"
    )
    added = diff.parse(sample)
    assert [item.text for item in added] == [f'TOKEN = "{FAKE_PAT}"']
    assert added[0].path == "app.py"


def test_path_rules_read_the_file_name():
    assert [item.rule for item in scan_path("/repo/.env")] == ["env-file"]
    assert [item.rule for item in scan_path("certs/server.pem")] == ["key-material-file"]
    assert [item.rule for item in scan_path("deploy/id_ed25519")] == ["private-key-file"]
    assert scan_path("src/app.py") == []
    assert scan_path(".env.example") == []


def test_path_rules_from_the_config_are_applied_too():
    custom = rules.Rule(
        id="dump-file", kind=rules.POLICY, severity=rules.WARN, pattern=r"\.sql$", hint="a database dump", where="path"
    )
    assert [item.rule for item in scan_path("backup/users.sql", extra=[custom])] == ["dump-file"]
    assert scan_path("backup/users.csv", extra=[custom]) == []


def test_policy_mutes_paths_and_rules():
    muted = policy.Policy({"ignore_paths": ["docs/*"], "ignore_rules": ["github-token"]})
    assert muted.ignored("docs/example.md")
    assert not muted.ignored("src/app.py")
    assert muted.muted("github-token")
    assert muted.failing_severities() == {rules.BLOCK}
    assert policy.Policy({"warn_as_error": True}).failing_severities() == {rules.BLOCK, rules.WARN}


def test_policy_rejects_broken_extra_rules():
    with pytest.raises(policy.ConfigError):
        _ = policy.Policy({"extra_rules": [{"id": "x", "pattern": "(", "hint": "h"}]}).extra_rules
    with pytest.raises(policy.ConfigError):
        _ = policy.Policy({"extra_rules": [{"id": "y", "pattern": "ok"}]}).extra_rules


def test_extra_rule_from_config_is_applied():
    strict = policy.Policy(
        {"extra_rules": [{"id": "internal-host", "pattern": r"\.internal\.", "hint": "internal hostname"}]}
    )
    found = scan_text("notes.md", 2, "db.internal.example is down", extra=strict.extra_rules)
    assert "internal-host" in [item.rule for item in found]


def test_counts_group_by_severity():
    summary = report.counts(scan_path("/repo/.env"))
    assert summary["findings"] == 1 and summary["files"] == 1
    assert summary["by_severity"][rules.BLOCK] == 1
    assert summary["warnings"] == 0


def test_human_report_stays_quiet_when_there_is_nothing_to_say():
    assert report.human([]) == ""


def test_cli_rules_lists_everything_and_exits_clean(capsys):
    assert cli.main(["rules"]) == 0
    out = capsys.readouterr().out
    for rule in rules.ALL_RULES:
        assert rule.id in out
