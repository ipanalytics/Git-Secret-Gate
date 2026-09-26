# Git-Secret-Gate

_Русская версия: [README.ru.md](README.ru.md)_

A git hook that stops a credential or a destructive command **before** it leaves the machine. No
network, no model, no service — a few milliseconds on `git commit` and `git push`.

## Why this exists

Every leaked key has the same story: it was already in the file when the commit was made. Once it is
pushed, rotating it is the only fix, and on a public repository the key was public for the few
minutes it takes to notice. Reviewers miss it because a diff is read for logic, not for entropy —
and the one commit where it matters is the one with forty other changes in it.

There are scanners that solve this over a network against a vendor's rule list. This one is the
small, offline half of the job: your own rules, in your own repository, checked locally, with the
output designed to be pasted into an issue or a CI log without the secret in it.

## What it checks

33 rules in three groups, and your own go into the same table.

**Credentials** — private keys (PEM/OpenSSH/PGP), GitHub and GitLab tokens, Slack and Telegram bot
tokens, Google API keys, OpenAI/Anthropic keys, AWS and Stripe identifiers, JWTs, credentials in
URLs (`https://user:password@host`), IBANs, and a high-entropy catch-all for literals that look like
keys but match no known shape.

**Destructive commands** — `rm -rf /`, `dd` and `wipe` onto a device, `mkfs`, `chmod -R 777 /`,
`curl … | bash`, `git push --force` to a shared branch, history rewrites, fork bombs.

**Environment leaks** — private addresses, home paths with a real user name, internal host names,
and key material by file name (`.env`, `id_rsa`, `*.pem`, `credentials`, `.netrc`).

The report never prints a match in full. A blocked commit tells you the rule, the file, the line and
a masked value (`ghp…(40 chars)`), which is enough to recognise the key and useless to anyone
reading the CI log.

## Install

```sh
pip install git-secret-gate          # or: pipx install git-secret-gate
secret-gate install                  # writes .git/hooks/pre-commit and pre-push
secret-gate init                     # writes secret-gate.toml with every option commented
```

Then, in the repository you care about:

```sh
secret-gate check --staged           # what the pre-commit hook will do
secret-gate check --range HEAD~5..   # the commits a push is about to send
secret-gate rules                    # the whole rule table, with hints
```

Exit codes are made for hooks and CI: `0` clean, `1` something blocking (or a warning, if
`warn_as_error` is on), `2` bad usage or a broken config. `--json` gives the same result as data.

## Judging a finding

Three ways, in order of preference:

1. Fix it — move the value into the environment and rotate what leaked.
2. Mark the line: `secret-gate: allow` on the line itself, which is what a test fixture needs.
3. Mute the rule or the path in `secret-gate.toml` (`ignore_rules`, `ignore_paths`).

A false positive on a fixture is expected; that is why the marker exists and why nothing is
reported twice.

## What it is not

It is not a history scanner: it looks at the commit and the push, not at 40 000 old commits. It is
not a replacement for a hosted scanner that knows the leaks of other people's repositories. And it
will not catch a secret that was assembled at run time from three innocent-looking halves — no rule
list does.

## Configuration

```toml
kinds = ["secret", "command", "policy"]
warn_as_error = false
ignore_paths = ["tests/fixtures/**", "*.lock"]
ignore_rules = []

[[extra_rules]]
id = "internal-hostname"
pattern = "\\b[a-z0-9-]+\\.our\\.lan\\b"
severity = "block"
kind = "policy"
hint = "an internal host name: keep it in a local config."
```

`where = "path"` makes a rule read the file name instead of the line — the same shape the built-in
key-material rules use.

## Layout

```
git_secret_gate/patterns.py   33 rules as data: id, kind, severity, pattern, hint, where
git_secret_gate/scan.py       matching, entropy, masking, the allow marker
git_secret_gate/policy.py     secret-gate.toml / .json, extra rules, mutes
git_secret_gate/diff.py       added lines from a diff: staged, working tree or a range
git_secret_gate/report.py     human report and the same as JSON
git_secret_gate/cli.py        check, install, init, rules
tests/                        21 tests, including the mask-never-leaks-the-secret one
```

## Tests

```sh
python -m pytest -q     # 21 passed
ruff check .
```

## License

MIT.
