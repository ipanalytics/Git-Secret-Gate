"""The rules. Deterministic, offline, no model: a gate that needs a network call is not a gate.

Every rule is a regular expression plus a hint a human can act on. Severities:

``block``
    A real credential or an unrecoverable command. The commit does not happen.
``warn``
    Information that should not leave a private machine (home paths, internal addresses) or a
    command that is legitimate on a good day. Reported; fails only with ``--warn-as-error``.

We do not try to be clever. A rule that fires on a dry run and cannot be explained in one line is
worse than no rule, so every hint says what to do, not what matched.
"""

from __future__ import annotations

from dataclasses import dataclass

BLOCK = "block"
WARN = "warn"
SECRET = "secret"
COMMAND = "command"
POLICY = "policy"


@dataclass(frozen=True)
class Rule:
    id: str
    kind: str
    severity: str
    pattern: str
    hint: str
    where: str = "text"  # "text" — the line content; "path" — the file name


SECRET_RULES = [
    Rule(
        "private-key",
        SECRET,
        BLOCK,
        r"-----BEGIN (?:RSA |EC |DSA |OPENSSH |PGP )?PRIVATE KEY-----",
        "a private key in the diff: remove it, rotate the key, and load it from a file at run time.",
    ),
    Rule(
        "aws-access-key-id",
        SECRET,
        BLOCK,
        r"\b(?:AKIA|ASIA)[0-9A-Z]{16}\b",
        "an AWS access key id: rotate the pair in IAM before anything else.",
    ),
    Rule(
        "aws-secret-access-key",
        SECRET,
        BLOCK,
        r"(?i)aws_secret_access_key\s*[=:]\s*['\"]?[A-Za-z0-9/+=]{40}",
        "an AWS secret: it is in the diff in full, rotate it.",
    ),
    Rule(
        "github-token",
        SECRET,
        BLOCK,
        r"\b(?:ghp|gho|ghu|ghs|ghr)_[A-Za-z0-9]{36,}\b",
        "a GitHub token: revoke it in Settings, tokens are free to recreate.",
    ),
    Rule(
        "github-fine-grained",
        SECRET,
        BLOCK,
        r"\bgithub_pat_[A-Za-z0-9_]{22,}\b",
        "a fine-grained GitHub token: revoke it, then put it in an environment variable.",
    ),
    Rule(
        "gitlab-token",
        SECRET,
        BLOCK,
        r"\bglpat-[A-Za-z0-9_\-]{20,}\b",
        "a GitLab token: revoke it in the project settings.",
    ),
    Rule("slack-token", SECRET, BLOCK, r"\bxox[baprs]-[A-Za-z0-9-]{10,}\b", "a Slack token: revoke the app token."),
    Rule(
        "telegram-bot-token",
        SECRET,
        BLOCK,
        r"\b\d{8,10}:AA[A-Za-z0-9_\-]{30,}\b",
        "a Telegram bot token: talk to BotFather, /revoke, then use an environment variable.",
    ),
    Rule(
        "google-api-key",
        SECRET,
        BLOCK,
        r"\bAIza[0-9A-Za-z_\-]{35}\b",
        "a Google API key: delete the key in the console, it is public the moment it is committed.",
    ),
    Rule(
        "openai-key",
        SECRET,
        BLOCK,
        r"\bsk-(?:proj-)?[A-Za-z0-9_\-]{20,}\b",
        "an OpenAI-style key (same shape as other vendors): revoke it and read it from the environment.",
    ),
    Rule(
        "anthropic-key", SECRET, BLOCK, r"\bsk-ant-[A-Za-z0-9_\-]{20,}\b", "an Anthropic key: revoke it in the console."
    ),
    Rule(
        "stripe-key",
        SECRET,
        BLOCK,
        r"\b(?:sk|rk)_(?:live|test)_[A-Za-z0-9]{16,}\b",
        "a Stripe key: roll it immediately, live keys move money.",
    ),
    Rule(
        "jwt",
        SECRET,
        BLOCK,
        r"\beyJ[A-Za-z0-9_\-]{8,}\.[A-Za-z0-9_\-]{8,}\.[A-Za-z0-9_\-]{8,}\b",
        "a JSON Web Token: it is signed, not encrypted — treat it as a password.",
    ),
    Rule(
        "credential-url",
        SECRET,
        BLOCK,
        r"[a-z][a-z0-9+.\-]{2,}://[^\s:/@]{2,}:[^\s:@]{4,}@[^\s/'\"]{3,}",
        "credentials inside a URL: move the user and password to the environment.",
    ),
    Rule(
        "password-assignment",
        SECRET,
        BLOCK,
        r"(?i)\b(?:password|passwd|secret|token|api[_-]?key)\s*[=:]\s*['\"][^'\"]{8,}['\"]",
        "a password or key assigned to a literal: keep the name, read the value from the environment.",
    ),
    Rule(
        "iban",
        SECRET,
        WARN,
        r"\b[A-Z]{2}\d{2}(?:[ ]?[A-Z0-9]{4}){3,7}[ ]?[A-Z0-9]{1,4}\b",
        "an IBAN: bank details belong to the account, not the repository.",
    ),
]


COMMAND_RULES = [
    Rule(
        "rm-rf-root",
        COMMAND,
        BLOCK,
        r"rm\s+(?:-[A-Za-z]*[rRf][A-Za-z]*\s+)+(?:/|\*|/\*|~|\$HOME|\$\{HOME\})(?:\s|$)",
        "recursive delete of a root or home path: say which directory you actually want gone.",
    ),
    Rule(
        "dd-to-device",
        COMMAND,
        BLOCK,
        r"\bdd\b[^\n]{0,80}\bof=/dev/(?:sd|hd|vd|nvme|mmcblk)",
        "dd writing straight to a device: one wrong letter is the whole disk.",
    ),
    Rule("mkfs", COMMAND, BLOCK, r"\bmkfs(?:\.[a-z0-9]+)?\b", "mkfs formats a filesystem and does not ask twice."),
    Rule(
        "chmod-777-root",
        COMMAND,
        BLOCK,
        r"\bchmod\s+(?:-R\s+)?0?777\s+/",
        "world-writable on a system path: pick the narrowest permission that works.",
    ),
    Rule(
        "curl-pipe-shell",
        COMMAND,
        WARN,
        r"\b(?:curl|wget)\b[^\n|]{0,120}\|\s*(?:sudo\s+)?(?:ba|z|da|k|fi)?sh\b",
        "piping a download into a shell: fetch it, read it, then run it.",
    ),
    Rule(
        "git-push-force",
        COMMAND,
        WARN,
        r"\bgit\s+push\b[^\n]{0,60}(?:--force\b|--force-with-lease\b|(?<!\w)-f(?!\w))",
        "a forced push: it can drop someone else's commits; --force-with-lease is the safe form.",
    ),
    Rule(
        "git-history-rewrite",
        COMMAND,
        WARN,
        r"\bgit\s+(?:filter-branch|filter-repo)\b",
        "a history rewrite: everyone downstream has to re-clone.",
    ),
    Rule(
        "fork-bomb",
        COMMAND,
        BLOCK,
        r":\(\)\s*\{\s*:\s*\|\s*:\s*&\s*\}\s*;\s*:",
        "a fork bomb: not even in a joke file.",
    ),
    Rule(
        "device-overwrite",
        COMMAND,
        BLOCK,
        r">\s*/dev/(?:sd|hd|vd|nvme|mmcblk)[a-z0-9]*",
        "output redirected onto a raw device: this is the erase itself.",
    ),
    Rule(
        "wipe-command",
        COMMAND,
        BLOCK,
        r"\b(?:wipefs|shred|blkdiscard)\b[^\n]{0,60}/dev/",
        "wiping a device: only on purpose, and never from a script that runs unattended.",
    ),
]

PATH_RULES = [
    Rule(
        "private-key-file",
        POLICY,
        BLOCK,
        r"(?:^|/)(?:id_rsa|id_dsa|id_ecdsa|id_ed25519)(?:$|[.\s])",
        "a private key file is being added by name: it must never live in a repository.",
        where="path",
    ),
    Rule(
        "key-material-file",
        POLICY,
        BLOCK,
        r"\.(?:pem|p12|pfx|jks|keystore|ppk)$",
        "key material in a file: keep it outside the tree and mount it at run time.",
        where="path",
    ),
    Rule(
        "env-file",
        POLICY,
        BLOCK,
        r"(?:^|/)\.env(?:$|\.(?!example|sample|template))",
        "a real .env: commit .env.example with names only, values stay on the machine.",
        where="path",
    ),
    Rule(
        "credential-store",
        POLICY,
        BLOCK,
        r"(?:^|/)(?:credentials|secrets|\.netrc|\.npmrc|\.pypirc|\.htpasswd)$",
        "a credential store in the tree: rotate what is inside, then take it out of the history.",
        where="path",
    ),
]

POLICY_RULES = [
    Rule(
        "private-ip",
        POLICY,
        WARN,
        r"\b(?:10\.\d{1,3}\.\d{1,3}\.\d{1,3}|192\.168\.\d{1,3}\.\d{1,3}|172\.(?:1[6-9]|2\d|3[01])\.\d{1,3}\.\d{1,3})\b",
        "a private address: it maps your network for anyone who reads the file.",
    ),
    Rule(
        "home-path",
        POLICY,
        WARN,
        r"/home/(?!user\b|runner\b|example\b|\$)[a-z0-9_.-]{2,}/",
        "an absolute home path: it carries the user name off the machine; use ~ or a variable.",
    ),
    Rule(
        "personal-host",
        POLICY,
        WARN,
        r"\b[a-z0-9-]+\.(?:local|lan|internal|home\.arpa)\b",
        "an internal host name: keep it in a local config, not in the diff.",
    ),
]

ALL_RULES = SECRET_RULES + COMMAND_RULES + PATH_RULES + POLICY_RULES
RULE_BY_ID = {rule.id: rule for rule in ALL_RULES}
KINDS = (SECRET, COMMAND, POLICY)
