"""git-secret-gate: a deterministic gate that screens a commit or a push before it leaves.

The idea is old and boring — a pre-commit hook that looks for credentials — and it is the only
thing that has ever stopped a key from reaching a public repository. What this package adds:

* the report masks every match, so a blocked commit does not print the secret into a CI log;
* rules are data: 33 of them across credentials, destructive commands and host information, and
  your own go in the same table (``extra_rules`` in the config);
* both ends are covered: ``pre-commit`` screens the index, ``pre-push`` screens the commits that
  are about to leave, which is where a credential usually hides after a rebase;
* everything is offline and deterministic, so the hook costs milliseconds and never depends on a
  model, a key or a network.
"""

from .patterns import ALL_RULES, BLOCK, COMMAND, POLICY, SECRET, WARN, Rule
from .policy import ConfigError, Policy, find, load
from .report import as_json, counts, human, payload
from .scan import ALLOW_MARKER, Finding, entropy, looks_random, mask, scan_path, scan_text

__version__ = "1.0.0"
__all__ = [
    "ALLOW_MARKER",
    "ALL_RULES",
    "BLOCK",
    "COMMAND",
    "ConfigError",
    "Finding",
    "POLICY",
    "Policy",
    "Rule",
    "SECRET",
    "WARN",
    "as_json",
    "counts",
    "entropy",
    "find",
    "human",
    "load",
    "looks_random",
    "mask",
    "payload",
    "scan_path",
    "scan_text",
]
