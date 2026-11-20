# -*- coding: utf-8 -*-
"""
pattern_engine.py
Rule-based engine for the languages not covered by the AST engines (JS/TS,
Java, C#, PHP) plus the generic checks (secrets, keys, sensitive files) that
apply to any text file, Python included.

Before the regexes are applied, the comment part of each line (// # --
depending on the language) is stripped, in order to reduce false positives on
commented-out or disabled code.
"""

import logging
import re

from rules import RULES, SENSITIVE_FILENAMES, SEVERITY_ORDER

log = logging.getLogger(__name__)

LINE_COMMENT_PREFIXES = {
    ".js": "//", ".jsx": "//", ".ts": "//", ".tsx": "//",
    ".java": "//", ".cs": "//", ".go": "//", ".c": "//", ".cpp": "//", ".h": "//", ".hpp": "//",
    ".php": "//", ".py": "#", ".sh": "#", ".rb": "#", ".yml": "#", ".yaml": "#",
    ".env": "#", ".rs": "//", ".kt": "//", ".kts": "//", ".swift": "//", ".mjs": "//", ".cjs": "//",
    ".sql": "--", ".cc": "//", ".cxx": "//", ".hh": "//", ".hxx": "//",
}


# CWE identifier for the pattern rules (shown in the UI and used in benchmarks)
RULE_CWE = {
    "JS-001": "CWE-95", "JS-002": "CWE-79", "JS-003": "CWE-79", "JS-004": "CWE-78", "JS-005": "CWE-942",
    "JS-006": "CWE-798", "JS-007": "CWE-89", "JS-008": "CWE-327", "JS-009": "CWE-922", "GEN-008": "CWE-295",
}


def strip_line_comment(line, ext):
    prefix = LINE_COMMENT_PREFIXES.get(ext)
    if not prefix:
        return line
    idx = line.find(prefix)
    if idx == -1:
        return line
    # Simple heuristic: if the prefix is preceded by an odd number of quotes,
    # it is probably inside a string literal -> do not cut the line.
    before = line[:idx]
    if before.count('"') % 2 == 1 or before.count("'") % 2 == 1:
        return line
    return line[:idx]


def compile_rules():
    compiled = []
    for rule in RULES:
        try:
            regex = re.compile(rule["pattern"], re.IGNORECASE)
        except re.error as exc:
            log.error(
                "Rule %s ('%s') has an invalid regular expression and was DISABLED: %s. "
                "Fix the 'pattern' field in rules.py.", rule.get("id", "?"), rule.get("name", "?"), exc)
            continue
        compiled.append((rule, regex))
    return compiled


def compile_filename_rules():
    return [(re.compile(p, re.IGNORECASE), sev, title, rec) for p, sev, title, rec in SENSITIVE_FILENAMES]


_COMPILED_RULES = compile_rules()
_COMPILED_FILENAME_RULES = compile_filename_rules()

# ---------------------------------------------------------------------------
# False-positive reduction for GEN-006 (hardcoded password/secret):
# many "matches" are actually placeholder values (examples, tests, TODOs...)
# rather than real secrets. We recognize and discard them instead of reporting them.
# ---------------------------------------------------------------------------
_PLACEHOLDER_VALUES = {
    "changeme", "change_me", "changethis", "your_password", "yourpassword",
    "example", "example_password", "test", "testing", "testpass", "test123",
    "password", "password123", "secret", "yoursecret", "your_secret",
    "xxx", "xxxx", "xxxxxxxx", "12345678", "123456", "123456789",
    "todo", "fixme", "placeholder", "dummy", "fake", "changeit",
    "insert_key_here", "your_api_key", "your-api-key", "youtapikey",
    "string", "null", "none", "n/a", "na", "admin", "admin123",
    "replace_me", "replaceme", "REPLACE_ME", "<password>", "<secret>",
    "<api_key>", "<your_key_here>", "foobar", "asdf", "qwerty",
}


def _looks_like_placeholder(value):
    """True if the captured value looks like a placeholder/example rather than a real secret."""
    stripped = value.strip()
    lowered = stripped.lower()
    if lowered in _PLACEHOLDER_VALUES:
        return True
    if len(stripped) < 6:
        return True  # too short to be a real key/password
    if len(set(lowered)) <= 2:
        return True  # e.g. "aaaaaaaa", "xxxxxxxx": no variation, not a real secret
    if stripped.isdigit() and (stripped == "0" * len(stripped) or
                                stripped in "0123456789012345678901234567890"[:len(stripped) + 1]):
        return True  # trivial numeric sequences such as "12345678"
    if lowered.startswith(("your_", "your-", "insert_", "<", "changeme")):
        return True
    return False


_GEN006_VALUE_RE = re.compile(
    r"(?i)(?:password|passwd|pwd|secret|api[_\-]?key|token)\s*[:=]\s*[\"']([^\"'\n]{2,})[\"']"
)
_GEN009_VALUE_RE = re.compile(
    r"(?i)^[A-Z0-9_]*(?:SECRET|PASSWORD|PASSWD|PWD|API[_-]?KEY|TOKEN|PRIVATE[_-]?KEY|ACCESS[_-]?KEY|"
    r"CLIENT[_-]?SECRET)[A-Z0-9_]*\s*=\s*(.+)$"
)


def check_filename(filename, rel_path):
    findings = []
    for regex, severity, title, recommendation in _COMPILED_FILENAME_RULES:
        if regex.match(filename):
            findings.append({
                "id": "FILE-CHECK",
                "name": title,
                "severity": severity,
                "confidence": "safe",
                "confidence_label": "Info",
                "file": rel_path,
                "line": 0,
                "snippet": filename,
                "description": f"The file '{filename}' requires attention.",
                "recommendation": recommendation,
                "engine": "filename",
            })
    return findings


def scan_text_content(rel_path, ext, content, python_generic_only=False):
    """
    Apply the pattern-based rules to the file content.
    If python_generic_only=True (because the .py file is already covered by
    the AST engine for the language-specific rules), only the generic rules
    (languages == ["*"]) are applied, avoiding duplicate findings.
    """
    findings = []
    lines = content.splitlines()

    for rule, regex in _COMPILED_RULES:
        is_generic = rule["languages"] == ["*"]
        if python_generic_only and not is_generic:
            continue
        applicable = is_generic or ext in rule["languages"]
        if not applicable:
            continue
        for line_number, raw_line in enumerate(lines, start=1):
            line_text = strip_line_comment(raw_line, ext) if not is_generic else raw_line
            if regex.search(line_text):
                if rule["id"] == "GEN-006":
                    value_match = _GEN006_VALUE_RE.search(line_text)
                    if value_match and _looks_like_placeholder(value_match.group(1)):
                        continue  # placeholder/example value: not a real secret, skip the finding
                elif rule["id"] == "GEN-009":
                    value_match = _GEN009_VALUE_RE.match(line_text.strip())
                    if value_match:
                        value = value_match.group(1).strip().strip("\"'")
                        if _looks_like_placeholder(value):
                            continue
                snippet = raw_line.strip()
                if len(snippet) > 160:
                    snippet = snippet[:160] + " …"
                findings.append({
                    "id": rule["id"],
                    "name": rule["name"],
                    "severity": rule["severity"],
                    "confidence": "unknown",
                    "confidence_label": "Detected by pattern matching: verify the context",
                    "file": rel_path,
                    "line": line_number,
                    "snippet": snippet,
                    "description": rule["description"],
                    "recommendation": rule["recommendation"],
                    "engine": "pattern",
                    **({"cwe": RULE_CWE[rule["id"]]} if rule["id"] in RULE_CWE else {}),
                })

    findings.sort(key=lambda f: (SEVERITY_ORDER.get(f["severity"], 99), f["line"]))
    return findings
