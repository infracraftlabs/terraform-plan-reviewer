"""Remove secrets and personal data from text before it is sent to any model.

Rules are deliberately conservative: it is better to hide a harmless string than to
leak a real key. Every rule is covered by planted-secret tests.
"""
from __future__ import annotations

import math
import re
from dataclasses import dataclass, field

# (name, pattern). Order matters: specific key formats before generic ones.
RULES: list[tuple[str, re.Pattern[str]]] = [
    ("private-key", re.compile(r"-----BEGIN [A-Z ]*PRIVATE KEY-----[\s\S]*?-----END [A-Z ]*PRIVATE KEY-----")),
    ("aws-access-key", re.compile(r"\b(?:AKIA|ASIA)[0-9A-Z]{16}\b")),
    ("github-token", re.compile(r"\b(?:gh[pousr]_[A-Za-z0-9]{36,}|github_pat_[A-Za-z0-9_]{22,})\b")),
    ("slack-token", re.compile(r"\bxox[abprs]-[A-Za-z0-9-]{10,}\b")),
    ("jwt", re.compile(r"\beyJ[A-Za-z0-9_-]{8,}\.[A-Za-z0-9_-]{8,}\.[A-Za-z0-9_-]{8,}\b")),
    ("bearer", re.compile(r"(?i)\b(bearer)\s+[A-Za-z0-9._~+/=-]{16,}")),
    ("url-credentials", re.compile(r"(?i)\b([a-z][a-z0-9+.-]*://)[^\s/:@]+:[^\s/@]+@")),
    ("key-value-secret", re.compile(
        r"(?i)\b([A-Za-z0-9_.-]*(?:password|passwd|secret|token|api[_-]?key|access[_-]?key|private[_-]?key|client[_-]?secret)[A-Za-z0-9_.-]*)"
        r"(\s*[:=]\s*[\"']?)([^\s\"',;]{4,})")),
    ("email", re.compile(r"\b[A-Za-z0-9._%+-]+@[A-Za-z0-9.-]+\.[A-Za-z]{2,}\b")),
    ("ipv4", re.compile(r"\b(?:\d{1,3}\.){3}\d{1,3}\b")),
]

_HIGH_ENTROPY = re.compile(r"\b[A-Za-z0-9+/_-]{32,}={0,2}\b")
_HEXISH = re.compile(r"^[0-9a-f]+$")


def _entropy(s: str) -> float:
    counts = {c: s.count(c) for c in set(s)}
    return -sum(n / len(s) * math.log2(n / len(s)) for n in counts.values())


@dataclass
class Redacted:
    text: str
    counts: dict[str, int] = field(default_factory=dict)

    @property
    def total(self) -> int:
        return sum(self.counts.values())


def redact(text: str, keep_ips: bool = False) -> Redacted:
    """Return text with secrets replaced by [REDACTED:<kind>] and a count per kind."""
    counts: dict[str, int] = {}

    def sub(name: str, pattern: re.Pattern[str], s: str) -> str:
        def repl(m: re.Match[str]) -> str:
            counts[name] = counts.get(name, 0) + 1
            if name == "key-value-secret":
                return f"{m.group(1)}{m.group(2)}[REDACTED:secret]"
            if name == "bearer":
                return f"{m.group(1)} [REDACTED:token]"
            if name == "url-credentials":
                return f"{m.group(1)}[REDACTED:credentials]@"
            return f"[REDACTED:{name}]"
        return pattern.sub(repl, s)

    for name, pattern in RULES:
        if name == "ipv4" and keep_ips:
            continue
        text = sub(name, pattern, text)

    # Long random-looking strings (e.g. unknown token formats). Git SHAs and other plain
    # hex are kept: they are useful evidence and not secrets.
    def entropy_repl(m: re.Match[str]) -> str:
        s = m.group(0)
        if "REDACTED" in s or _HEXISH.match(s.lower()) or _entropy(s) < 4.0:
            return s
        counts["high-entropy"] = counts.get("high-entropy", 0) + 1
        return "[REDACTED:high-entropy]"

    text = _HIGH_ENTROPY.sub(entropy_repl, text)
    return Redacted(text=text, counts=counts)
