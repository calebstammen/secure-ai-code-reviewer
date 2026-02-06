from __future__ import annotations

import re
from typing import Iterable

REDACTION_PATTERNS = [
    re.compile(r"AKIA[0-9A-Z]{16}"),
    re.compile(r"AIza[0-9A-Za-z\-_]{35}"),
    re.compile(r"xox[baprs]-[0-9A-Za-z-]{10,}"),
    re.compile(r"-----BEGIN (RSA|EC|DSA) PRIVATE KEY-----"),
    re.compile(r"(?i)api[_-]?key\s*[:=]\s*['\"]?[A-Za-z0-9_\-]{16,}"),
    re.compile(r"(?i)secret\s*[:=]\s*['\"]?[A-Za-z0-9_\-]{16,}"),
    re.compile(r"(?i)token\s*[:=]\s*['\"]?[A-Za-z0-9_\-]{16,}"),
]


def redact_text(text: str) -> str:
    redacted = text
    for pattern in REDACTION_PATTERNS:
        redacted = pattern.sub("[REDACTED]", redacted)
    return redacted


def redact_lines(lines: Iterable[str]) -> str:
    return "\n".join(redact_text(line) for line in lines)
