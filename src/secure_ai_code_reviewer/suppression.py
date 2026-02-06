from __future__ import annotations

import fnmatch
import re
from pathlib import Path
from typing import Dict, Iterable, List, Optional, Tuple

from .models import SuppressionEvent

INLINE_PATTERNS = [
    re.compile(r"#\s*saicr:\s*ignore=(?P<rule>[A-Z0-9-]+)\s*reason=\"(?P<reason>[^\"]+)\"") ,
    re.compile(r"//\s*saicr:\s*ignore=(?P<rule>[A-Z0-9-]+)\s*reason=\"(?P<reason>[^\"]+)\"") ,
    re.compile(r"/\*\s*saicr:\s*ignore=(?P<rule>[A-Z0-9-]+)\s*reason=\"(?P<reason>[^\"]+)\"\s*\*/"),
]


def parse_inline_suppressions(lines: Iterable[str], path: str) -> Dict[int, SuppressionEvent]:
    events: Dict[int, SuppressionEvent] = {}
    for idx, line in enumerate(lines, start=1):
        for pattern in INLINE_PATTERNS:
            match = pattern.search(line)
            if match:
                events[idx] = SuppressionEvent(
                    rule_id=match.group("rule"),
                    path=path,
                    line=idx,
                    reason=match.group("reason"),
                    source="inline",
                )
    return events


def parse_ignore_file(path: Path) -> List[Tuple[Optional[str], str]]:
    if not path.exists():
        return []
    rules: List[Tuple[Optional[str], str]] = []
    for line in path.read_text().splitlines():
        stripped = line.strip()
        if not stripped or stripped.startswith("#"):
            continue
        if ":" in stripped:
            rule_id, pattern = stripped.split(":", 1)
            rules.append((rule_id.strip(), pattern.strip()))
        else:
            rules.append((None, stripped))
    return rules


def is_suppressed_by_ignore(
    ignore_rules: List[Tuple[Optional[str], str]], rule_id: str, rel_path: str
) -> Optional[str]:
    for rule, pattern in ignore_rules:
        if fnmatch.fnmatch(rel_path, pattern) and (rule is None or rule == rule_id):
            return f"Matched ignore rule {rule or '*'}:{pattern}"
    return None
