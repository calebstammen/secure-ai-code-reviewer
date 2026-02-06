from __future__ import annotations

from dataclasses import dataclass
from typing import List, Optional


@dataclass(frozen=True)
class Rule:
    rule_id: str
    title: str
    severity: str
    category: str
    cwe: List[str]
    description: str
    recommendation: str
    references: List[str]
    cyber_flex: str
    confidence: float
    confidence_rationale: str
    languages: Optional[List[str]] = None
