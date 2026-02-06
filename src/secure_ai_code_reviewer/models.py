from __future__ import annotations

from enum import Enum
from typing import Dict, List, Optional

from pydantic import BaseModel, Field


class Severity(str, Enum):
    critical = "Critical"
    high = "High"
    medium = "Medium"
    low = "Low"
    info = "Info"


class Location(BaseModel):
    path: str
    start_line: int
    end_line: int
    snippet: str


class Confidence(BaseModel):
    score: float = Field(ge=0.0, le=1.0)
    rationale: str


class Finding(BaseModel):
    id: str
    title: str
    severity: Severity
    confidence: Confidence
    location: Location
    category: str
    cwe: List[str]
    exploit_scenario: str
    recommended_fix: str
    references: List[str]
    cyber_flex: str
    suppressed: bool = False
    suppression_reason: Optional[str] = None


class SuppressionEvent(BaseModel):
    rule_id: str
    path: str
    line: int
    reason: str
    source: str


class ReportSummary(BaseModel):
    total_findings: int
    suppressed_findings: int
    by_severity: Dict[str, int]


class Report(BaseModel):
    tool: str
    version: str
    findings: List[Finding]
    suppressed: List[SuppressionEvent]
    summary: ReportSummary


class LlmEnrichment(BaseModel):
    exploit_scenario: str
    recommended_fix: str
    confidence: Confidence


class SarifResult(BaseModel):
    rule_id: str
    message: str
    level: str
    uri: str
    start_line: int
    end_line: int
