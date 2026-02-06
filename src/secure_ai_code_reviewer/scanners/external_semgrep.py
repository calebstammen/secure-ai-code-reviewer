from __future__ import annotations

import json
import subprocess
from pathlib import Path
from typing import List

from ..models import Confidence, Finding, Location, Severity


def run_semgrep(root: Path) -> List[Finding]:
    try:
        result = subprocess.run(
            ["semgrep", "--config", "auto", "--json", str(root)],
            capture_output=True,
            text=True,
            check=False,
        )
    except FileNotFoundError:
        return []

    if result.returncode not in {0, 1}:
        return []
    payload = json.loads(result.stdout or "{}")
    findings: List[Finding] = []
    for match in payload.get("results", []):
        rule_id = f"SAICR-EXT-SEM-{match.get('check_id', 'UNKNOWN')}"
        path = match.get("path", "")
        start = match.get("start", {}).get("line", 1)
        end = match.get("end", {}).get("line", start)
        snippet = match.get("extra", {}).get("lines", "")
        findings.append(
            Finding(
                id=rule_id,
                title=match.get("extra", {}).get("message", "Semgrep finding"),
                severity=Severity.medium,
                confidence=Confidence(score=0.5, rationale="Semgrep external scan"),
                location=Location(path=path, start_line=start, end_line=end, snippet=snippet),
                category="Other",
                cwe=["CWE-Other"],
                exploit_scenario="External scanner reported a potential issue.",
                recommended_fix="Review Semgrep output for remediation guidance.",
                references=["https://semgrep.dev"],
                cyber_flex="External signal requires developer triage.",
            )
        )
    return findings
