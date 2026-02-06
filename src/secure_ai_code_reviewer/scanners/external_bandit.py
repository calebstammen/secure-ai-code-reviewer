from __future__ import annotations

import json
import subprocess
from pathlib import Path
from typing import List

from ..models import Confidence, Finding, Location, Severity


def run_bandit(root: Path) -> List[Finding]:
    try:
        result = subprocess.run(
            ["bandit", "-r", str(root), "-f", "json"],
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
    for issue in payload.get("results", []):
        rule_id = f"SAICR-EXT-BANDIT-{issue.get('test_id', 'UNKNOWN')}"
        path = issue.get("filename", "")
        start = issue.get("line_number", 1)
        snippet = issue.get("code", "")
        findings.append(
            Finding(
                id=rule_id,
                title=issue.get("issue_text", "Bandit finding"),
                severity=Severity.medium,
                confidence=Confidence(score=0.5, rationale="Bandit external scan"),
                location=Location(path=path, start_line=start, end_line=start, snippet=snippet),
                category="Other",
                cwe=[issue.get("issue_cwe", {}).get("id", "CWE-Other")],
                exploit_scenario="External scanner reported a potential issue.",
                recommended_fix="Review Bandit output for remediation guidance.",
                references=["https://bandit.readthedocs.io"],
                cyber_flex="External signal requires developer triage.",
            )
        )
    return findings
