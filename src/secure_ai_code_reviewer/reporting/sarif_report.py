from __future__ import annotations

import json
from pathlib import Path
from typing import List

from ..models import Finding


def _severity_to_level(severity: str) -> str:
    mapping = {
        "Critical": "error",
        "High": "error",
        "Medium": "warning",
        "Low": "note",
        "Info": "note",
    }
    return mapping.get(severity, "note")


def _rules(findings: List[Finding]) -> List[dict]:
    rules = {}
    for finding in findings:
        rules[finding.id] = {
            "id": finding.id,
            "name": finding.title,
            "shortDescription": {"text": finding.title},
            "fullDescription": {"text": finding.recommended_fix},
            "help": {"text": "\n".join(finding.references)},
        }
    return list(rules.values())


def _result(finding: Finding) -> dict:
    return {
        "ruleId": finding.id,
        "level": _severity_to_level(finding.severity.value),
        "message": {"text": f"{finding.title}: {finding.exploit_scenario}"},
        "locations": [
            {
                "physicalLocation": {
                    "artifactLocation": {"uri": finding.location.path},
                    "region": {
                        "startLine": finding.location.start_line,
                        "endLine": finding.location.end_line,
                    },
                }
            }
        ],
    }


def write_sarif_report(findings: List[Finding], output: Path) -> None:
    sarif = {
        "$schema": "https://json.schemastore.org/sarif-2.1.0.json",
        "version": "2.1.0",
        "runs": [
            {
                "tool": {
                    "driver": {
                        "name": "Secure AI Code Reviewer",
                        "rules": _rules(findings),
                    }
                },
                "results": [_result(finding) for finding in findings],
            }
        ],
    }
    output.write_text(json.dumps(sarif, indent=2))
