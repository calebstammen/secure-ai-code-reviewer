from __future__ import annotations

from pathlib import Path

from ..models import Finding, Report


def _finding_block(finding: Finding) -> str:
    return "\n".join(
        [
            f"### {finding.id}: {finding.title}",
            f"- Severity: **{finding.severity.value}**",
            f"- Confidence: **{finding.confidence.score:.2f}** ({finding.confidence.rationale})",
            f"- Category: {finding.category}",
            f"- CWE: {', '.join(finding.cwe)}",
            f"- Location: `{finding.location.path}:{finding.location.start_line}-{finding.location.end_line}`",
            "- Snippet:",
            "```",
            finding.location.snippet.strip(),
            "```",
            f"- Exploit scenario: {finding.exploit_scenario}",
            f"- Recommended fix: {finding.recommended_fix}",
            f"- Cyber flex: {finding.cyber_flex}",
            f"- References: {', '.join(finding.references)}",
        ]
    )


def write_md_report(report: Report, output: Path) -> None:
    header = [
        "# Secure AI Code Reviewer Report",
        "",
        f"Total findings: **{report.summary.total_findings}**",
        f"Suppressed findings: **{report.summary.suppressed_findings}**",
        "",
    ]
    body = "\n\n".join(_finding_block(finding) for finding in report.findings)
    output.write_text("\n".join(header) + body)
