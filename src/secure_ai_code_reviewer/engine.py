from __future__ import annotations

import ast
import re
from pathlib import Path
from typing import Dict, List, Optional, Tuple, TYPE_CHECKING

from .config import Config
from .discovery import detect_language, discover_files
from .models import Confidence, Finding, Location, Report, ReportSummary, Severity, SuppressionEvent
from .redaction import redact_text
from .rules.ai_prompt_injection import scan_ai_prompt_injection
from importlib.resources import files

import yaml

from .rules.registry import load_rules
from .scanners.external_bandit import run_bandit
from .scanners.external_semgrep import run_semgrep
from .scanners.llm_adapter import LlmAdapter, LlmAdapterConfig
from .suppression import is_suppressed_by_ignore, parse_ignore_file, parse_inline_suppressions

SEVERITY_ORDER = {
    "critical": 4,
    "high": 3,
    "medium": 2,
    "low": 1,
    "info": 0,
}


def _severity_allows(severity: Severity, threshold: str) -> bool:
    return SEVERITY_ORDER[severity.value.lower()] >= SEVERITY_ORDER[threshold.lower()]


def _snippet(lines: List[str], start: int, end: int) -> str:
    return "\n".join(lines[start - 1 : end])


def _build_finding(
    rule_id: str,
    title: str,
    severity: str,
    category: str,
    cwe: List[str],
    path: str,
    start: int,
    end: int,
    snippet: str,
    confidence: float,
    confidence_rationale: str,
    exploit_scenario: str,
    recommended_fix: str,
    references: List[str],
    cyber_flex: str,
) -> Finding:
    return Finding(
        id=rule_id,
        title=title,
        severity=Severity(severity),
        confidence=Confidence(score=confidence, rationale=confidence_rationale),
        location=Location(path=path, start_line=start, end_line=end, snippet=snippet),
        category=category,
        cwe=cwe,
        exploit_scenario=exploit_scenario,
        recommended_fix=recommended_fix,
        references=references,
        cyber_flex=cyber_flex,
    )


def scan_repository(root: Path, config: Config) -> Report:
    registry = load_rules()
    findings: List[Finding] = []
    suppressed_events: List[SuppressionEvent] = []
    ignore_rules = parse_ignore_file(root / ".saicrignore")
    regex_rules = _load_regex_rules()

    for file_path in discover_files(root, config.include_globs, config.exclude_globs):
        language = detect_language(file_path)
        if language == "unknown":
            continue
        rel_path = file_path.relative_to(root).as_posix()
        text = file_path.read_text(errors="ignore")
        lines = text.splitlines()
        inline_suppressions = parse_inline_suppressions(lines, rel_path)

        # Regex rules
        for rule_id, data in regex_rules.items():
            if data["languages"] and language not in data["languages"]:
                continue
            for match in re.finditer(data["pattern"], text, re.MULTILINE):
                start_line = text[: match.start()].count("\n") + 1
                end_line = start_line
                snippet = _snippet(lines, start_line, end_line)
                finding = _build_finding(
                    rule_id=rule_id,
                    title=data["title"],
                    severity=data["severity"],
                    category=data["category"],
                    cwe=data["cwe"],
                    path=rel_path,
                    start=start_line,
                    end=end_line,
                    snippet=snippet,
                    confidence=data["confidence"],
                    confidence_rationale=data["confidence_rationale"],
                    exploit_scenario=data["description"],
                    recommended_fix=data["recommendation"],
                    references=data["references"],
                    cyber_flex=data["cyber_flex"],
                )
                _apply_suppression(
                    finding, inline_suppressions, ignore_rules, rel_path, suppressed_events
                )
                findings.append(finding)

        # AST python rules
        if language == "python":
            try:
                tree = ast.parse(text)
            except SyntaxError:
                continue
            ast_matches = _scan_python_ast(tree, registry)
            for match in ast_matches:
                snippet = _snippet(lines, match.lineno, match.end_lineno)
                finding = _build_finding(
                    rule_id=match.rule.rule_id,
                    title=match.rule.title,
                    severity=match.rule.severity,
                    category=match.rule.category,
                    cwe=match.rule.cwe,
                    path=rel_path,
                    start=match.lineno,
                    end=match.end_lineno,
                    snippet=snippet,
                    confidence=match.rule.confidence,
                    confidence_rationale=match.rule.confidence_rationale,
                    exploit_scenario=match.rule.description,
                    recommended_fix=match.rule.recommendation,
                    references=match.rule.references,
                    cyber_flex=match.rule.cyber_flex,
                )
                _apply_suppression(
                    finding, inline_suppressions, ignore_rules, rel_path, suppressed_events
                )
                findings.append(finding)

        ai_rule = registry.get("SAICR-AI-001")
        ai_matches = scan_ai_prompt_injection(lines, ai_rule)
        for match in ai_matches:
            snippet = _snippet(lines, match.line, match.line)
            finding = _build_finding(
                rule_id=ai_rule.rule_id,
                title=ai_rule.title,
                severity=ai_rule.severity,
                category=ai_rule.category,
                cwe=ai_rule.cwe,
                path=rel_path,
                start=match.line,
                end=match.line,
                snippet=snippet,
                confidence=ai_rule.confidence,
                confidence_rationale=ai_rule.confidence_rationale,
                exploit_scenario=ai_rule.description,
                recommended_fix=ai_rule.recommendation,
                references=ai_rule.references,
                cyber_flex=ai_rule.cyber_flex,
            )
            _apply_suppression(
                finding, inline_suppressions, ignore_rules, rel_path, suppressed_events
            )
            findings.append(finding)

    if config.enable_external_scanners:
        findings.extend(run_semgrep(root))
        findings.extend(run_bandit(root))

    if config.enable_llm and config.llm_mode != "off":
        adapter = LlmAdapter(
            LlmAdapterConfig(
                mode=config.llm_mode,
                remote_url=config.remote_llm.base_url,
                api_key_env_var=config.remote_llm.api_key_env_var,
                model_name=config.remote_llm.model_name,
                redaction_enabled=config.redaction.enabled,
            )
        )
        for finding in findings:
            if finding.suppressed:
                continue
            snippet = finding.location.snippet
            if config.redaction.enabled:
                snippet = redact_text(snippet)
                finding.location.snippet = snippet
            enrichment = adapter.enrich(finding)
            finding.exploit_scenario = enrichment.exploit_scenario
            finding.recommended_fix = enrichment.recommended_fix
            finding.confidence = enrichment.confidence

    filtered = [f for f in findings if not f.suppressed and _severity_allows(f.severity, config.severity_threshold)]
    summary = _build_summary(findings, suppressed_events)
    return Report(
        tool="secure-ai-code-reviewer",
        version="0.1.0",
        findings=filtered,
        suppressed=suppressed_events,
        summary=summary,
    )


def _build_summary(findings: List[Finding], suppressed: List[SuppressionEvent]) -> ReportSummary:
    counts: Dict[str, int] = {level.value: 0 for level in Severity}
    for finding in findings:
        if not finding.suppressed:
            counts[finding.severity.value] += 1
    return ReportSummary(
        total_findings=sum(counts.values()),
        suppressed_findings=len(suppressed),
        by_severity=counts,
    )


def _scan_python_ast(tree: ast.AST, registry) -> List["AstMatch"]:
    from .rules.ast_python import scan_ast

    rules = [rule for rule in registry.all() if rule.languages and "python" in rule.languages]
    return scan_ast(tree, rules)


def _load_regex_rules() -> Dict[str, Dict[str, object]]:
    rules: Dict[str, Dict[str, object]] = {}
    data_path = files("secure_ai_code_reviewer.rules.data") / "regex_rules.yaml"
    payload = yaml.safe_load(data_path.read_text()) or []
    for entry in payload:
        rules[entry["id"]] = entry
    return rules


def _apply_suppression(
    finding: Finding,
    inline_suppressions: Dict[int, SuppressionEvent],
    ignore_rules: List[Tuple[Optional[str], str]],
    rel_path: str,
    suppressed_events: List[SuppressionEvent],
) -> None:
    ignore_reason = is_suppressed_by_ignore(ignore_rules, finding.id, rel_path)
    if ignore_reason:
        finding.suppressed = True
        finding.suppression_reason = ignore_reason
        suppressed_events.append(
            SuppressionEvent(
                rule_id=finding.id,
                path=rel_path,
                line=finding.location.start_line,
                reason=ignore_reason,
                source=".saicrignore",
            )
        )
        return

    inline = inline_suppressions.get(finding.location.start_line)
    if inline and inline.rule_id == finding.id:
        finding.suppressed = True
        finding.suppression_reason = inline.reason
        suppressed_events.append(inline)
if TYPE_CHECKING:
    from .rules.ast_python import AstMatch
