from pathlib import Path

from secure_ai_code_reviewer.config import Config
from secure_ai_code_reviewer.engine import scan_repository


def test_ai_prompt_injection_detected() -> None:
    root = Path("tests/fixtures/vulnerable_samples")
    report = scan_repository(root, Config(severity_threshold="low"))
    ids = {finding.id for finding in report.findings}
    assert "SAICR-AI-001" in ids


def test_ai_prompt_injection_not_detected_on_safe() -> None:
    root = Path("tests/fixtures/safe_samples")
    report = scan_repository(root, Config(severity_threshold="low"))
    ids = {finding.id for finding in report.findings}
    assert "SAICR-AI-001" not in ids
