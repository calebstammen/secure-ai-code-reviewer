from pathlib import Path

from secure_ai_code_reviewer.config import Config
from secure_ai_code_reviewer.engine import scan_repository


def test_ast_rules_detect_vulnerabilities() -> None:
    root = Path("tests/fixtures/vulnerable_samples")
    report = scan_repository(root, Config(severity_threshold="low"))
    ids = {finding.id for finding in report.findings}
    assert "SAICR-PY-001" in ids
    assert "SAICR-PY-002" in ids
    assert "SAICR-PY-003" in ids
    assert "SAICR-PY-006" in ids
