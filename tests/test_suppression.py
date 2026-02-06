from pathlib import Path

from secure_ai_code_reviewer.suppression import (
    is_suppressed_by_ignore,
    parse_ignore_file,
    parse_inline_suppressions,
)


def test_inline_suppression() -> None:
    lines = ["print('ok')", "# saicr: ignore=SAICR-PY-001 reason=\"false positive\""]
    events = parse_inline_suppressions(lines, "sample.py")
    assert 2 in events
    assert events[2].rule_id == "SAICR-PY-001"


def test_ignore_file(tmp_path: Path) -> None:
    ignore = tmp_path / ".saicrignore"
    ignore.write_text("SAICR-PY-001:tests/**\n")
    rules = parse_ignore_file(ignore)
    reason = is_suppressed_by_ignore(rules, "SAICR-PY-001", "tests/sample.py")
    assert reason is not None
