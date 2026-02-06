from secure_ai_code_reviewer.redaction import redact_text


def test_redaction_removes_api_keys() -> None:
    sample = "api_key=AKIA1234567890ABCDEF"
    redacted = redact_text(sample)
    assert "AKIA" not in redacted
    assert "[REDACTED]" in redacted
