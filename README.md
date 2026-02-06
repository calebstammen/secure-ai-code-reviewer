# Secure AI Code Reviewer (SAICR)

Secure AI Code Reviewer is a production-ready CLI and GitHub Action that scans codebases for security risks across the OWASP Top 10, auth bugs, insecure crypto, and AI prompt injection risks. It combines lightweight static analysis (AST/regex), optional external scanners (Semgrep/Bandit), and an opt-in LLM enrichment pass that is safe-by-default.

## Secure SDLC Fit
- **PR checks**: Run in GitHub Actions with SARIF output for code scanning.
- **CI hardening**: Enforce severity thresholds and suppress verified false positives.
- **Developer workflow**: Quick local scans to spot issues before review.

## Install

### Pipx (recommended)
```bash
pipx install -e .
```

### Pip
```bash
pip install -e .
```

## Quickstart
```bash
saicr scan . --format json --out saicr_report.json
saicr scan . --format md --out saicr_report.md
saicr scan . --format sarif --out results.sarif
```

## Example JSON Output (short)
```json
{
  "tool": "secure-ai-code-reviewer",
  "version": "0.1.0",
  "findings": [
    {
      "id": "SAICR-PY-001",
      "title": "SQL injection via string formatting",
      "severity": "High",
      "confidence": {"score": 0.7, "rationale": "AST detects execute() with formatted string."},
      "location": {"path": "app/db.py", "start_line": 12, "end_line": 12, "snippet": "cursor.execute(f\"SELECT * FROM users WHERE id={user_id}\")"},
      "category": "OWASP",
      "cwe": ["CWE-89: SQL Injection"],
      "exploit_scenario": "SQL queries built via string formatting can allow injection.",
      "recommended_fix": "Use parameterized queries or ORM parameter binding.",
      "references": ["CWE-89: https://cwe.mitre.org/data/definitions/89.html"],
      "cyber_flex": "This is a classic CWE-89 footgun that turns string formatting into arbitrary SQL."
    }
  ]
}
```

## Example Markdown Report (short)
```text
### SAICR-PY-002: Command injection via shell=True
- Severity: **High**
- Confidence: **0.65** (AST sees subprocess calls with shell=True.)
- Category: OWASP
- CWE: CWE-78: OS Command Injection
- Location: `scripts/run.py:22-22`
```

## Suppressions
### Inline
```python
# saicr: ignore=SAICR-PY-001 reason="Query is parameterized by trusted ORM"
```

### Repository ignore file
Create `.saicrignore` at repo root:
```
# ignore all findings in vendor
vendor/**
# ignore a specific rule in generated code
SAICR-REG-001:generated/**
```

## Configuration
Place `.saicr.yaml` at repo root. CLI flags override config.

### LLM Modes
- **off (default):** no model calls.
- **local:** deterministic local adapter with strict schema validation.
- **remote:** explicit opt-in only; redaction + minimal context window.

## Reports
- **JSON**: machine readable, full schema.
- **Markdown**: human-friendly summary.
- **SARIF**: GitHub code scanning integration.

## GitHub Actions
Add `.github/workflows/saicr.yml` (included in this repo) to scan PRs and upload SARIF.

## Safety Docs
- [Model isolation](MODEL_ISOLATION.md)
- [Prompt injection hardening](prompt_injection_hardening.md)

## Extending Rules Safely
Rules are data-driven via YAML and code rules for AST/AI heuristics. When adding new rules, prefer minimal context extraction, strict confidence scoring, and explicit CWE mapping. Ensure rule IDs are stable, avoid sending sensitive data to remote analyzers unless explicitly enabled, and add tests for both vulnerable and safe examples to keep false positives low.
