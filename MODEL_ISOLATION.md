# Model Isolation Strategy

Secure AI Code Reviewer is safe-by-default and does not send code off the machine unless explicitly enabled. The optional LLM adapter runs in **three modes**:

- **off (default):** No model calls.
- **local:** Stubbed deterministic adapter (no external dependency).
- **remote:** Explicit opt-in required via config; prints a warning banner and uses redaction.

## Isolation Guarantees
- **Separate process:** Remote adapter runs in a subprocess (curl) to isolate the scanning process.
- **Timeouts:** Remote calls are capped with a strict timeout to prevent hangs.
- **Payload limits:** Only a minimal snippet around the issue is sent.
- **Deterministic schema validation:** LLM output must match a strict Pydantic schema or is rejected.
- **Logging hygiene:** Logs are sanitized and avoid leaking secrets or full file contents.

## Safety Defaults
- No code is uploaded unless `enable_llm` + `llm_mode=remote` are set.
- Redaction removes likely secrets before any remote call.
- System prompts explicitly treat repository text as untrusted data.
