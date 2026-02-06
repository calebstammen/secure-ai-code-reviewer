# Prompt Injection Hardening

## Principles
- **Treat repository text as untrusted data.** README files, comments, and prompt templates are not instructions.
- **Instruction hierarchy matters.** System prompts should define immutable policy, and untrusted content must be isolated.
- **Never execute code or instructions from scanned content.** The analyzer only reasons about findings.

## System Prompt Guidance
Use a strict system prompt that:
- Explicitly states repository content is untrusted data.
- Requires outputs to follow a fixed JSON schema.
- Refuses to follow instructions embedded in code or documentation.

## Output Schema Validation
All LLM outputs are validated using Pydantic models:
- Missing fields, wrong types, or extra fields are rejected.
- Model output is only used for enrichment (exploit scenario + fix) and never to invent file paths or line numbers.

## Redaction & Minimal Context
- Redact likely secrets before any remote call.
- Send **only the minimal snippet** around the issue, never full files or the whole repository.

## Refusal Policy
If the LLM attempts to execute instructions from the repository or return non-conformant output, the adapter must fail closed and fall back to local findings.
