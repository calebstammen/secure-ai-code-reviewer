from __future__ import annotations

import re
from dataclasses import dataclass
from typing import List

from .base import Rule


@dataclass
class AiMatch:
    rule: Rule
    line: int
    message: str


SYSTEM_PATTERN = re.compile(r"role\s*[:=]\s*['\"]system['\"]", re.IGNORECASE)
USER_VAR_PATTERN = re.compile(r"\{\s*(user|input|query|prompt|message)[^}]*\}")
TOOL_PATTERN = re.compile(r"tool|function_call|tool_choice", re.IGNORECASE)
RAG_PATTERN = re.compile(r"retrieved|context_docs|documents|chunks", re.IGNORECASE)


def scan_ai_prompt_injection(lines: List[str], rule: Rule) -> List[AiMatch]:
    matches: List[AiMatch] = []
    for idx, line in enumerate(lines, start=1):
        if SYSTEM_PATTERN.search(line) and USER_VAR_PATTERN.search(line):
            matches.append(AiMatch(rule=rule, line=idx, message="User input in system prompt"))
        if RAG_PATTERN.search(line) and SYSTEM_PATTERN.search(line):
            matches.append(
                AiMatch(rule=rule, line=idx, message="Retrieved content injected into system prompt")
            )
        if TOOL_PATTERN.search(line) and USER_VAR_PATTERN.search(line):
            matches.append(AiMatch(rule=rule, line=idx, message="Untrusted input in tool definition"))
    return matches
