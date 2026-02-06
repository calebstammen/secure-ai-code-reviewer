from __future__ import annotations

from importlib.resources import files
from typing import Dict, List

import yaml

from .base import Rule


class RuleRegistry:
    def __init__(self) -> None:
        self._rules: Dict[str, Rule] = {}

    def register(self, rule: Rule) -> None:
        self._rules[rule.rule_id] = rule

    def get(self, rule_id: str) -> Rule:
        return self._rules[rule_id]

    def all(self) -> List[Rule]:
        return list(self._rules.values())


def load_rules() -> RuleRegistry:
    registry = RuleRegistry()
    data_path = files("secure_ai_code_reviewer.rules.data")
    for file_name in ["regex_rules.yaml", "ast_rules.yaml"]:
        content = (data_path / file_name).read_text()
        payload = yaml.safe_load(content) or []
        for entry in payload:
            registry.register(
                Rule(
                    rule_id=entry["id"],
                    title=entry["title"],
                    severity=entry["severity"],
                    category=entry["category"],
                    cwe=entry["cwe"],
                    description=entry["description"],
                    recommendation=entry["recommendation"],
                    references=entry["references"],
                    cyber_flex=entry["cyber_flex"],
                    confidence=entry["confidence"],
                    confidence_rationale=entry["confidence_rationale"],
                    languages=entry.get("languages"),
                )
            )
    return registry
