from __future__ import annotations

import ast
from dataclasses import dataclass
from typing import Iterable, List, Optional

from .base import Rule


@dataclass
class AstMatch:
    rule: Rule
    lineno: int
    end_lineno: int
    message: str


def _is_string_concat(node: ast.AST) -> bool:
    return isinstance(node, (ast.BinOp, ast.JoinedStr, ast.FormattedValue))


def _call_name(node: ast.AST) -> Optional[str]:
    if isinstance(node, ast.Attribute):
        return node.attr
    if isinstance(node, ast.Name):
        return node.id
    return None


def _get_full_attr(node: ast.AST) -> Optional[str]:
    if isinstance(node, ast.Attribute):
        base = _get_full_attr(node.value)
        return f"{base}.{node.attr}" if base else node.attr
    if isinstance(node, ast.Name):
        return node.id
    return None


def scan_ast(tree: ast.AST, rules: Iterable[Rule]) -> List[AstMatch]:
    rule_map = {rule.rule_id: rule for rule in rules}
    matches: List[AstMatch] = []

    for node in ast.walk(tree):
        if isinstance(node, ast.Call):
            func_name = _get_full_attr(node.func)
            # SQL injection heuristic
            if func_name and func_name.endswith("execute"):
                if node.args and _is_string_concat(node.args[0]):
                    rule = rule_map.get("SAICR-PY-001")
                    if rule:
                        matches.append(
                            AstMatch(
                                rule=rule,
                                lineno=node.lineno,
                                end_lineno=getattr(node, "end_lineno", node.lineno),
                                message="SQL execute with string formatting",
                            )
                        )
            # Command injection
            if func_name in {"os.system", "subprocess.call", "subprocess.run", "subprocess.Popen"}:
                shell_true = any(
                    kw.arg == "shell" and isinstance(kw.value, ast.Constant) and kw.value.value is True
                    for kw in node.keywords
                )
                if shell_true:
                    rule = rule_map.get("SAICR-PY-002")
                    if rule:
                        matches.append(
                            AstMatch(
                                rule=rule,
                                lineno=node.lineno,
                                end_lineno=getattr(node, "end_lineno", node.lineno),
                                message="shell=True enables command injection",
                            )
                        )
            # JWT verification disabled
            if func_name == "jwt.decode":
                for kw in node.keywords:
                    if kw.arg == "options" and isinstance(kw.value, ast.Dict):
                        for key, value in zip(kw.value.keys, kw.value.values):
                            if isinstance(key, ast.Constant) and key.value == "verify_signature":
                                if isinstance(value, ast.Constant) and value.value is False:
                                    rule = rule_map.get("SAICR-PY-003")
                                    if rule:
                                        matches.append(
                                            AstMatch(
                                                rule=rule,
                                                lineno=node.lineno,
                                                end_lineno=getattr(node, "end_lineno", node.lineno),
                                                message="JWT signature verification disabled",
                                            )
            # AES ECB mode
            if func_name == "AES.new":
                for arg in node.args:
                    if isinstance(arg, ast.Attribute) and arg.attr == "MODE_ECB":
                        rule = rule_map.get("SAICR-PY-006")
                        if rule:
                            matches.append(
                                AstMatch(
                                    rule=rule,
                                    lineno=node.lineno,
                                    end_lineno=getattr(node, "end_lineno", node.lineno),
                                    message="AES ECB mode used",
                                )
            # random used for tokens
            if func_name and func_name.startswith("random."):
                rule = rule_map.get("SAICR-PY-007")
                if rule:
                    matches.append(
                        AstMatch(
                            rule=rule,
                            lineno=node.lineno,
                            end_lineno=getattr(node, "end_lineno", node.lineno),
                            message="random module used for security-sensitive value",
                        )
            # SSRF heuristic
            if func_name and func_name.startswith("requests."):
                if node.args and not isinstance(node.args[0], ast.Constant):
                    rule = rule_map.get("SAICR-PY-004")
                    if rule:
                        matches.append(
                            AstMatch(
                                rule=rule,
                                lineno=node.lineno,
                                end_lineno=getattr(node, "end_lineno", node.lineno),
                                message="requests call with non-literal URL",
                            )
            # insecure cookie flags
            if func_name in {"set_cookie", "response.set_cookie"}:
                for kw in node.keywords:
                    if kw.arg in {"secure", "httponly"} and isinstance(kw.value, ast.Constant):
                        if kw.value.value is False:
                            rule = rule_map.get("SAICR-PY-005")
                            if rule:
                                matches.append(
                                    AstMatch(
                                        rule=rule,
                                        lineno=node.lineno,
                                        end_lineno=getattr(node, "end_lineno", node.lineno),
                                        message="cookie flag disabled",
                                    )
    return matches
