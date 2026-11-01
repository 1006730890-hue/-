"""Data-only policy DSL. No eval, code strings, or caller supplied predicates."""
from __future__ import annotations
import json
from pathlib import Path

FIELDS = {"tool", "classification", "trust", "code_review_task", "memory_blocked",
          "sensitive_payload", "untrusted_destination", "credential_handoff", "dangerous_command", "sensitive_write", "tool_requested"}


def condition(expr, facts):
    if not isinstance(expr, dict) or len(expr) != 1:
        raise ValueError("策略条件必须含唯一操作符")
    op, value = next(iter(expr.items()))
    if op in {"all", "any"}:
        matches = [condition(child, facts) for child in value]
        return all(matches) if op == "all" else any(matches)
    if op == "not":
        return not condition(value, facts)
    if op in {"eq", "in"}:
        field, expected = value
        if field not in FIELDS:
            raise ValueError("策略引用未知语义事实")
        return facts.get(field) == expected if op == "eq" else facts.get(field) in expected
    raise ValueError("不支持的策略操作符")


def load_rules(path):
    payload = json.loads(Path(path).read_text(encoding="utf-8"))
    if payload.get("version") != 1:
        raise ValueError("未知 DSL 版本")
    rules = payload["rules"]
    for rule in rules:
        if rule["decision"] not in {"allow", "ask", "deny"} or rule["risk"] not in {"low", "medium", "high"}:
            raise ValueError("未知策略三态或风险等级")
        condition(rule["when"], {})
    return rules
