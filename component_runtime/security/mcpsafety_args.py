"""Argument-scanning adapter for MCP Safety Warden."""
from __future__ import annotations

import asyncio
from dataclasses import dataclass, field
from typing import Any, Mapping

__all__ = [
    "ArgScanResult",
    "ArgScanner",
    "MCPSAFETY_AVAILABLE",
    "MCPSAFETY_IMPORT_ERROR",
    "KNOWN_FALSE_POSITIVES",
]

try:
    from mcpsafetywarden.scan.args import scan_args_for_threats
    from mcpsafetywarden.core.security_utils import redact_text, sanitise_for_prompt

    MCPSAFETY_AVAILABLE = True
    MCPSAFETY_IMPORT_ERROR: str | None = None
except Exception as exc:                                  # noqa: BLE001 — 要如实报出来
    scan_args_for_threats = None                          # type: ignore[assignment]
    redact_text = None                                    # type: ignore[assignment]
    sanitise_for_prompt = None                             # type: ignore[assignment]
    MCPSAFETY_AVAILABLE = False
    MCPSAFETY_IMPORT_ERROR = f"{type(exc).__name__}: {exc}"


#: 已知的误报类别。命中这些**不自动放行**，但审计里要标出来，
#: 让人知道这条拒绝是保守取向而非确凿威胁。
#:
#: `ssrf_target`：mcpsafetywarden 会把任何回环/内网地址都当 SSRF。
#: 本项目的演示工具本来就跑在 `127.0.0.1:18080`，所以这是**已预期**的误报。
KNOWN_FALSE_POSITIVES: dict[str, str] = {
    "ssrf_target": "回环/内网地址被判为 SSRF；本项目本地沙箱本身就在 127.0.0.1 上",
}


@dataclass
class ArgScanResult:
    """一次参数扫描的结论。"""

    decision: str                       # allow | deny | unavailable
    categories: tuple[str, ...] = ()
    flagged_arg: str = ""
    flagged_value: str = ""
    reason: str = ""
    available: bool = True
    false_positive_hint: str = ""
    raw: Mapping[str, Any] = field(default_factory=dict)

    @property
    def blocked(self) -> bool:
        return self.decision == "deny"

    def to_dict(self) -> dict[str, Any]:
        return {
            "decision": self.decision,
            "categories": list(self.categories),
            "flagged_arg": self.flagged_arg,
            "flagged_value": self.flagged_value[:200],
            "reason": self.reason,
            "available": self.available,
            "false_positive_hint": self.false_positive_hint,
            "source": "mcpsafetywarden",
        }

    def policy_reasons(self) -> list[str]:
        """给策略引擎用的可读理由。"""
        if self.decision == "allow":
            return []
        if not self.available:
            return [f"mcpsafetywarden 不可用：{self.reason or '未安装'}"]
        text = "mcpsafetywarden 参数检查命中：" + "、".join(self.categories or ("unknown",))
        if self.flagged_arg:
            text += f"（参数 {self.flagged_arg}）"
        if self.false_positive_hint:
            text += f"。注意：{self.false_positive_hint}"
        return [text]


class ArgScanner:
    """参数级注入扫描组件。"""

    def __init__(self, *, use_llm: bool = False, llm_provider: str | None = None,
                 llm_model: str | None = None, llm_api_key: str | None = None) -> None:
        # 默认**不启用 LLM 二审**：本部署要求离线，而且规则模式已覆盖
        # SSRF / 路径遍历 / 命令注入这些确定性的东西。
        self.use_llm = use_llm
        self.llm_provider = llm_provider if use_llm else None
        self.llm_model = llm_model if use_llm else None
        self.llm_api_key = llm_api_key if use_llm else None

    @property
    def available(self) -> bool:
        return MCPSAFETY_AVAILABLE

    # -- 扫描 -------------------------------------------------------------
    def scan(self, tool: str, args: Mapping[str, Any],
             tool_description: str = "") -> ArgScanResult:
        if not MCPSAFETY_AVAILABLE:
            return ArgScanResult(
                decision="unavailable", available=False,
                reason=MCPSAFETY_IMPORT_ERROR or "未安装",
            )
        try:
            threat = asyncio.run(scan_args_for_threats(
                str(tool), dict(args), str(tool_description or ""),
                llm_provider=self.llm_provider, llm_model=self.llm_model,
                llm_api_key=self.llm_api_key,
            ))
        except Exception as exc:                          # noqa: BLE001 — 扫描失败要如实报
            return ArgScanResult(decision="unavailable", available=False,
                                 reason=f"{type(exc).__name__}: {exc}")

        if not threat:
            return ArgScanResult(decision="allow")

        categories = tuple(str(item) for item in (threat.get("categories") or []))
        hints = [KNOWN_FALSE_POSITIVES[name] for name in categories
                 if name in KNOWN_FALSE_POSITIVES]
        return ArgScanResult(
            decision="deny",
            categories=categories,
            flagged_arg=str(threat.get("flagged_arg") or ""),
            flagged_value=str(threat.get("flagged_value") or ""),
            reason=str(threat.get("reason") or ""),
            false_positive_hint="；".join(hints),
            raw=dict(threat),
        )

    # -- 输出侧辅助（同一包提供，顺手用上） -------------------------------
    @staticmethod
    def redact(text: str) -> tuple[str, bool]:
        """从自由文本里抹掉凭据形状的内容。用于把工具返回写进审计之前。"""
        if not MCPSAFETY_AVAILABLE or redact_text is None:
            return str(text), False
        try:
            return redact_text(str(text))
        except Exception:                                 # noqa: BLE001
            return str(text), False

    @staticmethod
    def sanitise_for_prompt(text: str, max_len: int = 300) -> str:
        """去掉控制字符/零宽字符后再放进 prompt。"""
        if not MCPSAFETY_AVAILABLE or sanitise_for_prompt is None:
            return str(text)[:max_len]
        try:
            return sanitise_for_prompt(str(text), max_len)
        except Exception:                                 # noqa: BLE001
            return str(text)[:max_len]
