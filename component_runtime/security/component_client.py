"""HTTP client for optional security services."""
from __future__ import annotations

import json
import os
import urllib.error
import urllib.request
from dataclasses import dataclass, field
from typing import Any, Mapping, Sequence

__all__ = [
    "RemoteArgScanner",
    "RemoteSemanticAligner",
    "RemoteMemoryGate",
    "RemoteArgScanResult",
    "RemoteSemanticResult",
    "DEFAULT_COMPONENT_SERVICE_URL",
]

DEFAULT_COMPONENT_SERVICE_URL = os.environ.get(
    "COMPONENT_SERVICE_URL", "http://127.0.0.1:8055")

#: 语义对齐要跑一次本地模型推理，超时给宽松些。
_SEMANTIC_TIMEOUT = float(os.environ.get("COMPONENT_SEMANTIC_TIMEOUT", "120"))
_ARG_TIMEOUT = float(os.environ.get("COMPONENT_ARG_TIMEOUT", "15"))


def _post(base_url: str, path: str, payload: Mapping[str, Any],
          timeout: float) -> dict[str, Any]:
    """POST 到组件服务。**绕过代理** —— 调试用的 HTTP_PROXY 会把 127.0.0.1 也代理掉。"""
    body = json.dumps(dict(payload), ensure_ascii=False).encode("utf-8")
    request = urllib.request.Request(
        base_url.rstrip("/") + path, data=body,
        headers={"Content-Type": "application/json; charset=utf-8"}, method="POST",
    )
    opener = urllib.request.build_opener(urllib.request.ProxyHandler({}))
    with opener.open(request, timeout=timeout) as response:
        return json.loads(response.read().decode("utf-8"))


@dataclass
class RemoteArgScanResult:
    decision: str
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
            "source": "mcpsafetywarden(remote)",
        }

    def policy_reasons(self) -> list[str]:
        if self.decision == "allow":
            return []
        if not self.available:
            return [f"参数扫描服务不可用：{self.reason or '未启动'}"]
        text = "参数检查命中：" + "、".join(self.categories or ("unknown",))
        if self.flagged_arg:
            text += f"（参数 {self.flagged_arg}）"
        if self.false_positive_hint:
            text += f"。注意：{self.false_positive_hint}"
        return [text]


@dataclass
class RemoteSemanticResult:
    decision: str
    misaligned: bool = False
    available: bool = True
    reason: str = ""
    observation: str = ""
    thought: str = ""
    raw: Mapping[str, Any] = field(default_factory=dict)

    @property
    def blocked(self) -> bool:
        return self.decision in {"ask", "deny"}

    def to_dict(self) -> dict[str, Any]:
        return {
            "decision": self.decision,
            "misaligned": self.misaligned,
            "available": self.available,
            "observation": self.observation,
            "thought": self.thought,
            "reason": self.reason,
            "source": "llamafirewall.AlignmentCheck@ollama(remote)",
        }

    def policy_reasons(self) -> list[str]:
        if not self.available:
            return [f"语义对齐服务不可用：{self.reason or '未启动'}"]
        if not self.misaligned:
            return []
        detail = (self.observation or self.thought or "").strip()
        text = "语义对齐检测到 Agent 动作偏离用户原始意图"
        if detail:
            text += f"：{detail[:200]}"
        return [text]


class RemoteArgScanner:
    """参数级注入扫描的远程客户端。接口与本地 `ArgScanner` 一致。"""

    def __init__(self, base_url: str = DEFAULT_COMPONENT_SERVICE_URL) -> None:
        self.base_url = base_url
        self._last_error = ""

    @property
    def available(self) -> bool:
        """探一次健康。不缓存 —— 服务可能刚起来或刚挂。"""
        try:
            request = urllib.request.Request(
                self.base_url.rstrip("/") + "/health", method="GET")
            opener = urllib.request.build_opener(urllib.request.ProxyHandler({}))
            with opener.open(request, timeout=2) as response:
                body = json.loads(response.read().decode("utf-8"))
            return bool(body.get("components", {}).get("arg_scanner", {}).get("available"))
        except Exception as exc:                      # noqa: BLE001
            self._last_error = f"{type(exc).__name__}: {exc}"
            return False

    def scan(self, tool: str, args: Mapping[str, Any],
             tool_description: str = "") -> RemoteArgScanResult:
        try:
            body = _post(self.base_url, "/arg-scan",
                         {"tool": tool, "args": dict(args or {}),
                          "tool_description": tool_description}, _ARG_TIMEOUT)
        except Exception as exc:                      # noqa: BLE001 — 要如实报出来
            return RemoteArgScanResult(decision="unavailable", available=False,
                                       reason=f"{type(exc).__name__}: {exc}")
        if not body.get("available", True):
            return RemoteArgScanResult(decision="unavailable", available=False,
                                       reason=str(body.get("reason") or "服务报告不可用"))
        return RemoteArgScanResult(
            decision=str(body.get("decision") or "allow"),
            categories=tuple(body.get("categories") or ()),
            flagged_arg=str(body.get("flagged_arg") or ""),
            flagged_value=str(body.get("flagged_value") or ""),
            reason=str(body.get("reason") or ""),
            false_positive_hint=str(body.get("false_positive_hint") or ""),
            raw=body,
        )


class RemoteMemoryGate:
    """记忆信任门的远程客户端。

    这是**跨会话记忆**在链路里的落点：读取时按 provenance 过滤，
    `privileged=True`（内容会影响工具选择）时只有 VERIFIED 及以上能过关。

    服务端常驻同一个 memward 实例，所以记忆在多次请求之间是持久的 ——
    这正是"跨会话"的含义。
    """

    def __init__(self, base_url: str = DEFAULT_COMPONENT_SERVICE_URL) -> None:
        self.base_url = base_url
        self._last_error = ""

    @property
    def available(self) -> bool:
        try:
            request = urllib.request.Request(
                self.base_url.rstrip("/") + "/health", method="GET")
            opener = urllib.request.build_opener(urllib.request.ProxyHandler({}))
            with opener.open(request, timeout=2) as response:
                body = json.loads(response.read().decode("utf-8"))
            return bool(body.get("components", {})
                        .get("memory_trust_gate", {}).get("available"))
        except Exception as exc:                      # noqa: BLE001
            self._last_error = f"{type(exc).__name__}: {exc}"
            return False

    def write(self, content: str, *, source_type: str = "user_instruction",
              source_id: str = "", session_id: str = "", metadata: dict | None = None) -> dict[str, Any]:
        return self._post("/memory/write", {
            "content": content, "source_type": source_type,
            "source_id": source_id, "session_id": session_id,
            "metadata": metadata or {},
        })

    def read(self, query: str, *, k: int = 5, privileged: bool = True,
             session_id: str = "") -> dict[str, Any]:
        return self._post("/memory/read", {
            "query": query, "k": k, "privileged": privileged,
            "session_id": session_id,
        })

    def audit(self) -> dict[str, Any]:
        return self._post("/memory/audit", {})

    def stats(self) -> dict[str, Any]:
        request = urllib.request.Request(self.base_url.rstrip("/") + "/health", method="GET")
        opener = urllib.request.build_opener(urllib.request.ProxyHandler({}))
        with opener.open(request, timeout=3) as response:
            body = json.loads(response.read().decode("utf-8"))
        info = body.get("components", {}).get("memory_trust_gate", {})
        if not info.get("available"):
            raise RuntimeError(info.get("error") or "Chroma memory unavailable")
        return dict(info.get("vector_store") or {})

    def rollback(self, record_id: str) -> dict[str, Any]:
        return self._post("/memory/rollback", {"record_id": record_id})

    def _post(self, path: str, payload: Mapping[str, Any]) -> dict[str, Any]:
        try:
            body = _post(self.base_url, path, payload, _ARG_TIMEOUT)
        except Exception as exc:                      # noqa: BLE001 — 要如实报出来
            return {"available": False,
                    "reason": f"{type(exc).__name__}: {exc}"}
        if not body.get("available", True):
            return {"available": False,
                    "reason": str(body.get("reason") or "服务报告不可用"),
                    "kept": [], "excluded": []}
        return body


class RemoteSemanticAligner:
    """语义对齐的远程客户端。接口与本地 `SemanticAlignment` 一致。"""

    def __init__(self, base_url: str = DEFAULT_COMPONENT_SERVICE_URL) -> None:
        self.base_url = base_url

    @property
    def available(self) -> bool:
        try:
            request = urllib.request.Request(
                self.base_url.rstrip("/") + "/health", method="GET")
            opener = urllib.request.build_opener(urllib.request.ProxyHandler({}))
            with opener.open(request, timeout=2) as response:
                body = json.loads(response.read().decode("utf-8"))
            return bool(body.get("components", {}).get("semantic_aligner", {}).get("available"))
        except Exception:                             # noqa: BLE001
            return False

    def check(self, user_request: str, action: str,
              action_input: Mapping[str, Any] | str | None = None, *,
              thought: str = "", history: Sequence[str] = ()) -> RemoteSemanticResult:
        try:
            body = _post(self.base_url, "/semantic-align", {
                "user_request": user_request, "action": action,
                "action_input": action_input, "thought": thought,
                "history": list(history),
            }, _SEMANTIC_TIMEOUT)
        except Exception as exc:                      # noqa: BLE001 — 要如实报出来
            return RemoteSemanticResult(decision="unavailable", available=False,
                                        reason=f"{type(exc).__name__}: {exc}")
        if not body.get("available", True):
            return RemoteSemanticResult(decision="unavailable", available=False,
                                        reason=str(body.get("reason") or "服务报告不可用"))
        return RemoteSemanticResult(
            decision=str(body.get("decision") or "allow"),
            misaligned=bool(body.get("misaligned")),
            reason=str(body.get("reason") or ""),
            observation=str(body.get("observation") or ""),
            thought=str(body.get("thought") or ""),
            raw=body,
        )
