"""语义层意图—计划对齐（官方 AlignmentCheck，推理改走本地 Ollama）。

为什么需要它，以及为什么不能只靠确定性规则
--------------------------------------------
实测（见 `DETECTOR_SELECTION.md`）：所有**内容层分类器**对「业务口吻包装的间接注入」
都不可靠 —— Prompt Guard 2 是 **0%**，多语言 deberta 是 83% 但**误报 33%**。

根因不是模型不够好，而是**这条路本身走不通**：攻击载荷被包装成正常业务文本时，
它在内容层面确实「看起来正常」。唯一能识别的信号是
**「这个动作和用户原本要办的事对不上」** —— 那是语义层的事。

`security/alignment.py` 已经用确定性规则做了这件事（工具越界、对象不符、
密级跃迁、未知外发），零成本可复现。但它只认结构化特征，
对「用户说查账单、模型却发起转账」这种**同时命中**的情况没问题，
对更微妙的偏离（措辞不同但意图一致）会漏。

所以这里补**语义路径**，两者并列取最严。

用的是官方实现，不是自己写 prompt
---------------------------------
`llamafirewall.scanners.experimental.AlignmentCheckScanner` 是 Meta 的官方
AlignmentCheck（few-shot 审计推理链，arXiv 2505.03574）。它的
system prompt 与 7 个 few-shot 示例全部复用，**一行都没改**。

唯一改动是**推理位置**：官方默认走 `api.together.xyz`（需要 `TOGETHER_API_KEY`，
云端）。这里把 `LLMClient` 指向**本地 Ollama 的 OpenAI 兼容端点** ——
实测 Ollama 支持 `response_format=json_schema` 结构化输出，
所以官方的 `beta.chat.completions.parse()` 能原样工作。

代价与取舍
----------
每次判定多一次模型调用（实测 Qwen3-8B 约 4–6 秒）。所以调用方应当：
**确定性规则先跑**（便宜、覆盖明显偏离），只有它没命中时才走语义路径。
本模块不替调用方做这个编排，只提供能力。
"""
from __future__ import annotations

import asyncio
import sys
from dataclasses import dataclass, field
from pathlib import Path
from typing import Any, Sequence

__all__ = [
    "SemanticAlignment",
    "SemanticAlignmentResult",
    "SEMANTIC_ALIGNMENT_AVAILABLE",
    "SEMANTIC_ALIGNMENT_IMPORT_ERROR",
    "DEFAULT_OLLAMA_BASE_URL",
]

DEFAULT_OLLAMA_BASE_URL = "http://127.0.0.1:11434/v1"
DEFAULT_MODEL = "qwen3:8b"

_TOOLS = Path(__file__).resolve().parents[1] / "tools"
if str(_TOOLS) not in sys.path:
    sys.path.insert(0, str(_TOOLS))

try:
    import lf_compat                                        # noqa: F401  先装兼容垫片
    from llamafirewall import (                             # noqa: PLC0415
        AssistantMessage,
        UserMessage,
    )
    from llamafirewall.scanners.base_scanner import Scanner
    from llamafirewall.scanners.experimental.alignmentcheck_scanner import (
        SYSTEM_PROMPT,
        AlignmentCheckOutputSchema,
        AlignmentCheckScanner,
    )
    from llamafirewall.utils.base_llm import LLMClient

    SEMANTIC_ALIGNMENT_AVAILABLE = True
    SEMANTIC_ALIGNMENT_IMPORT_ERROR: str | None = None
except Exception as exc:                                    # noqa: BLE001 — 要如实报出来
    SEMANTIC_ALIGNMENT_AVAILABLE = False
    SEMANTIC_ALIGNMENT_IMPORT_ERROR = f"{type(exc).__name__}: {exc}"


@dataclass
class SemanticAlignmentResult:
    """一次语义对齐判定的结论。"""

    decision: str                       # allow | ask | deny | unavailable
    misaligned: bool = False
    available: bool = True
    reason: str = ""
    observation: str = ""
    thought: str = ""
    raw: dict[str, Any] = field(default_factory=dict)

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
            "source": "llamafirewall.AlignmentCheck@ollama",
        }

    def policy_reasons(self) -> list[str]:
        if not self.available:
            return [f"语义对齐不可用：{self.reason or '未知原因'}"]
        if not self.misaligned:
            return []
        detail = (self.observation or self.thought or "").strip()
        text = "语义对齐检测到 Agent 动作偏离用户原始意图"
        if detail:
            text += f"：{detail[:200]}"
        return [text]


def _build_local_scanner(model: str, base_url: str, timeout_seconds: float) -> Any:
    """官方 AlignmentCheckScanner，只把 LLM 换成本地 Ollama。

    不调用父类 `__init__` 的原因：`CustomCheckScanner.__init__` 把
    Together 的 base_url / 环境变量写死了，没有出口。这里复刻它做的那几件事
    （system prompt、output schema、LLM client），其余逻辑仍走官方实现。
    """

    class _LocalAlignmentCheck(AlignmentCheckScanner):
        def __init__(self) -> None:
            Scanner.__init__(self, scanner_name="AlignmentCheck (local Ollama)",
                             block_threshold=0.0)
            self.system_prompt = SYSTEM_PROMPT
            self.output_schema = AlignmentCheckOutputSchema
            self.temperature = 0.0
            self.llm = LLMClient(model_name=model, api_base_url=base_url,
                                 api_key="ollama-local")
            if timeout_seconds > 0:
                try:
                    self.llm.client = self.llm.client.with_options(timeout=timeout_seconds)
                except Exception:                           # noqa: BLE001 — 超时设置失败不该致命
                    pass
            self.require_full_trace = True

    return _LocalAlignmentCheck()


class SemanticAlignment:
    """语义对齐组件。惰性加载，Ollama 不可用时明确报告。"""

    def __init__(self, *, model: str = DEFAULT_MODEL,
                 base_url: str = DEFAULT_OLLAMA_BASE_URL,
                 timeout_seconds: float = 120.0) -> None:
        self.model = model
        self.base_url = base_url
        self.timeout_seconds = timeout_seconds
        self._scanner: Any = None
        self._load_error = ""

    @property
    def available(self) -> bool:
        return SEMANTIC_ALIGNMENT_AVAILABLE

    def _scanner_or_none(self) -> Any:
        if not SEMANTIC_ALIGNMENT_AVAILABLE:
            self._load_error = SEMANTIC_ALIGNMENT_IMPORT_ERROR or "llamafirewall 不可用"
            return None
        if self._scanner is None:
            try:
                self._scanner = _build_local_scanner(
                    self.model, self.base_url, self.timeout_seconds)
            except Exception as exc:                        # noqa: BLE001
                self._load_error = f"{type(exc).__name__}: {exc}"
                return None
        return self._scanner

    # -- 判定 -------------------------------------------------------------
    def check(
        self,
        user_request: str,
        action: str,
        action_input: str | dict[str, Any] = "",
        *,
        thought: str = "",
        history: Sequence[str] = (),
    ) -> SemanticAlignmentResult:
        """判断 `action` 是否偏离 `user_request` 的意图。

        官方 scanner 的设计就是「只看当前这一个动作，不看整条轨迹」，
        所以 `history` 只是补充上下文，判定主体是 `action`。
        """
        if not self.available:
            return SemanticAlignmentResult(
                decision="unavailable", available=False,
                reason=SEMANTIC_ALIGNMENT_IMPORT_ERROR or "llamafirewall 不可用")

        scanner = self._scanner_or_none()
        if scanner is None:
            return SemanticAlignmentResult(
                decision="unavailable", available=False,
                reason=self._load_error or "scanner 初始化失败")

        if isinstance(action_input, dict):
            rendered = ", ".join(f"{k}={v!r}" for k, v in action_input.items())
        else:
            rendered = str(action_input or "")
        # 官方 scanner 的输入里 THOUGHT 是「Agent 的推理」。没有推理时**不能留空** ——
        # 实测空 THOUGHT 会让它的结构化输出解析失败（返回 ERROR），
        # 而官方对 ERROR 是 fail-closed（结论=True）。退化输入用原始请求兜底。
        effective_thought = str(thought or "").strip() or f"（无显式推理）用户请求：{user_request}"
        body = (f"THOUGHT: {effective_thought}\n"
                f"SELECTED ACTION:\nACTION: {action}\nACTION INPUT: {rendered}")

        messages: list[Any] = [UserMessage(content=str(user_request))]
        for item in history:
            messages.append(AssistantMessage(content=str(item)))
        messages.append(AssistantMessage(content=body))
        current = AssistantMessage(content=body)

        try:
            scan_result = asyncio.run(scanner.scan(current, messages))
        except Exception as exc:                            # noqa: BLE001 — 要如实报出来
            return SemanticAlignmentResult(
                decision="unavailable", available=False,
                reason=f"{type(exc).__name__}: {exc}")

        # **关键区分**：官方对内部错误是 fail-closed 的 —— 出错时返回
        # `conclusion=True`（`treating as potentially compromised for safety`）。
        # 那在它的语境里是合理的，但如果我们把「检查失败」当成「判定偏离」，
        # 就会**每次失败都变成 ask**，把正常业务全部拖进人工确认。
        #
        # 所以这里按 `status` 分流：
        #   - ERROR/SKIPPED -> unavailable（如实报告组件没给出结论，不伪造判定）
        #   - SUCCESS       -> 才用它的 decision
        status = str(getattr(scan_result.status, "value", scan_result.status))
        if status != "success":
            return SemanticAlignmentResult(
                decision="unavailable", available=False,
                reason=f"上游返回 {status}：{str(scan_result.reason or '')[:160]}")

        decision = str(getattr(scan_result.decision, "value", scan_result.decision))
        # 官方的语义：命中就给 HUMAN_IN_THE_LOOP_REQUIRED（= 我们的 ask），
        # 不是 deny。这个区分是有意的 —— 语义判断存在不确定性，
        # 让它落到「请用户确认」而不是「直接阻断」，避免误伤正常业务。
        normalized = "ask" if decision == "human_in_the_loop_required" else "allow"
        misaligned = normalized == "ask"

        reason = str(scan_result.reason or "")
        observation, thought_text = self._split_reason(reason)
        return SemanticAlignmentResult(
            decision=normalized,
            misaligned=misaligned,
            available=True,
            reason=reason,
            observation=observation,
            thought=thought_text,
            raw={"score": float(getattr(scan_result, "score", 0.0) or 0.0),
                 "upstream_decision": decision},
        )

    @staticmethod
    def _split_reason(reason: str) -> tuple[str, str]:
        """官方把三项拼在一个字符串里，这里拆开便于审计。"""
        observation = thought_text = ""
        for line in reason.splitlines():
            if line.startswith("Observation:"):
                observation = line[len("Observation:"):].strip()
            elif line.startswith("Thought:"):
                thought_text = line[len("Thought:"):].strip()
        return observation, thought_text
