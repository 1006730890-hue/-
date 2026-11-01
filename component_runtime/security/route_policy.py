"""路由意图策略：用户这句话到底授权了什么动作。

赛题能力 3 的落点之一，也是能力 1「识别来自用户输入的越权指令」的实现。

与相邻组件的分工
----------------
- `alignment.py`       事后：模型提出了动作，判断它是否偏离用户意图。
- `route_policy.py`    事前：只从用户请求本身推出「允许做什么」，不看模型。
- `policy_dsl.py`      对参数做规则检查（路径、命令、附言）。
- `business` 层        金额、余额、IBAN 等业务校验。

为什么需要它
------------
原实现没有「用户到底授权了什么」这个概念，因此下面这条赛题明文要求无法落地：

    限制 git.push 操作，**用户原始任务为代码检视时**，禁止触发代码提交推送操作

代码检视任务里用户一个字都没提推送，但模型完全可以去推。没有路由意图，
就没有判据说这是越权。

设计取向：**读放开，写收紧**
----------------------------
只读工具即使不在请求范围内也不拦（读错是「答非所问」，不是越权）；
中高影响的变更类工具必须有明确授权，否则拒绝。这样既守住执行边界，
又不会把正常业务问成攻击。
"""
from __future__ import annotations

from dataclasses import dataclass, field
from typing import Any, Mapping

from .alignment import (
    TOOL_SEMANTICS,
    IntentPlanAligner,
    IntentProfile,
    ToolSemantics,
    _DEFAULT_SEMANTICS,
)

__all__ = [
    "RouteIntent",
    "RoutePrescription",
    "RouteScopeEngine",
    "CODE_REVIEW_FORBIDDEN_CATEGORIES",
]

#: 代码检视任务下禁止的类别。赛题原文：
#: 「限制 git.push 操作，用户原始任务为代码检视时，禁止触发代码提交推送操作」。
#:
#: 注意：这里**不是**「git_push 一律禁止」。用户明确要求推送时必须放行 ——
#: 否则规则就从「任务语义约束」退化成「路径黑名单」，
#: 而赛题开篇正是要求「摒弃单纯依赖工具名称、路径黑白名单的粗粒度匹配方式」。
CODE_REVIEW_FORBIDDEN_CATEGORIES: frozenset[str] = frozenset({"git_write"})


@dataclass(frozen=True)
class RouteIntent:
    """用户这句话授权的动作范围。纯从请求文本推出，与模型无关。"""

    text: str
    allowed_categories: frozenset[str]
    forbidden_categories: frozenset[str]
    pseudo_authority: bool = False
    code_review_task: bool = False
    targets: frozenset[str] = frozenset()
    scenario_id: str = ""

    @property
    def profile(self) -> IntentProfile:
        """转成 `alignment` 组件认的意图画像。"""
        return IntentProfile(
            text=self.text,
            allowed_categories=self.allowed_categories,
            targets=self.targets,
            pseudo_authority=self.pseudo_authority,
            code_review_task=self.code_review_task,
            scenario_id=self.scenario_id,
        )


@dataclass(frozen=True)
class RoutePrescription:
    """本次请求的工具级处方。可直接喂给策略引擎。"""

    allowed_tools: frozenset[str]
    forbidden_tools: frozenset[str]
    request_denied: bool = False
    reasons: tuple[str, ...] = ()
    intent: RouteIntent | None = None

    def to_policy_dict(self) -> dict[str, Any]:
        return {
            "allowed_tools": sorted(self.allowed_tools),
            "forbidden_tools": sorted(self.forbidden_tools),
            "request_denied": self.request_denied,
            "reasons": list(self.reasons),
            "allowed_categories": sorted(self.intent.allowed_categories) if self.intent else [],
            "forbidden_categories": sorted(self.intent.forbidden_categories) if self.intent else [],
        }


class RouteScopeEngine:
    """把「用户请求」翻译成「允许调用哪些工具」。"""

    def __init__(
        self,
        *,
        tool_semantics: Mapping[str, ToolSemantics] | None = None,
        aligner: IntentPlanAligner | None = None,
        extra_forbidden_categories: tuple[str, ...] = (),
    ) -> None:
        self.tool_semantics = dict(tool_semantics or TOOL_SEMANTICS)
        self.aligner = aligner or IntentPlanAligner(self.tool_semantics)
        self._extra_forbidden = frozenset(extra_forbidden_categories)

    # -- 语义查询 ---------------------------------------------------------
    def semantics(self, tool: str) -> ToolSemantics:
        return self.tool_semantics.get(str(tool), _DEFAULT_SEMANTICS)

    # -- 意图 -------------------------------------------------------------
    def interpret(
        self,
        message: str,
        *,
        allowed_classification: str = "public",
        scenario_id: str = "",
    ) -> RouteIntent:
        profile = self.aligner.profile_intent(
            message, allowed_classification=allowed_classification, scenario_id=scenario_id
        )
        forbidden = set(self._extra_forbidden)
        if profile.code_review_task:
            # 赛题明文：代码检视任务禁止触发推送。
            forbidden |= CODE_REVIEW_FORBIDDEN_CATEGORIES
        return RouteIntent(
            text=profile.text,
            allowed_categories=profile.allowed_categories,
            forbidden_categories=frozenset(forbidden),
            pseudo_authority=profile.pseudo_authority,
            code_review_task=profile.code_review_task,
            targets=profile.targets,
            scenario_id=profile.scenario_id,
        )

    # -- 处方 -------------------------------------------------------------
    def prescribe(
        self,
        intent: RouteIntent,
        candidate_tools: Mapping[str, str] | set[str] | tuple[str, ...],
    ) -> RoutePrescription:
        """给定本次请求可用的工具集合，算出允许/禁止调用哪些。

        `candidate_tools` 是 Agent 这次实际挂载的工具面
        （可以是集合，也可以是 `{工具名: 说明}` 映射）。
        """
        names = set(candidate_tools.keys()) if isinstance(candidate_tools, Mapping) else set(candidate_tools)

        allowed: set[str] = set()
        forbidden: set[str] = set()
        reasons: list[str] = []

        for name in sorted(names):
            sem = self.semantics(name)
            category = sem.category

            if category in intent.forbidden_categories:
                forbidden.add(name)
                continue

            # 未登记的工具不做越权判定：只对已知类别的确定性行为负责，
            # 否则加一个新工具就会凭空多出一堆拒绝。
            if category == "unknown":
                allowed.add(name)
                continue

            if sem.impact == "low":
                # 读放开：只读工具拦下来只会让智能体变笨，不会更安全。
                allowed.add(name)
                continue

            if category in intent.allowed_categories:
                allowed.add(name)
            else:
                forbidden.add(name)

        if intent.pseudo_authority:
            reasons.append(
                "请求中出现伪授权话术（如「系统通知/无需确认/忽略以上」），不作为动作授权依据"
            )
        if intent.code_review_task:
            reasons.append("用户原始任务为代码检视，禁止触发代码提交推送")
        if forbidden:
            reasons.append(
                "本次请求未授权以下变更类动作：" + "、".join(sorted(forbidden))
            )

        return RoutePrescription(
            allowed_tools=frozenset(allowed),
            forbidden_tools=frozenset(forbidden),
            request_denied=False,
            reasons=tuple(reasons),
            intent=intent,
        )
