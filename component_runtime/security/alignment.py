"""意图—计划—工具语义对齐（确定性组件）。

赛题能力 2 要求：

    基于 Agent 对话上下文与全量工具调用序列，精准刻画「用户原始任务意图」
    与「Agent 实际执行计划」之间的语义偏离度，实现攻击行为的可解释研判。
    系统需输出清晰、可落地的研判结论。

设计取舍
--------
本模块**不调用模型、不引入向量库**，用结构化意图画像比对得出偏离度。理由：

1. 赛题要的是「语义策略 DSL」的同类物 —— 确定性、可解释、可复现。
   一个数字如果说不清怎么来的，在安全研判里没有价值。
2. 词面相似度算不出「工具越界」。用户问账单、Agent 要转账，这两句
   在词面上毫无交集，任何相似度只会说「不像」，说不出
   「因为 send_money 不在本次请求的许可集内」。

所以偏离度 = 若干**具名分项**之和，每项都带证据。模型只用于把
`AlignmentResult.conclusion_facts` 润色成给用户看的研判结论句。

权重与关键词表都是**数据**（模块级常量），可审计、可单测、可调参。

与 policy_dsl 的分工
--------------------
- `policy_dsl.ToolPolicyEngine`：看**参数本身**是否危险（路径、命令、附言）。
- `alignment.IntentPlanAligner`：看**这次调用是否偏离用户意图**。
两者独立判定，由调用方按最严合并。
"""
from __future__ import annotations

import re
from dataclasses import dataclass, field
from typing import Any, Iterable, Mapping

__all__ = [
    "IntentProfile",
    "PlanProfile",
    "AlignmentResult",
    "IntentPlanAligner",
    "TOOL_SEMANTICS",
    "TRUSTED_EGRESS_DOMAINS",
]


# --------------------------------------------------------------------------
# 偏离分项权重。和为 1.0，便于把 deviation 解释成「占满分偏离的比例」。
# 每项的具体来源见 _score_* 方法。
# --------------------------------------------------------------------------
WEIGHT_TOOL_OUT_OF_SCOPE = 0.50
WEIGHT_TARGET_MISMATCH = 0.20
WEIGHT_CLASSIFICATION_ESCALATION = 0.20
WEIGHT_UNKNOWN_EGRESS = 0.10

#: 密级偏序。数字越大越敏感。
_CLASSIFICATION_RANK = {"public": 0, "internal": 1, "sensitive": 2, "secret": 3}

#: 可信外发域名后缀。不在此列即视为未知外发目标。
#: 这里刻意写得很窄：本地回环 + 业务示例域。
TRUSTED_EGRESS_DOMAINS: tuple[str, ...] = (
    "127.0.0.1",
    "localhost",
    "example.test",
    "bank.internal",
)


# --------------------------------------------------------------------------
# 工具语义分类。
#   category      : 粗粒度类别，用于「显式请求」判定与报告措辞
#   impact        : low / medium / high —— 越界时的严重程度
#   target_args   : 这些参数指向「操作对象」，用于 target_mismatch
#   egress_arg    : 若存在，该参数是外发目标，用于 unknown_egress
# --------------------------------------------------------------------------
@dataclass(frozen=True)
class ToolSemantics:
    category: str
    impact: str
    target_args: tuple[str, ...] = ()
    egress_arg: str = ""


TOOL_SEMANTICS: dict[str, ToolSemantics] = {
    # ---- 读类：低影响 ----
    "get_balance": ToolSemantics("account_read", "low"),
    "get_iban": ToolSemantics("account_read", "low"),
    "get_user_info": ToolSemantics("account_read", "low"),
    "get_most_recent_transactions": ToolSemantics("account_read", "low"),
    "get_scheduled_transactions": ToolSemantics("account_read", "low"),
    "fs.read": ToolSemantics("file_read", "low", target_args=("path", "file_path")),
    "read_file": ToolSemantics("file_read", "low", target_args=("path", "file_path")),
    "memory.read": ToolSemantics("memory_read", "low"),
    "mcp.call": ToolSemantics("mcp_read", "medium", target_args=("name", "tool")),
    # ---- 外发类 ----
    "net.fetch": ToolSemantics("egress", "medium", egress_arg="url"),
    "web_fetch": ToolSemantics("egress", "medium", egress_arg="url"),
    # ---- 写类：中高影响 ----
    "fs.write": ToolSemantics("file_write", "high", target_args=("path", "file_path")),
    "file_write": ToolSemantics("file_write", "high", target_args=("path", "file_path")),
    "report_write": ToolSemantics("file_write", "high", target_args=("path", "file_path")),
    "memory.write": ToolSemantics("memory_write", "medium"),
    # ---- 高影响：动钱、动凭证、动仓库、起子 Agent ----
    "send_money": ToolSemantics("money", "high", target_args=("recipient",)),
    "transfer": ToolSemantics("money", "high", target_args=("recipient",)),
    "schedule_transaction": ToolSemantics("money", "high", target_args=("recipient",)),
    "update_password": ToolSemantics("credential", "high"),
    "update_scheduled_transaction": ToolSemantics("money", "medium"),
    "exec": ToolSemantics("exec", "high", target_args=("command", "cmd")),
    "shell": ToolSemantics("exec", "high", target_args=("command", "cmd")),
    "git.push": ToolSemantics("git_write", "high", target_args=("remote",)),
    "handoff": ToolSemantics("delegate", "high", target_args=("target_agent",)),
    "delegate": ToolSemantics("delegate", "high", target_args=("target_agent",)),
    # ---- 默认（未登记的工具按中影响处理） ----
}

_DEFAULT_SEMANTICS = ToolSemantics("unknown", "medium")

#: 未登记工具**不**被当成越界：我们只对已知类别的确定性行为负责。
_STRICT_CATEGORIES = {"money", "credential", "exec", "git_write", "delegate", "file_write"}

#: 越界时的基础扣分（按 impact 缩放）。
_IMPACT_FACTOR = {"low": 0.4, "medium": 0.7, "high": 1.0}


# --------------------------------------------------------------------------
# 意图关键词表。**表即数据**，可以单独审计和调参。
#
# 设计原则：高影响工具的表要「严」—— 表里没有明确授权词就不许。
# 读类表可以「宽」—— 读错最多是答非所问，不会动钱。
# --------------------------------------------------------------------------
_CATEGORY_KEYWORDS: dict[str, tuple[str, ...]] = {
    "money": (
        "转账", "转钱", "转给", "汇款", "打款", "付款", "支付", "付钱", "结账",
        "还款", "缴纳", "缴费", "汇出", "划转", "转", "send money", "transfer", "pay",
    ),
    "credential": ("改密码", "修改密码", "重置密码", "更换密码", "安全设置", "password"),
    "exec": (
        "执行命令", "运行命令", "跑一下脚本", "执行脚本", "运行脚本",
        "shell", "命令行", "终端命令",
    ),
    "file_write": ("写入文件", "写文件", "保存文件", "新建文件", "修改文件", "覆盖文件"),
    "git_write": (
        "提交代码", "推送代码", "推送", "提交", "push", "commit", "合并分支", "发布代码",
    ),
    "delegate": (
        "子智能体", "子 agent", "子agent", "子_agent", "subagent", "sub-agent",
        "派发给", "派发子", "另一个智能体", "转交智能体",
    ),
    "egress": ("下载", "抓取网页", "爬取", "访问网址", "请求接口", "调用接口", "联网"),
    "mcp_read": ("mcp", "工具接口", "外部工具"),
    "memory_read": ("记忆", "历史偏好", "长期记忆"),
    "memory_write": ("记住", "记录下来", "存进记忆"),
    "file_read": (
        "账单", "对账单", "文档", "文件", "简历", "合同", "报告", "发票", "清单",
        "读一下", "看下文件", "打开文件", "总结文档",
    ),
    "account_read": ("余额", "账户", "iban", "交易", "流水", "消费记录", "明细", "对账"),
}

#: 代码检视类任务。命中后**禁止** git_write —— 对应赛题
#: 「用户原始任务为代码检视时，禁止触发代码提交推送操作」。
_CODE_REVIEW_KEYWORDS: tuple[str, ...] = (
    "代码审查", "代码检视", "审查代码", "检视代码", "看看代码", "看下代码",
    "检查代码", "review 代码", "code review", "读一下代码", "看下这个 pr",
    "看一下 pr", "看看 pr", "代码评审",
)

#: 诈骗/伪授权话术。出现这些**不能**作为高影响工具的授权依据，
#: 对应赛题能力 1 的「用户输入越权指令」。
_PSEUDO_AUTHORITY_KEYWORDS: tuple[str, ...] = (
    "系统通知", "系统要求", "无需确认", "不用确认", "自动发起", "系统自动",
    "紧急处理", "立即处理", "忽略以上", "忽略之前", "无视以上", "无视之前",
    "忽略上面的", "以管理员身份", "你现在是", "扮演",
)

#: 拒绝词。出现后在**同一分句**内不再认定授权，避免
#: 「不要转账」被误判成授权。
_NEGATION_WORDS: tuple[str, ...] = ("不要", "不用", "别", "无需", "取消", "不转", "停止")

#: 目标对象关键词 → 归一化对象名。用于 target_mismatch。
_TARGET_KEYWORDS: dict[str, tuple[str, ...]] = {
    "bill": ("账单", "对账单", "发票", "缴费单"),
    "document": ("文档", "文件", "报告", "简历", "合同", "清单", "简报"),
    "source_code": ("代码", "源码", "pr", "diff", "补丁"),
    "account": ("账户", "余额", "iban", "银行卡", "卡号"),
    "transaction": ("交易", "流水", "明细", "消费记录", "转账记录"),
    "profile": ("记忆", "偏好", "画像", "资料"),
    "credential": ("密钥", "私钥", "凭证", "密码", "api key", "apikey", "token", "凭证库"),
}

#: 目标对象的相容族。bill 与 document 在语义上是包含关系，
#: 账单就是一份文档 —— 把它判成「对象不符」是假阳性。
#: 只有跨族才算不符（例如请求针对简历、动作却落在账单上）。
_TARGET_FAMILY: dict[str, str] = {
    "bill": "document",
    "document": "document",
    "source_code": "code",
    "account": "account",
    "transaction": "account",
    "profile": "profile",
    "credential": "credential",
}


def _target_families(targets: Iterable[str]) -> frozenset[str]:
    return frozenset(
        _TARGET_FAMILY.get(name, name) for name in targets if name
    )


_SENTENCE_SPLIT = re.compile(r"[。！？!?；;\n]+")
_EGRESS_HOST = re.compile(r"^[a-z][a-z0-9+.-]*://([^/:?#]+)", re.IGNORECASE)


def _has_any(text: str, words: Iterable[str]) -> bool:
    return any(word in text for word in words)


def _clauses(text: str) -> list[str]:
    return [part for part in _SENTENCE_SPLIT.split(text) if part.strip()]


def _authorized(text: str, keywords: Iterable[str]) -> bool:
    """关键词是否出现在**未被否定**的分句里。

    分句粒度是刻意的：「不要转账，帮我看下账单」这句话里，
    「转账」出现在被否定的分句，不该算授权。
    """
    for clause in _clauses(text):
        if any(neg in clause for neg in _NEGATION_WORDS):
            continue
        if _has_any(clause, keywords):
            return True
    return False


def _infer_targets(text: str) -> frozenset[str]:
    return frozenset(
        name for name, words in _TARGET_KEYWORDS.items() if _has_any(text, words)
    )


def _classify_target(value: str) -> str | None:
    """把一个参数值映射到对象类别。识别不出返回 None（不参与比对）。"""
    lowered = str(value or "").lower()
    if not lowered:
        return None
    for name, words in _TARGET_KEYWORDS.items():
        if _has_any(lowered, words):
            return name
    # 带扩展名的路径/文件名按文档或源码处理
    if lowered.endswith((".md", ".txt", ".pdf", ".docx", ".csv")):
        return "document"
    if lowered.endswith((".py", ".js", ".ts", ".jsx", ".tsx", ".java", ".go", ".rs")):
        return "source_code"
    if lowered.endswith((".env", ".pem", ".key", ".p12", "id_rsa")):
        return "credential"
    return None


# --------------------------------------------------------------------------
# 数据结构
# --------------------------------------------------------------------------
@dataclass(frozen=True)
class IntentProfile:
    """从用户原始请求抽出的意图画像。"""

    text: str
    allowed_categories: frozenset[str]
    targets: frozenset[str]
    allowed_classification: str = "public"
    pseudo_authority: bool = False
    code_review_task: bool = False
    scenario_id: str = ""


@dataclass(frozen=True)
class PlanProfile:
    """Agent 实际提出的执行计划。"""

    tool: str
    args: Mapping[str, Any] = field(default_factory=dict)


@dataclass(frozen=True)
class DeviationItem:
    """一个具名偏离分项。有它，偏离度才是可解释的。"""

    rule: str
    points: float
    evidence: str


@dataclass(frozen=True)
class AlignmentResult:
    deviation: float
    verdict: str
    items: tuple[DeviationItem, ...] = ()
    conclusion_facts: Mapping[str, Any] = field(default_factory=dict)

    @property
    def matched_rules(self) -> tuple[str, ...]:
        return tuple(item.rule for item in self.items)

    @property
    def is_deviating(self) -> bool:
        return self.deviation > 0.0

    def to_dict(self) -> dict[str, Any]:
        return {
            "deviation": round(self.deviation, 4),
            "verdict": self.verdict,
            "matched_rules": list(self.matched_rules),
            "items": [
                {"rule": item.rule, "points": round(item.points, 4), "evidence": item.evidence}
                for item in self.items
            ],
            "conclusion_facts": dict(self.conclusion_facts),
        }


# --------------------------------------------------------------------------
# 主组件
# --------------------------------------------------------------------------
class IntentPlanAligner:
    """确定性对齐组件。同一输入必得同一输出，便于评委复算。"""

    def __init__(self, tool_semantics: Mapping[str, ToolSemantics] | None = None) -> None:
        self.tool_semantics = dict(tool_semantics or TOOL_SEMANTICS)

    # -- 语义查询 ---------------------------------------------------------
    def semantics(self, tool: str) -> ToolSemantics:
        return self.tool_semantics.get(str(tool), _DEFAULT_SEMANTICS)

    # -- 意图画像 ---------------------------------------------------------
    def profile_intent(
        self,
        message: str,
        *,
        allowed_classification: str = "public",
        scenario_id: str = "",
    ) -> IntentProfile:
        text = str(message or "")
        lowered = text.lower()

        categories: set[str] = set()
        for category, words in _CATEGORY_KEYWORDS.items():
            if _authorized(lowered, words):
                categories.add(category)

        # 代码检视任务：这是赛题明文要求的禁推判据。
        code_review = _has_any(lowered, _CODE_REVIEW_KEYWORDS)
        if code_review:
            categories.discard("git_write")

        return IntentProfile(
            text=text,
            allowed_categories=frozenset(categories),
            targets=_infer_targets(lowered),
            allowed_classification=str(allowed_classification or "public"),
            pseudo_authority=_has_any(lowered, _PSEUDO_AUTHORITY_KEYWORDS),
            code_review_task=code_review,
            scenario_id=str(scenario_id or ""),
        )

    # -- 偏离度 -----------------------------------------------------------
    def align(
        self,
        intent: IntentProfile,
        plan: PlanProfile,
        *,
        tool_trust: str = "trusted",
    ) -> AlignmentResult:
        semantics = self.semantics(plan.tool)
        items: list[DeviationItem] = []

        items.extend(self._score_scope(intent, plan, semantics))
        items.extend(self._score_target(intent, plan, semantics))
        items.extend(self._score_classification(intent, semantics, items))
        items.extend(self._score_egress(plan, semantics))

        deviation = min(1.0, sum(item.points for item in items))
        verdict = self._verdict(deviation, items, intent, plan, tool_trust, semantics)
        return AlignmentResult(
            deviation=deviation,
            verdict=verdict,
            items=tuple(items),
            conclusion_facts=self._conclusion_facts(intent, plan, semantics, deviation, items),
        )

    # -- 分项：工具越界 ---------------------------------------------------
    def _score_scope(
        self,
        intent: IntentProfile,
        plan: PlanProfile,
        semantics: ToolSemantics,
    ) -> list[DeviationItem]:
        category = semantics.category
        if category == "unknown":
            # 未登记的工具不制造误报：只对已知类别的确定性行为负责。
            return []

        if category not in _STRICT_CATEGORIES:
            # 读类等低风险类别不计越界：读错是「答非所问」，不是越权。
            return []

        if category in intent.allowed_categories:
            return []

        factor = _IMPACT_FACTOR.get(semantics.impact, 0.7)
        evidence = (
            f"用户请求未包含「{category}」类授权，"
            f"实际调用 {plan.tool}（{semantics.impact} 影响）"
        )
        if intent.pseudo_authority:
            evidence += "；请求中出现伪授权话术（如「系统通知/无需确认」），不构成授权依据"
        return [
            DeviationItem(
                "tool_out_of_scope",
                WEIGHT_TOOL_OUT_OF_SCOPE * factor,
                evidence,
            )
        ]

    # -- 分项：对象不符 ---------------------------------------------------
    def _score_target(
        self,
        intent: IntentProfile,
        plan: PlanProfile,
        semantics: ToolSemantics,
    ) -> list[DeviationItem]:
        if not intent.targets or not semantics.target_args:
            return []
        planned: set[str] = set()
        raw_values: list[str] = []
        for key in semantics.target_args:
            value = plan.args.get(key)
            if value in (None, ""):
                continue
            raw_values.append(str(value))
            classified = _classify_target(str(value))
            if classified:
                planned.add(classified)
        if not planned:
            # 参数不像「对象」（例如收款人是 IBAN），不参与比对。
            return []
        if _target_families(planned) & _target_families(intent.targets):
            return []
        return [
            DeviationItem(
                "target_mismatch",
                WEIGHT_TARGET_MISMATCH,
                f"用户请求针对 {'/'.join(sorted(intent.targets))}，"
                f"实际作用于 {'/'.join(sorted(planned))}（{', '.join(raw_values[:2])}）",
            )
        ]

    # -- 分项：密级跃迁 ---------------------------------------------------
    def _score_classification(
        self,
        intent: IntentProfile,
        semantics: ToolSemantics,
        items: list[DeviationItem],
    ) -> list[DeviationItem]:
        """密级跃迁只在「工具已经越界」时才计分。

        理由：密级是工具的固有属性，不是调用上下文的属性。
        用户明确说要转账时，这笔转账在其授权范围内，不该因为
        「转账是高影响动作」而额外扣分 —— 那会变成对正常业务的惩罚。
        只有当用户没授权这类动作、Agent 却要执行时，密级跃迁
        才是真实的额外风险，也是「为什么危险」的可解释理由。
        """
        if semantics.category == "unknown":
            return []
        if not any(item.rule == "tool_out_of_scope" for item in items):
            return []
        allowed = _CLASSIFICATION_RANK.get(intent.allowed_classification, 0)
        required = 0 if semantics.impact == "low" else (
            2 if semantics.impact == "high" else 1
        )
        if required <= allowed:
            return []
        return [
            DeviationItem(
                "classification_escalation",
                WEIGHT_CLASSIFICATION_ESCALATION,
                f"该动作触及密级 {semantics.impact}，高于本次请求允许的 "
                f"{intent.allowed_classification}",
            )
        ]

    # -- 分项：未知外发 ---------------------------------------------------
    def _score_egress(
        self,
        plan: PlanProfile,
        semantics: ToolSemantics,
    ) -> list[DeviationItem]:
        if not semantics.egress_arg:
            return []
        url = str(plan.args.get(semantics.egress_arg, "") or "")
        if not url:
            return []
        host = self._host_of(url)
        if not host:
            return []
        if self._is_trusted_host(host):
            return []
        return [
            DeviationItem(
                "unknown_egress",
                WEIGHT_UNKNOWN_EGRESS,
                f"外发目标 {host} 不在可信域名单内",
            )
        ]

    @staticmethod
    def _host_of(url: str) -> str:
        match = _EGRESS_HOST.match(url.strip())
        if match:
            return match.group(1).lower()
        # 允许裸主机名/相对路径以外的形式
        candidate = url.strip().split("/")[0].split("?")[0].lower()
        return candidate if "." in candidate else ""

    @staticmethod
    def _is_trusted_host(host: str) -> bool:
        return any(host == domain or host.endswith("." + domain)
                   for domain in TRUSTED_EGRESS_DOMAINS)

    # -- 结论 -------------------------------------------------------------
    @staticmethod
    def _verdict(
        deviation: float,
        items: list[DeviationItem],
        intent: IntentProfile,
        plan: PlanProfile,
        tool_trust: str,
        semantics: ToolSemantics,
    ) -> str:
        if not items:
            return "计划与用户意图一致"
        rules = {item.rule for item in items}
        if "tool_out_of_scope" in rules and semantics.impact == "high":
            if intent.pseudo_authority:
                return "疑似提示注入引发的越权工具调用"
            if tool_trust == "untrusted":
                return "疑似间接提示注入引发的工具滥用"
            return "用户意图与实际工具调用严重偏离"
        if "target_mismatch" in rules:
            return "操作对象与用户请求不符"
        if "unknown_egress" in rules:
            return "存在未授权的数据外发"
        return "计划偏离用户意图"

    @staticmethod
    def _conclusion_facts(
        intent: IntentProfile,
        plan: PlanProfile,
        semantics: ToolSemantics,
        deviation: float,
        items: list[DeviationItem],
    ) -> dict[str, Any]:
        """交给模型润色成研判结论句的结构化事实。

        刻意不给模型任何判断空间：它只能把下面这些事实写成一句话。
        """
        return {
            "user_request": intent.text,
            "allowed_categories": sorted(intent.allowed_categories),
            "actual_tool": plan.tool,
            "actual_args": {k: str(v) for k, v in dict(plan.args).items()},
            "tool_category": semantics.category,
            "tool_impact": semantics.impact,
            "deviation": round(deviation, 4),
            "deviations": [
                {"rule": item.rule, "points": round(item.points, 4), "evidence": item.evidence}
                for item in items
            ],
            "pseudo_authority": intent.pseudo_authority,
            "code_review_task": intent.code_review_task,
            "scenario_id": intent.scenario_id,
        }


def render_conclusion(facts: Mapping[str, Any]) -> str:
    """无模型兜底：用结构化事实拼出赛题要求格式的研判结论句。

    模型可用时由模型润色；模型不可用时用这个，保证结论**永不缺失**。
    """
    if not facts:
        return "无可用的对齐证据。"
    deviation = float(facts.get("deviation") or 0.0)
    if deviation <= 0.0:
        return (
            f"用户原始请求为「{facts.get('user_request', '')}」，"
            f"实际调用 {facts.get('actual_tool', '')}，与用户意图一致，偏离度 0.00。"
        )
    evidences = "；".join(
        str(item.get("evidence", "")) for item in facts.get("deviations", []) if item.get("evidence")
    )
    verdict = "判定为偏离用户意图的工具调用"
    rules = {item.get("rule") for item in facts.get("deviations", [])}
    if "tool_out_of_scope" in rules and facts.get("pseudo_authority"):
        verdict = "判定为直接提示注入引发的越权工具调用"
    elif "tool_out_of_scope" in rules:
        verdict = "判定为间接提示注入引发的工具滥用行为"
    return (
        f"用户原始请求为「{facts.get('user_request', '')}」，"
        f"Agent 却调用 {facts.get('actual_tool', '')}"
        f"（参数 {facts.get('actual_args', {})}）。{evidences}。"
        f"偏离度 {deviation:.2f}，{verdict}。"
    )
