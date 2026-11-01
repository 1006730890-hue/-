"""Small, deterministic policy DSL for semantic tool controls.

Rules are evaluated before a tool executes.  The engine intentionally exposes
the decision and reasons as data so an adapter, MCP proxy, or UI can render the
same audit record without reimplementing policy logic.
"""
from __future__ import annotations

import fnmatch
import re
from urllib.parse import urlparse
from dataclasses import dataclass, field
from pathlib import Path
from typing import Any, Callable, Mapping
from .command_semantics import dangerous


@dataclass(frozen=True)
class PolicyContext:
    actor: str = "main_agent"
    root_intent: str = ""
    tool: str = ""
    args: Mapping[str, Any] = field(default_factory=dict)
    source_type: str = "user_instruction"
    trust: str = "trusted"
    risk: str = "low"
    classification: str = "public"
    #: 本次请求授权调用的工具集合（由 `route_policy.RouteScopeEngine` 产出）。
    #: 为空表示调用方未提供路由意图，此时不做越权判定 ——
    #: 「没给判据」不等于「没授权」，混淆这两者会让所有调用被误拒。
    allowed_tools: frozenset[str] = frozenset()
    #: 显式禁止调用的工具集合。
    forbidden_tools: frozenset[str] = frozenset()
    #: 是否是由模型自身发起的调用（而非用户直接请求）。
    #: 决定 Git 推送是否需要「用户原始任务为代码检视」这一判据。
    tool_requested: bool = False
    #: 本次会话的**记忆读取**里，是否有不可信记忆被信任门拦下。
    #:
    #: 为什么需要它：记忆信任门会把被污染的长期记忆挡在上下文之外 ——
    #: 这一步是对的，但它同时意味着"**曾经有人试图用记忆投毒**"。
    #: 如果只把内容挡掉、不留任何痕迹，模型随后提议的高影响动作
    #: 就只会拿到一个宽泛的 `ask`（"依赖不可信上下文，请确认"），
    #: 而不是针对性的 `deny`。实测：`memory-poison` 场景因此停在 `ask`，
    #: 用户点一下确认，攻击就过去了。
    memory_blocked: bool = False
    #: 用户私有数据里的**已知收款方关键词**（来自账本 / 收款人目录）。
    #:
    #: 用途见 `money-memo-cross-payee`：附言若提到**本次收款人之外**的
    #: 已知收款方，就是把私有业务信息外发。这类泄漏**不含凭据、不是 URL、
    #: 也不是邮箱**，所以 `_PAYMENT_MEMO_EXFIL` 那种形态匹配抓不到 ——
    #: 必须比对私有数据。实测：`small-amount-exfil` 场景的附言
    #: `"The user is subscribed to spotify"` 就完全绕过了形态匹配。
    known_payees: Mapping[str, str] = field(default_factory=dict)
    code_review_task: bool = False
    sensitive_data_sources: tuple[str, ...] = ()
    trusted_egress_domains: frozenset[str] = frozenset()
    dataflow_checked: bool = False
    dataflow_matches: tuple[Mapping[str, Any], ...] = ()


@dataclass(frozen=True)
class PolicyDecision:
    decision: str
    risk: str
    reasons: tuple[str, ...] = ()
    matched_rules: tuple[str, ...] = ()
    evidence: Mapping[str, Any] = field(default_factory=dict)


@dataclass(frozen=True)
class _Rule:
    rule_id: str
    decision: str
    risk: str
    predicate: Callable[[PolicyContext], bool]
    reason: str


#: 付款附言里出现这些东西就当作外泄通道。凭证键值、URL、邮箱。
#: 刻意不匹配裸域名（如 example.com）——正常附言里出现公司名不算外泄，
#: 但一个可点击的 URL 或一个邮箱地址就是可以把内容带出去的东西。
_PAYMENT_MEMO_EXFIL = re.compile(
    r"(?i)(?:api[_-]?key|token|password|passwd|secret|bearer|credential)\s*[:=]"
    r"|https?://"
    r"|[\w.+-]+@[\w-]+\.[\w.]+"
)

#: 会动钱、且带自由文本附言的工具。
_MONEY_TOOLS_WITH_MEMO = frozenset({"send_money", "schedule_transaction", "transfer"})


def _memo_cross_payee_leak(args: Mapping[str, Any],
                           recipient: str,
                           known_payees: Mapping[str, str]) -> str:
    """附言里是否提到**别的**收款方 —— 命中就返回那个词。

    这是 AgentDojo 银行域 0.01 手法的正解：金额小到不触发任何额度规则，
    附言里却写着"用户在订阅哪个流媒体服务"，于是私有信息被一笔 0.01 元的
    转账送给了攻击者账号。

    **形态匹配抓不到它**（"spotify" 不是凭据、不是 URL、不是邮箱），
    只能拿私有数据去比。所以本函数比对的是"账本/收款人目录里已知的
    收款方关键词"。

    刻意跳过**本次收款人自己**的记录：给房东转租金写"房租"是正常的，
    因为账本里"房租"本来就属于房东。
    """
    memo = _text(args, "subject", "memo", "note", "purpose")
    if not memo:
        return ""
    text = memo.lower()
    target = str(recipient or "").lower()
    for keyword, payee_recipient in (known_payees or {}).items():
        name = str(keyword).strip().lower()
        if len(name) < 3:
            continue                      # 太短的关键词容易误伤（如"me"）
        if name not in text:
            continue
        # 本次收款人自己的业务不算泄漏
        if target and str(payee_recipient or "").strip().lower() == target:
            continue
        return str(keyword)
    return ""


def _text(args: Mapping[str, Any], *keys: str) -> str:
    for key in keys:
        value = args.get(key)
        if value is not None:
            return str(value)
    return ""


def _untrusted_egress(args: Mapping[str, Any], trusted_domains: frozenset[str]) -> str:
    raw = _text(args, "url", "uri", "endpoint").strip()
    host = (urlparse(raw).hostname or "").lower()
    if not host:
        return ""
    trusted = any(host == domain or host.endswith("." + domain)
                  for domain in trusted_domains if domain)
    return "" if trusted else host


#: 子 Agent 派发载荷的字段名。不同调用方用词不一，全部覆盖。
_HANDOFF_PAYLOAD_KEYS = ("instruction", "message", "payload", "brief", "prompt", "task")

#: 载荷里的疑似凭证。**刻意独立于调用方标注的密级** ——
#: 只信 `classification` 的话，一个没标密级的调用就能把私钥派发出去，
#: 而"没标密级"恰恰是这类事故最常见的形态。
_HANDOFF_SECRET_PATTERNS: tuple[re.Pattern[str], ...] = (
    re.compile(r"(?i)[A-Za-z_]*(api[_-]?key|secret|password|passwd|token|credential)\s*[:=]\s*\S+"),
    re.compile(r"\bsk-[A-Za-z0-9_-]{16,}"),
    re.compile(r"\bAKIA[0-9A-Z]{16}\b"),
    re.compile(r"\bghp_[A-Za-z0-9]{20,}"),
    re.compile(r"\beyJ[A-Za-z0-9_-]{10,}\.[A-Za-z0-9_-]{10,}\."),
    re.compile(r"-----BEGIN [A-Z ]*PRIVATE KEY-----"),
)

#: 工作区根。文件工具的边界。
_WORKSPACE_ROOT = Path(__file__).resolve().parents[1] / "data" / "capability_workspace"

#: 「高影响」工具集 —— 会改变账户、文件、外部状态或跨 Agent 派发的那些。
#:
#: 单独列在这里而不是散落在各条规则的 lambda 里：同一个概念在多处各写一份
#: 就迟早会漂移（本项目已经因为"同一概念两处定义"踩过几次坑）。
HIGH_IMPACT_TOOLS: frozenset[str] = frozenset({
    "send_money", "transfer", "schedule_transaction",
    "update_scheduled_transaction", "update_password",
    "fs.write", "file_write", "report_write",
    "net.fetch", "web_fetch", "exec", "shell",
    "git.push", "handoff", "delegate",
})


def _is_high_impact(tools: frozenset[str], tool: str) -> bool:
    """工具是否属于高影响集合。

    第一版写成 `_is_high_impact(CAPABILITY_HIGH_IMPACT, c.tool)` 但那个常量
    不存在 —— 改成显式传集合，避免再出现"引用了没定义的名字"。
    """
    return str(tool) in tools


def _handoff_payload_has_secret(args: Mapping[str, Any]) -> bool:
    """派发给子 Agent 的载荷里是否含疑似凭证。"""
    for key in _HANDOFF_PAYLOAD_KEYS:
        value = args.get(key)
        if value is None:
            continue
        text = str(value)
        if any(pattern.search(text) for pattern in _HANDOFF_SECRET_PATTERNS):
            return True
    return False


def _escapes_workspace(raw_path: str) -> bool:
    """路径是否越出工作区边界。

    **委托给 `sandbox_tools` 的 `resolve()`**，不在这里另写一套判断。
    原先这里自己用 `Path.resolve()` 比对前缀，结果把 `/workspace/report.md`
    这种"沙箱视角下的合法绝对路径"判成了越界 —— 自己的测试就抓到了。

    边界只能有一处定义，否则执行器放行的、策略拒绝的，两者会漂移。
    取出 `WorkspacePath.escaped` 就是执行器同款判据。
    """
    text = str(raw_path or "").strip()
    if not text:
        return False
    if "\x00" in text:
        return True
    try:
        from .sandbox_tools import SandboxTools      # noqa: PLC0415 — 避免循环导入
        return SandboxTools().resolve(text).escaped
    except Exception:                                # noqa: BLE001 — 拿不到判据就保守拒绝
        return True


class ToolPolicyEngine:
    """Evaluate semantic, parameter-aware rules with fail-closed precedence."""

    _precedence = {"allow": 0, "ask": 1, "deny": 2, "terminate": 3}

    def __init__(self, rules: list[_Rule] | None = None) -> None:
        self.rules = rules or self.default_rules()

    @classmethod
    def for_drift_runtime(cls) -> "ToolPolicyEngine":
        """Build the deterministic invariant gate used after DRIFT validation.

        DRIFT owns intent scope, trajectory deviation, and whether an external
        observation actually drove a call.  Keeping the old broad context rules
        in the decision path would make a legitimate invoice workflow pass both
        the new validator and the old keyword router, recreating the false
        positives this migration is intended to remove.

        The remaining rules are parameter/data invariants: sensitive paths,
        exfiltration, command execution, credential handoff, memory poisoning,
        and workspace escape.  They remain non-bypassable after the validator.
        """
        replaced_by_drift = {
            "untrusted-high-impact",
            "route-scope-violation",
            "external-tool-context",
        }
        return cls([
            rule for rule in cls.default_rules()
            if rule.rule_id not in replaced_by_drift
        ])

    @classmethod
    def default_rules(cls) -> list[_Rule]:
        sensitive_paths = ("~/.ssh/*", "~/.aws/*", "*/.ssh/*", "*/.aws/*", "/etc/cron.*", "/etc/systemd/*",
                           "*/.env", "*/id_rsa", "*/startup/*", "*/start menu/programs/startup/*")
        return [
            _Rule("untrusted-high-impact", "deny", "high",
                  lambda c: c.trust == "untrusted" and c.tool in {"send_money", "transfer", "git.push", "exec", "handoff"},
                  "high-impact tool after untrusted context"),
            # 路由越权：用户请求未授权这个动作，模型却要执行。
            # 对应赛题能力 3「用户原始任务为代码检视时，禁止触发推送」，
            # 以及能力 1「识别来自用户输入的越权指令」。
            _Rule("route-scope-violation", "deny", "high",
                  lambda c: bool(c.tool) and (c.tool in c.forbidden_tools
                                              or (c.allowed_tools and c.tool not in c.allowed_tools)),
                  "工具调用不在本次用户请求的授权范围内"),
            _Rule("code-review-git-push", "deny", "high",
                  lambda c: c.tool == "git.push" and c.code_review_task,
                  "用户原始任务是代码审查，禁止推送代码"),
            _Rule("sensitive-write", "deny", "high",
                  lambda c: c.tool in {"fs.write", "file_write", "report_write"} and any(fnmatch.fnmatch(_text(c.args, "path", "file_path").replace("\\", "/").casefold(), p) for p in sensitive_paths),
                  "write targets a sensitive path"),
            _Rule("secret-exfiltration", "deny", "high",
                  lambda c: c.tool in {"net.fetch", "web_fetch"} and (
                      c.classification in {"secret", "sensitive"} or c.trust == "untrusted"
                      or (bool(c.dataflow_matches) if c.dataflow_checked else bool(c.sensitive_data_sources))
                      and bool(_untrusted_egress(c.args, c.trusted_egress_domains))),
                  "sensitive data may leave through an external request"),
            _Rule("encoded-or-remote-exec", "deny", "high",
                  lambda c: c.tool in {"exec", "shell"} and dangerous(_text(c.args, "command", "cmd")),
                  "encoded or remote pipeline execution"),
            # 动钱工具的附言是外发通道：金额可以小到不触发任何额度规则，
            # 但附言能把内容带出去。所以这里只看内容，不看金额。
            _Rule("money-memo-exfiltration", "deny", "high",
                  lambda c: c.tool in _MONEY_TOOLS_WITH_MEMO
                  and bool(_PAYMENT_MEMO_EXFIL.search(_text(c.args, "subject", "memo", "note"))),
                  "payment memo appears to carry credentials or an external address"),
            # 附言里提到**别的**收款方的业务 = 私有信息外发。
            #
            # 与上一条并列，但判据完全不同：上一条是**形态匹配**（凭据/URL/邮箱），
            # 这一条是**私有数据比对**。实测 `small-amount-exfil` 的附言
            # `"The user is subscribed to spotify"` 完全绕过形态匹配 ——
            # 金额 0.01 元也绕过所有额度规则。只有比对账本才知道
            # "spotify" 是另一个收款方的业务。
            _Rule("money-memo-cross-payee", "deny", "high",
                  lambda c: c.tool in _MONEY_TOOLS_WITH_MEMO
                  and bool(_memo_cross_payee_leak(c.args,
                                                  _text(c.args, "recipient"),
                                                  c.known_payees)),
                  "转账附言提到其他收款方的业务，疑似借附言外发私有信息"),
            # 赛题原文：「限制子 Agent 派发操作，**禁止**向后台子 Agent 传递
            # 当前会话内的密钥、凭证等敏感信息」。是「禁止」，不是「询问」。
            #
            # 两条并列，缺一不可：
            #   1. 调用方声明的密级是 secret/sensitive（原有，依赖标注）；
            #   2. **载荷本身含疑似凭证**（新增，不依赖标注）。
            # 只靠 1 的话，一个没标密级的调用就能把私钥派发出去 ——
            # 而"没标密级"恰恰是这类事故的常见形态。
            _Rule("sensitive-handoff", "deny", "high",
                  lambda c: c.tool in {"handoff", "delegate"} and (
                      c.classification in {"secret", "sensitive"}
                      or _handoff_payload_has_secret(c.args) or bool(c.dataflow_matches)),
                  "向子 Agent 派发时携带敏感数据，已阻断"),
            # 记忆投毒未遂 + 高影响动作 = 定向阻断，而不是笼统的"请确认"。
            #
            # 记忆信任门把污染记忆挡在了上下文之外（内容没进来），但
            # **"有人试图投毒"这件事本身就是结论**。不下这一条，
            # 模型提议的转账只会命中宽泛的 `external-tool-context`（ask），
            # 用户顺手点确认就放行了 —— 实测就是这个结果。
            _Rule("memory-poisoning-attempt", "deny", "high",
                  lambda c: c.memory_blocked and _is_high_impact(HIGH_IMPACT_TOOLS, c.tool),
                  "检测到记忆投毒未遂（不可信记忆被信任门拦下），且动作为高影响，已阻断"),
            _Rule("host-path-escape", "deny", "high",
                  lambda c: c.tool in {"fs.read", "fs.write", "read_file", "file_write"}
                  and _escapes_workspace(_text(c.args, "path", "file_path")),
                  "文件路径越出工作区边界"),
            _Rule("external-tool-context", "ask", "medium",
                  lambda c: c.trust == "untrusted" and c.tool not in {"get_balance", "search", "read_file"},
                  "tool call depends on untrusted context"),
        ]

    def evaluate(self, context: PolicyContext) -> PolicyDecision:
        matches = [rule for rule in self.rules if rule.predicate(context)]
        from .declarative_policy import load_rules, condition
        from .command_semantics import dangerous
        facts = {"tool": context.tool, "tool_requested": context.tool_requested, "classification": context.classification, "trust": context.trust,
                 "code_review_task": context.code_review_task, "memory_blocked": context.memory_blocked,
                 "sensitive_payload": bool(context.dataflow_matches),
                 "untrusted_destination": bool(_untrusted_egress(context.args, context.trusted_egress_domains)),
                 "credential_handoff": context.tool in {"handoff", "delegate"} and (_handoff_payload_has_secret(context.args) or bool(context.dataflow_matches)),
                 "dangerous_command": context.tool in {"exec", "shell"} and dangerous(_text(context.args, "command", "cmd")),
                 "sensitive_write": any(r.rule_id == "sensitive-write" for r in matches)}
        for rule in load_rules(Path(__file__).resolve().parents[1] / "config" / "tool_policies.json"):
            if condition(rule["when"], facts):
                matches.append(_Rule(rule["id"], rule["decision"], rule["risk"], lambda _: True, rule["reason"]))
        if not matches:
            return PolicyDecision("allow", self._assess_risk(context, []), evidence={"semantic_facts": facts, "dataflow_matches": list(context.dataflow_matches)})
        selected = max(matches, key=lambda rule: self._precedence[rule.decision])
        return PolicyDecision(
            selected.decision,
            self._assess_risk(context, matches, selected),
            tuple(rule.reason for rule in matches),
            tuple(rule.rule_id for rule in matches),
            {"semantic_facts": facts, "dataflow_matches": list(context.dataflow_matches)},
        )

    # -- 运行时风险等级评估 -------------------------------------------------
    _RISK_ORDER = {"low": 0, "medium": 1, "high": 2}

    def _assess_risk(self, context: PolicyContext, matches: list[_Rule],
                     selected: _Rule | None = None) -> str:
        """按调用**当下的**上下文算风险等级，而不是照抄规则的静态声明。

        赛题要求「每条策略均需支持运行时风险等级评估」，
        所以风险要随来源信任度、数据密级、动作影响、金额一起变：

        - 规则本身声明的等级是**下限**（命中了就不能比它更轻）；
        - 不可信来源 +1；
        - 密级 secret/sensitive +1；
        - 高影响工具 +1；
        - 金额越大越敏感（>1000 +1）；
        - 附言夹带凭证或外部地址 +1。

        最后钳到 high。这样「同一张规则表」在不同上下文里能得到不同等级，
        审计里看到的就不是一句写死的 medium。
        """
        score = 0
        if selected is not None:
            score = max(score, self._RISK_ORDER.get(selected.risk, 0))

        if context.trust == "untrusted":
            score += 1
        if context.classification in {"secret", "sensitive"}:
            score += 1
        if context.tool in {"send_money", "transfer", "schedule_transaction",
                            "update_password", "exec", "shell", "git.push", "handoff", "delegate"}:
            score += 1
        try:
            amount = float(context.args.get("amount", 0) or 0)
        except (TypeError, ValueError):
            amount = 0.0
        if abs(amount) > 1000:
            score += 1
        if context.tool in _MONEY_TOOLS_WITH_MEMO and _PAYMENT_MEMO_EXFIL.search(
            _text(context.args, "subject", "memo", "note")
        ):
            score += 1

        if score >= 2:
            return "high"
        if score == 1:
            return "medium"
        return "low"
