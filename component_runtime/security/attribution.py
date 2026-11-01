"""能力 4：token 级归属 + 影响范围 + 时序链路。

赛题点名的四项，`provenance_graph.py` 只覆盖了最基础的一层（节点/边/DAG）。
本模块补上其余三项：

| 赛题要求 | 本模块 |
|---|---|
| **token 级归属** | `attribute_output` —— 字符归属 + 本地 Prompt Guard tokenizer token offset |
| **影响范围** | `impact_scope` —— 从任一来源出发，可达哪些节点与工具调用 |
| 时序链路图 | `build_timeline` —— 按时间/阶段串起来源→模型→裁决→执行 |
| 跨 MCP / 子 Agent 溯源 | 节点种类与边的扩展（见 `provenance_graph.py`） |

## 归属为什么用**精确子串**而不是模型自报

要求模型说明"这句话来自哪段上下文"是不可靠的 —— 它可能编造，
而溯源的全部价值就在于**不可被编造**。所以我们用确定性的字符串比对：

- 找出来源文本中出现在模型输出里的最长连续片段（≥ `min_span` 字符）；
- 按最长优先、不重叠地分配，得到字符级区间；
- 覆盖不到的区间标为 `model_generated`（模型自己生成的，不归因于任何来源）。

这样得到的结论是**可复现、可验证**的：任何人拿同样的输入都能算出同样的区间。
"""
from __future__ import annotations

from dataclasses import dataclass, field
from difflib import SequenceMatcher
from pathlib import Path
from typing import Any, Iterable, Mapping, Sequence

__all__ = [
    "AttributionSpan",
    "OutputAttribution",
    "attribute_output",
    "impact_scope",
    "build_timeline",
    "DEFAULT_MIN_SPAN",
]

_TOKENIZER = None
_TOKENIZER_ERROR = ""


def _token_offsets(text: str) -> tuple[list[tuple[int, int]], list[str], str | None]:
    """Use the local Prompt Guard fast tokenizer for real token offsets."""
    global _TOKENIZER, _TOKENIZER_ERROR
    if _TOKENIZER is None and not _TOKENIZER_ERROR:
        try:
            from transformers import AutoTokenizer
            model_path = Path(__file__).resolve().parents[1] / "models" / "from_models_zip" / "Llama-Prompt-Guard-2-86M"
            _TOKENIZER = AutoTokenizer.from_pretrained(str(model_path), local_files_only=True, use_fast=True)
        except Exception as exc:
            _TOKENIZER_ERROR = f"{type(exc).__name__}: {exc}"
    if _TOKENIZER is None:
        try:
            from .component_client import _post, DEFAULT_COMPONENT_SERVICE_URL
            payload = _post(DEFAULT_COMPONENT_SERVICE_URL, "/tokenize", {"text": text}, timeout=10)
            if not payload.get("available"):
                raise RuntimeError(payload.get("reason", "tokenizer unavailable"))
            pairs = [(tuple(map(int, offset)), token) for offset, token in zip(payload["offsets"], payload["tokens"])
                     if offset[1] > offset[0]]
            return [p[0] for p in pairs], [p[1] for p in pairs], None
        except Exception as exc:
            return [], [], f"tokenizer service unavailable: {type(exc).__name__}: {exc}"
    try:
        encoded = _TOKENIZER(text, add_special_tokens=False, return_offsets_mapping=True)
        offsets = [(int(start), int(end)) for start, end in encoded.get("offset_mapping", []) if end > start]
        ids = list(encoded.get("input_ids", []))
        return offsets, _TOKENIZER.convert_ids_to_tokens(ids), None
    except Exception as exc:
        return [], [], f"{type(exc).__name__}: {exc}"

#: 最短归属片段。
#:
#: 定成 8 是**实测**结果，不是拍脑袋：一次真实对话里，注入原文
#: 「本季度的客户回访满意度调查结果是九十二点七个百分点」被模型**改写**成
#: 「本季度客户回访满意度调查结果为九十二点七个百分点」——
#: 最长公共子串只有 11 字符（`客户回访满意度调查结果`）。
#: 原来定 12，结果真实改写一个都没归因上。
#:
#: 也不能定太低：`the`、`的`、`结果` 这类片段在任何文本里都出现，
#: 归属上去就是噪声。8 是「有辨识度的短语」与「噪声」之间的平衡点。
DEFAULT_MIN_SPAN = 8

#: 这些来源被归因到输出时视为**外泄风险**（内容不该出现在回复里）。
_LEAKY_TRUST = frozenset({"untrusted", "quarantined"})


@dataclass(frozen=True)
class AttributionSpan:
    """模型输出中的一段，及其来源。"""

    start: int
    end: int
    text: str
    source_id: str
    source_label: str
    source_trust: str
    token_start: int | None = None
    token_end: int | None = None
    tokens: tuple[str, ...] = ()

    @property
    def length(self) -> int:
        return self.end - self.start

    @property
    def is_leak(self) -> bool:
        """来自不可信来源的内容出现在输出里 —— 这是外泄信号。"""
        return self.source_trust in _LEAKY_TRUST

    def to_dict(self) -> dict[str, Any]:
        return {
            "start": self.start, "end": self.end, "length": self.length,
            "text": self.text, "source_id": self.source_id,
            "source_label": self.source_label, "source_trust": self.source_trust,
            "is_leak": self.is_leak,
            "token_start": self.token_start, "token_end": self.token_end,
            "tokens": list(self.tokens),
        }


@dataclass
class OutputAttribution:
    """模型输出的完整归属结果。"""

    output_length: int
    spans: list[AttributionSpan] = field(default_factory=list)
    unattributed_length: int = 0
    min_span: int = DEFAULT_MIN_SPAN

    @property
    def attributed_length(self) -> int:
        return sum(span.length for span in self.spans)

    @property
    def coverage(self) -> float:
        if not self.output_length:
            return 0.0
        return round(self.attributed_length / self.output_length, 4)

    @property
    def leaks(self) -> list[AttributionSpan]:
        return [span for span in self.spans if span.is_leak]

    @property
    def leak_count(self) -> int:
        """输出里来自不可信来源的片段数 —— 外泄信号。"""
        return len(self.leaks)

    @property
    def leaked_sources(self) -> list[str]:
        return sorted({span.source_id for span in self.leaks})

    def by_source(self) -> dict[str, int]:
        counts: dict[str, int] = {}
        for span in self.spans:
            counts[span.source_id] = counts.get(span.source_id, 0) + span.length
        return counts

    def to_dict(self) -> dict[str, Any]:
        return {
            "output_length": self.output_length,
            "attributed_length": self.attributed_length,
            "unattributed_length": self.unattributed_length,
            "coverage": self.coverage,
            "min_span": self.min_span,
            "spans": [span.to_dict() for span in self.spans],
            "by_source": self.by_source(),
            "leak_count": self.leak_count,
            "leaked_sources": self.leaked_sources,
        }


def attribute_output(
    output: str,
    sources: Sequence[Mapping[str, Any]],
    *,
    min_span: int = DEFAULT_MIN_SPAN,
) -> OutputAttribution:
    """把模型输出归因到各个来源。

    `sources` 每项需要 `id` / `text`，可选 `label` / `trust`。

    算法：对每个来源枚举长度 ≥ `min_span` 的子串，在输出里查找；
    按长度降序、不重叠地占用区间。复杂度是 O(来源数 × 子串数 × 查找)，
    但来源与输出都是短文本（几百到几千字符），实际很快。

    刻意**不做模糊匹配**：模糊匹配会引入阈值调参，而归属结论必须可复现。
    """
    text = str(output or "")
    attribution = OutputAttribution(output_length=len(text), min_span=min_span)
    if not text:
        return attribution
    token_offsets, token_values, _tokenizer_error = _token_offsets(text)

    def normalise(value: Any) -> str:
        return " ".join(str(value or "").split())

    candidates: list[tuple[int, str, int, int]] = []      # (长度, 来源id, 起, 止)

    for source in sources:
        source_id = str(source.get("id") or "")
        source_text = normalise(source.get("text"))
        if not source_id or len(source_text) < min_span:
            continue
        # 用 SequenceMatcher 找**所有**匹配块，而不是枚举子串再 `find`。
        #
        # 早期版本枚举来源的所有子串（O(n²) 次 `str.find`），本质是在
        # 手工重实现最长公共子串 —— 既慢又只取到第一处匹配。
        # SequenceMatcher 是标准做法，一次给出全部匹配块。
        #
        # `autojunk=False` 关掉「高频元素视为垃圾」的启发式：
        # 中文里常见字的重复度极高，开着它会把真实的匹配块吞掉。
        matcher = SequenceMatcher(None, source_text, text, autojunk=False)
        for block in matcher.get_matching_blocks():
            if block.size >= min_span:
                candidates.append((block.size, source_id,
                                   block.b, block.b + block.size))

    # 最长优先，保证"能归因到更长片段"的优先落地；不重叠写入。
    candidates.sort(key=lambda item: -item[0])
    taken = [False] * len(text)
    by_id = {str(s.get("id") or ""): s for s in sources}
    for length, source_id, start, end in candidates:
        if any(taken[start:end]):
            continue
        for index in range(start, end):
            taken[index] = True
        source = by_id.get(source_id) or {}
        token_hits = [(index, token_values[index]) for index, (token_start, token_end) in enumerate(token_offsets)
                      if token_end > start and token_start < end]
        attribution.spans.append(AttributionSpan(
            start=start, end=end, text=text[start:end], source_id=source_id,
            source_label=str(source.get("label") or source_id),
            source_trust=str(source.get("trust") or "trusted"),
            token_start=token_hits[0][0] if token_hits else None,
            token_end=(token_hits[-1][0] + 1) if token_hits else None,
            tokens=tuple(token_values[index] for index, _token in token_hits),
        ))

    attribution.spans.sort(key=lambda span: span.start)
    attribution.unattributed_length = sum(1 for flag in taken if not flag)
    return attribution


def impact_scope(graph: Mapping[str, Any], source_id: str) -> dict[str, Any]:
    """从某个来源出发的可达范围。

    回答的问题是：「这段不可信内容最远影响到了哪里」——
    是只被读了一下，还是驱动了策略判定、工具调用、乃至执行。
    """
    nodes = {str(node.get("node_id")): node for node in graph.get("nodes") or []}
    if source_id not in nodes:
        return {"source_id": source_id, "found": False, "reachable": [],
                "reached_kinds": {}, "reached_tools": [], "max_depth": 0}

    adjacency: dict[str, list[str]] = {node_id: [] for node_id in nodes}
    for edge in graph.get("edges") or []:
        adjacency.setdefault(str(edge.get("source")), []).append(str(edge.get("target")))

    reached: dict[str, int] = {}
    frontier = [(source_id, 0)]
    while frontier:
        current, depth = frontier.pop()
        if current in reached and reached[current] <= depth:
            continue
        reached[current] = depth
        for child in adjacency.get(current, []):
            if child not in reached or reached[child] > depth + 1:
                frontier.append((child, depth + 1))

    reached.pop(source_id, None)
    reachable = sorted(reached.items(), key=lambda item: (item[1], item[0]))
    kinds: dict[str, int] = {}
    tools: list[str] = []
    source_node = nodes.get(source_id) or {}
    if str(source_node.get("classification") or "") == "tool_result":
        tools.append(str(source_node.get("label") or source_id).removesuffix(" result"))
    for node_id, _depth in reachable:
        node = nodes.get(node_id) or {}
        kind = str(node.get("kind") or "unknown")
        kinds[kind] = kinds.get(kind, 0) + 1
        if kind in {"tool_call", "mcp_call", "subagent"}:
            tools.append(str(node.get("label") or node_id))
        if kind == "source" and str(node.get("classification") or "") == "tool_result":
            tools.append(str(node.get("label") or node_id).removesuffix(" result"))

    return {
        "source_id": source_id,
        "found": True,
        "reachable": [{"node_id": node_id, "depth": depth,
                       "kind": str((nodes.get(node_id) or {}).get("kind") or "")}
                      for node_id, depth in reachable],
        "reached_kinds": kinds,
        "reached_tools": tools,
        "max_depth": max(reached.values()) if reached else 0,
    }


def build_timeline(timeline: Iterable[Mapping[str, Any]],
                   *, provenance: Mapping[str, Any] | None = None
                   ) -> dict[str, Any]:
    """把链路事件整理成时序视图。

    比审计事件列表多两件事：
    1. **阶段归并**（输入 → 模型 → 裁决 → 执行 → 回复），便于读；
    2. **每条事件附上它涉及哪些溯源节点**，于是时间轴与 DAG 能互相跳转。
    """
    events = [dict(event) for event in timeline]
    for index, event in enumerate(events):
        event.setdefault("seq", index + 1)

    phases: dict[str, list[int]] = {}
    for event in events:
        phases.setdefault(str(event.get("phase") or "other"), []).append(int(event["seq"]))

    # 事件 → 溯源节点：靠 event_type 与节点 kind 的对应关系推。
    kind_of_event = {
        "component": {"source", "mcp_call"},
        "provenance": set(),
        "model_call": {"agent"},
        "policy": {"policy"},
        "tool": {"tool_call", "mcp_call", "subagent"},
        "alignment": {"policy"},
        "reply": {"reply"},
        "confirmation": {"tool_call"},
    }
    nodes_by_kind: dict[str, list[str]] = {}
    for node in (provenance or {}).get("nodes") or []:
        nodes_by_kind.setdefault(str(node.get("kind") or ""), []).append(str(node.get("node_id")))

    for event in events:
        kinds = kind_of_event.get(str(event.get("event_type") or ""), set())
        event["provenance_nodes"] = sorted(
            node_id for kind in kinds for node_id in nodes_by_kind.get(kind, []))

    return {
        "events": events,
        "phases": phases,
        "phase_order": [phase for phase in ("input", "model", "output", "other")
                        if phase in phases],
        "event_count": len(events),
    }
