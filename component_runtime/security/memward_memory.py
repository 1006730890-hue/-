"""Provenance-aware memory adapter for Memward."""
from __future__ import annotations

from dataclasses import dataclass
from pathlib import Path
from typing import Any

__all__ = [
    "MemwardMemory",
    "MemwardUnavailable",
    "SOURCE_TYPE_MAP",
    "MEMWARD_AVAILABLE",
    "MEMWARD_IMPORT_ERROR",
]

try:
    from memward import Memward, SourceType, ToolClaimExtractor, ConsensusValidator
    from memward.adapters import InMemoryStore

    MEMWARD_AVAILABLE = True
    MEMWARD_IMPORT_ERROR: str | None = None
except Exception as exc:                              # noqa: BLE001 — 要如实报出来
    Memward = None                                    # type: ignore[assignment,misc]
    SourceType = None                                 # type: ignore[assignment,misc]
    ToolClaimExtractor = None                         # type: ignore[assignment,misc]
    ConsensusValidator = None                         # type: ignore[assignment,misc]
    InMemoryStore = None                              # type: ignore[assignment,misc]
    MEMWARD_AVAILABLE = False
    MEMWARD_IMPORT_ERROR = f"{type(exc).__name__}: {exc}"


#: 本项目的 `source_type` -> memward 的 `SourceType`。
#:
#: 映射口径：**只有用户自己说的话是 USER**，其余外部来源一律不是。
#: 这正是 memward 文档里强调的那个「footgun」——把什么都标成 USER
#: 就等于什么都信任、什么都没保护。
SOURCE_TYPE_MAP: dict[str, str] = {
    "user_instruction": "USER",
    "direct_prompt": "USER",            # 用户自己发的注入：来源仍是用户
    "external_document": "WEB_CONTENT",
    "external_web_content": "WEB_CONTENT",
    "external_source_code": "WEB_CONTENT",
    "external_ticket": "WEB_CONTENT",
    "mcp_tool_result": "TOOL_OUTPUT",
    "mcp_tool_description": "TOOL_OUTPUT",
    "untrusted_tool_output": "TOOL_OUTPUT",
    "subagent_handoff": "AGENT_REFLECTION",
    "memory_poison": "AGENT_REFLECTION",
    "agent_reflection": "AGENT_REFLECTION",
}


class MemwardUnavailable(RuntimeError):
    """memward 未安装。调用方应据此降级，而不是当成"检查通过"。"""


@dataclass
class MemoryReadResult:
    """一次读取的结果，含被信任门排除的原因 —— 审计要能看到"为什么没给模型"。"""

    kept: list[dict[str, Any]]
    excluded: list[dict[str, Any]]

    @property
    def kept_contents(self) -> list[str]:
        return [item["content"] for item in self.kept]

    def to_dict(self) -> dict[str, Any]:
        return {"kept": self.kept, "excluded": self.excluded,
                "kept_count": len(self.kept), "excluded_count": len(self.excluded)}


class MemwardMemory:
    """跨会话记忆，带 provenance 信任门。

    `privileged_read()` 是给**工具选择**用的：默认只放行 `VERIFIED` 及以上
    （用户 + 已核实工具）。未核实的外部内容即使高度相关也进不去 ——
    这是「记忆污染不得驱动高影响动作」在实现层的落点。
    """

    def __init__(
        self,
        *,
        screen_threshold: float = 0.5,
        quarantine: bool = True,
        tool_vocabulary: list[str] | None = None,
        llm_judge: Any = None,
        store_path: str | Path | None = ":memory:",
        store_backend: str = "chroma",
        legacy_path: str | Path | None = None,
    ) -> None:
        if not MEMWARD_AVAILABLE:
            raise MemwardUnavailable(
                f"memward 不可用：{MEMWARD_IMPORT_ERROR}。"
                "请安装：pip install --user --no-deps memward"
            )
        # Production passes a filesystem path from component_service.  The
        # standalone adapter defaults to an isolated in-memory store so unit
        # tests and one-off callers do not share state accidentally.
        if str(store_path) == ":memory:":
            store = InMemoryStore()
        elif store_backend == "chroma":
            from security.chroma_memory_store import ChromaMemoryStore
            default = Path(__file__).resolve().parents[1] / "data" / "chroma_memory"
            store = ChromaMemoryStore(store_path or default, legacy_path=legacy_path)
        elif store_backend == "sqlite":
            from security.vector_memory_store import SQLiteVectorStore
            default = Path(__file__).resolve().parents[1] / "data" / "memory_vectors.sqlite3"
            store = SQLiteVectorStore(store_path or default)
        else:
            raise ValueError(f"Unsupported memory backend: {store_backend}")
        self._store = store
        self._mem = Memward(
            store,
            screen_threshold=screen_threshold,
            quarantine=quarantine,
            llm_judge=llm_judge,
            # 工具词表给共识校验用：它能抓「单独看无害、与其他记忆不一致」的
            # 上下文投毒（例如被篡改的"已核实"工具输出）。
            consensus=(ConsensusValidator(ToolClaimExtractor(list(tool_vocabulary)))
                       if tool_vocabulary else None),
        )

    # -- 写 ---------------------------------------------------------------
    def write(
        self,
        content: str,
        *,
        source_type: str = "user_instruction",
        source_id: str | None = None,
        session_id: str = "",
        derived_from: list[str] | None = None,
        metadata: dict[str, Any] | None = None,
    ) -> dict[str, Any]:
        """写入一条记忆。非用户来源命中投毒特征会被**隔离**。"""
        source = self._source(source_type)
        merged = dict(metadata or {})
        if session_id:
            merged.setdefault("session_id", session_id)
        result = self._mem.add(
            content, source=source, source_id=source_id,
            metadata=merged, derived_from=derived_from,
        )
        record = result.record
        return {
            "record_id": record.id,
            "source_type": source_type,
            "source": record.provenance.source.value,
            "trust": record.provenance.trust.name,
            "trust_level": int(record.provenance.trust),
            "screen_score": round(record.provenance.screen_score, 4),
            "flags": list(record.provenance.flags),
            "quarantined": result.quarantined,
            "session_id": session_id,
        }

    # -- 读 ---------------------------------------------------------------
    def read(self, query: str, *, k: int = 5, privileged: bool = False,
             session_id: str = "") -> MemoryReadResult:
        """读取记忆。`privileged=True` 用于工具选择，门槛更严。"""
        hits = self._mem.search(query, k=k, privileged=privileged)
        kept = [self._describe(score.record, score.score) for score in hits]

        kept_ids = {item["record_id"] for item in kept}
        # 被排除的项 memward 不直接返回（filter_for_retrieval 的结果被 core 吃掉了），
        # 只检查本次向量检索的候选，不能把库中无关污染归因给当前请求。
        excluded: list[dict[str, Any]] = []
        for candidate in self._mem.store.search(query, k=k):
            record = candidate.record
            if record.id in kept_ids:
                continue
            trust = record.provenance.trust
            if privileged and int(trust) < 2:
                excluded.append({
                    **self._describe(record, candidate.score),
                    "record_id": record.id,
                    "content": record.content,
                    "trust": trust.name,
                    "reason": ("quarantined" if trust.name == "QUARANTINED"
                               else f"trust {trust.name} 低于 privileged 要求的 VERIFIED"),
                })
            elif trust.name == "QUARANTINED":
                excluded.append({
                    **self._describe(record, candidate.score),
                    "record_id": record.id, "content": record.content,
                    "trust": trust.name, "reason": "quarantined（命中投毒特征）",
                })
        if session_id:
            for item in [*kept, *excluded]:
                item["replayed_across_session"] = bool(
                    item.get("session_id") and item["session_id"] != session_id
                )
        return MemoryReadResult(kept=kept, excluded=excluded)

    # -- 决策归因与回滚 ---------------------------------------------------
    def remember_decision(self, action: str) -> dict[str, Any] | None:
        """记录 agent 选了哪个动作，绑定到影响它的记忆。漂移会被报出来。"""
        alert = self._mem.remember_decision(action)
        if alert is None:
            return None
        return {"action": getattr(alert, "action", action),
                "detail": str(getattr(alert, "reason", "") or alert)}

    def attribute(self, action: str) -> list[dict[str, Any]]:
        return [self._describe(record) for record in self._mem.attribute(action)]

    def rollback(self, record_id: str) -> list[str]:
        """清除一条被污染的记忆**以及所有由它蒸馏出来的**（打断错误循环）。"""
        return list(self._mem.rollback(record_id))

    # -- 审计与全量扫描 ---------------------------------------------------
    def audit(self) -> list[dict[str, Any]]:
        return [self._describe(record) for record in self._mem.store.all()]

    def stats(self) -> dict[str, Any]:
        """Expose the backing vector database for health/audit UI."""
        stats = getattr(self._store, "stats", None)
        if callable(stats):
            return dict(stats())
        return {"backend": type(self._store).__name__, "count": len(self._mem.store.all())}

    def scan(self) -> list[dict[str, Any]]:
        """对已存在的记忆重新筛查（审计一个早于 memward 之前就存在记忆库）。"""
        return [self._describe(record) | {"screen_score": round(result.score, 4),
                                          "reasons": list(result.reasons)}
                for record, result in self._mem.scan()]

    # -- 内部 -------------------------------------------------------------
    @staticmethod
    def _source(source_type: str):
        name = SOURCE_TYPE_MAP.get(str(source_type or "").strip(), "UNKNOWN")
        return getattr(SourceType, name)

    @staticmethod
    def _describe(record: Any, score: float | None = None) -> dict[str, Any]:
        item = {
            "record_id": record.id,
            "content": record.content,
            "source": record.provenance.source.value,
            "source_id": record.provenance.source_id,
            "trust": record.provenance.trust.name,
            "trust_level": int(record.provenance.trust),
            "screen_score": round(record.provenance.screen_score, 4),
            "flags": list(record.provenance.flags),
            "session_id": (record.metadata or {}).get("session_id", ""),
            "metadata": dict(record.metadata or {}),
            "quarantined": record.quarantined,
        }
        if score is not None:
            item["score"] = round(float(score), 4)
        return item

    # 兼容旧接口形态，便于替换 memory_store.TrustAwareMemory
    def __len__(self) -> int:
        return len(self._mem.store.all())
