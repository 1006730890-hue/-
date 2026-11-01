"""审计记录的哈希链（防篡改 / 不可否认）。

为什么需要它
------------
本项目已经有两张审计面：`audit_events`（每步链路证据）与 `turns`（待确认申请）。
但它们都是**可变表** —— 谁有写权限谁就能改一行，改完看不出痕迹。
赛题要求的是「可复核」，而「可复核」的前提是**记录没被事后修改过**。

为什么不用 anchor-gateway
-------------------------
调研发现 [anchor-gateway](https://pypi.org/project/anchor-gateway/) 提供了
正好这种哈希链裁决日志（`VerdictLog` + `verify_chain`）。但实测它**跑不起来**：
`gateway/server.py` 依赖 `anchor_v1.*`（`canonical`/`crypto`/`store`/`acs_guardian`），
而那个内核**既不在 PyPI 上、也不在 sdist 里**。

更糟的是它的失败方式：`ImportError` 被捕获后把 `sha256_hex` 之类的名字设成 `None`，
注释说「`_require_kernel()` 会在触碰之前快速失败」，但 `VerdictLog.append()`
并没有调它 —— 于是抛的是 `TypeError: 'NoneType' object is not callable`，
而不是一句清楚的「内核缺失」。**导入成功、功能是坏的**，这是最难排查的一类。

所以这里用标准库实现同一个不变量，一行 SHA-256 而已。

设计
----
链式定义（`prev` 是上一条的 `hash`，首条为 64 个 0）：

    hash_n = sha256( canonical(prev_hash, seq, payload_json) )

`canonical` 用 `json.dumps(sort_keys=True, separators=(",",":"))` —— 保证
**同一份 payload 在任何机器上都得到同一个字节序列**，否则校验会在别处失败。

校验时逐条重算并比对两件事：
1. 本条记录的 `hash` 是否等于按内容重算的值（**内容被改**会被发现）；
2. 本条的 `prev` 是否等于上一条的 `hash`（**删改/插入**会被发现）。

破坏点会被明确报出来（第几条、哪种破坏），而不是只给一个 False。
"""
from __future__ import annotations

import hashlib
import json
from dataclasses import dataclass
from pathlib import Path
from typing import Any, Iterable, Mapping

__all__ = [
    "GENESIS",
    "canonical_bytes",
    "entry_hash",
    "AuditChain",
    "ChainVerification",
    "verify_chain_file",
]

#: 链首的 prev 值。
GENESIS = "0" * 64

#: 参与哈希的字段。刻意**不含**任何由外部传入的 `hash`/`prev`，
#: 那两个是从链状态推出来的，不能由调用方决定。
_HASHED_FIELDS = ("seq", "event_type", "decision", "tool", "payload")


def canonical_bytes(*, prev: str, seq: int, event_type: str, decision: str,
                    tool: str, payload: Any) -> bytes:
    """把一个条目序列化成**确定性**字节串。

    `sort_keys=True` + 紧凑分隔符是关键：换一台机器、换一个 Python 版本，
    只要内容一样，字节就一样。用默认的 `json.dumps` 会因为空格/键序不同
    导致校验在别处失败。
    """
    body = {
        "prev": str(prev),
        "seq": int(seq),
        "event_type": str(event_type),
        "decision": str(decision or ""),
        "tool": str(tool or ""),
        "payload": payload if payload is not None else {},
    }
    return json.dumps(body, ensure_ascii=False, sort_keys=True,
                      separators=(",", ":"), default=str).encode("utf-8")


def entry_hash(*, prev: str, seq: int, event_type: str, decision: str,
               tool: str, payload: Any) -> str:
    return hashlib.sha256(canonical_bytes(
        prev=prev, seq=seq, event_type=event_type, decision=decision,
        tool=tool, payload=payload,
    )).hexdigest()


@dataclass
class ChainVerification:
    """链校验结果。**报出坏在哪一条**，而不是只给一个布尔。"""

    ok: bool
    entries: int
    broken_at: int | None = None
    reason: str = ""

    def to_dict(self) -> dict[str, Any]:
        return {"ok": self.ok, "entries": self.entries,
                "broken_at": self.broken_at, "reason": self.reason}


class AuditChain:
    """追加式的哈希链审计日志（JSONL，一行一条）。

    追加而不是改写：链的意义就在于历史**只能被检测出篡改、不能被悄悄修改**。
    """

    def __init__(self, path: str | Path) -> None:
        self.path = Path(path)
        self.path.parent.mkdir(parents=True, exist_ok=True)

    # -- 追加 -------------------------------------------------------------
    def append(self, *, event_type: str, decision: str = "", tool: str = "",
               payload: Mapping[str, Any] | None = None) -> dict[str, Any]:
        previous = self._last_hash()
        seq = self._next_seq()
        digest = entry_hash(prev=previous, seq=seq, event_type=event_type,
                            decision=decision, tool=tool, payload=dict(payload or {}))
        record = {
            "seq": seq, "prev": previous, "hash": digest,
            "event_type": str(event_type), "decision": str(decision or ""),
            "tool": str(tool or ""), "payload": dict(payload or {}),
        }
        with self.path.open("a", encoding="utf-8") as handle:
            handle.write(json.dumps(record, ensure_ascii=False,
                                    sort_keys=True, default=str) + "\n")
        return record

    # -- 读取与校验 -------------------------------------------------------
    def entries(self) -> list[dict[str, Any]]:
        if not self.path.exists():
            return []
        out: list[dict[str, Any]] = []
        with self.path.open("r", encoding="utf-8") as handle:
            for line in handle:
                line = line.strip()
                if not line:
                    continue
                try:
                    out.append(json.loads(line))
                except json.JSONDecodeError:
                    out.append({"_unparsable": line[:200]})
        return out

    def verify(self) -> ChainVerification:
        return self._verify(self.entries())

    @staticmethod
    def _verify(entries: Iterable[dict[str, Any]]) -> ChainVerification:
        expected_prev = GENESIS
        count = 0
        for index, record in enumerate(entries, start=1):
            count = index
            if "_unparsable" in record:
                return ChainVerification(False, count, index, "该行不是合法 JSON（被截断或改写）")
            if str(record.get("prev")) != expected_prev:
                return ChainVerification(
                    False, count, index,
                    f"prev 不匹配：记录里是 {str(record.get('prev'))[:16]}…，"
                    f"按链推算应为 {expected_prev[:16]}…（说明前面有记录被删除或插入）")
            recomputed = entry_hash(
                prev=str(record.get("prev")), seq=int(record.get("seq") or 0),
                event_type=str(record.get("event_type") or ""),
                decision=str(record.get("decision") or ""),
                tool=str(record.get("tool") or ""),
                payload=record.get("payload") or {},
            )
            if recomputed != str(record.get("hash")):
                return ChainVerification(
                    False, count, index,
                    "内容与哈希不符（该条记录被修改过）")
            expected_prev = recomputed
        return ChainVerification(True, count)

    # -- 内部 -------------------------------------------------------------
    def _last_hash(self) -> str:
        entries = self.entries()
        for record in reversed(entries):
            if isinstance(record.get("hash"), str):
                return record["hash"]
        return GENESIS

    def _next_seq(self) -> int:
        entries = self.entries()
        for record in reversed(entries):
            try:
                return int(record.get("seq") or 0) + 1
            except (TypeError, ValueError):
                continue
        return 1


def verify_chain_file(path: str | Path) -> ChainVerification:
    """独立校验一个链文件（不需要构造 AuditChain）。"""
    return AuditChain(path).verify()
