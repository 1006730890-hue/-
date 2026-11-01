"""Trust-aware memory store used for cross-session poisoning tests."""
from __future__ import annotations

from dataclasses import asdict, dataclass
from typing import Any


@dataclass(frozen=True)
class MemoryRecord:
    record_id: str
    text: str
    source_type: str
    trust: str
    classification: str
    session_id: str


class TrustAwareMemory:
    """A deterministic in-memory store that never upgrades untrusted content."""

    def __init__(self) -> None:
        self._records: dict[str, MemoryRecord] = {}

    def write(self, record_id: str, text: str, *, source_type: str = "user_instruction",
              trust: str = "trusted", classification: str = "public", session_id: str = "session") -> MemoryRecord:
        record = MemoryRecord(record_id, str(text), source_type, trust, classification, session_id)
        self._records[record_id] = record
        return record

    def read(self, record_id: str, *, session_id: str | None = None) -> dict[str, Any] | None:
        record = self._records.get(record_id)
        if record is None:
            return None
        data = asdict(record)
        data["replayed_across_session"] = session_id is not None and session_id != record.session_id
        data["requires_review"] = record.trust != "trusted" or data["replayed_across_session"]
        return data

    def audit(self) -> list[dict[str, Any]]:
        return [asdict(record) for record in self._records.values()]
