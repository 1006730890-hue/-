"""Persistent vector store adapter for memward.

The previous component used memward's ``InMemoryStore``.  That was useful for
unit tests, but it lost all cross-session memory on process restart.  This
adapter keeps memward's provenance/trust objects while persisting records and
hashed text vectors in SQLite.  Retrieval is cosine similarity over the stored
vectors, not keyword lookup.

It intentionally has no model dependency: feature hashing is deterministic,
local, and stable across service restarts.  A deployment can later replace the
encoder without changing the memward/store contract.
"""
from __future__ import annotations

import hashlib
from contextlib import contextmanager
import json
import math
import sqlite3
import struct
import threading
import time
from pathlib import Path
from typing import Any, Iterator

from memward.adapters.base import ScoredRecord
from memward.types import MemoryRecord, Provenance


class SQLiteVectorStore:
    """A small persistent vector database implementing memward's store API."""

    dimension = 256

    def __init__(self, path: str | Path) -> None:
        self.path = Path(path)
        self.path.parent.mkdir(parents=True, exist_ok=True)
        self._lock = threading.RLock()
        self._init_schema()

    @contextmanager
    def _connect(self) -> Iterator[sqlite3.Connection]:
        conn = sqlite3.connect(str(self.path), timeout=10.0, check_same_thread=False)
        conn.row_factory = sqlite3.Row
        try:
            with conn:
                yield conn
        finally:
            conn.close()

    def _init_schema(self) -> None:
        with self._connect() as conn:
            conn.execute(
                """CREATE TABLE IF NOT EXISTS memory_vectors (
                    record_id TEXT PRIMARY KEY,
                    content TEXT NOT NULL,
                    metadata_json TEXT NOT NULL,
                    provenance_json TEXT NOT NULL,
                    vector BLOB NOT NULL,
                    created_at REAL NOT NULL DEFAULT 0
                )"""
            )
            conn.execute("CREATE INDEX IF NOT EXISTS idx_memory_vectors_created ON memory_vectors(created_at)")

    @classmethod
    def _vector(cls, text: str) -> list[float]:
        values = [0.0] * cls.dimension
        # Character n-grams work for Chinese, English, punctuation and mixed
        # payloads without requiring a heavyweight embedding model.
        normalized = " ".join(str(text or "").lower().split())
        grams = [normalized[i:i + 3] for i in range(max(0, len(normalized) - 2))]
        grams.extend(normalized.split())
        for gram in grams:
            digest = hashlib.blake2b(gram.encode("utf-8"), digest_size=8).digest()
            bucket = int.from_bytes(digest[:4], "little") % cls.dimension
            sign = 1.0 if digest[4] & 1 else -1.0
            values[bucket] += sign
        norm = math.sqrt(sum(item * item for item in values))
        return [item / norm for item in values] if norm else values

    @staticmethod
    def _pack(vector: list[float]) -> bytes:
        return struct.pack(f"<{len(vector)}f", *vector)

    @classmethod
    def _unpack(cls, blob: bytes) -> list[float]:
        return list(struct.unpack(f"<{cls.dimension}f", blob))

    @staticmethod
    def _record(row: sqlite3.Row) -> MemoryRecord:
        return MemoryRecord(
            content=str(row["content"]),
            id=str(row["record_id"]),
            metadata=json.loads(row["metadata_json"] or "{}"),
            provenance=Provenance.from_dict(json.loads(row["provenance_json"] or "{}")),
        )

    def add(self, record: MemoryRecord) -> str:
        provenance = record.provenance.to_dict()
        with self._lock, self._connect() as conn:
            conn.execute(
                """INSERT INTO memory_vectors
                   (record_id, content, metadata_json, provenance_json, vector, created_at)
                   VALUES (?, ?, ?, ?, ?, ?)
                   ON CONFLICT(record_id) DO UPDATE SET
                     content=excluded.content,
                     metadata_json=excluded.metadata_json,
                     provenance_json=excluded.provenance_json,
                     vector=excluded.vector""",
                (record.id, record.content, json.dumps(record.metadata, ensure_ascii=False),
                 json.dumps(provenance, ensure_ascii=False), self._pack(self._vector(record.content)), time.time()),
            )
        return record.id

    def get(self, record_id: str) -> MemoryRecord | None:
        with self._lock, self._connect() as conn:
            row = conn.execute("SELECT * FROM memory_vectors WHERE record_id=?", (record_id,)).fetchone()
        return self._record(row) if row else None

    def search(self, query: str, k: int = 5) -> list[ScoredRecord]:
        query_vector = self._vector(query)
        scored: list[ScoredRecord] = []
        with self._lock, self._connect() as conn:
            rows = conn.execute("SELECT * FROM memory_vectors").fetchall()
        for row in rows:
            vector = self._unpack(row["vector"])
            score = sum(left * right for left, right in zip(query_vector, vector))
            scored.append(ScoredRecord(self._record(row), float(score)))
        scored.sort(key=lambda item: item.score, reverse=True)
        return scored[:max(0, int(k))]

    def delete(self, record_id: str) -> bool:
        with self._lock, self._connect() as conn:
            cursor = conn.execute("DELETE FROM memory_vectors WHERE record_id=?", (record_id,))
            return cursor.rowcount > 0

    def all(self) -> list[MemoryRecord]:
        with self._lock, self._connect() as conn:
            rows = conn.execute("SELECT * FROM memory_vectors ORDER BY created_at, record_id").fetchall()
        return [self._record(row) for row in rows]

    def stats(self) -> dict[str, Any]:
        with self._lock, self._connect() as conn:
            count = int(conn.execute("SELECT COUNT(*) FROM memory_vectors").fetchone()[0])
        return {"backend": "sqlite_vector_store", "path": str(self.path),
                "dimension": self.dimension, "metric": "cosine", "count": count}
