"""memward backend using Chroma's persistent collection and vector index.

Vectors intentionally retain the legacy feature-hashing encoder during this
backend migration. Search/indexing is performed by Chroma, not a Python scan.
No automatic embedding-model download is needed or silently substituted.
"""
from __future__ import annotations

import json
import sqlite3
from pathlib import Path
from typing import Any

import chromadb
from chromadb.config import Settings
from memward.adapters.base import ScoredRecord
from memward.types import MemoryRecord, Provenance

from .vector_memory_store import SQLiteVectorStore


class ChromaMemoryStore:
    dimension = 256
    collection_name = "agent_memory_v1"

    def __init__(self, path: str | Path, *, legacy_path: str | Path | None = None) -> None:
        self.path = Path(path).resolve()
        self.client = chromadb.PersistentClient(
            path=str(self.path), settings=Settings(anonymized_telemetry=False))
        self.collection = self.client.get_or_create_collection(
            name=self.collection_name, embedding_function=None,
            metadata={"hnsw:space": "cosine", "encoder": "char_ngram_hash_v1",
                      "dimension": self.dimension})
        if legacy_path is not None:
            self.migrate_sqlite(legacy_path)

    @staticmethod
    def _record(record_id: str, document: str, metadata: dict) -> MemoryRecord:
        return MemoryRecord(id=record_id, content=document,
                            metadata=json.loads(metadata["metadata_json"]),
                            provenance=Provenance.from_dict(json.loads(metadata["provenance_json"])))

    def add(self, record: MemoryRecord) -> str:
        self.collection.upsert(
            ids=[record.id], documents=[record.content],
            embeddings=[SQLiteVectorStore._vector(record.content)],
            metadatas=[{"metadata_json": json.dumps(record.metadata, ensure_ascii=False),
                        "provenance_json": json.dumps(record.provenance.to_dict(), ensure_ascii=False),
                        "source": record.provenance.source.value,
                        "trust": int(record.provenance.trust)}])
        return record.id

    def get(self, record_id: str) -> MemoryRecord | None:
        result = self.collection.get(ids=[record_id], include=["documents", "metadatas"])
        if not result["ids"]:
            return None
        return self._record(result["ids"][0], result["documents"][0], result["metadatas"][0])

    def search(self, query: str, k: int = 5) -> list[ScoredRecord]:
        count = self.collection.count()
        if not count or k <= 0:
            return []
        result = self.collection.query(
            query_embeddings=[SQLiteVectorStore._vector(query)], n_results=min(int(k), count),
            include=["documents", "metadatas", "distances"])
        return [ScoredRecord(self._record(record_id, document, metadata), 1.0 - float(distance))
                for record_id, document, metadata, distance in zip(
                    result["ids"][0], result["documents"][0], result["metadatas"][0], result["distances"][0])]

    def delete(self, record_id: str) -> bool:
        if self.get(record_id) is None:
            return False
        self.collection.delete(ids=[record_id])
        return True

    def all(self) -> list[MemoryRecord]:
        result = self.collection.get(include=["documents", "metadatas"])
        return [self._record(record_id, document, metadata)
                for record_id, document, metadata in zip(result["ids"], result["documents"], result["metadatas"])]

    def stats(self) -> dict[str, Any]:
        return {"backend": "chroma", "version": chromadb.__version__, "path": str(self.path),
                "collection": self.collection_name, "dimension": self.dimension,
                "encoder": "char_ngram_hash_v1", "metric": "cosine",
                "index": "chroma_hnsw", "count": self.collection.count()}

    def migrate_sqlite(self, legacy_path: str | Path) -> int:
        """Copy existing records once, preserving IDs and trust; never modify the source."""
        legacy_path = Path(legacy_path).resolve()
        marker = self.path / "sqlite_migration_v1.json"
        if marker.exists() or not legacy_path.is_file():
            return 0
        connection = sqlite3.connect(legacy_path.as_uri() + "?mode=ro", uri=True)
        connection.row_factory = sqlite3.Row
        try:
            rows = connection.execute("SELECT * FROM memory_vectors").fetchall()
        finally:
            connection.close()
        copied = 0
        for row in rows:
            record_id = str(row["record_id"])
            if self.get(record_id) is None:
                self.add(self._record(record_id, row["content"], dict(row)))
                copied += 1
        # Marker is written only after every upsert succeeds. Interrupted runs
        # resume without overwriting newer records or re-adding rolled-back data.
        marker.write_text(json.dumps({"source": str(legacy_path), "records": len(rows),
                                      "copied": copied}, ensure_ascii=False), encoding="utf-8")
        return copied
