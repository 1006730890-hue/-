"""Isolated Chroma + memward service; no detector dependencies in this environment."""
from __future__ import annotations

import argparse
import json
import os
import sys
import threading
from http.server import BaseHTTPRequestHandler, ThreadingHTTPServer
from pathlib import Path

ROOT = Path(__file__).resolve().parents[1]
sys.path.insert(0, str(ROOT))
from security.memward_memory import MemwardMemory


def build_handler(gate: MemwardMemory) -> type[BaseHTTPRequestHandler]:
    lock = threading.RLock()

    class Handler(BaseHTTPRequestHandler):
        def send_json(self, status: int, value: dict) -> None:
            raw = json.dumps(value, ensure_ascii=False).encode("utf-8")
            self.send_response(status)
            self.send_header("Content-Type", "application/json; charset=utf-8")
            self.send_header("Content-Length", str(len(raw)))
            self.end_headers()
            self.wfile.write(raw)

        def do_GET(self) -> None:
            if self.path != "/health":
                self.send_json(404, {"error": "not found"})
                return
            with lock:
                stats = gate.stats()
            self.send_json(200, {"status": "ok", "service": "chroma-memory", "pid": os.getpid(),
                "components": {"memory_trust_gate": {"available": True, "error": None,
                                                       "vector_store": stats}}})

        def do_POST(self) -> None:
            try:
                size = int(self.headers.get("Content-Length", "0"))
                if not 0 <= size <= 1024 * 1024:
                    raise ValueError("memory request too large")
                body = json.loads(self.rfile.read(size) or b"{}")
                with lock:
                    if self.path == "/memory/write":
                        result = gate.write(str(body.get("content", "")),
                            source_type=str(body.get("source_type", "external_web_content")),
                            source_id=str(body.get("source_id") or "") or None,
                            session_id=str(body.get("session_id") or ""),
                            derived_from=body.get("derived_from"), metadata=body.get("metadata"))
                    elif self.path == "/memory/read":
                        k = int(body.get("k", 5))
                        if not 1 <= k <= 100:
                            raise ValueError("k must be between 1 and 100")
                        result = gate.read(str(body.get("query", "")), k=k,
                            privileged=bool(body.get("privileged", True)),
                            session_id=str(body.get("session_id") or "")).to_dict()
                    elif self.path == "/memory/audit":
                        result = {"records": gate.audit()}
                    elif self.path == "/memory/rollback":
                        result = {"removed": gate.rollback(str(body.get("record_id", "")))}
                    else:
                        self.send_json(404, {"available": False, "error": "unknown endpoint"})
                        return
                    result.update({"available": True, "vector_store": gate.stats()})
                self.send_json(200, result)
            except Exception as exc:
                self.send_json(503, {"available": False, "decision": "unavailable",
                                    "reason": f"{type(exc).__name__}: {exc}"})

        def log_message(self, *_args: object) -> None:
            return

    return Handler


def main() -> None:
    parser = argparse.ArgumentParser()
    parser.add_argument("--host", default="127.0.0.1")
    parser.add_argument("--port", type=int, default=8064)
    parser.add_argument("--path", default=os.environ.get("CHROMA_MEMORY_PATH", str(ROOT / "data" / "chroma_memory")))
    parser.add_argument("--legacy-path", default=str(ROOT / "data" / "memory_vectors.sqlite3"))
    args = parser.parse_args()
    gate = MemwardMemory(store_path=args.path, store_backend="chroma", legacy_path=args.legacy_path,
        tool_vocabulary=["send_money", "process_refund", "wire_transfer", "get_balance", "fs.write"])
    server = ThreadingHTTPServer((args.host, args.port), build_handler(gate))
    print(json.dumps({"service": "chroma-memory", "port": args.port, **gate.stats()}, ensure_ascii=False), flush=True)
    server.serve_forever()


if __name__ == "__main__":
    main()
