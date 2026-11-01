"""Optional argument-scanning service."""
from __future__ import annotations

import argparse
import json
import os
import sys
import threading
import time
from http import HTTPStatus
from http.server import BaseHTTPRequestHandler, ThreadingHTTPServer
from pathlib import Path
from typing import Any

ROOT = Path(__file__).resolve().parents[1]
if str(ROOT) not in sys.path:
    sys.path.insert(0, str(ROOT))

#: **绕过代理访问本地服务**。
#:
#: 本机开发时设了 HTTP_PROXY/HTTPS_PROXY（例如抓包或走外网），而 OpenAI 客户端、
#: urllib 默认会把 127.0.0.1 也代理掉 —— 表现为莫名其妙的 `502 Bad Gateway`。
#: 实测踩过一次：本机 Ollama 明明在线，语义对齐却一直返回 ERROR。
#:
#: 所以这里在**进程内**把回环地址加进 NO_PROXY，不依赖启动时的环境变量。
for _host in ("127.0.0.1", "localhost", "::1"):
    _existing = os.environ.get("NO_PROXY", "")
    if _host not in _existing:
        os.environ["NO_PROXY"] = f"{_existing},{_host}".strip(",")
        os.environ["no_proxy"] = os.environ["NO_PROXY"]

DEFAULT_HOST = "127.0.0.1"
DEFAULT_PORT = 8055

#: 版本号在 `/health` 里暴露。用途是**识别陈旧进程** ——
#: 改了组件代码但服务没重启时，接口会一直返回旧行为，而这一点
#: 从响应体本身看不出来。踩过一次，所以加它。
SERVICE_VERSION = "1.1.0"


class ComponentSet:
    """惰性加载并缓存两个组件。任一个加载失败只影响自己。"""

    def __init__(self) -> None:
        self._lock = threading.Lock()
        self.arg_scanner: Any = None
        self.semantic_aligner: Any = None
        self.arg_error = ""
        self.semantic_error = ""
        self.arg_calls = 0
        self.semantic_calls = 0
        #: 记忆门是**跨会话状态**，必须只构造一次、常驻。
        self._memory: Any = None
        self._memory_error = ""
        self.memory_writes = 0
        self.memory_reads = 0
        self.started_at = time.time()
        self._load_arg_scanner()
        self.semantic_error = "已由在线 DRIFT 计划与动态校验替代，旧服务停用"

    def _load_arg_scanner(self) -> None:
        try:
            from security.mcpsafety_args import ArgScanner, MCPSAFETY_AVAILABLE
            if not MCPSAFETY_AVAILABLE:
                self.arg_error = "mcpsafetywarden 不可用"
                return
            self.arg_scanner = ArgScanner()
        except Exception as exc:                      # noqa: BLE001 — 要如实报出来
            self.arg_error = f"{type(exc).__name__}: {exc}"

    def _load_semantic_aligner(self) -> None:
        try:
            from security.semantic_alignment import (  # noqa: PLC0415
                SEMANTIC_ALIGNMENT_AVAILABLE,
                SemanticAlignment,
            )
            if not SEMANTIC_ALIGNMENT_AVAILABLE:
                # 只报「不可用」——具体原因（缺 llamafirewall 还是 Ollama 没起）
                # 在实际调用时才暴露，避免启动期就依赖 Ollama 在线。
                self.semantic_error = "llamafirewall/语义对齐不可用"
                return
            self.semantic_aligner = SemanticAlignment()
        except Exception as exc:                      # noqa: BLE001
            self.semantic_error = f"{type(exc).__name__}: {exc}"

    # -- 能力 -------------------------------------------------------------
    def arg_scan(self, tool: str, args: dict[str, Any],
                 tool_description: str = "") -> dict[str, Any]:
        if self.arg_scanner is None:
            return {"decision": "unavailable", "available": False,
                    "reason": self.arg_error or "参数扫描不可用",
                    "categories": [], "source": "mcpsafetywarden"}
        with self._lock:
            self.arg_calls += 1
            result = self.arg_scanner.scan(tool, args, tool_description)
        return result.to_dict()

    def semantic_align(self, user_request: str, action: str,
                       action_input: Any = None, thought: str = "",
                       history: list[str] | None = None) -> dict[str, Any]:
        if self.semantic_aligner is None:
            return {"decision": "unavailable", "available": False,
                    "reason": self.semantic_error or "语义对齐不可用",
                    "misaligned": False,
                    "source": "llamafirewall.AlignmentCheck@ollama"}
        payload = action_input if isinstance(action_input, dict) else (action_input or "")
        result = self.semantic_aligner.check(
            user_request=str(user_request), action=str(action),
            action_input=payload, thought=str(thought or ""),
            history=tuple(history or ()),
        )
        with self._lock:
            self.semantic_calls += 1
        return result.to_dict()

    # -- 记忆信任门（memward） --------------------------------------------
    def _memory_gate(self) -> Any:
        """Chroma runs in its own environment; never fall back to SQLite."""
        if self._memory is None:
            from security.component_client import RemoteMemoryGate
            self._memory = RemoteMemoryGate(os.environ.get("MEMORY_SERVICE_URL", "http://127.0.0.1:8164"))
        try:
            self._memory.stats()
            self._memory_error = ""
            return self._memory
        except Exception as exc:
            self._memory_error = f"{type(exc).__name__}: {exc}"
            return None

    def memory_write(self, content: str, source_type: str = "user_instruction",
                     source_id: str = "", session_id: str = "", metadata: dict | None = None) -> dict[str, Any]:
        gate = self._memory_gate()
        if gate is None:
            return {"available": False, "reason": self._memory_error or "记忆门不可用"}
        with self._lock:
            self.memory_writes += 1
            result = gate.write(content, source_type=source_type,
                                source_id=source_id or None, session_id=session_id, metadata=metadata)
        return {"available": True, **result}

    def memory_read(self, query: str, k: int = 5, privileged: bool = True,
                    session_id: str = "") -> dict[str, Any]:
        """读记忆。`privileged=True` 表示这批内容会**影响工具选择**，
        此时默认只有 VERIFIED 及以上（用户 + 已核实工具）能过关。"""
        gate = self._memory_gate()
        if gate is None:
            return {"available": False, "reason": self._memory_error or "记忆门不可用",
                    "kept": [], "excluded": []}
        with self._lock:
            self.memory_reads += 1
            result = gate.read(query, k=k, privileged=privileged, session_id=session_id)
        return result

    def memory_audit(self) -> dict[str, Any]:
        gate = self._memory_gate()
        if gate is None:
            return {"available": False, "reason": self._memory_error or "记忆门不可用"}
        return gate.audit()

    def memory_rollback(self, record_id: str) -> dict[str, Any]:
        gate = self._memory_gate()
        if gate is None:
            return {"available": False, "reason": self._memory_error or "记忆门不可用"}
        return gate.rollback(record_id)

    def raw_align_probe(self, user_request: str, action: str,                        action_input: Any = None, thought: str = "") -> dict[str, Any]:
        """诊断：直接调官方 scanner，把被吞掉的异常暴露出来。"""
        if self.semantic_aligner is None:
            return {"error": self.semantic_error or "语义对齐不可用"}
        import asyncio                                          # noqa: PLC0415
        import traceback                                        # noqa: PLC0415
        scanner = self.semantic_aligner._scanner_or_none()      # noqa: SLF001
        if scanner is None:
            return {"error": self.semantic_aligner._load_error or "scanner 未初始化"}
        from llamafirewall import AssistantMessage, UserMessage  # noqa: PLC0415
        from llamafirewall.scanners.experimental.alignmentcheck_scanner import (  # noqa: PLC0415
            SYSTEM_PROMPT, AlignmentCheckOutputSchema, USER_PROMPT_FORMAT)
        rendered = ", ".join(f"{k}={v!r}" for k, v in (action_input or {}).items()) \
            if isinstance(action_input, dict) else str(action_input or "")
        body = (f"THOUGHT: {thought or '（无）'}\nSELECTED ACTION:\n"
                f"ACTION: {action}\nACTION INPUT: {rendered}")
        messages = [UserMessage(content=user_request), AssistantMessage(content=body)]
        out: dict[str, Any] = {"module": "security.semantic_alignment"}
        try:
            out["scanner_class"] = type(scanner).__name__
            out["base_url"] = str(scanner.llm.client.base_url)
            out["model"] = scanner.llm.model_name
        except Exception as exc:                                # noqa: BLE001
            out["introspect_error"] = f"{type(exc).__name__}: {exc}"
        # 1) 直接用官方 LLM client（绕开我们的包装）
        try:
            parsed = asyncio.run(scanner.llm.call(
                prompt=USER_PROMPT_FORMAT.format(user_message=user_request, trace=body),
                system_prompt=SYSTEM_PROMPT, output_schema=AlignmentCheckOutputSchema,
                temperature=0.0))
            out["direct_llm_call"] = "ok"
            out["direct_conclusion"] = bool(getattr(parsed, "conclusion", None))
        except BaseException as exc:                            # noqa: BLE001
            out["direct_llm_call"] = "failed"
            out["direct_error"] = f"{type(exc).__name__}: {exc}"
            out["direct_traceback"] = traceback.format_exc()[-1200:]
        # 2) 走官方 scanner
        try:
            scan = asyncio.run(scanner.scan(AssistantMessage(content=body), messages))
            out["scan_status"] = str(getattr(scan.status, "value", scan.status))
            out["scan_decision"] = str(getattr(scan.decision, "value", scan.decision))
            out["scan_reason"] = str(scan.reason or "")[:200]
        except BaseException as exc:                            # noqa: BLE001
            out["scan_error"] = f"{type(exc).__name__}: {exc}"
        return out

    def health(self) -> dict[str, Any]:        return {
            "status": "ok",
            "service": "duoduo-bank-components",
            "version": SERVICE_VERSION,
            "components": {
                "arg_scanner": {
                    "available": self.arg_scanner is not None,
                    "error": self.arg_error or None,
                    "calls": self.arg_calls,
                },
                "semantic_aligner": {
                    "available": self.semantic_aligner is not None,
                    "error": self.semantic_error or None,
                    "calls": self.semantic_calls,
                },
                "memory_trust_gate": {
                    "available": self._memory_gate() is not None,
                    "error": self._memory_error or None,
                    "reads": self.memory_reads,
                    "writes": self.memory_writes,
                    "vector_store": (self._memory.stats() if not self._memory_error and self._memory is not None else None),
                    "service_url": os.environ.get("MEMORY_SERVICE_URL", "http://127.0.0.1:8064"),
                },
            },
            "uptime_seconds": round(time.time() - self.started_at, 1),
        }


def build_handler(components: ComponentSet) -> type[BaseHTTPRequestHandler]:
    class Handler(BaseHTTPRequestHandler):
        server_version = "StudioComponents/1.0"

        def log_message(self, fmt: str, *args: Any) -> None:          # noqa: A003
            return

        def _send(self, status: int, payload: dict[str, Any]) -> None:
            body = json.dumps(payload, ensure_ascii=False).encode("utf-8")
            self.send_response(status)
            self.send_header("Content-Type", "application/json; charset=utf-8")
            self.send_header("Content-Length", str(len(body)))
            self.send_header("Access-Control-Allow-Origin", "*")
            self.end_headers()
            self.wfile.write(body)

        def do_GET(self) -> None:                                      # noqa: N802
            if self.path.split("?")[0] in ("/health", "/api/health"):
                self._send(HTTPStatus.OK, components.health())
                return
            self._send(HTTPStatus.NOT_FOUND, {"error": "unknown endpoint"})

        def do_POST(self) -> None:                                     # noqa: N802
            path = self.path.split("?")[0]
            length = int(self.headers.get("content-length", "0") or 0)
            raw = self.rfile.read(length).decode("utf-8") if length else "{}"
            try:
                body = json.loads(raw or "{}")
            except json.JSONDecodeError as exc:
                self._send(HTTPStatus.BAD_REQUEST, {"error": f"invalid json: {exc}"})
                return
            try:
                if path == "/arg-scan":
                    result = components.arg_scan(
                        str(body.get("tool", "")),
                        body.get("args") if isinstance(body.get("args"), dict) else {},
                        str(body.get("tool_description", "")),
                    )
                elif path == "/tokenize":
                    from tokenizers import Tokenizer
                    tokenizer = Tokenizer.from_file(str(ROOT / "models" / "from_models_zip" / "Llama-Prompt-Guard-2-86M" / "tokenizer.json"))
                    tokenizer.no_truncation()
                    tokenizer.no_padding()
                    text = str(body.get("text", ""))
                    if len(text) > 262144:
                        raise ValueError("文本超过 token 定位上限")
                    encoded = tokenizer.encode(text, add_special_tokens=False)
                    result = {"available": True, "tokenizer": "Llama-Prompt-Guard-2-86M",
                              "offsets": encoded.offsets, "tokens": encoded.tokens, "ids": encoded.ids}
                elif path == "/semantic-align":
                    result = components.semantic_align(
                        str(body.get("user_request", "")),
                        str(body.get("action", "")),
                        body.get("action_input"),
                        str(body.get("thought", "")),
                        body.get("history") if isinstance(body.get("history"), list) else [],
                    )
                elif path == "/memory/write":
                    result = components.memory_write(
                        str(body.get("content", "")),
                        str(body.get("source_type", "user_instruction")),
                        str(body.get("source_id", "")),
                        str(body.get("session_id", "")),
                        body.get("metadata"),
                    )
                elif path == "/memory/read":
                    result = components.memory_read(
                        str(body.get("query", "")),
                        int(body.get("k", 5) or 5),
                        bool(body.get("privileged", True)),
                        str(body.get("session_id", "")),
                    )
                elif path == "/memory/audit":
                    result = components.memory_audit()
                elif path == "/memory/rollback":
                    result = components.memory_rollback(str(body.get("record_id", "")))
                elif path == "/debug/raw-align":
                    # 诊断用：**不经过我们的包装**，直接调官方 scanner，
                    # 把被它吞掉的异常原因暴露出来。定位「到底是谁在失败」时用。
                    result = components.raw_align_probe(
                        str(body.get("user_request", "")), str(body.get("action", "")),
                        body.get("action_input"), str(body.get("thought", "")),
                    )
                else:
                    self._send(HTTPStatus.NOT_FOUND, {"error": "unknown endpoint"})
                    return
            except Exception as exc:                                   # noqa: BLE001
                # 出错不伪装成 allow/allow —— 调用方按降级处理。
                self._send(HTTPStatus.OK, {
                    "decision": "unavailable", "available": False,
                    "reason": f"{type(exc).__name__}: {exc}",
                })
                return
            self._send(HTTPStatus.OK, result)

    return Handler


def main(argv: list[str] | None = None) -> int:
    parser = argparse.ArgumentParser(
        description="Studio 可选安全组件服务（参数扫描 / 语义对齐）")
    parser.add_argument("--host", default=os.environ.get("COMPONENTS_HOST", DEFAULT_HOST))
    parser.add_argument("--port", type=int, default=int(os.environ.get("COMPONENTS_PORT", DEFAULT_PORT)))
    args = parser.parse_args(argv)

    print("[components] 加载可选组件…", flush=True)
    components = ComponentSet()
    health = components.health()["components"]
    for name, info in health.items():
        state = "就绪" if info["available"] else f"不可用（{info['error']}）"
        print(f"  {name}: {state}", flush=True)
    server = ThreadingHTTPServer((args.host, args.port), build_handler(components))
    print(f"[components] 监听 http://{args.host}:{args.port}"
          f"  GET /health  POST /arg-scan  POST /semantic-align", flush=True)
    try:
        server.serve_forever()
    except KeyboardInterrupt:
        print("[components] 停止", flush=True)
    finally:
        server.server_close()
    return 0


if __name__ == "__main__":
    sys.exit(main())
