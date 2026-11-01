"""Local Prompt Guard model service."""
from __future__ import annotations

import argparse
import asyncio
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
TOOLS = Path(__file__).resolve().parent
if str(TOOLS) not in sys.path:
    sys.path.insert(0, str(TOOLS))

#: **绕过代理访问本地服务**。理由同 `component_service.py`：
#: 本机若设了 HTTP_PROXY，urllib 会把 127.0.0.1 也代理掉，
#: 表现为莫名的 502。这里在进程内兜住，不依赖启动时的环境变量。
for _host in ("127.0.0.1", "localhost", "::1"):
    _existing = os.environ.get("NO_PROXY", "")
    if _host not in _existing:
        os.environ["NO_PROXY"] = f"{_existing},{_host}".strip(",")
        os.environ["no_proxy"] = os.environ["NO_PROXY"]

#: LlamaFirewall 按 `HF_HOME/<model_name 把 / 换成 -->` 找模型。
#: 这里必须**不依赖环境变量**：本机系统级 `HF_HOME` 指向别处，
#: 一旦被它带偏，LlamaFirewall 就去 HuggingFace 下载 —— 而
#: `meta-llama/Llama-Prompt-Guard-2-86M` 是 gated repo，会直接 403。
#:
#: 所以走「候选路径逐个探测」：谁真的有 `config.json` 就用谁。
PROJECT_ROOT = ROOT
DEFAULT_HF_HOME = ROOT / "models" / "from_models_zip"
MODEL_DIR_NAME = "meta-llama--Llama-Prompt-Guard-2-86M"


def resolve_hf_home(explicit: Path | None = None) -> Path:
    """挑一个**确实含模型**的 HF_HOME。

    顺序：显式参数 -> 项目内置模型目录 -> 环境变量 HF_HOME -> 项目内置目录。
    显式参数与环境变量都只在其中真有模型时才采用，避免被引去下载 gated 模型。
    """
    candidates: list[Path] = []
    if explicit:
        candidates.append(Path(explicit))
    candidates.append(DEFAULT_HF_HOME)
    env_home = os.environ.get("HF_HOME")
    if env_home:
        candidates.append(Path(env_home))
    for candidate in candidates:
        if (candidate / MODEL_DIR_NAME / "config.json").exists():
            return candidate
    # 都不含模型：回内置目录，让 LlamaFirewall 报出真实的缺失原因，
    # 而不是静默去下载一个我们无权访问的 gated 模型。
    return DEFAULT_HF_HOME


DEFAULT_DENY_THRESHOLD = 0.65
DEFAULT_ASK_THRESHOLD = 0.10
MAX_TEXT_CHARS = 20_000


def _env_float(name: str, default: float) -> float:
    try:
        return float(os.environ.get(name, "") or default)
    except (TypeError, ValueError):
        return default


class DetectorSet:
    """原版 LlamaFirewall 扫描器的封装。单实例、推理串行化。"""

    def __init__(self, deny_threshold: float, ask_threshold: float,
                 hf_home: Path | None = None) -> None:
        home = resolve_hf_home(hf_home)
        # LlamaFirewall 读的是 os.environ["HF_HOME"]，所以这里必须设进环境。
        # 但我们已经用 resolve_hf_home 保证它**确实含模型**，不会触发下载。
        os.environ["HF_HOME"] = str(home)
        os.environ.setdefault("TOKENIZERS_PARALLELISM", "true")

        import lf_compat                                    # noqa: PLC0415  先装垫片
        from llamafirewall import UserMessage               # noqa: PLC0415
        from llamafirewall.scanners import (                # noqa: PLC0415
            HiddenASCIIScanner,
            PromptGuardScanner,
        )

        self._UserMessage = UserMessage
        self.hf_home = home
        self.hf_folder_patched = lf_compat.HF_FOLDER_PATCHED
        self.deny_threshold = deny_threshold
        self.ask_threshold = ask_threshold

        started = time.time()
        # 把 LlamaFirewall 的 block_threshold 设成我们的 deny 阈值，
        # 这样 BLOCK 与 deny 语义一致，ask 区间由我们自己按 score 切。
        self.prompt_guard = PromptGuardScanner(block_threshold=deny_threshold)
        self.hidden_ascii = HiddenASCIIScanner()
        self.load_seconds = round(time.time() - started, 2)
        self._lock = threading.Lock()
        self.calls = 0
        from tokenizers import Tokenizer
        self.offset_tokenizer = Tokenizer.from_file(str(home / MODEL_DIR_NAME / "tokenizer.json"))
        self.offset_tokenizer.no_truncation()
        self.offset_tokenizer.no_padding()

    # -- 打分 -------------------------------------------------------------
    def _scan(self, scanner: Any, text: str) -> Any:
        return asyncio.run(scanner.scan(self._UserMessage(content=text)))

    def review(self, text: str) -> dict[str, Any]:
        value = str(text or "")
        if len(value) > 262144:
            raise ValueError("输入超过完整检测上限，拒绝截断后放行")
        if not value.strip():
            return {"available": True, "decision": "allow", "confidence": None,
                    "model": "Llama-Prompt-Guard-2-86M", "reasons": ["empty_text"],
                    "scanners": []}

        from security.robustness import normalize_hardened
        normalized = normalize_hardened(value)
        encoded = self.offset_tokenizer.encode(normalized, add_special_tokens=False)
        offsets = [pair for pair in encoded.offsets if pair[1] > pair[0]]
        windows = [(offsets[i][0], offsets[min(i + 383, len(offsets) - 1)][1])
                   for i in range(0, len(offsets), 288)] if offsets else [(0, len(normalized))]
        if len(windows) > 128:
            raise ValueError("输入超过完整 token 窗口检测上限")
        with self._lock:
            self.calls += 1
            hidden = self._scan(self.hidden_ascii, value)
            scans = [(start, end, self._scan(self.prompt_guard, normalized[start:end])) for start, end in windows]
            pg = max(scans, key=lambda item: float(item[2].score))[2]

        score = float(pg.score)
        reasons: list[str] = []
        decision = "allow"
        if score >= self.deny_threshold:
            decision = "deny"
            reasons.append(f"promptguard2:malicious={score:.4f}")
        elif score >= self.ask_threshold:
            decision = "ask"
            reasons.append(f"promptguard2:suspicious={score:.4f}")

        # 隐藏 ASCII 走私：命中即强制阻断。它的 block_threshold 默认 1.0，
        # 即「存在标签块字符」就 BLOCK —— 正常文本里不该出现这些码位。
        hidden_hit = str(getattr(hidden.decision, "value", hidden.decision)) == "block"
        if hidden_hit:
            decision = "deny"
            decoded = str(hidden.reason or "").replace("Hidden ASCII: ", "")
            reasons.append(f"hidden_ascii:{decoded[:120]!r}")

        return {
            "available": True,
            "decision": decision,
            "confidence": round(score, 6),
            "model": "Llama-Prompt-Guard-2-86M (via llamafirewall)",
            "reasons": reasons,
            "scanners": [
                {"id": "promptguard2", "decision": str(getattr(pg.decision, "value", pg.decision)),
                 "score": round(score, 6)},
                {"id": "hidden_ascii", "decision": str(getattr(hidden.decision, "value", hidden.decision)),
                 "score": float(hidden.score)},
            ],
            "normalization_changed": normalized != value,
            "window_count": len(windows), "scanned_token_count": len(offsets),
            "window_evidence": [{"start": start, "end": end, "score": round(float(scan.score), 6),
                                 "coordinate_space": "normalized_text_characters"} for start, end, scan in scans],
        }

    def health(self) -> dict[str, Any]:
        return {
            "status": "ok",
            "implementation": "llamafirewall (upstream) + lf_compat shim",
            "model": "Llama-Prompt-Guard-2-86M",
            "hf_home": str(self.hf_home),
            "hf_folder_shim_installed": self.hf_folder_patched,
            "thresholds": {"deny": self.deny_threshold, "ask": self.ask_threshold},
            "scanners": [
                {"id": "promptguard2", "block_threshold": self.prompt_guard.block_threshold},
                {"id": "hidden_ascii", "block_threshold": self.hidden_ascii.block_threshold},
            ],
            "load_seconds": self.load_seconds,
            "calls": self.calls,
        }


def build_handler(detectors: DetectorSet) -> type[BaseHTTPRequestHandler]:
    class Handler(BaseHTTPRequestHandler):
        server_version = "PromptGuardService/2.0"

        def log_message(self, fmt: str, *args: Any) -> None:              # noqa: A003
            return

        def _send(self, status: int, payload: dict[str, Any]) -> None:
            body = json.dumps(payload, ensure_ascii=False).encode("utf-8")
            self.send_response(status)
            self.send_header("Content-Type", "application/json; charset=utf-8")
            self.send_header("Content-Length", str(len(body)))
            self.send_header("Access-Control-Allow-Origin", "*")
            self.send_header("Access-Control-Allow-Headers", "Content-Type")
            self.end_headers()
            self.wfile.write(body)

        def do_GET(self) -> None:                                          # noqa: N802
            if self.path.split("?")[0] in ("/health", "/api/health"):
                self._send(HTTPStatus.OK, detectors.health())
                return
            self._send(HTTPStatus.NOT_FOUND, {"error": "unknown endpoint"})

        def do_POST(self) -> None:                                         # noqa: N802
            if self.path.split("?")[0] not in ("/review", "/api/review"):
                self._send(HTTPStatus.NOT_FOUND, {"error": "unknown endpoint"})
                return
            length = int(self.headers.get("content-length", "0") or 0)
            raw = self.rfile.read(length).decode("utf-8") if length else "{}"
            try:
                body = json.loads(raw or "{}")
            except json.JSONDecodeError as exc:
                self._send(HTTPStatus.BAD_REQUEST, {"error": f"invalid json: {exc}"})
                return
            try:
                result = detectors.review(str(body.get("text", "")))
            except Exception as exc:                                       # noqa: BLE001
                # 出错不伪装成 allow —— 调用方按 fail-closed 处理。
                self._send(HTTPStatus.OK, {
                    "available": False, "decision": "unavailable",
                    "reason": f"{type(exc).__name__}: {exc}", "reasons": [], "scanners": [],
                })
                return
            self._send(HTTPStatus.OK, result)

    return Handler


def main(argv: list[str] | None = None) -> int:
    parser = argparse.ArgumentParser(description="Prompt Guard 2 detection service for AgentDojo Studio")
    parser.add_argument("--host", default=os.environ.get("PROMPTGUARD_HOST", "127.0.0.1"))
    parser.add_argument("--port", type=int, default=int(os.environ.get("PROMPTGUARD_PORT", "8050")))
    parser.add_argument("--hf-home", type=Path, default=None,
                        help="含 meta-llama--Llama-Prompt-Guard-2-86M 的目录；"
                             "默认自动探测项目内置模型")
    parser.add_argument("--deny-threshold", type=float,
                        default=_env_float("PROMPTGUARD_DENY_THRESHOLD", DEFAULT_DENY_THRESHOLD))
    parser.add_argument("--ask-threshold", type=float,
                        default=_env_float("PROMPTGUARD_ASK_THRESHOLD", DEFAULT_ASK_THRESHOLD))
    args = parser.parse_args(argv)

    print(f"[promptguard] 加载原版 LlamaFirewall 扫描器（HF_HOME={resolve_hf_home(args.hf_home)}）", flush=True)
    detectors = DetectorSet(args.deny_threshold, args.ask_threshold, args.hf_home)
    health = detectors.health()
    print("[promptguard] 就绪：%s  deny=%s ask=%s 加载 %.2fs"
          % (health["implementation"], args.deny_threshold, args.ask_threshold,
             health["load_seconds"]), flush=True)
    server = ThreadingHTTPServer((args.host, args.port), build_handler(detectors))
    print(f"[promptguard] 监听 http://{args.host}:{args.port}  GET /health  POST /review", flush=True)
    try:
        server.serve_forever()
    except KeyboardInterrupt:
        print("[promptguard] 停止", flush=True)
    finally:
        server.server_close()
    return 0


if __name__ == "__main__":
    sys.exit(main())
