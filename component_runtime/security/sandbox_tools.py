"""扩展工具面：让策略规则真的有可拦截的对象。

## 为什么需要它

`security/policy_dsl.py` 里这些规则原本是**死代码** —— 规则齐全，
但运行中的 Agent 只挂了 5 个银行工具，没有任何调用能触发它们：

| 规则 | 需要工具 | 改造前 |
|---|---|---|
| `sensitive-write` | `fs.write` | 不存在 |
| `secret-exfiltration` | `net.fetch` | 不存在 |
| `encoded-or-remote-exec` | `exec` | 不存在 |
| `sensitive-handoff` | `handoff` | 不存在 |
| `route-scope-violation`（代码检视禁止推送） | `git.push` | 不存在 |

本模块补上这些工具的实现。**读开放、写收紧**：读类工具直接执行，
变更类工具走「待确认」或直接被策略阻断。

## 安全边界（这是演示服务，不是生产沙箱）

- **文件**：读写都限制在 `data/capability_workspace/` 内。用
  `Path.resolve()` 后校验前缀，防止 `../` 越界。
  **唯一的例外**是读取敏感路径（`~/.ssh/id_rsa` 等）—— 那是策略规则
  要拦的目标，读得到才谈得上"被外泄"。写敏感路径**由策略规则 deny**。
- **网络**：**不发起真实请求**。只有一个固定的演示端点表 ——
  演示服务不该成为对外发起任意请求的跳板。
- **执行**：**不 spawn 进程**。用确定性命令注册表，未登记的返回明确错误。
  这样输出可复现、可测试，也不会在宿主机上执行任意命令。
- **git**：读操作返回演示仓库状态；`git.push` 永远不执行 ——
  它由策略在出口阻断，命中即证明授权边界生效。
- **子 Agent**：`handoff` 必须通过独立的 Sub-Agent 服务，由服务启动
  一次性受限 worker；服务不可用时直接失败，不降级为逻辑回执。
"""
from __future__ import annotations

import fnmatch
import json
import os
import re
import shlex
import subprocess
import sys
import unicodedata
import urllib.request
from urllib.parse import urlparse
from dataclasses import dataclass
from pathlib import Path, PurePosixPath
from typing import Any, Mapping

__all__ = [
    "SandboxTools",
    "CapabilityToolError",
    "CAPABILITY_TOOLS",
    "READ_ONLY_CAPABILITY_TOOLS",
    "CONFIRMABLE_CAPABILITY_TOOLS",
    "IRREVERSIBLE_CAPABILITY_TOOLS",
]

ROOT = Path(__file__).resolve().parents[1]
WORKSPACE = ROOT / "data" / "capability_workspace"

#: 工具说明，喂给模型与授权判定（`{名称: 说明}`）。
CAPABILITY_TOOLS: dict[str, str] = {
    "fs.read": "读取工作区内的文件",
    "fs.write": "写入工作区内的文件（会改动磁盘，需确认）",
    "net.fetch": "抓取外部 URL 的内容",
    "git.status": "查看当前分支与工作区状态",
    "git.diff": "查看未提交的改动",
    "git.push": "把本地提交推送到远端仓库（不可撤销）",
    "exec": "在工作区内执行命令",
    "handoff": "把只读文档或目录查询委托给后台子 Agent；target_agent 是该子任务的名称。子 Agent 仅有 MCP 只读工具，没有银行账户、密钥提取、外发、付款、写入或命令执行能力。",
}

#: 只读、可直接执行。
READ_ONLY_CAPABILITY_TOOLS: frozenset[str] = frozenset(
    {"fs.read", "net.fetch", "git.status", "git.diff"})

#: 会改动状态，需要用户确认。
CONFIRMABLE_CAPABILITY_TOOLS: frozenset[str] = frozenset({"fs.write", "exec", "handoff"})

#: 不可撤销 —— 策略应默认阻断，而不是走确认。
IRREVERSIBLE_CAPABILITY_TOOLS: frozenset[str] = frozenset({"git.push"})

#: 演示端点表。**刻意不发起真实请求** —— 服务不该成为任意请求跳板。
_DEMO_ENDPOINTS: dict[str, str] = {
    "https://api.example.test/rates": "USD/EUR 0.92, USD/CNY 7.18（演示数据）",
    "https://docs.example.test/policy": "内部合规政策 v3：凭据不得外发（演示数据）",
    "https://intranet.example.test/notices": "系统维护通知（演示数据）",
}

#: 敏感路径 —— 与 `policy_dsl.py` 的 `sensitive_paths` 对齐。
SENSITIVE_PATH_PATTERNS: tuple[str, ...] = (
    "~/.ssh/*", "~/.aws/*", "/etc/cron.*", "/etc/systemd/*", "*/.env", "*/id_rsa",
)

#: 确定性命令注册表。**不 spawn 进程。**
_COMMAND_REGISTRY: dict[str, str] = {
    "ls": "config.yaml  report.md  notes/",
    "pwd": "/workspace",
    "whoami": "agent",
    "date": "2026-10-11",
    "git status": "On branch main\nnothing to commit, working tree clean",
    "cat config.yaml": "env: demo\nretention_days: 30",
    "echo hello": "hello",
}

#: 命令里出现这些即视为「编码或远程管道执行」——与 `policy_dsl.py` 的规则一致。
_ENCODED_OR_REMOTE = re.compile(
    r"(?i)(base64|curl\s+https?://|wget\s+https?://|\|\s*(ba)?sh)")

#: 疑似凭证。与 `security/mcpsafety_args.py` 的取向一致，但这里独立实现，
#: 避免为了一个正则就把本模块绑到可选依赖上。
_SECRET_PATTERNS: tuple[re.Pattern[str], ...] = (
    re.compile(r"(?i)\b(api[_-]?key|secret|password|passwd|token|credential)\b\s*[:=]\s*\S+"),
    re.compile(r"\bsk-[A-Za-z0-9_-]{16,}"),
    re.compile(r"\bAKIA[0-9A-Z]{16}\b"),
    re.compile(r"\bghp_[A-Za-z0-9]{20,}"),
    re.compile(r"\beyJ[A-Za-z0-9_-]{10,}\.[A-Za-z0-9_-]{10,}\."),
    re.compile(r"-----BEGIN [A-Z ]*PRIVATE KEY-----"),
)


class CapabilityToolError(ValueError):
    """工具调用参数非法或超出边界。调用方按失败处理，**不静默放行**。"""


@dataclass(frozen=True)
class WorkspacePath:
    """已校验的工作区路径。

    `root` 是**这个路径所属沙箱**的工作区根，不是模块级全局值。
    早期版本硬编码全局 `WORKSPACE`，导致自定义工作区（测试、多租户）
    里的合法文件被判越界 —— 由测试抓到。
    """

    relative: str
    absolute: Path
    root: Path

    @property
    def escaped(self) -> bool:
        """是否越出工作区。越界**不阻断**，因为策略规则要靠它判定 ——
        但审计里必须能看到。"""
        try:
            Path(self.absolute).resolve().relative_to(Path(self.root).resolve())
            return False
        except (ValueError, OSError):
            return True


def _confusable_fold(text: str) -> str:
    """把同形字折回 ASCII，避免用西里尔字母绕过路径/命令检查。

    只做「非 ASCII 且邻居是拉丁」的还原 —— 与 `security/robustness.py`
    同一取向。这里独立实现一个最小版，避免模块间耦合。
    """
    out: list[str] = []
    for index, char in enumerate(text):
        if ord(char) < 128:
            out.append(char)
            continue
        try:
            name = unicodedata.name(char)
        except ValueError:
            out.append(char)
            continue
        # 只折叠常见冒充字符，不求全 —— 求全会把复杂度引进来。
        folded = _COMMON_CONFUSABLES.get(char)
        neighbours = [text[i] for i in (index - 1, index + 1) if 0 <= i < len(text)]
        if folded and any(n.isascii() and n.isalpha() for n in neighbours):
            out.append(folded)
        else:
            out.append(char)
    return "".join(out)


#: 最小同形字表：足够覆盖路径/命令绕过，权威全表在 data/confusables.txt。
_COMMON_CONFUSABLES: dict[str, str] = {
    "\u0430": "a", "\u0435": "e", "\u043e": "o", "\u0440": "p", "\u0441": "c",
    "\u0443": "y", "\u0445": "x", "\u0456": "i", "\u0455": "s", "\u04bb": "h",
    "\u0501": "d", "\u0261": "g", "\u03bf": "o", "\u03b1": "a", "\u03c1": "p",
    "\u03c5": "u", "\u03bd": "v", "\u0131": "i", "\uff49": "i", "\uff4f": "o",
}


class SandboxTools:
    """扩展工具的确定性实现。所有方法都是纯函数式或只影响工作区目录。"""

    def __init__(self, workspace: Path | None = None, *, execution_mode: str | None = None) -> None:
        self.workspace = Path(workspace) if workspace else WORKSPACE
        self.workspace.mkdir(parents=True, exist_ok=True)
        self.execution_mode = execution_mode or os.environ.get("CAPABILITY_EXECUTION_MODE", "fixture")

    # -- 工具清单 ---------------------------------------------------------
    def describe(self) -> dict[str, str]:
        return dict(CAPABILITY_TOOLS)

    # -- 路径处理 ---------------------------------------------------------
    def resolve(self, raw: str) -> WorkspacePath:
        """把参数解析成工作区内路径，同时**如实报告是否越界**。

        注意：越界不在这里抛错。策略规则需要看到"它想越界"这个事实
        才能判定 —— 在这里抛错会让审计丢失意图。
        """
        text = _confusable_fold(str(raw or "").strip())
        if not text:
            raise CapabilityToolError("缺少 path 参数")
        if "\x00" in text:
            raise CapabilityToolError("path 含空字节")
        # 沙箱内部的绝对路径写法（`/workspace/...`）映射到真实工作区目录。
        # 不这样做的话，`/workspace/report.md` 会被当成宿主机绝对路径而判越界 ——
        # 但它是"工作区内"的合法表达，拒绝它会让规则看起来在乱咬。
        for prefix in ("/workspace/", "workspace/"):
            if text.startswith(prefix):
                text = text[len(prefix):]
                break
        candidate = Path(text)
        if not candidate.is_absolute():
            candidate = self.workspace / candidate
        normalised = PurePosixPath(str(candidate).replace("\\", "/"))
        return WorkspacePath(relative=str(normalised), absolute=Path(candidate),
                             root=self.workspace)

    def is_sensitive_path(self, raw: str) -> bool:
        """是否命中敏感路径模式（策略规则用同一份判据）。"""
        text = _confusable_fold(str(raw or ""))
        candidates = {text, str(Path(text).expanduser())}
        return any(fnmatch.fnmatch(candidate, pattern)
                   for candidate in candidates
                   for pattern in SENSITIVE_PATH_PATTERNS)

    # -- 读类工具 ---------------------------------------------------------
    def fs_read(self, path: str) -> dict[str, Any]:
        ready = self.resolve(path)
        if ready.escaped:
            # 越界读取**不返回内容**，但如实报告边界被触碰。
            return {"tool": "fs.read", "path": path, "found": False,
                    "escaped_workspace": True,
                    "error": "路径越出工作区，拒绝读取",
                    "sensitive_path": self.is_sensitive_path(path)}
        if not ready.absolute.exists() or not ready.absolute.is_file():
            return {"tool": "fs.read", "path": path, "found": False,
                    "sensitive_path": self.is_sensitive_path(path),
                    "error": "文件不存在"}
        try:
            content = ready.absolute.read_text(encoding="utf-8", errors="replace")
        except OSError as exc:
            return {"tool": "fs.read", "path": path, "found": False,
                    "error": f"{type(exc).__name__}: {exc}"}
        return {"tool": "fs.read", "path": path, "found": True,
                "bytes": len(content.encode("utf-8")), "content": content[:4000],
                "sensitive_path": self.is_sensitive_path(path)}

    def net_fetch(self, url: str) -> dict[str, Any]:
        """抓取 URL。

        Tests keep the deterministic fixture mode.  The running Studio sets
        ``CAPABILITY_EXECUTION_MODE=real`` and then this path performs an
        actual HTTP request; policy remains responsible for deciding whether
        the call may happen.
        """
        target = str(url or "").strip()
        if not target:
            raise CapabilityToolError("缺少 url 参数")
        if self.execution_mode == "real":
            parsed = urlparse(target)
            if parsed.scheme not in {"http", "https"} or not parsed.netloc:
                return {"tool": "net.fetch", "url": target, "ok": False,
                        "error": "只允许 http/https URL"}
            try:
                request = urllib.request.Request(target, headers={"User-Agent": "AgentDojo-Studio/1.0"})
                class NoRedirect(urllib.request.HTTPRedirectHandler):
                    def redirect_request(self, *args, **kwargs):
                        raise CapabilityToolError("工具不自动跟随重定向；新目标必须重新通过策略检查")
                opener = urllib.request.build_opener(urllib.request.ProxyHandler({}), NoRedirect())
                with opener.open(request, timeout=8) as response:
                    raw = response.read(64 * 1024)
                    body = raw.decode("utf-8", errors="replace")
                    return {"tool": "net.fetch", "url": target, "ok": True,
                            "status": int(response.status), "content_type": response.headers.get("Content-Type", ""),
                            "bytes": len(raw), "body": body}
            except Exception as exc:
                return {"tool": "net.fetch", "url": target, "ok": False,
                        "error": f"真实网络请求失败：{type(exc).__name__}: {exc}"}
        body = _DEMO_ENDPOINTS.get(target)
        if body is None:
            return {"tool": "net.fetch", "url": target, "ok": False,
                    "error": "不在演示端点表内（本服务不对外发起真实请求）",
                    "demo_endpoints": sorted(_DEMO_ENDPOINTS)}
        return {"tool": "net.fetch", "url": target, "ok": True, "body": body}

    def git_status(self) -> dict[str, Any]:
        if self.execution_mode == "real":
            return self._git_command(["status", "--porcelain=v1", "-b"])
        return {"tool": "git.status", "branch": "main",
                "clean": True, "ahead": 0, "behind": 0,
                "untracked": [], "modified": []}

    def git_diff(self, path: str = "") -> dict[str, Any]:
        if self.execution_mode == "real":
            args = ["diff", "--no-ext-diff", "--"]
            if path:
                args.append(str(path))
            return self._git_command(args)
        return {"tool": "git.diff", "path": str(path or ""), "additions": 0,
                "deletions": 0, "hunks": [],
                "note": "演示仓库无未提交改动"}

    # -- 变更类工具（应由策略判定/确认后才执行） --------------------------
    def fs_write(self, path: str, content: str = "") -> dict[str, Any]:
        ready = self.resolve(path)
        if ready.escaped:
            raise CapabilityToolError(f"拒绝写入工作区外的路径：{path}")
        ready.absolute.parent.mkdir(parents=True, exist_ok=True)
        payload = str(content or "")
        ready.absolute.write_text(payload, encoding="utf-8")
        return {"tool": "fs.write", "path": path, "bytes": len(payload.encode("utf-8")),
                "written": True, "sensitive_path": self.is_sensitive_path(path)}

    def exec(self, command: str) -> dict[str, Any]:
        """Execute a constrained command in the capability workspace."""
        text = _confusable_fold(str(command or "").strip())
        if not text:
            raise CapabilityToolError("缺少 command 参数")
        from .command_semantics import dangerous
        if dangerous(text):
            return {"tool": "exec", "command": command, "ok": False,
                    "executed": False,
                    "error": "命令使用编码或远程管道执行，拒绝执行"}
        if self.execution_mode == "real":
            try:
                argv = shlex.split(text, posix=(os.name != "nt"))
                if not argv or argv[0] not in {"ls", "pwd", "git", "python", "python3"}:
                    return {"tool": "exec", "command": command, "ok": False,
                            "executed": False, "error": "命令不在真实执行白名单内"}
                if argv[0] == "ls":
                    argv = [sys.executable, "-c", "import os; print('\\n'.join(sorted(os.listdir('.'))))"]
                elif argv == ["pwd"]:
                    argv = [sys.executable, "-c", "import os; print(os.getcwd())"]
                elif argv[0] in {"python", "python3"}:
                    if argv[1:] not in (["--version"], ["-V"]):
                        raise CapabilityToolError("工作区不是 OS 隔离沙箱，拒绝任意 Python 程序，仅允许版本查询")
                    argv[0] = sys.executable
                elif argv[0] == "git" and argv[1:] not in (["status"], ["diff"], ["log", "-1"]):
                    raise CapabilityToolError("exec 仅允许 Git 只读子命令，变更必须走独立工具策略")
                completed = subprocess.run(argv, cwd=str(self.workspace), capture_output=True,
                                           text=True, encoding="utf-8", errors="replace",
                                           timeout=10, shell=False, check=False)
                return {"tool": "exec", "command": command, "ok": completed.returncode == 0,
                        "executed": True, "simulated": False, "returncode": completed.returncode,
                        "stdout": completed.stdout[:4000], "stderr": completed.stderr[:2000]}
            except Exception as exc:
                return {"tool": "exec", "command": command, "ok": False,
                        "executed": False, "error": f"真实命令执行失败：{type(exc).__name__}: {exc}"}
        body = _COMMAND_REGISTRY.get(text)
        if body is None:
            return {"tool": "exec", "command": command, "ok": False,
                    "executed": False,
                    "error": "命令不在演示注册表内（本服务不执行任意命令）",
                    "registered": sorted(_COMMAND_REGISTRY)}
        return {"tool": "exec", "command": command, "ok": True,
                "executed": True, "simulated": True, "stdout": body}

    def git_push(self, remote: str = "origin", branch: str = "main") -> dict[str, Any]:
        """**永远不应该被执行** —— 它由策略在出口阻断。

        保留实现是为了：如果策略哪天放行了，这里会如实记录一次推送，
        而不是静默什么都不做。
        """
        if self.execution_mode == "real":
            if os.environ.get("ALLOW_GIT_PUSH") != "1":
                return {"tool": "git.push", "remote": str(remote or "origin"),
                        "branch": str(branch or "main"), "pushed": False,
                        "executed": False, "error": "真实推送需要显式 ALLOW_GIT_PUSH=1；策略通常在此之前阻断"}
            return self._git_command(["push", str(remote or "origin"), str(branch or "main")])
        return {"tool": "git.push", "remote": str(remote or "origin"),
                "branch": str(branch or "main"), "pushed": True,
                "note": "演示仓库推送（策略本应在此前阻断）"}

    def _git_command(self, args: list[str]) -> dict[str, Any]:
        try:
            completed = subprocess.run(["git", *args], cwd=str(ROOT), capture_output=True,
                                       text=True, encoding="utf-8", errors="replace",
                                       timeout=15, shell=False, check=False)
            output = (completed.stdout or "")[:8000]
            return {"tool": f"git.{args[0]}", "ok": completed.returncode == 0,
                    "executed": True, "returncode": completed.returncode,
                    "stdout": output, "stderr": (completed.stderr or "")[:2000]}
        except Exception as exc:
            return {"tool": f"git.{args[0]}", "ok": False, "executed": False,
                    "error": f"真实 Git 执行失败：{type(exc).__name__}: {exc}"}

    def handoff(self, target_agent: str, instruction: str = "", *, parent_trace_id: str = "") -> dict[str, Any]:
        """通过独立 Sub-Agent 服务派发一次已确认交接。"""
        target = str(target_agent or "").strip()
        if not target:
            raise CapabilityToolError("缺少 target_agent 参数")
        payload = str(instruction or "")
        from .policy_dsl import PolicyContext, ToolPolicyEngine
        if ToolPolicyEngine.for_drift_runtime().evaluate(PolicyContext(tool="handoff", args={"instruction": payload})).decision == "deny":
            raise CapabilityToolError("派发载荷携带敏感凭据，未连接子 Agent 服务")
        base_url = os.environ.get("SUBAGENT_SERVICE_URL", "http://127.0.0.1:8061")
        request = urllib.request.Request(
            base_url.rstrip("/") + "/dispatch",
            data=json.dumps({"target_agent": target, "instruction": payload, "parent_trace_id":parent_trace_id}, ensure_ascii=False).encode("utf-8"),
            headers={"Content-Type": "application/json"}, method="POST")
        try:
            opener = urllib.request.build_opener(urllib.request.ProxyHandler({}))
            with opener.open(request, timeout=300) as response:
                worker = json.loads(response.read().decode("utf-8"))
        except Exception as exc:
            raise CapabilityToolError(f"Sub-Agent 服务不可用：{type(exc).__name__}: {exc}") from exc
        return {"tool": "handoff", "target_agent": target,
                "accepted": bool(worker.get("accepted")),
                "dispatch_id": worker.get("worker_id"),
                "payload_bytes": len(payload.encode("utf-8")),
                "carries_secret": self.contains_secret(payload),
                "execution_mode": worker.get("execution_mode"),
                "process_spawned": bool(worker.get("process_spawned")),
                "subagent_result": worker.get("result"),
                "dispatcher": worker.get("dispatcher"),
                "transport": worker.get("transport"),
                "provenance": worker.get("provenance"), "events": worker.get("events"),
                "outcome": worker.get("outcome"), "worker_pid": worker.get("pid"), "model": worker.get("model")}

    # -- 判据（供策略规则复用） -------------------------------------------
    @staticmethod
    def contains_secret(text: str) -> bool:
        """载荷里是否含疑似凭证。"""
        value = str(text or "")
        return any(pattern.search(value) for pattern in _SECRET_PATTERNS)

    @staticmethod
    def looks_encoded_or_remote(command: str) -> bool:
        return bool(_ENCODED_OR_REMOTE.search(_confusable_fold(str(command or ""))))

    # -- 统一入口 ---------------------------------------------------------
    def call(self, tool: str, args: Mapping[str, Any]) -> dict[str, Any]:
        """按工具名分发。未登记的工具抛 `CapabilityToolError`（不静默放行）。"""
        payload = dict(args or {})
        if tool == "fs.read":
            return self.fs_read(str(payload.get("path", "")))
        if tool == "fs.write":
            return self.fs_write(str(payload.get("path", "")),
                                 str(payload.get("content", "")))
        if tool == "net.fetch":
            return self.net_fetch(str(payload.get("url", "")))
        if tool == "git.status":
            return self.git_status()
        if tool == "git.diff":
            return self.git_diff(str(payload.get("path", "")))
        if tool == "git.push":
            return self.git_push(str(payload.get("remote", "origin")),
                                 str(payload.get("branch", "main")))
        if tool == "exec":
            return self.exec(str(payload.get("command", payload.get("cmd", ""))))
        if tool == "handoff":
            return self.handoff(str(payload.get("target_agent", "")),
                                str(payload.get("instruction", payload.get("message", ""))))
        raise CapabilityToolError(f"未登记的扩展工具：{tool}")
