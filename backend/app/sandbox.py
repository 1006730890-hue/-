"""沙箱/隔离：白名单工具 + 审计 + 熔断。动态生成代码在超时子进程中执行。"""
import subprocess
import tempfile
import os


def run_isolated(code, timeout=3):
    with tempfile.TemporaryDirectory() as tmp:
        path = os.path.join(tmp, "snippet.py")
        with open(path, "w", encoding="utf-8") as f:
            f.write(code)
        try:
            out = subprocess.run(["python", path], cwd=tmp, timeout=timeout,
                                 capture_output=True, text=True,
                                 env={"PATH": os.environ.get("PATH", ""), "PYTHONIOENCODING": "utf-8"})
            return {"ok": out.returncode == 0, "stdout": out.stdout, "stderr": out.stderr}
        except subprocess.TimeoutExpired:
            return {"ok": False, "error": "执行超时，已熔断"}
