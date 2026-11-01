"""Canonical dangerous-command checks shared by policy and execution boundary."""
import re
from .robustness import normalize_hardened


def dangerous(command):
    text = normalize_hardened(str(command)).casefold()
    compact = re.sub(r"[\s\"'`]+", "", text)
    patterns = (r"base64", r"frombase64string", r"-enc(?:odedcommand)?\b", r"\|\s*(?:ba)?sh",
                r"(?:curl|wget|invoke-webrequest|iwr|downloadstring|urlopen|requests\.get).*(?:https?:|exec\(|iex|;|&&)",
                r"(?:eval|exec)\s*\(.*(?:decode|bytes|chr|http)", r"certutil.*-decode", r"xxd.*-r.*\|",
                r"(?:sh|bash|cmd|powershell|pwsh)\s+(?:-c|/c).*(?:http|base64)")
    return any(re.search(p, text) for p in patterns) or any(p in compact for p in
        ("curlhttp", "wgethttp", "downloadstring(", "frombase64string(", "exec(bytes.fromhex(", "|iex"))
