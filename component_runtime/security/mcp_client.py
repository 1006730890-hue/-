"""Lightweight host adapter; protocol is owned by the real MCP proxy."""
import json
import os
import urllib.request


def request(path, payload=None, timeout=90):
    url = os.environ.get("MCP_PROXY_URL", "http://127.0.0.1:8060") + path
    req = urllib.request.Request(url, data=None if payload is None else json.dumps(payload, ensure_ascii=False).encode(),
                                 headers={"Content-Type": "application/json"})
    with urllib.request.build_opener(urllib.request.ProxyHandler({})).open(req, timeout=timeout) as response:
        return json.load(response)


def catalogue():
    try:
        return request("/catalogue")["tools"]
    except Exception:
        return []  # No MCP tools are mounted on failure; invocation cannot fall back.


def invoke(name, arguments):
    return request("/invoke", {"name": name, "arguments": arguments})
