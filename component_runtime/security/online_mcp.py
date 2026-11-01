"""Online MCP proxy: configured peers, SDK discovery, real inspection and calls."""
from __future__ import annotations
import asyncio
import hashlib
import json
import os
import threading
import time
import urllib.request
import uuid
from .mcp_transport import exchange
from .mcp_proxy import MCPProxy, MCPTool
from .provenance_graph import ProvenanceGraph

SERVERS = {"workspace": "http://127.0.0.1:8062/mcp",
           "documents": "http://127.0.0.1:8065/mcp"}
# Permissions belong to the operator, never to untrusted annotations/descriptions.
READ_TOOLS = {"list_files", "read_document"}


def review(text: str) -> dict:
    req = urllib.request.Request(os.environ.get("PROMPTGUARD_URL", "http://127.0.0.1:8050") + "/review",
        data=json.dumps({"text": text}, ensure_ascii=False).encode(),
        headers={"Content-Type": "application/json"})
    with urllib.request.build_opener(urllib.request.ProxyHandler({})).open(req, timeout=20) as response:
        verdict = json.load(response)
    if not verdict.get("available") or verdict.get("decision") == "unavailable":
        raise RuntimeError("MCP 边界所需的 Prompt Guard 不可用")
    return verdict


class OnlineMCP:
    def __init__(self):
        self.lock = threading.RLock()
        self.bindings = {}
        self.rejected = []
        self.errors = {}
        self.updated = 0.0

    def catalogue(self, refresh=False):
        with self.lock:
            if refresh or time.monotonic() - self.updated > 30:
                bindings, rejected, errors = {}, [], {}
                for server, url in SERVERS.items():
                    try:
                        envelope = asyncio.run(exchange(url))
                        for item in envelope["result"].get("tools", []):
                            tool = MCPTool(item["name"], item.get("description", ""), server, item["inputSchema"])
                            verdict = review(tool.description)
                            rule = MCPProxy().register(tool)
                            allowed = (tool.name in READ_TOOLS and verdict["decision"] == "allow"
                                       and rule["decision"] == "allow")
                            row = {"name": f"mcp.{server}.{tool.name}", "server_id": server,
                                   "remote_name": tool.name, "description": tool.description,
                                   "input_schema": dict(tool.parameters),
                                   "output_schema":item.get("outputSchema") or (
                                       {"type":"object","properties":{"files":{"type":"array","items":{"type":"string"}}}}
                                       if tool.name == "list_files" else
                                       {"type":"object","properties":{"path":{"type":"string"},"content":{"type":"string"},
                                           "source_type":{"type":"string"},"server_id":{"type":"string"}}}
                                       if tool.name == "read_document" else {}),
                                   "registered": allowed, "detector": verdict,
                                   "source_type": "mcp_tool_description", "initialize": envelope["initialize"]}
                            row["description_sha256"] = hashlib.sha256(tool.description.encode()).hexdigest()
                            if allowed:
                                bindings[row["name"]] = row
                            else:
                                rejected.append(row)
                    except Exception as exc:
                        errors[server] = f"{type(exc).__name__}: {exc}"
                self.bindings, self.rejected, self.errors = bindings, rejected, errors
                self.updated = time.monotonic()
            return {"tools": list(self.bindings.values()), "rejected": self.rejected,
                    "errors": self.errors, "transport": "official_sdk_streamable_http",
                    "available": bool(self.bindings)}

    def call(self, name, arguments, *, call_id=""):
        catalogue = self.catalogue()
        binding = next((r for r in catalogue["tools"] if r["name"] == name), None)
        if binding is None:
            raise ValueError("工具尚未通过标准 MCP 发现和描述安全检查")
        description_verdict = review(binding["description"])
        if description_verdict.get("decision") != "allow":
            raise ValueError("执行前工具描述复核未通过，未向 MCP server 转发")
        from .component_client import RemoteArgScanner
        scanned = RemoteArgScanner().scan(name, arguments)
        if not scanned.available or scanned.decision != "allow":
            raise ValueError("MCP 参数扫描未通过，未向服务转发")
        envelope = asyncio.run(exchange(SERVERS[binding["server_id"]], binding["remote_name"], arguments))
        raw = envelope["result"]
        if raw.get("isError"):
            raise RuntimeError("MCP server 工具实际执行失败：" + json.dumps(raw, ensure_ascii=False)[:500])
        text = json.dumps(raw, ensure_ascii=False)
        verdict = review(text)
        tool = MCPTool(binding["remote_name"], binding["description"], binding["server_id"], binding["input_schema"])
        suspicious = verdict["decision"] != "allow" or MCPProxy().inspect_result(tool, raw, call_id="check")["suspicious"]
        cid = call_id or uuid.uuid4().hex
        graph = ProvenanceGraph()
        proxy = graph.add_node(f"mcp-proxy:{cid}", "mcp_proxy", "MCP 安全中间代理", transport="streamable-http")
        server = graph.add_node(f"mcp-server:{cid}", "mcp_server", binding["server_id"], endpoint=SERVERS[binding["server_id"]])
        call = graph.add_node(f"mcp-call:{cid}", "tool_call", name, arguments=arguments, executed=True)
        source = graph.add_node(f"mcp-result:{cid}", "source", "MCP 原始返回", trust="untrusted",
            source_type="mcp_tool_result", result=raw, content_hash=hashlib.sha256(text.encode()).hexdigest())
        gate = graph.add_node(f"mcp-isolation:{cid}", "isolation", "Prompt Guard 返回检查",
            quarantined=suspicious, detector=verdict)
        description = graph.add_node(f"mcp-description:{cid}", "source", "MCP 工具注册描述", trust="untrusted",
            source_type="mcp_tool_description", content=binding["description"], content_hash=binding["description_sha256"],
            detector=description_verdict, server_id=binding["server_id"])
        graph.link(description, proxy, "screened_before_registration_and_call")
        graph.link(proxy, call, "forwards"); graph.link(call, server, "invokes")
        graph.link(server, source, "returns"); graph.link(source, gate, "screened_by")
        # Normalize the MCP envelope into the result described by output_schema;
        # retain the untouched protocol message separately for auditing.
        content = raw.get("structuredContent")
        if content is None:
            text_blocks = [block["text"] for block in raw.get("content", []) if block.get("type") == "text"]
            combined = "\n".join(text_blocks)
            try:
                content = json.loads(combined)
            except (TypeError, ValueError):
                content = {"text":combined}
        return {"name": name, "server_id": binding["server_id"], "decision": "quarantine" if suspicious else "allow",
                "content": "" if suspicious else content, "raw_result": raw, "quarantined": suspicious,
                "detector": verdict, "graph": graph.to_dict(), "protocol": "MCP",
                "transport": "official_sdk_streamable_http", "initialize": envelope["initialize"]}
