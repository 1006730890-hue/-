"""Side-effect-free MCP catalog and result proxy for competition tests."""
from __future__ import annotations

import re
from dataclasses import dataclass
from typing import Any, Mapping

from .provenance_graph import ProvenanceGraph


@dataclass(frozen=True)
class MCPTool:
    name: str
    description: str
    server_id: str
    parameters: Mapping[str, Any]


class MCPProxy:
    """Scan descriptions/results and emit auditable graph nodes without calling a server."""

    _instruction = re.compile(
        r"(?i)(ignore\s+(?:all\s+)?previous|system\s+prompt|send.{0,40}secret|"
        r"run.{0,40}command|disable.{0,40}security|忽略.{0,12}(?:指令|规则|安全)|"
        r"无视.{0,12}(?:指令|规则|安全)|绕过.{0,12}安全|向.{0,32}(?:发送|外发).{0,24}(?:密钥|凭据|秘密))"
    )

    def __init__(self) -> None:
        self.graph = ProvenanceGraph()

    def register(self, tool: MCPTool) -> dict[str, Any]:
        node_id = f"mcp:{tool.server_id}:{tool.name}"
        poisoned = bool(self._instruction.search(tool.description))
        server_id = f"mcp-server:{tool.server_id}"
        self.graph.add_node(server_id, "mcp_server", tool.server_id, trust="trusted", classification="catalog")
        self.graph.add_node(node_id, "mcp_tool", tool.name,
                           trust="untrusted" if poisoned else "trusted",
                           classification="tool_description", server_id=tool.server_id,
                           poisoned=poisoned, description_sha256=__import__("hashlib").sha256(
                               tool.description.encode("utf-8")).hexdigest())
        self.graph.link(server_id, node_id, "registers")
        return {"tool": tool.name, "server_id": tool.server_id, "poisoned": poisoned,
                "decision": "deny" if poisoned else "allow",
                "reason": "mcp_tool_description_injection" if poisoned else None,
                "node_id": node_id}

    def inspect_result(self, tool: MCPTool, result: Any, *, call_id: str) -> dict[str, Any]:
        source_id = f"mcp-result:{call_id}"
        tool_id = f"mcp-call:{call_id}"
        self.graph.add_node(source_id, "mcp_result", tool.name, trust="untrusted",
                           classification="tool_result", value_preview=str(result)[:160])
        self.graph.add_node(tool_id, "tool_call", tool.name, server_id=tool.server_id)
        catalog_id = f"mcp:{tool.server_id}:{tool.name}"
        if catalog_id in self.graph.nodes:
            self.graph.link(catalog_id, source_id, "describes_result")
        server_id = f"mcp-server:{tool.server_id}"
        if server_id not in self.graph.nodes:
            self.graph.add_node(server_id, "mcp_server", tool.server_id, trust="trusted", classification="catalog")
        proxy_id = f"mcp-proxy:{call_id}"
        self.graph.add_node(proxy_id, "mcp_proxy", "MCP 中间代理", trust="trusted",
                           classification="tool_boundary", call_id=call_id)
        agent_id = f"agent:main:{call_id}"
        policy_id = f"policy:{call_id}"
        self.graph.add_node(agent_id, "agent", "main_agent", trust="trusted", classification="execution")
        self.graph.add_node(policy_id, "policy", "security_policy", trust="trusted", classification="decision")
        self.graph.link(server_id, proxy_id, "routed_through")
        self.graph.link(proxy_id, source_id, "screens_result")
        self.graph.link(source_id, agent_id, "read_by")
        self.graph.link(agent_id, policy_id, "evaluated_by")
        self.graph.link(policy_id, tool_id, "controls")
        self.graph.link(source_id, tool_id, "flows_to")
        suspicious = bool(self._instruction.search(str(result)))
        return {"call_id": call_id, "tool": tool.name, "decision": "deny" if suspicious else "allow",
                "suspicious": suspicious, "reason": "mcp_result_injection" if suspicious else None,
                "transport": "local_proxy_only", "graph": self.graph.to_dict()}
