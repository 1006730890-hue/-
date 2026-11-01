"""Standard MCP initialization/discovery/call through the official SDK."""
from __future__ import annotations
from mcp import ClientSession
from mcp.client.streamable_http import streamable_http_client


async def exchange(url: str, name: str | None = None, arguments: dict | None = None) -> dict:
    async with streamable_http_client(url) as streams:
        async with ClientSession(streams[0], streams[1], read_timeout_seconds=20) as session:
            initialized = await session.initialize()
            result = await session.list_tools() if name is None else await session.call_tool(name, arguments or {})
            return {"initialize": initialized.model_dump(mode="json", by_alias=True),
                    "result": result.model_dump(mode="json", by_alias=True)}
