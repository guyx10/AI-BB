# src/tools/mcp_integration.py
import asyncio
from mcp import ClientSession, StdioServerParameters
from mcp.client.stdio import stdio_client

class MCPIntegration:
    async def connect_to_villager(self):
        """Connect to Villager MCP server for Kali tools"""
        server_params = StdioServerParameters(
            command="python",
            args=["-m", "villager.mcp_server"]
        )
        
        async with stdio_client(server_params) as (read, write):
            async with ClientSession(read, write) as session:
                # Initialize session
                await session.initialize()
                
                # Now you can call MCP tools
                result = await session.call_tool(
                    "nmap_scan",
                    {"target": "example.com", "options": "-sV"}
                )
                return result
