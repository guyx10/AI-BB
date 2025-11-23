#!/usr/bin/env python3
"""
Simple MCP server for penetration testing tools
"""
import asyncio
import subprocess
import json
from mcp.server import Server
from mcp.server.models import InitializationOptions
import mcp.server.stdio
import mcp.types as types

server = Server("pentest-tools")

@server.list_tools()
async def handle_list_tools() -> list[types.Tool]:
    """List available tools"""
    return [
        types.Tool(
            name="nmap_scan",
            description="Run nmap network scanning",
            inputSchema={
                "type": "object",
                "properties": {
                    "target": {"type": "string", "description": "Target host or IP"},
                    "command": {"type": "string", "description": "Nmap command to run"}
                },
                "required": ["target"]
            }
        ),
        types.Tool(
            name="ssl_scan", 
            description="Run SSL/TLS scanning",
            inputSchema={
                "type": "object", 
                "properties": {
                    "target": {"type": "string", "description": "Target host"},
                    "tool": {"type": "string", "description": "SSL tool to use"}
                },
                "required": ["target"]
            }
        ),
        types.Tool(
            name="smb_scan",
            description="Run SMB enumeration",
            inputSchema={
                "type": "object",
                "properties": {
                    "target": {"type": "string", "description": "Target host"},
                    "command": {"type": "string", "description": "SMB command to run"}
                },
                "required": ["target"]
            }
        )
    ]

@server.call_tool()
async def handle_call_tool(name: str, arguments: dict) -> list[types.TextContent]:
    """Execute tools"""
    try:
        if name == "nmap_scan":
            target = arguments.get("target", "")
            command = arguments.get("command", f"nmap -sS -sV {target}")
            
            process = await asyncio.create_subprocess_shell(
                command,
                stdout=asyncio.subprocess.PIPE,
                stderr=asyncio.subprocess.PIPE
            )
            stdout, stderr = await process.communicate()
            
            return [types.TextContent(
                type="text",
                text=f"Command: {command}\nReturn code: {process.returncode}\nOutput:\n{stdout.decode()}\nErrors:\n{stderr.decode()}"
            )]
        
        elif name == "ssl_scan":
            target = arguments.get("target", "")
            tool = arguments.get("tool", "sslscan")
            
            if tool == "sslscan":
                command = f"sslscan {target}"
            else:
                command = f"nmap --script ssl-* -p 443 {target}"
            
            process = await asyncio.create_subprocess_shell(
                command,
                stdout=asyncio.subprocess.PIPE,
                stderr=asyncio.subprocess.PIPE
            )
            stdout, stderr = await process.communicate()
            
            return [types.TextContent(
                type="text", 
                text=f"SSL Scan Results for {target}:\n{stdout.decode()}"
            )]
        
        elif name == "smb_scan":
            target = arguments.get("target", "")
            command = arguments.get("command", f"nmap --script smb-* -p 445 {target}")
            
            process = await asyncio.create_subprocess_shell(
                command,
                stdout=asyncio.subprocess.PIPE,
                stderr=asyncio.subprocess.PIPE
            )
            stdout, stderr = await process.communicate()
            
            return [types.TextContent(
                type="text",
                text=f"SMB Scan Results for {target}:\n{stdout.decode()}"
            )]
        
        else:
            return [types.TextContent(type="text", text=f"Unknown tool: {name}")]
            
    except Exception as e:
        return [types.TextContent(type="text", text=f"Error executing {name}: {str(e)}")]

async def main():
    async with mcp.server.stdio.stdio_server() as (read_stream, write_stream):
        await server.run(
            read_stream,
            write_stream,
            InitializationOptions(
                server_name="pentest-tools",
                server_version="1.0.0",
                capabilities=server.get_capabilities(
                    notification_options=None,
                    experimental_capabilities=None,
                )
            )
        )

if __name__ == "__main__":
    asyncio.run(main())
