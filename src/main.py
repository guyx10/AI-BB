#!/usr/bin/env python3
import asyncio
import sys
import os
from pathlib import Path

sys.path.append(str(Path(__file__).parent))

async def debug_agent():
    from core.agent import AutonomousPentestAgent
    
    print("1. Creating agent...")
    agent = AutonomousPentestAgent(
        config_path='config/agent_config.yaml',
        debug=True,
        max_workers=15
    )
    
    print("2. Starting assessment...")
    await agent.run_full_assessment("testphp.vulnweb.com")
    
    print("3. Assessment completed!")

if __name__ == "__main__":
    print("🚀 Starting debug run...")
    asyncio.run(debug_agent())