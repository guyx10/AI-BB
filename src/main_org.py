#!/usr/bin/env python3
"""
Autonomous Pentest Agent - Main Entry Point
"""
import asyncio
import sys
import os
from pathlib import Path

# Add the src directory to Python path
sys.path.append(str(Path(__file__).parent))

from core.agent import AutonomousPentestAgent

async def main():
    """Main entry point for the autonomous pentest agent"""
    
    print("🚀 Autonomous Pentest Agent Starting...")
    print("=" * 50)
    
    # Check if target is provided
    if len(sys.argv) < 2:
        print("Usage: python main.py <target> [--config config_path]")
        print("Example: python main.py example.com")
        sys.exit(1)
    
    target = sys.argv[1]
    config_path = "config/agent_config.yaml"
    
    # Use custom config if provided
    if "--config" in sys.argv:
        config_index = sys.argv.index("--config") + 1
        if config_index < len(sys.argv):
            config_path = sys.argv[config_index]
    
    # Check if config exists
    if not os.path.exists(config_path):
        print(f"❌ Config file not found: {config_path}")
        print("📁 Creating default config...")
        create_default_config(config_path)
    
    try:
        # Initialize and run the agent
        agent = AutonomousPentestAgent(config_path)
        await agent.run_full_assessment(target)
        
    except Exception as e:
        print(f"❌ Error during assessment: {e}")
        import traceback
        traceback.print_exc()

def create_default_config(config_path):
    """Create a default configuration file"""
    default_config = """
target_scope:
  domains: []
  urls: []
  out_of_scope: []

tools:
  reconnaissance:
    - subfinder
    - amass
    - httpx
    - nmap
  vulnerability_scanning:
    - nuclei
    - sqlmap
    - ffuf

ai:
  primary_provider: "deepseek"
  local_model: "codellama:13b"
  temperature: 0.1
  max_tokens: 4000

limits:
  max_requests_per_minute: 60
  respect_robots_txt: true
  user_agent: "Autonomous-Pentester-Agent/1.0"
"""
    os.makedirs(os.path.dirname(config_path), exist_ok=True)
    with open(config_path, 'w') as f:
        f.write(default_config)
    print(f"✅ Created default config: {config_path}")

if __name__ == "__main__":
    asyncio.run(main())

