#!/usr/bin/env python3
"""
Autonomous Pentest Agent - Main Entry Point
FIXED VERSION with proper argument parsing and async context
"""
import asyncio
import sys
import os
import argparse
from pathlib import Path

# Add the src directory to Python path
sys.path.append(str(Path(__file__).parent))

from core.agent import AutonomousPentestAgent

async def main():
    """Main entry point for the autonomous pentest agent"""
    
    parser = argparse.ArgumentParser(description='Autonomous Pentest Agent')
    parser.add_argument('target', nargs='?', help='Single target to scan (URL or domain)')  # Make optional
    parser.add_argument('--batch', '-b', help='Batch file containing list of targets')
    parser.add_argument('--config', '-c', default='config/agent_config.yaml', help='Config file path')
    parser.add_argument('--debug', '-d', action='store_true', help='Enable debug mode')
    parser.add_argument('--workers', '-w', type=int, default=5, help='Number of parallel workers')
    parser.add_argument('--output-dir', '-o', help='Custom output directory for reports')
    
    args = parser.parse_args()
    
    # Validate arguments
    if not args.target and not args.batch:
        parser.error("Either provide a single target or use --batch with a targets file")
    
    if args.target and args.batch:
        parser.error("Cannot use both single target and batch mode simultaneously")
    
    print("🚀 Autonomous Pentest Agent Starting...")
    print("=" * 50)
    
    config_path = args.config
    
    # Check if config exists
    if not os.path.exists(config_path):
        print(f"❌ Config file not found: {config_path}")
        print("📁 Creating default config...")
        create_default_config(config_path)
    
    try:
        # Initialize agent
        async with AutonomousPentestAgent(
            config_path=config_path,
            debug=args.debug,
            max_workers=args.workers
        ) as agent:
            
            # Handle batch mode
            if args.batch:
                print(f"📁 Batch mode: Processing targets from {args.batch}")
                print(f"👷 Workers: {args.workers}")
                if args.output_dir:
                    print(f"📂 Output directory: {args.output_dir}")
                print("-" * 40)
                
                await agent.process_batch_targets(
                    args.batch, 
                    output_dir=args.output_dir
                )
            else:
                # Single target mode
                print(f"🎯 Starting assessment of: {args.target}")
                print(f"🔧 Debug mode: {args.debug}")
                print(f"👷 Workers: {args.workers}")
                print("-" * 40)
                
                await agent.run_full_assessment(args.target)
        
    except KeyboardInterrupt:
        print("\n⏹️  Scan interrupted by user")
        sys.exit(1)
    except Exception as e:
        print(f"❌ Error during assessment: {e}")
        if args.debug:
            import traceback
            traceback.print_exc()
        sys.exit(1)

        # Run vulnerability scanning
        print("🔍 Starting vulnerability scanning...")
        scan_results = await agent.run_vulnerability_scan(targets)
        
        # Analyze results
        print("🧠 Analyzing scan results...")
        analysis_results = analyzer.analyze_scan_results(scan_results)

def create_default_config(config_path):
    """Create a default configuration file"""
    default_config = """target_scope:
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
  primary_provider: "ollama"
  strategy_model: "mistral:7b-instruct"
  code_model: "deepseek-coder:6.7b"
  fallback_model: "codellama:13b"
  temperature: 0.3
  max_tokens: 4000

limits:
  max_requests_per_minute: 60
  respect_robots_txt: true
  user_agent: "Autonomous-Pentester-Agent/1.0"

zap:
  enabled: true
  path: "zap"
  port: 8080
  api_key: ""
  max_scan_duration: 60
"""
    os.makedirs(os.path.dirname(config_path), exist_ok=True)
    with open(config_path, 'w') as f:
        f.write(default_config)
    print(f"✅ Created default config: {config_path}")

if __name__ == "__main__":
    asyncio.run(main())