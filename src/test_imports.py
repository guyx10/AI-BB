# src/test_imports.py
import sys
import os
sys.path.append(os.path.dirname(os.path.dirname(os.path.abspath(__file__))))

try:
    from core.agent import PentestAgent
    print("✅ PentestAgent imported successfully")
except ImportError as e:
    print(f"❌ PentestAgent import failed: {e}")

# List what's actually in the agent module
try:
    import core.agent as agent_module
    print("Available in agent module:", [x for x in dir(agent_module) if not x.startswith('_')])
except Exception as e:
    print(f"❌ Couldn't inspect agent module: {e}")
