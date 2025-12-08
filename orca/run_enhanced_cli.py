#!/usr/bin/env python3
"""
Enhanced BinSleuth CLI Runner
Simple script to run the enhanced CLI with all workflows
"""
import sys
import os
from pathlib import Path

# Add the src/cmd directory to the path
current_dir = Path(__file__).parent
src_cmd_dir = current_dir / "src" / "cmd"
sys.path.insert(0, str(src_cmd_dir))

# Import and run the enhanced CLI
try:
    from main_enhanced import main
    
    if __name__ == "__main__":
        print("Starting BinSleuth Enhanced CLI...")
        main()
        
except ImportError as e:
    print(f"Error importing enhanced CLI: {e}")
    print("Make sure all required modules are available.")
    sys.exit(1)
except Exception as e:
    print(f"Error running enhanced CLI: {e}")
    sys.exit(1)
