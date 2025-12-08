"""
title: orca/src/orca/app/agents.py
project: orca
description: main agentic
"""
import docker
import time
import sys
from pathlib import Path
from typing import Optional, Dict, Any
import json
from typing import List, TypedDict, Annotated, Optional
from langgraph.prebuilt import ToolNode, tools_condition
# Check for Binary Ninja API
BINARY_NINJA_PATH = "/Applications/Binary Ninja.app/Contents/Resources/python"
if not os.path.exists(BINARY_NINJA_PATH):
    print(f"Binary Ninja python API not found in expected folder: {BINARY_NINJA_PATH}")
    sys.exit(1)
sys.path.insert(0, BINARY_NINJA_PATH)
from binaryninja import BinaryView, open_view, SymbolType
from .state import AnalysisState

def dynamic_analysis(state: AnalysisState) -> AnalysisState:
    """Docker-based dynamic analysis"""
    sandbox = DockerSandbox()
    error = sandbox.start(state['file_path'])
    
    if error:
        return {**state, "dynamic_analysis": {"error": error}}
    
    try:
        results = sandbox.run_analysis()
        
        # Process syscalls for interesting patterns
        suspicious_syscalls = []
        for line in results.get('syscalls', []):
            if any(s in line for s in ["execve", "ptrace", "connect", "bind", "listen"]):
                suspicious_syscalls.append(line)
        
        results["suspicious_syscalls"] = suspicious_syscalls[:50]  # Limit output
        
        return {**state, "dynamic_analysis": results}
    finally:
        sandbox.cleanup()
