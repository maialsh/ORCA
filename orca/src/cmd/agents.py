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
from langchain_openai import ChatOpenAI
from langchain_core.messages import AnyMessage, SystemMessage, HumanMessage
from langgraph.graph.message import add_messages
from langgraph.graph import START, StateGraph
from langgraph.prebuilt import ToolNode, tools_condition
# Check for Binary Ninja API
BINARY_NINJA_PATH = "/Applications/Binary Ninja.app/Contents/Resources/python"
if not os.path.exists(BINARY_NINJA_PATH):
    print(f"Binary Ninja python API not found in expected folder: {BINARY_NINJA_PATH}")
    sys.exit(1)
sys.path.insert(0, BINARY_NINJA_PATH)
# Import ORCA modules
from utils import batched, _clean_json
from config import config
from llm_module import llm_handler
from sandbox import DockerSandbox
from binaryninja import BinaryView, open_view, SymbolType
from smart_static_analysis import SmartStaticAnalysis
import subprocess
import hashlib
import os
import tempfile
import time
import base64
import codecs
import socket
import psutil
import signal
from .state import AnalysisState

analyzer = SmartStaticAnalyzer(llm_model=config.get('llm.model'), llm_api_base=config.get('llm.api_base'))

# Analysis nodes
def initialize_analysis(state: AnalysisState) -> AnalysisState:
    """Initialize analysis with enhanced checks"""
    file_path = state['file_path']
    try:
        # Basic file checks
        if not os.path.exists(file_path):
            return {**state, "analysis_report": "Error: File not found"}
    
        if os.path.getsize(file_path) > MAX_FILE_SIZE:
            return {**state, "analysis_report": "Error: File too large for analysis"}
        results = analyzer.analyze(Path(sys.argv[1]), use_llm=config.get('analysis.enable_llm_analysis', True))
        
        return {
            **state,
            "binary_view": results['bv'],
            "size": results['file_info']['size'],
            "file_type": results['file_info']['type'],
            "file_hash_sha256": results['file_info']['sha256'],
            "file_hash_md5": results['file_info']['md5'],
            "permissions": results['file_info']['permissions'],
            "is_executable": results['file_info']['is_executable'],
            "strings": results['strings'],
            "elf_info": results['elf_info'],
            "imports": results['imports'],
            "exports": results['exports'],
            "sections": results['sections'],
            "linux_checks": results['linux_checks'],
            "behavior": results['behavior'],
            "functions": results['functions'],
            "decoded_strings": results['decoded_strings'],
            "analysis_summary": results['analysis_summary'],
        }
    except Exception as e:
        return {**state, "analysis_report": f"Initialization error: {str(e)}"}
