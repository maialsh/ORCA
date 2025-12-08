import os
import sys
from typing import Type, Dict, Any, List, TypedDict, Annotated, Optional
from langgraph.graph import StateGraph, END, START
from langgraph.graph.message import add_messages
from langchain_core.messages import AnyMessage
from langgraph.prebuilt import ToolNode, tools_condition
BINARY_NINJA_PATH = "/Applications/Binary Ninja.app/Contents/Resources/python"
if os.path.exists(BINARY_NINJA_PATH):
    sys.path.insert(0, BINARY_NINJA_PATH)
else:
    print(f"Warning: Binary Ninja python API not found in expected folder: {BINARY_NINJA_PATH}")
    print("Will attempt to continue, but some functionality may be limited.")
from binaryninja import BinaryView

# Define the enhanced agent state
class AnalysisState(TypedDict):
    file_path: str
    name: str
    size: int
    file_hash_sha256: str
    file_hash_md5: str
    permissions: str
    is_executable: bool
    binary_view: Optional[BinaryView]
    file_hash: str
    file_type: str
    strings: Dict[str, List[str]]
    imports: List[str]
    exports: List[str]
    sections: List[Dict[str, Any]]
    functions: List[Dict[str, Any]]
    linux_checks: Dict[str, List[str]]
    behavior: Dict[str, List[Dict]]
    dynamic_analysis: Dict[str, Any]
    import_analysis: Dict[str, List[str]]
    potential_backdoors: List[str]
    analysis_report: str
    messages: Annotated[list[AnyMessage], add_messages]
