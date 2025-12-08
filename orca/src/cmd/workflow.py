"""
Enhanced Multi-agentic workflow for comprehensive binary analysis using Langgraph
Implements a supervisor agent, planning agent, and specialized analysis agents
Focuses on capabilities identification and provides comprehensive analysis results
Supports chatbot interactions with user messages
"""
import os
import sys
import json
from typing import Dict, List, Any, TypedDict, Annotated, Optional, Tuple, Union
from pathlib import Path

# Langgraph imports
from langchain_openai import ChatOpenAI
from langchain_core.messages import AnyMessage, SystemMessage, HumanMessage, AIMessage
from langgraph.graph import StateGraph, END
from langgraph.graph.message import add_messages
from langgraph.prebuilt import ToolNode, tools_condition

# Check for Binary Ninja API
BINARY_NINJA_PATH = "/Applications/Binary Ninja.app/Contents/Resources/python"
if os.path.exists(BINARY_NINJA_PATH):
    sys.path.insert(0, BINARY_NINJA_PATH)
else:
    print(f"Warning: Binary Ninja python API not found in expected folder: {BINARY_NINJA_PATH}")
    print("Will attempt to continue, but some functionality may be limited.")

# Import BinSleuth modules
from config import config
from llm_module import llm_handler
from smart_static_analysis import SmartStaticAnalyzer
from api_crossrefs import ApiCrossReferenceTool
from api_clustering import FunctionClusteringTool
from binary_summary import BinarySummaryGenerator
from api_analysis_agent import ApiAnalysisAgent
from enhanced_string_analysis import EnhancedStringAnalyzer
from smart_string_analysis import SmartStringAnalyzer, SmartStringValidator
from code_reference_analyzer import CodeReferenceAnalyzer
from api_reference_analyzer import ApiReferenceAnalyzer
from utils import _clean_json
from sandbox import DockerSandbox
from timing_utils import TimingCollector

# Define the workflow state
class WorkflowState(TypedDict):
    # Input parameters
    binary_path: Optional[str]
    binary_functionality: Optional[str]
    goal: Optional[str]
    user_message: Optional[str]  # For chatbot interactions
    
    # Analysis state
    binary_view: Optional[Any]
    static_analysis_results: Optional[Dict[str, Any]]
    api_crossrefs_results: Optional[Dict[str, Any]]
    api_clustering_results: Optional[Dict[str, Any]]
    api_analysis_results: Optional[Dict[str, Any]]
    dynamic_analysis_results: Optional[Dict[str, Any]]
    comprehensive_string_results: Optional[Dict[str, Any]]
    
    # Workflow state
    plan: Optional[List[str]]
    current_step: Optional[int]
    completed_steps: List[str]
    analysis_complete: Optional[bool]
    
    # Output state
    capabilities: Optional[Dict[str, Any]]
    malware_analysis_results: Optional[Dict[str, Any]]
    binary_summary_results: Optional[Dict[str, Any]]
    final_summary: Optional[Dict[str, Any]]
    
    # Chat history
    messages: Annotated[List[AnyMessage], add_messages]

# Initialize LLM
llm = ChatOpenAI(
    model=config.get('llm.model'),
    temperature=config.get('llm.temperature'),
    api_key=os.environ.get('OPENAI_API_KEY')
)

def chatbot_agent(state: WorkflowState) -> Dict:
    """
    Agent that handles chatbot interactions using comprehensive analysis context
    """
    user_message = state.get("user_message", "")
    
    if not user_message:
        return {
            "messages": [
                AIMessage(content="No user message provided for chatbot interaction.")
            ]
        }
    
    # Prepare comprehensive context from all analysis results
    context = {
        "static_analysis_results": state.get("static_analysis_results", {}),
        "api_crossrefs_results": state.get("api_crossrefs_results", {}),
        "api_clustering_results": state.get("api_clustering_results", {}),
        "api_analysis_results": state.get("api_analysis_results", {}),
        "dynamic_analysis_results": state.get("dynamic_analysis_results", {}),
        "capabilities": state.get("capabilities", {}),
        "malware_analysis_results": state.get("malware_analysis_results", {}),
        "binary_summary_results": state.get("binary_summary_results", {}),
        "final_summary": state.get("final_summary", {}),
        "binary_view": state.get("binary_view"),
        "binary_path": state.get("binary_path"),
        "binary_functionality": state.get("binary_functionality"),
        "goal": state.get("goal")
    }
    
    # Create a comprehensive context summary for the LLM
    context_summary = _prepare_chatbot_context(context)
    
    system_prompt = """You are ORCA, an expert binary analysis assistant with access to comprehensive
    analysis results from static analysis, API analysis, string analysis, and other security analysis modules.
    
    You have detailed knowledge about the binary including:
    - File information and metadata
    - Imported and exported functions
    - String analysis results
    - API cross-references and usage patterns
    - Function clustering and behavior analysis
    - Capabilities and potential malware indicators
    - Dynamic analysis results (if available)
    
    Answer the user's question based on the provided analysis context. Be helpful, accurate, and provide 
    specific details when available. If you don't have enough information to answer a question, say so clearly.
    
    You can help with:
    - Explaining binary capabilities and functionality
    - Identifying suspicious or malicious behavior
    - Finding specific strings, APIs, or functions
    - Analyzing code patterns and security implications
    - Providing recommendations for further analysis
    - Cross-referencing APIs and functions
    - Explaining the purpose of specific functions or code sections
    """
    
    user_prompt = f"""Analysis Context:
{context_summary}

User Question: {user_message}

Please provide a helpful and detailed response based on the comprehensive analysis context."""
    
    try:
        response = llm_handler.query(system_prompt, user_prompt)
        return {
            "messages": [
                AIMessage(content=response)
            ]
        }
    except Exception as e:
        error_msg = f"I apologize, but I encountered an error processing your question: {str(e)}"
        return {
            "messages": [
                AIMessage(content=error_msg)
            ]
        }

def _prepare_chatbot_context(context: Dict[str, Any]) -> str:
    """
    Prepare a comprehensive context summary for the chatbot
    
    Args:
        context: Dictionary containing all analysis results
        
    Returns:
        Formatted context summary
    """
    summary_parts = []
    
    # Basic file information
    static_results = context.get("static_analysis_results", {})
    if static_results.get("file_info"):
        file_info = static_results["file_info"]
        summary_parts.append("=== FILE INFORMATION ===")
        summary_parts.append(f"File: {file_info.get('name', 'Unknown')}")
        summary_parts.append(f"Path: {file_info.get('path', 'Unknown')}")
        summary_parts.append(f"Size: {file_info.get('size', 'Unknown')} bytes")
        summary_parts.append(f"SHA256: {file_info.get('sha256', 'Unknown')}")
        summary_parts.append(f"Type: {file_info.get('type', 'Unknown')}")
        summary_parts.append("")
    
    # Binary functionality and goal
    if context.get("binary_functionality"):
        summary_parts.append("=== BINARY PURPOSE ===")
        summary_parts.append(f"Declared Functionality: {context['binary_functionality']}")
        summary_parts.append(f"Analysis Goal: {context.get('goal', 'Unknown')}")
        summary_parts.append("")
    
    # Imports and exports
    if static_results.get("imports"):
        imports = static_results["imports"]
        summary_parts.append("=== IMPORTED FUNCTIONS ===")
        summary_parts.append(f"Total Imports: {len(imports)}")
        if len(imports) <= 20:
            summary_parts.append("Imports: " + ", ".join(imports))
        else:
            summary_parts.append("Sample Imports: " + ", ".join(imports[:20]) + f" ... and {len(imports)-20} more")
        summary_parts.append("")
    
    # String analysis
    if static_results.get("strings"):
        strings_data = static_results["strings"]
        summary_parts.append("=== STRING ANALYSIS ===")
        for category, strings in strings_data.items():
            if isinstance(strings, list) and strings:
                summary_parts.append(f"{category.title()}: {len(strings)} items")
                if len(strings) <= 5:
                    for s in strings:
                        summary_parts.append(f"  - {s}")
                else:
                    for s in strings[:5]:
                        summary_parts.append(f"  - {s}")
                    summary_parts.append(f"  ... and {len(strings)-5} more")
        summary_parts.append("")
    
    # Functions
    if static_results.get("functions"):
        functions = static_results["functions"]
        summary_parts.append("=== FUNCTIONS ===")
        summary_parts.append(f"Total Functions: {len(functions)}")
        
        # Show functions with interesting behavior
        interesting_functions = []
        for func in functions[:10]:  # Limit to first 10 for context
            if func.get("behavior"):
                interesting_functions.append(f"{func.get('name', 'unknown')} - {len(func['behavior'])} behaviors")
        
        if interesting_functions:
            summary_parts.append("Functions with Notable Behavior:")
            for func_desc in interesting_functions:
                summary_parts.append(f"  - {func_desc}")
        summary_parts.append("")
    
    # API Analysis
    api_analysis = context.get("api_analysis_results", {})
    if api_analysis:
        summary_parts.append("=== API ANALYSIS ===")
        summary_parts.append(f"Referenced APIs: {len(api_analysis.get('referenced_apis', []))}")
        summary_parts.append(f"Functions with API calls: {len(api_analysis.get('filtered_functions', []))}")
        summary_parts.append("")
    
    # API Clustering
    api_clustering = context.get("api_clustering_results", {})
    if api_clustering.get("clusters"):
        summary_parts.append("=== API CLUSTERS ===")
        for cluster in api_clustering["clusters"][:5]:  # Show first 5 clusters
            summary_parts.append(f"Cluster: {cluster.get('name', 'Unknown')}")
            summary_parts.append(f"  Description: {cluster.get('description', 'No description')}")
            summary_parts.append(f"  APIs: {len(cluster.get('apis', []))} functions")
            summary_parts.append(f"  Security: {cluster.get('security_assessment', 'Unknown')}")
        summary_parts.append("")
    
    # Capabilities
    capabilities = context.get("capabilities", {})
    if capabilities:
        summary_parts.append("=== CAPABILITIES ===")
        for category, items in capabilities.items():
            if items and category != "error":
                if isinstance(items, list) and items:
                    summary_parts.append(f"{category.replace('_', ' ').title()}: {len(items)} items")
                    for item in items[:3]:  # Show first 3 items
                        summary_parts.append(f"  - {item}")
                    if len(items) > 3:
                        summary_parts.append(f"  ... and {len(items)-3} more")
                elif isinstance(items, str):
                    summary_parts.append(f"{category.replace('_', ' ').title()}: {items}")
        summary_parts.append("")
    
    # Malware analysis
    malware_analysis = context.get("malware_analysis_results", {})
    if malware_analysis:
        summary_parts.append("=== MALWARE ANALYSIS ===")
        summary_parts.append(f"Classification: {malware_analysis.get('classification', 'Unknown')}")
        summary_parts.append(f"Threat Level: {malware_analysis.get('threat_level', 'Unknown')}")
        summary_parts.append(f"Confidence: {malware_analysis.get('confidence_level', 0)}%")
        
        if malware_analysis.get("malicious_indicators"):
            summary_parts.append("Malicious Indicators:")
            for indicator in malware_analysis["malicious_indicators"][:5]:
                summary_parts.append(f"  - {indicator}")
        summary_parts.append("")
    
    # Binary summary
    binary_summary = context.get("binary_summary_results", {})
    if binary_summary and binary_summary.get("summary"):
        summary_parts.append("=== BINARY SUMMARY ===")
        summary_parts.append(binary_summary["summary"][:500] + "..." if len(binary_summary["summary"]) > 500 else binary_summary["summary"])
        summary_parts.append("")
    
    # Dynamic analysis
    dynamic_results = context.get("dynamic_analysis_results", {})
    if dynamic_results and not dynamic_results.get("error"):
        summary_parts.append("=== DYNAMIC ANALYSIS ===")
        if dynamic_results.get("suspicious_syscalls"):
            summary_parts.append(f"Suspicious System Calls: {len(dynamic_results['suspicious_syscalls'])}")
            for syscall in dynamic_results["suspicious_syscalls"][:3]:
                summary_parts.append(f"  - {syscall}")
        summary_parts.append("")
    
    return "\n".join(summary_parts) if summary_parts else "No analysis context available."

# Agent definitions (keeping existing agents but adding chatbot support)
def supervisor_agent(state: WorkflowState) -> Dict:
    """
    Supervisor agent that checks if required information is provided
    and manages the overall workflow
    """
    # If this is a chatbot interaction and analysis is complete, route to chatbot
    if state.get("user_message") and state.get("analysis_complete"):
        return {"route_to": "chatbot"}
    
    # Check if binary path is provided
    if not state.get("binary_path"):
        return {
            "messages": [
                AIMessage(content="Please provide the path to the binary file you want to analyze.")
            ]
        }
    
    # Check if binary functionality is provided
    if not state.get("binary_functionality"):
        return {
            "messages": [
                AIMessage(content="Please provide a brief description of the binary's intended functionality.")
            ]
        }
    
    # Check if goal is provided
    if not state.get("goal"):
        return {
            "messages": [
                AIMessage(content="Please specify your analysis goal (e.g., 'capabilities', 'malware analysis').")
            ]
        }
    
    # If all required information is provided, proceed to planning
    return {"current_step": 0}

def planning_agent(state: WorkflowState) -> Dict:
    """
    Planning agent that derives a plan based on the user's goal and available tools
    """
    goal = state.get("goal", "").lower()
    binary_functionality = state.get("binary_functionality", "")
    
    plan = []
    
    # Always start with static analysis
    plan.append("static_analysis")
    
    if "api" in goal or "capabilities" in goal:
        plan.append("api_crossrefs")
        plan.append("api_clustering")
        plan.append("api_analysis")
    
    # Dynamic analysis completely disabled - never add to plan
    
    if "capabilities" in goal:
        plan.append("capabilities_analysis")
    
    if "malware" in goal or "malicious" in goal:
        plan.append("malware_analysis")
    
    # Add comprehensive string analysis for all goals (unless disabled)
    if not os.environ.get('DISABLE_COMPREHENSIVE_STRINGS'):
        plan.append("comprehensive_string_analysis")
    
    # Add binary summary and final summary steps
    plan.append("binary_summary")
    plan.append("generate_summary")
    
    # Update state with plan
    return {
        "plan": plan,
        "current_step": 0,
        "completed_steps": [],
        "messages": [
            AIMessage(content=f"Analysis plan created based on goal: '{goal}' and binary functionality: '{binary_functionality}'.\n\nPlan steps:\n" + "\n".join([f"{i+1}. {step}" for i, step in enumerate(plan)]))
        ]
    }

def static_analysis_agent(state: WorkflowState) -> Dict:
    """
    Agent that performs static analysis on the binary
    """
    binary_path = state.get("binary_path")
    
    if os.environ.get('DEBUG'):
        print(f"Static analysis agent: Analyzing binary at {binary_path}")
    
    try:
        # Initialize analyzer
        analyzer = SmartStaticAnalyzer(
            llm_model=config.get('llm.model'),
            llm_api_base=config.get('llm.api_base')
        )
        
        # Perform analysis
        results = analyzer.analyze(Path(binary_path), use_llm=True)
        
        # Update state with results
        updated_state = {
            "static_analysis_results": results,
            "binary_view": results.get("bv"),
            "current_step": state.get("current_step", 0) + 1,
            "completed_steps": state.get("completed_steps", []) + ["static_analysis"],
            "messages": [
                AIMessage(content="Static analysis completed successfully.")
            ]
        }
        
        if os.environ.get('DEBUG'):
            print(f"Static analysis completed successfully. Current step now: {updated_state['current_step']}")
            print(f"Completed steps: {updated_state['completed_steps']}")
        
        return updated_state
    except Exception as e:
        error_msg = f"Error during static analysis: {str(e)}"
        if os.environ.get('DEBUG'):
            print(f"Static analysis failed: {error_msg}")
            import traceback
            traceback.print_exc()
        
        # Create a minimal result to allow workflow to continue
        minimal_results = {
            "file_info": {"path": binary_path, "name": os.path.basename(binary_path)},
            "imports": [],
            "strings": {"apis": [], "urls": [], "paths": []},
            "error": error_msg
        }
        
        return {
            "static_analysis_results": minimal_results,
            "current_step": state.get("current_step", 0) + 1,
            "completed_steps": state.get("completed_steps", []) + ["static_analysis"],
            "messages": [
                AIMessage(content=f"Static analysis completed with errors: {error_msg}")
            ]
        }

def api_crossrefs_agent(state: WorkflowState) -> Dict:
    """
    Agent that analyzes API cross-references in the binary
    """
    binary_view = state.get("binary_view")
    static_results = state.get("static_analysis_results", {})
    
    if os.environ.get('DEBUG'):
        print(f"API cross-references agent: Starting analysis")
    
    if not binary_view:
        if os.environ.get('DEBUG'):
            print("API cross-references agent: Binary view not available")
        
        # Create minimal results to allow workflow to continue
        minimal_results = {}
        
        return {
            "api_crossrefs_results": minimal_results,
            "current_step": state.get("current_step", 0) + 1,
            "completed_steps": state.get("completed_steps", []) + ["api_crossrefs"],
            "messages": [
                AIMessage(content="API cross-references analysis skipped: Binary view not available.")
            ]
        }
    
    try:
        # Initialize API cross-reference tool
        api_tool = ApiCrossReferenceTool(binary_view)
        
        # Get imports from static analysis
        imports = static_results.get("imports", [])
        
        # Ensure imports is not None and is a list
        if imports is None:
            imports = []
        elif not isinstance(imports, list):
            imports = []
        
        # Analyze API cross-references
        results = api_tool.batch_analyze(imports[:50])  # Limit to 50 imports for performance
        
        # Update state with results
        updated_state = {
            "api_crossrefs_results": results,
            "current_step": state.get("current_step", 0) + 1,
            "completed_steps": state.get("completed_steps", []) + ["api_crossrefs"],
            "messages": [
                AIMessage(content=f"API cross-references analysis completed for {len(results)} imports.")
            ]
        }
        
        if os.environ.get('DEBUG'):
            print(f"API cross-references completed successfully. Current step now: {updated_state['current_step']}")
            print(f"Completed steps: {updated_state['completed_steps']}")
        
        return updated_state
    except Exception as e:
        error_msg = f"Error during API cross-references analysis: {str(e)}"
        if os.environ.get('DEBUG'):
            print(f"API cross-references failed: {error_msg}")
            import traceback
            traceback.print_exc()
        
        # Create minimal results to allow workflow to continue
        minimal_results = {}
        
        return {
            "api_crossrefs_results": minimal_results,
            "current_step": state.get("current_step", 0) + 1,
            "completed_steps": state.get("completed_steps", []) + ["api_crossrefs"],
            "messages": [
                AIMessage(content=f"API cross-references analysis completed with errors: {error_msg}")
            ]
        }

def api_analysis_agent(state: WorkflowState) -> Dict:
    """
    Agent that analyzes the connection between APIs and the user's goal/description
    Filters APIs based on their usage in the binary, focusing on those with code cross-references
    """
    binary_view = state.get("binary_view")
    static_results = state.get("static_analysis_results", {})
    api_crossrefs_results = state.get("api_crossrefs_results", {})
    
    if os.environ.get('DEBUG'):
        print(f"API analysis agent: Starting analysis")
    
    if not binary_view or not static_results or not api_crossrefs_results:
        if os.environ.get('DEBUG'):
            print("API analysis agent: Required data not available")
        
        # Create minimal results to allow workflow to continue
        minimal_results = {
            "referenced_apis": [],
            "filtered_functions": [],
            "api_relevance": {}
        }
        
        return {
            "api_analysis_results": minimal_results,
            "current_step": state.get("current_step", 0) + 1,
            "completed_steps": state.get("completed_steps", []) + ["api_analysis"],
            "messages": [
                AIMessage(content="API analysis skipped: Required data not available.")
            ]
        }
    
    try:
        # Initialize API analysis agent
        analysis_agent = ApiAnalysisAgent(
            llm_model=config.get('llm.model'),
            llm_api_base=config.get('llm.api_base')
        )
        
        # Prepare state for analysis
        analysis_state = {
            "binary_view": binary_view,
            "imports": static_results.get("imports", []),
            "functions": static_results.get("functions", []),
            "goal": state.get("goal", ""),
            "binary_functionality": state.get("binary_functionality", "")
        }
        
        # Perform analysis
        result_state = analysis_agent.analyze(analysis_state)
        
        # Extract results
        results = {
            "referenced_apis": result_state.get("referenced_apis", []),
            "filtered_functions": result_state.get("filtered_functions", []),
            "api_relevance": result_state.get("api_relevance", {})
        }
        
        # Update state with results
        updated_state = {
            "api_analysis_results": results,
            "current_step": state.get("current_step", 0) + 1,
            "completed_steps": state.get("completed_steps", []) + ["api_analysis"],
            "messages": [
                AIMessage(content=f"API analysis completed successfully. Found {len(results.get('referenced_apis', []))} APIs with code cross-references and {len(results.get('filtered_functions', []))} functions that reference APIs.")
            ]
        }
        
        if os.environ.get('DEBUG'):
            print(f"API analysis completed successfully. Current step now: {updated_state['current_step']}")
            print(f"Completed steps: {updated_state['completed_steps']}")
        
        return updated_state
    except Exception as e:
        error_msg = f"Error during API analysis: {str(e)}"
        if os.environ.get('DEBUG'):
            print(f"API analysis failed: {error_msg}")
            import traceback
            traceback.print_exc()
        
        # Create minimal results to allow workflow to continue
        minimal_results = {
            "referenced_apis": [],
            "filtered_functions": [],
            "api_relevance": {},
            "error": error_msg
        }
        
        return {
            "api_analysis_results": minimal_results,
            "current_step": state.get("current_step", 0) + 1,
            "completed_steps": state.get("completed_steps", []) + ["api_analysis"],
            "messages": [
                AIMessage(content=f"API analysis completed with errors: {error_msg}")
            ]
        }

def api_clustering_agent(state: WorkflowState) -> Dict:
    """
    Agent that clusters API functions into logical groups
    """
    static_results = state.get("static_analysis_results", {})
    
    if os.environ.get('DEBUG'):
        print(f"API clustering agent: Starting analysis")
    
    if not static_results:
        if os.environ.get('DEBUG'):
            print("API clustering agent: Static analysis results not available")
        
        # Create minimal results to allow workflow to continue
        minimal_results = {"clusters": []}
        
        return {
            "api_clustering_results": minimal_results,
            "current_step": state.get("current_step", 0) + 1,
            "completed_steps": state.get("completed_steps", []) + ["api_clustering"],
            "messages": [
                AIMessage(content="API clustering analysis skipped: Static analysis results not available.")
            ]
        }
    
    try:
        # Initialize API clustering tool
        clustering_tool = FunctionClusteringTool(
            llm_model=config.get('llm.model'),
            llm_api_base=config.get('llm.api_base')
        )
        
        # Get imports from static analysis
        imports = static_results.get("imports", [])
        
        # Ensure imports is not None and is a list
        if imports is None:
            imports = []
        elif not isinstance(imports, list):
            imports = []
        
        # Cluster API functions
        results = clustering_tool.analyze_apis(imports[:100])  # Limit to 100 imports for performance
        
        # Update state with results
        updated_state = {
            "api_clustering_results": results,
            "current_step": state.get("current_step", 0) + 1,
            "completed_steps": state.get("completed_steps", []) + ["api_clustering"],
            "messages": [
                AIMessage(content=f"API clustering analysis completed with {len(results.get('clusters', []))} clusters.")
            ]
        }
        
        if os.environ.get('DEBUG'):
            print(f"API clustering completed successfully. Current step now: {updated_state['current_step']}")
            print(f"Completed steps: {updated_state['completed_steps']}")
        
        return updated_state
    except Exception as e:
        error_msg = f"Error during API clustering analysis: {str(e)}"
        if os.environ.get('DEBUG'):
            print(f"API clustering failed: {error_msg}")
            import traceback
            traceback.print_exc()
        
        # Create minimal results to allow workflow to continue
        minimal_results = {"clusters": []}
        
        return {
            "api_clustering_results": minimal_results,
            "current_step": state.get("current_step", 0) + 1,
            "completed_steps": state.get("completed_steps", []) + ["api_clustering"],
            "messages": [
                AIMessage(content=f"API clustering analysis completed with errors: {error_msg}")
            ]
        }

# Dynamic analysis disabled by user request
# def dynamic_analysis_agent(state: WorkflowState) -> Dict:
#     """
#     Agent that performs dynamic analysis on the binary
#     """
#     binary_path = state.get("binary_path")
#     
#     try:
#         # Initialize sandbox
#         sandbox = DockerSandbox()
#         error = sandbox.start(binary_path)
#         
#         if error:
#             return {
#                 "dynamic_analysis_results": {"error": error},
#                 "current_step": state.get("current_step", 0) + 1,
#                 "completed_steps": state.get("completed_steps", []) + ["dynamic_analysis"],
#                 "messages": [
#                     AIMessage(content=f"Error starting dynamic analysis sandbox: {error}")
#                 ]
#             }
#         
#         # Run analysis
#         results = sandbox.run_analysis()
#         
#         # Process syscalls for interesting patterns
#         suspicious_syscalls = []
#         for line in results.get('syscalls', []):
#             if any(s in line for s in ["execve", "ptrace", "connect", "bind", "listen"]):
#                 suspicious_syscalls.append(line)
#         
#         results["suspicious_syscalls"] = suspicious_syscalls[:50]  # Limit output
#         
#         # Update state with results
#         return {
#             "dynamic_analysis_results": results,
#             "current_step": state.get("current_step", 0) + 1,
#             "completed_steps": state.get("completed_steps", []) + ["dynamic_analysis"],
#             "messages": [
#                 AIMessage(content="Dynamic analysis completed successfully.")
#             ]
#         }
#     except Exception as e:
#         return {
#             "dynamic_analysis_results": {"error": str(e)},
#             "current_step": state.get("current_step", 0) + 1,
#             "completed_steps": state.get("completed_steps", []) + ["dynamic_analysis"],
#             "messages": [
#                 AIMessage(content=f"Error during dynamic analysis: {str(e)}")
#             ]
#         }
#     finally:
#         if 'sandbox' in locals():
#             sandbox.cleanup()

def dynamic_analysis_agent(state: WorkflowState) -> Dict:
    """
    Dynamic analysis agent - DISABLED by user request
    Returns minimal results to allow workflow to continue
    """
    return {
        "dynamic_analysis_results": {"error": "Dynamic analysis disabled by user", "status": "disabled"},
        "current_step": state.get("current_step", 0) + 1,
        "completed_steps": state.get("completed_steps", []) + ["dynamic_analysis"],
        "messages": [
            AIMessage(content="Dynamic analysis skipped - disabled by user request.")
        ]
    }

def capabilities_analysis_agent(state: WorkflowState) -> Dict:
    """
    Agent that analyzes the capabilities of the binary
    """
    static_results = state.get("static_analysis_results", {})
    api_crossrefs = state.get("api_crossrefs_results", {})
    api_clusters = state.get("api_clustering_results", {})
    
    if os.environ.get('DEBUG'):
        print(f"Capabilities analysis agent: Starting analysis")
    
    if not static_results:
        if os.environ.get('DEBUG'):
            print("Capabilities analysis agent: Static analysis results not available")
        
        # Create minimal results to allow workflow to continue
        minimal_results = {
            "core_functionality": "Unknown - analysis failed",
            "network_capabilities": [],
            "file_system_operations": [],
            "process_manipulation": [],
            "persistence_mechanisms": [],
            "anti_analysis_techniques": [],
            "other_capabilities": []
        }
        
        return {
            "capabilities": minimal_results,
            "current_step": state.get("current_step", 0) + 1,
            "completed_steps": state.get("completed_steps", []) + ["capabilities_analysis"],
            "messages": [
                AIMessage(content="Capabilities analysis skipped: Static analysis results not available.")
            ]
        }
    
    try:
        # Prepare prompt for LLM
        system_prompt = """You are a binary analysis expert specializing in determining the capabilities of binary files.
        Analyze the provided information and identify the key capabilities of the binary."""
        
        # Prepare data for analysis
        analysis_data = {
            "binary_info": static_results.get("file_info", {}),
            "imports": ",".join(static_results.get("imports", [])),
            "strings": static_results.get("strings", {}),
            "functions": static_results.get("functions", [])[:50],  # Limit functions
            "api_crossrefs": api_crossrefs,
            "api_clusters": api_clusters
        }
        
        user_prompt = f"""Analyze the following binary analysis data and determine the capabilities of the binary:
        
        {json.dumps(analysis_data, indent=2)}
        
        Provide a comprehensive analysis of the binary's capabilities, including:
        1. Core functionality
        2. Network capabilities
        3. File system operations
        4. Process manipulation
        5. Persistence mechanisms
        6. Anti-analysis techniques
        7. Other notable capabilities
        
        Return a JSON object with these categories and your findings."""
        
        # Get capabilities analysis from LLM
        capabilities = llm_handler.get_json_response(system_prompt, user_prompt)
        
        # Update state with results
        updated_state = {
            "capabilities": capabilities,
            "current_step": state.get("current_step", 0) + 1,
            "completed_steps": state.get("completed_steps", []) + ["capabilities_analysis"],
            "messages": [
                AIMessage(content="Capabilities analysis completed successfully.")
            ]
        }
        
        if os.environ.get('DEBUG'):
            print(f"Capabilities analysis completed successfully. Current step now: {updated_state['current_step']}")
            print(f"Completed steps: {updated_state['completed_steps']}")
        
        return updated_state
    except Exception as e:
        error_msg = f"Error during capabilities analysis: {str(e)}"
        if os.environ.get('DEBUG'):
            print(f"Capabilities analysis failed: {error_msg}")
            import traceback
            traceback.print_exc()
        
        # Create minimal results to allow workflow to continue
        minimal_results = {
            "core_functionality": "Unknown - analysis failed",
            "network_capabilities": [],
            "file_system_operations": [],
            "process_manipulation": [],
            "persistence_mechanisms": [],
            "anti_analysis_techniques": [],
            "other_capabilities": [],
            "error": error_msg
        }
        
        return {
            "capabilities": minimal_results,
            "current_step": state.get("current_step", 0) + 1,
            "completed_steps": state.get("completed_steps", []) + ["capabilities_analysis"],
            "messages": [
                AIMessage(content=f"Capabilities analysis completed with errors: {error_msg}")
            ]
        }

def malware_analysis_agent(state: WorkflowState) -> Dict:
    """
    Agent that analyzes if the binary is malicious
    """
    static_results = state.get("static_analysis_results", {})
    dynamic_results = state.get("dynamic_analysis_results", {})
    api_clusters = state.get("api_clustering_results", {})
    
    if os.environ.get('DEBUG'):
        print(f"Malware analysis agent: Starting analysis")
    
    if not static_results:
        if os.environ.get('DEBUG'):
            print("Malware analysis agent: Static analysis results not available")
        
        # Create minimal results to allow workflow to continue
        minimal_results = {
            "malicious_indicators": [],
            "suspicious_behaviors": [],
            "classification": "Unknown - analysis failed",
            "threat_level": "unknown",
            "confidence_level": 0,
            "iocs": []
        }
        
        return {
            "malware_analysis_results": minimal_results,
            "current_step": state.get("current_step", 0) + 1,
            "completed_steps": state.get("completed_steps", []) + ["malware_analysis"],
            "messages": [
                AIMessage(content="Malware analysis skipped: Static analysis results not available.")
            ]
        }
    
    try:
        # Prepare prompt for LLM
        system_prompt = """You are a malware analysis expert specializing in identifying malicious behavior in binary files.
        Analyze the provided information and determine if the binary is malicious."""
        
        # Prepare data for analysis
        analysis_data = {
            "binary_info": static_results.get("file_info", {}),
            "imports": static_results.get("imports", []),
            "strings": static_results.get("strings", {}),
            "suspicious_functions": [f for f in static_results.get("functions", [])[:50] if any(b.get("type") in ["network", "anti_analysis", "privilege_escalation"] for b in f.get("behavior", []))],
            "linux_checks": static_results.get("linux_checks", {}),
            "potential_backdoors": static_results.get("potential_backdoors", []),
            "dynamic_analysis": dynamic_results,
            "api_clusters": api_clusters
        }
        
        user_prompt = f"""Analyze the following binary analysis data and determine if the binary is malicious:
        
        {json.dumps(analysis_data, indent=2)}
        
        Provide a comprehensive malware analysis, including:
        1. Malicious indicators
        2. Suspicious behaviors
        3. Potential malware classification
        4. Threat level (low, medium, high)
        5. Confidence level (percentage)
        6. IOCs (Indicators of Compromise)
        
        Return a JSON object with these categories and your findings."""
        
        # Get malware analysis from LLM
        malware_analysis = llm_handler.get_json_response(system_prompt, user_prompt)
        
        # Update state with results
        updated_state = {
            "malware_analysis_results": malware_analysis,
            "current_step": state.get("current_step", 0) + 1,
            "completed_steps": state.get("completed_steps", []) + ["malware_analysis"],
            "messages": [
                AIMessage(content="Malware analysis completed successfully.")
            ]
        }
        
        if os.environ.get('DEBUG'):
            print(f"Malware analysis completed successfully. Current step now: {updated_state['current_step']}")
            print(f"Completed steps: {updated_state['completed_steps']}")
        
        return updated_state
    except Exception as e:
        error_msg = f"Error during malware analysis: {str(e)}"
        if os.environ.get('DEBUG'):
            print(f"Malware analysis failed: {error_msg}")
            import traceback
            traceback.print_exc()
        
        # Create minimal results to allow workflow to continue
        minimal_results = {
            "malicious_indicators": [],
            "suspicious_behaviors": [],
            "classification": "Unknown - analysis failed",
            "threat_level": "unknown",
            "confidence_level": 0,
            "iocs": [],
            "error": error_msg
        }
        
        return {
            "malware_analysis_results": minimal_results,
            "current_step": state.get("current_step", 0) + 1,
            "completed_steps": state.get("completed_steps", []) + ["malware_analysis"],
            "messages": [
                AIMessage(content=f"Malware analysis completed with errors: {error_msg}")
            ]
        }

def binary_summary_agent(state: WorkflowState) -> Dict:
    """
    Agent that generates a comprehensive summary of the binary based on analysis results
    and identifies suspicious APIs that don't match the binary's declared functionality
    """
    binary_path = state.get("binary_path")
    binary_functionality = state.get("binary_functionality", "")
    static_results = state.get("static_analysis_results", {})
    api_crossrefs = state.get("api_crossrefs_results", {})
    api_clusters = state.get("api_clustering_results", {})
    
    if os.environ.get('DEBUG'):
        print(f"Binary summary agent: Starting analysis")
    
    if not static_results:
        if os.environ.get('DEBUG'):
            print("Binary summary agent: Static analysis results not available")
        
        # Create minimal results to allow workflow to continue
        minimal_results = {
            "summary": "Unable to generate binary summary due to missing static analysis results."
        }
        
        return {
            "binary_summary_results": minimal_results,
            "current_step": state.get("current_step", 0) + 1,
            "completed_steps": state.get("completed_steps", []) + ["binary_summary"],
            "messages": [
                AIMessage(content="Binary summary analysis skipped: Static analysis results not available.")
            ]
        }
    
    try:
        # Initialize binary summary generator
        summary_generator = BinarySummaryGenerator()
        
        # Prepare analysis results for summary
        analysis_results = {
            "file_info": static_results.get("file_info", {}),
            "imports": static_results.get("imports", []),
            "strings": static_results.get("strings", {}),
            "api_crossrefs_results": api_crossrefs,
            "api_clustering_results": api_clusters
        }
        
        # Generate summary
        summary = summary_generator.generate_summary(
            analysis_results, 
            binary_functionality,
            binary_path
        )
        
        # Update state with results
        updated_state = {
            "binary_summary_results": summary,
            "current_step": state.get("current_step", 0) + 1,
            "completed_steps": state.get("completed_steps", []) + ["binary_summary"],
            "messages": [
                AIMessage(content="Binary summary analysis completed successfully.")
            ]
        }
        
        if os.environ.get('DEBUG'):
            print(f"Binary summary completed successfully. Current step now: {updated_state['current_step']}")
            print(f"Completed steps: {updated_state['completed_steps']}")
        
        return updated_state
    except Exception as e:
        error_msg = f"Error during binary summary analysis: {str(e)}"
        if os.environ.get('DEBUG'):
            print(f"Binary summary failed: {error_msg}")
            import traceback
            traceback.print_exc()
        
        # Create minimal results to allow workflow to continue
        minimal_results = {
            "summary": f"Error generating binary summary: {error_msg}",
            "error": error_msg
        }
        
        return {
            "binary_summary_results": minimal_results,
            "current_step": state.get("current_step", 0) + 1,
            "completed_steps": state.get("completed_steps", []) + ["binary_summary"],
            "messages": [
                AIMessage(content=f"Binary summary analysis completed with errors: {error_msg}")
            ]
        }

def comprehensive_string_analysis_agent(state: WorkflowState) -> Dict:
    """
    Agent that performs comprehensive string analysis using both validation and threat detection
    """
    static_results = state.get("static_analysis_results", {})
    
    if os.environ.get('DEBUG'):
        print(f"Comprehensive string analysis agent: Starting analysis")
    
    if not static_results:
        if os.environ.get('DEBUG'):
            print("Comprehensive string analysis agent: Static analysis results not available")
        
        # Create minimal results to allow workflow to continue
        minimal_results = {
            "string_validation": {"valid": {}, "invalid": {}},
            "threat_analysis": {"risk_score": 0, "summary": "No strings to analyze"},
            "combined_insights": "Unable to perform string analysis without static analysis results."
        }
        
        return {
            "comprehensive_string_results": minimal_results,
            "current_step": state.get("current_step", 0) + 1,
            "completed_steps": state.get("completed_steps", []) + ["comprehensive_string_analysis"],
            "messages": [
                AIMessage(content="Comprehensive string analysis skipped: Static analysis results not available.")
            ]
        }
    
    try:
        # Extract all strings from static analysis
        strings_data = static_results.get("strings", {})
        all_strings = []
        
        # Collect strings from all categories
        for category, string_list in strings_data.items():
            if isinstance(string_list, list):
                all_strings.extend(string_list)
        
        if not all_strings:
            minimal_results = {
                "string_validation": {"valid": {}, "invalid": {}},
                "threat_analysis": {"risk_score": 0, "summary": "No strings found"},
                "combined_insights": "No strings available for analysis."
            }
            
            return {
                "comprehensive_string_results": minimal_results,
                "current_step": state.get("current_step", 0) + 1,
                "completed_steps": state.get("completed_steps", []) + ["comprehensive_string_analysis"],
                "messages": [
                    AIMessage(content="Comprehensive string analysis completed: No strings found.")
                ]
            }
        
        # Initialize both analyzers
        smart_analyzer = SmartStringAnalyzer(use_llm=True)
        enhanced_analyzer = EnhancedStringAnalyzer(use_llm=True)
        
        print(f"Analyzing {len(all_strings)} strings with both validation and threat detection...")
        
        # Phase 1: Smart validation and categorization
        validation_results = smart_analyzer.analyze_strings(all_strings)
        
        # Phase 2: Enhanced threat detection
        threat_results = enhanced_analyzer.find_suspicious_strings(all_strings)
        
        # Phase 3: Combined analysis using LLM
        combined_insights = _generate_combined_string_insights(
            validation_results, 
            threat_results,
            static_results.get("file_info", {}).get("name", "unknown")
        )
        
        # Combine results
        comprehensive_results = {
            "string_validation": validation_results,
            "threat_analysis": threat_results,
            "combined_insights": combined_insights,
            "statistics": {
                "total_strings_analyzed": len(all_strings),
                "valid_strings": sum(len(strings) for strings in validation_results["valid"].values()),
                "invalid_strings": sum(len(strings) for strings in validation_results["invalid"].values()),
                "suspicious_strings": sum(len(strings) for strings in threat_results["suspicious_strings"].values()),
                "risk_score": threat_results.get("risk_score", 0)
            }
        }
        
        # Update state with results
        updated_state = {
            "comprehensive_string_results": comprehensive_results,
            "current_step": state.get("current_step", 0) + 1,
            "completed_steps": state.get("completed_steps", []) + ["comprehensive_string_analysis"],
            "messages": [
                AIMessage(content=f"Comprehensive string analysis completed. Analyzed {len(all_strings)} strings with risk score {threat_results.get('risk_score', 0)}/100.")
            ]
        }
        
        if os.environ.get('DEBUG'):
            print(f"Comprehensive string analysis completed successfully. Current step now: {updated_state['current_step']}")
            print(f"Risk score: {threat_results.get('risk_score', 0)}/100")
            print(f"Completed steps: {updated_state['completed_steps']}")
        
        return updated_state
        
    except Exception as e:
        error_msg = f"Error during comprehensive string analysis: {str(e)}"
        if os.environ.get('DEBUG'):
            print(f"Comprehensive string analysis failed: {error_msg}")
            import traceback
            traceback.print_exc()
        
        # Create minimal results to allow workflow to continue
        minimal_results = {
            "string_validation": {"valid": {}, "invalid": {}},
            "threat_analysis": {"risk_score": 0, "summary": f"Analysis failed: {error_msg}"},
            "combined_insights": f"Unable to complete string analysis due to error: {error_msg}",
            "error": error_msg
        }
        
        return {
            "comprehensive_string_results": minimal_results,
            "current_step": state.get("current_step", 0) + 1,
            "completed_steps": state.get("completed_steps", []) + ["comprehensive_string_analysis"],
            "messages": [
                AIMessage(content=f"Comprehensive string analysis completed with errors: {error_msg}")
            ]
        }

def _generate_combined_string_insights(validation_results: Dict[str, Any], 
                                     threat_results: Dict[str, Any],
                                     binary_name: str) -> str:
    """
    Generate combined insights from both string analysis approaches
    
    Args:
        validation_results: Results from smart string validation
        threat_results: Results from enhanced threat detection
        binary_name: Name of the binary being analyzed
        
    Returns:
        Combined insights string
    """
    try:
        system_prompt = """You are a combined string analysis expert. Analyze both the validation results and threat detection results 
        to provide comprehensive insights about the strings found in a binary file."""
        
        analysis_data = {
            "binary_name": binary_name,
            "validation_summary": {
                "valid_strings": sum(len(strings) for strings in validation_results["valid"].values()),
                "invalid_strings": sum(len(strings) for strings in validation_results["invalid"].values()),
                "valid_categories": {k: len(v) for k, v in validation_results["valid"].items() if v},
                "invalid_categories": {k: len(v) for k, v in validation_results["invalid"].items() if v}
            },
            "threat_summary": {
                "risk_score": threat_results.get("risk_score", 0),
                "suspicious_categories": {k: len(v) for k, v in threat_results["suspicious_strings"].items() if v},
                "high_risk_count": len(threat_results.get("high_risk_strings", [])),
                "encoded_strings_count": len(threat_results.get("encoded_strings", []))
            }
        }
        
        user_prompt = f"""Analyze this comprehensive string analysis data:
        
        {json.dumps(analysis_data, indent=2)}
        
        Provide insights covering:
        1. Quality Assessment: How well-formed are the strings?
        2. Security Assessment: What threat indicators were found?
        3. Behavioral Indicators: What do the strings suggest about binary behavior?
        4. Risk Correlation: How do validation failures correlate with threats?
        5. Overall Assessment: Combined view of string analysis findings
        
        Provide a detailed analysis that combines both validation and threat perspectives."""
        
        response = llm_handler.query(system_prompt, user_prompt, request_type="string_analysis_combined")
        return response
        
    except Exception as e:
        return f"Failed to generate combined insights: {str(e)}"

def generate_summary_agent(state: WorkflowState) -> Dict:
    """
    Agent that generates a summary of the analysis
    """
    static_results = state.get("static_analysis_results", {})
    capabilities = state.get("capabilities", {})
    malware_analysis = state.get("malware_analysis_results", {})
    binary_summary = state.get("binary_summary_results", {})
    api_analysis = state.get("api_analysis_results", {})
    dynamic_results = state.get("dynamic_analysis_results", {})
    
    if os.environ.get('DEBUG'):
        print(f"Summary generation agent: Starting final summary")
    
    try:
        # Prepare LIGHTWEIGHT analysis data for summary to avoid token limits
        analysis_data = {
            "binary_info": {
                "name": static_results.get("file_info", {}).get("name", "unknown"),
                "size": static_results.get("file_info", {}).get("size", 0)
            },
            "static_analysis": {
                "imports_count": len(static_results.get("imports", [])),
                "functions_count": len(static_results.get("functions", [])),
                "strings_count": {k: len(v) if isinstance(v, list) else 0 for k, v in static_results.get("strings", {}).items()},
                "sample_imports": static_results.get("imports", [])[:10],  # Only first 10 imports
                "has_error": "error" in static_results
            },
            "capabilities_summary": {
                "core_functionality": str(capabilities.get("core_functionality", ""))[:200] if capabilities.get("core_functionality") else "",
                "network_capabilities": str(capabilities.get("network_capabilities", ""))[:200] if capabilities.get("network_capabilities") else "",
                "file_system_operations": str(capabilities.get("file_system_operations", ""))[:200] if capabilities.get("file_system_operations") else ""
            },
            "malware_analysis_summary": {
                "classification": malware_analysis.get("classification", "unknown") if malware_analysis else "not_analyzed",
                "threat_level": malware_analysis.get("threat_level", "unknown") if malware_analysis else "unknown",
                "has_indicators": len(malware_analysis.get("malicious_indicators", [])) > 0 if malware_analysis else False
            },
            "api_analysis": {
                "referenced_apis_count": len(api_analysis.get("referenced_apis", [])),
                "filtered_functions_count": len(api_analysis.get("filtered_functions", []))
            },
            "dynamic_analysis": {
                "status": "completed" if dynamic_results and not dynamic_results.get("error") else "failed_or_skipped"
            }
        }
        
        # Generate final summary using LLM
        system_prompt = """You are a binary analysis expert. Create a comprehensive final summary 
        of the binary analysis based on all the analysis results provided."""
        
        user_prompt = f"""Generate a comprehensive final summary based on the following binary analysis results:
        
        {json.dumps(analysis_data, indent=2)}
        
        Provide a structured summary including:
        1. Executive Summary - High-level overview of the binary
        2. Technical Analysis - Key technical findings
        3. Security Assessment - Risk level and potential threats
        4. Capabilities Identified - What the binary can do
        5. Recommendations - Next steps or actions to take
        
        Return a JSON object with these sections."""
        
        final_summary = llm_handler.get_json_response(system_prompt, user_prompt)
        
        # Update state with final summary and mark analysis as complete
        updated_state = {
            "final_summary": final_summary,
            "analysis_complete": True,
            "current_step": state.get("current_step", 0) + 1,
            "completed_steps": state.get("completed_steps", []) + ["generate_summary"],
            "messages": [
                AIMessage(content="Final summary generation completed successfully. Analysis is now complete.")
            ]
        }
        
        if os.environ.get('DEBUG'):
            print(f"Summary generation completed successfully. Current step now: {updated_state['current_step']}")
            print(f"Completed steps: {updated_state['completed_steps']}")
        
        return updated_state
        
    except Exception as e:
        error_msg = f"Error during summary generation: {str(e)}"
        if os.environ.get('DEBUG'):
            print(f"Summary generation failed: {error_msg}")
            import traceback
            traceback.print_exc()
        
        # Create minimal summary to allow workflow to complete
        minimal_summary = {
            "executive_summary": f"Analysis completed with errors: {error_msg}",
            "technical_analysis": "Unable to generate technical analysis due to errors",
            "security_assessment": "Unknown - analysis failed",
            "capabilities_identified": [],
            "recommendations": ["Review analysis errors and retry"],
            "error": error_msg
        }
        
        return {
            "final_summary": minimal_summary,
            "analysis_complete": True,
            "current_step": state.get("current_step", 0) + 1,
            "completed_steps": state.get("completed_steps", []) + ["generate_summary"],
            "messages": [
                AIMessage(content=f"Final summary generation completed with errors: {error_msg}")
            ]
        }

# Workflow routing functions
def should_continue(state: WorkflowState) -> str:
    """
    Determine the next step in the workflow based on the current state
    """
    # If this is a chatbot interaction, route to chatbot
    if state.get("user_message") and state.get("analysis_complete"):
        return "chatbot"
    
    plan = state.get("plan", [])
    current_step = state.get("current_step", 0)
    
    if os.environ.get('DEBUG'):
        print(f"Workflow router: Current step {current_step}, Plan: {plan}")
    
    # Check if we've completed all steps
    if current_step >= len(plan):
        if os.environ.get('DEBUG'):
            print("Workflow router: All steps completed, ending workflow")
        return END
    
    # Get the next step from the plan
    next_step = plan[current_step]
    
    if os.environ.get('DEBUG'):
        print(f"Workflow router: Next step is {next_step}")
    
    return next_step

def save_graph_to_disk(data, filename):
    """
    Save workflow graph to a file on disk.
    
    Args:
        data: The graph data to save.
        filename (str): The name of the file to save the data to.
    """
    with open(filename, 'wb') as file:
        file.write(data)
    file.close()

def route_to_next_agent(state: WorkflowState) -> str:
    """
    Route to the appropriate agent based on the current step
    """
    plan = state.get("plan", [])
    current_step = state.get("current_step", 0)
    
    if current_step >= len(plan):
        return END
    
    next_step = plan[current_step]
    
    # Map plan steps to agent functions
    agent_mapping = {
        "static_analysis": "static_analysis_agent",
        "api_crossrefs": "api_crossrefs_agent", 
        "api_clustering": "api_clustering_agent",
        "api_analysis": "api_analysis_agent",
        "dynamic_analysis": "dynamic_analysis_agent",
        "capabilities_analysis": "capabilities_analysis_agent",
        "malware_analysis": "malware_analysis_agent",
        "comprehensive_string_analysis": "comprehensive_string_analysis_agent",
        "binary_summary": "binary_summary_agent",
        "generate_summary": "generate_summary_agent"
    }
    
    return agent_mapping.get(next_step, END)

# Create the workflow graph
def create_workflow() -> StateGraph:
    """
    Create and configure the LangGraph workflow
    """
    # Create the state graph
    workflow = StateGraph(WorkflowState)
    
    # Add nodes for each agent
    workflow.add_node("supervisor", supervisor_agent)
    workflow.add_node("planning", planning_agent)
    workflow.add_node("static_analysis_agent", static_analysis_agent)
    workflow.add_node("api_crossrefs_agent", api_crossrefs_agent)
    workflow.add_node("api_clustering_agent", api_clustering_agent)
    workflow.add_node("api_analysis_agent", api_analysis_agent)
    workflow.add_node("dynamic_analysis_agent", dynamic_analysis_agent)  # Keep node but disabled functionality
    workflow.add_node("capabilities_analysis_agent", capabilities_analysis_agent)
    workflow.add_node("malware_analysis_agent", malware_analysis_agent)
    workflow.add_node("comprehensive_string_analysis_agent", comprehensive_string_analysis_agent)
    workflow.add_node("binary_summary_agent", binary_summary_agent)
    workflow.add_node("generate_summary_agent", generate_summary_agent)
    workflow.add_node("chatbot", chatbot_agent)
    
    # Set entry point
    workflow.set_entry_point("supervisor")
    
    # Add conditional edges
    workflow.add_conditional_edges(
        "supervisor",
        lambda state: "chatbot" if state.get("route_to") == "chatbot" else ("planning" if state.get("current_step") == 0 else END),
        {
            "chatbot": "chatbot",
            "planning": "planning",
            END: END
        }
    )
    
    workflow.add_conditional_edges(
        "planning",
        should_continue,
        {
            "static_analysis": "static_analysis_agent",
            "api_crossrefs": "api_crossrefs_agent",
            "api_clustering": "api_clustering_agent", 
            "api_analysis": "api_analysis_agent",
            "dynamic_analysis": "dynamic_analysis_agent",
            "capabilities_analysis": "capabilities_analysis_agent",
            "malware_analysis": "malware_analysis_agent",
            "comprehensive_string_analysis": "comprehensive_string_analysis_agent",
            "binary_summary": "binary_summary_agent",
            "generate_summary": "generate_summary_agent",
            "chatbot": "chatbot",
            END: END
        }
    )
    
    # Add conditional edges for each agent to route to the next step
    for agent_name in ["static_analysis_agent", "api_crossrefs_agent", "api_clustering_agent", 
                       "api_analysis_agent", "dynamic_analysis_agent", "capabilities_analysis_agent",
                       "malware_analysis_agent", "comprehensive_string_analysis_agent", 
                       "binary_summary_agent", "generate_summary_agent"]:
        workflow.add_conditional_edges(
            agent_name,
            should_continue,
            {
                "static_analysis": "static_analysis_agent",
                "api_crossrefs": "api_crossrefs_agent",
                "api_clustering": "api_clustering_agent",
                "api_analysis": "api_analysis_agent", 
                "dynamic_analysis": "dynamic_analysis_agent",
                "capabilities_analysis": "capabilities_analysis_agent",
                "malware_analysis": "malware_analysis_agent",
                "comprehensive_string_analysis": "comprehensive_string_analysis_agent",
                "binary_summary": "binary_summary_agent",
                "generate_summary": "generate_summary_agent",
                "chatbot": "chatbot",
                END: END
            }
        )
    
    # Chatbot always ends the workflow
    workflow.add_edge("chatbot", END)
    
    return workflow

# Main execution function
def run_workflow(binary_path: str, binary_functionality: str, goal: str, user_message: Optional[str] = None) -> Dict[str, Any]:
    """
    Run the complete workflow for binary analysis with timing and metrics collection
    
    Args:
        binary_path: Path to the binary file to analyze
        binary_functionality: Description of the binary's intended functionality
        goal: Analysis goal (e.g., 'capabilities', 'malware analysis')
        user_message: Optional user message for chatbot interactions
        
    Returns:
        Complete analysis results with timing and LLM usage metrics
    """
    # Initialize timing collector for the workflow
    workflow_timer = TimingCollector()
    workflow_timer.start_timer("total_workflow", {
        "binary_path": binary_path,
        "goal": goal,
        "user_message_provided": user_message is not None
    })
    
    # Reset LLM handler metrics for this analysis
    llm_handler.reset_metrics()
    
    # Create workflow
    workflow = create_workflow()
    app = workflow.compile()
    # graph = workflow.compile()
    # graph.get_graph().draw_mermaid_png()
    # sys.exit(0)
    
    # Initial state
    initial_state = {
        "binary_path": binary_path,
        "binary_functionality": binary_functionality,
        "goal": goal,
        "user_message": user_message,
        "messages": [HumanMessage(content=user_message if user_message else f"Analyze binary: {binary_path}")],
        "completed_steps": []
    }
    
    if os.environ.get('DEBUG'):
        print(f"Starting workflow for binary: {binary_path}")
        print(f"Goal: {goal}")
        print(f"Functionality: {binary_functionality}")
        if user_message:
            print(f"User message: {user_message}")
    
    # Run the workflow
    try:
        workflow_timer.start_timer("workflow_execution", {
            "steps_planned": len(goal.split())  # Rough estimate
        })
        
        final_state = app.invoke(initial_state)
        
        workflow_timer.end_timer("workflow_execution")
        workflow_timer.end_timer("total_workflow")
        
        # Get LLM metrics from the handler
        llm_metrics = llm_handler.get_timing_metrics()
        
        # Get workflow timing metrics
        workflow_metrics = workflow_timer.get_summary()
        
        # Combine metrics
        combined_metrics = {
            "workflow_timing": workflow_metrics["timing_metrics"],
            "workflow_session": workflow_metrics["session_info"],
            "llm_usage_summary": llm_metrics["llm_usage_summary"],
            "llm_model_breakdown": llm_metrics["llm_model_breakdown"],
            "detailed_llm_usage": llm_metrics["detailed_llm_usage"]
        }
        
        # Add metrics to final state
        final_state["timing_metrics"] = combined_metrics
        
        if os.environ.get('DEBUG'):
            print("Workflow completed successfully")
            print(f"Completed steps: {final_state.get('completed_steps', [])}")
            print(f"Total time: {workflow_metrics['session_info']['total_session_time_minutes']:.2f} minutes")
            print(f"Total LLM cost: ${llm_metrics['llm_usage_summary']['total_cost_usd']:.4f}")
        
        # Print summary metrics
        print(f"\n=== Analysis Complete ===")
        print(f"Total time: {workflow_metrics['session_info']['total_session_time_minutes']:.2f} minutes")
        print(f"LLM requests: {llm_metrics['llm_usage_summary']['total_requests']}")
        print(f"Total tokens: {llm_metrics['llm_usage_summary']['total_tokens']:,}")
        print(f"Total cost: ${llm_metrics['llm_usage_summary']['total_cost_usd']:.4f}")
        
        # AUTOMATIC RESULT SAVING - Save complete analysis results to specified directory
        try:
            # Create save directory if it doesn't exist
            save_directory = "/Users/maitha/Desktop/ORCA_Evaluations_October/ORCA-Newrun-NoDynamic"
            Path(save_directory).mkdir(parents=True, exist_ok=True)
            
            # Generate filename from binary path
            binary_name = Path(binary_path).name
            save_filename = f"{binary_name}.json"
            save_path = Path(save_directory) / save_filename
            
            # Create serializable version of complete analysis results
            serializable_results = {
                "binary_path": final_state.get("binary_path"),
                "binary_functionality": final_state.get("binary_functionality"), 
                "goal": final_state.get("goal"),
                "analysis_complete": final_state.get("analysis_complete"),
                "completed_steps": final_state.get("completed_steps", []),
                
                # Core analysis results
                "static_analysis_results": final_state.get("static_analysis_results"),
                "api_crossrefs_results": final_state.get("api_crossrefs_results"),
                "api_clustering_results": final_state.get("api_clustering_results"),
                "api_analysis_results": final_state.get("api_analysis_results"),
                "dynamic_analysis_results": final_state.get("dynamic_analysis_results"),
                "comprehensive_string_results": final_state.get("comprehensive_string_results"),
                
                # Analysis outputs
                "capabilities": final_state.get("capabilities"),
                "malware_analysis_results": final_state.get("malware_analysis_results"),
                "binary_summary_results": final_state.get("binary_summary_results"),
                "final_summary": final_state.get("final_summary"),
                
                # Metadata
                "timing_metrics": combined_metrics,
                "messages": [{"type": msg.type if hasattr(msg, 'type') else 'unknown', 
                             "content": msg.content if hasattr(msg, 'content') else str(msg)} 
                            for msg in final_state.get("messages", [])],
                
                # Analysis metadata
                "metadata": {
                    "analysis_timestamp": workflow_timer.session_start if hasattr(workflow_timer, 'session_start') else None,
                    "orca_version": "orca",
                    "total_steps_completed": len(final_state.get("completed_steps", [])),
                    "analysis_successful": final_state.get("analysis_complete", False)
                }
            }
            
            # Save results to JSON file
            with open(save_path, 'w') as f:
                json.dump(serializable_results, f, indent=2, default=str)
            
            print(f"\n=== Results Automatically Saved ===")
            print(f"Analysis results saved to: {save_path}")
            print(f"File size: {save_path.stat().st_size:,} bytes")
            
            # Add save info to final state
            final_state["save_info"] = {
                "saved": True,
                "save_path": str(save_path),
                "save_directory": save_directory,
                "filename": save_filename
            }
            
        except Exception as save_error:
            print(f"\nWarning: Failed to automatically save results: {str(save_error)}")
            # Add save error info to final state but don't fail the analysis
            final_state["save_info"] = {
                "saved": False,
                "error": str(save_error),
                "attempted_path": str(Path(save_directory) / save_filename) if 'save_filename' in locals() else "unknown"
            }
        
        return final_state
        
    except Exception as e:
        # End timers even on failure
        try:
            workflow_timer.end_timer("workflow_execution")
        except:
            pass
        try:
            workflow_timer.end_timer("total_workflow")
        except:
            pass
        
        error_msg = f"Workflow execution failed: {str(e)}"
        if os.environ.get('DEBUG'):
            print(error_msg)
            import traceback
            traceback.print_exc()
        
        # Still include partial metrics even on failure
        try:
            llm_metrics = llm_handler.get_timing_metrics()
            workflow_metrics = workflow_timer.get_summary()
            
            combined_metrics = {
                "workflow_timing": workflow_metrics["timing_metrics"],
                "workflow_session": workflow_metrics["session_info"],
                "llm_usage_summary": llm_metrics["llm_usage_summary"],
                "llm_model_breakdown": llm_metrics["llm_model_breakdown"],
                "detailed_llm_usage": llm_metrics["detailed_llm_usage"],
                "error": "Analysis failed - partial metrics only"
            }
        except:
            combined_metrics = {"error": "Failed to collect metrics"}
        
        return {
            "error": error_msg,
            "completed_steps": initial_state.get("completed_steps", []),
            "messages": [AIMessage(content=error_msg)],
            "timing_metrics": combined_metrics
        }

if __name__ == "__main__":
    # Example usage
    import sys
    
    if len(sys.argv) < 4:
        print("Usage: python workflow.py <binary_path> <binary_functionality> <goal> [user_message]")
        sys.exit(1)
    
    binary_path = sys.argv[1]
    binary_functionality = sys.argv[2]
    goal = sys.argv[3]
    user_message = sys.argv[4] if len(sys.argv) > 4 else None
    
    # Enable debug mode
    os.environ['DEBUG'] = '1'
    
    # Run workflow
    results = run_workflow(binary_path, binary_functionality, goal, user_message)
    
    # Print results
    print("\n" + "="*50)
    print("WORKFLOW RESULTS")
    print("="*50)
    print(json.dumps(results, indent=2, default=str))
