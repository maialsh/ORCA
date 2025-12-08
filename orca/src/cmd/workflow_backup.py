"""
Multi-agentic workflow for binary analysis using Langgraph
Implements a supervisor agent, planning agent, and specialized analysis agents
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

# Import ORCA modules
from config import config
from llm_module import llm_handler
from smart_static_analysis import SmartStaticAnalyzer
from api_crossrefs import ApiCrossReferenceTool
from api_clustering import FunctionClusteringTool
from binary_summary import BinarySummaryGenerator
from api_analysis_agent import ApiAnalysisAgent
from enhanced_string_analysis import EnhancedStringAnalyzer
from utils import _clean_json
from sandbox import DockerSandbox

# Define the workflow state
class WorkflowState(TypedDict):
    # Input parameters
    binary_path: Optional[str]
    binary_functionality: Optional[str]
    goal: Optional[str]
    
    # Analysis state
    binary_view: Optional[Any]
    static_analysis_results: Optional[Dict[str, Any]]
    api_crossrefs_results: Optional[Dict[str, Any]]
    api_clustering_results: Optional[Dict[str, Any]]
    api_analysis_results: Optional[Dict[str, Any]]
    dynamic_analysis_results: Optional[Dict[str, Any]]
    
    # Workflow state
    plan: Optional[List[str]]
    current_step: Optional[int]
    completed_steps: List[str]
    
    # Output state
    capabilities: Optional[Dict[str, Any]]
    malware_analysis_results: Optional[Dict[str, Any]]
    binary_summary_results: Optional[Dict[str, Any]]
    
    # Chat history
    messages: Annotated[List[AnyMessage], add_messages]

# Initialize LLM
llm = ChatOpenAI(
    model=config.get('llm.model'),
    temperature=config.get('llm.temperature'),
    api_key=os.environ.get('OPENAI_API_KEY')
)

# Agent definitions
def supervisor_agent(state: WorkflowState) -> Dict:
    """
    Supervisor agent that checks if required information is provided
    and manages the overall workflow
    """
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
    
    # Dynamic analysis disabled by user request
    # if "malware" in goal or "malicious" in goal:
    #     plan.append("dynamic_analysis")
    
    if "capabilities" in goal:
        plan.append("capabilities_analysis")
    
    if "malware" in goal or "malicious" in goal:
        plan.append("malware_analysis")
    
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

def dynamic_analysis_agent(state: WorkflowState) -> Dict:
    """
    Agent that performs dynamic analysis on the binary
    """
    binary_path = state.get("binary_path")
    
    try:
        # Initialize sandbox
        sandbox = DockerSandbox()
        error = sandbox.start(binary_path)
        
        if error:
            return {
                "dynamic_analysis_results": {"error": error},
                "current_step": state.get("current_step", 0) + 1,
                "completed_steps": state.get("completed_steps", []) + ["dynamic_analysis"],
                "messages": [
                    AIMessage(content=f"Error starting dynamic analysis sandbox: {error}")
                ]
            }
        
        # Run analysis
        results = sandbox.run_analysis()
        
        # Process syscalls for interesting patterns
        suspicious_syscalls = []
        for line in results.get('syscalls', []):
            if any(s in line for s in ["execve", "ptrace", "connect", "bind", "listen"]):
                suspicious_syscalls.append(line)
        
        results["suspicious_syscalls"] = suspicious_syscalls[:50]  # Limit output
        
        # Update state with results
        return {
            "dynamic_analysis_results": results,
            "current_step": state.get("current_step", 0) + 1,
            "completed_steps": state.get("completed_steps", []) + ["dynamic_analysis"],
            "messages": [
                AIMessage(content="Dynamic analysis completed successfully.")
            ]
        }
    except Exception as e:
        return {
            "messages": [
                AIMessage(content=f"Error during dynamic analysis: {str(e)}")
            ]
        }
    finally:
        if 'sandbox' in locals():
            sandbox.cleanup()

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
            "imports": static_results.get("imports", []),
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

def generate_summary_agent(state: WorkflowState) -> Dict:
    """
    Agent that generates a summary of the analysis
    """
    static_results = state.get("static_analysis_results", {})
    capabilities = state.get("capabilities", {})
    malware_analysis = state.get("malware_analysis_results", {})
    
    if os.environ.get('DEBUG'):
        print(f"Summary generation agent: Starting analysis")
    
    if not static_results:
        if os.environ.get('DEBUG'):
            print("Summary generation agent: Static analysis
