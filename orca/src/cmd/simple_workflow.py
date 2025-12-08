"""
Simplified workflow for binary analysis
Uses SimpleStaticAnalyzer instead of SmartStaticAnalyzer to avoid Binary Ninja dependency
"""
import os
import sys
import json
from typing import Dict, List, Any, Optional
from pathlib import Path

# Import BinSleuth modules
from config import config
from llm_module import llm_handler
from simple_static_analysis import SimpleStaticAnalyzer

def run_workflow(
    binary_path: str,
    binary_functionality: str,
    goal: str,
    user_message: Optional[str] = None
) -> Dict[str, Any]:
    """
    Run a simplified binary analysis workflow
    
    Args:
        binary_path: Path to the binary file
        binary_functionality: Description of the binary's functionality
        goal: Analysis goal (e.g., 'capabilities', 'malware_analysis')
        user_message: Optional user message for the chatbot
        
    Returns:
        Dictionary containing the workflow state
    """
    # Initialize state
    state = {
        "binary_path": binary_path,
        "binary_functionality": binary_functionality,
        "goal": goal,
        "static_analysis_results": None,
        "api_crossrefs_results": None,
        "api_clustering_results": None,
        "dynamic_analysis_results": None,
        "capabilities": None,
        "malware_analysis_results": None,
        "completed_steps": [],
        "messages": []
    }
    
    # Check if binary exists
    if not os.path.exists(binary_path):
        print(f"Error: Binary file not found: {binary_path}")
        state["error"] = f"Binary file not found: {binary_path}"
        return state
    
    try:
        # Step 1: Static Analysis
        print(f"Performing static analysis on {binary_path}...")
        analyzer = SimpleStaticAnalyzer()
        static_results = analyzer.analyze(Path(binary_path))
        state["static_analysis_results"] = static_results
        state["completed_steps"].append("static_analysis")
        print("Static analysis completed.")
        
        # Step 2: Capabilities Analysis
        if "capabilities" in goal.lower():
            print("Analyzing binary capabilities...")
            capabilities = analyze_capabilities(static_results, binary_functionality)
            state["capabilities"] = capabilities
            state["completed_steps"].append("capabilities_analysis")
            print("Capabilities analysis completed.")
        
        # Step 3: Generate Summary
        if user_message:
            print(f"Answering question: {user_message}")
            answer = answer_question(state, user_message)
            state["messages"].append({"type": "human", "content": user_message})
            state["messages"].append({"type": "ai", "content": answer})
            print("Question answered.")
        
    except Exception as e:
        error_msg = f"Error during analysis: {str(e)}"
        print(error_msg)
        state["error"] = error_msg
        import traceback
        traceback.print_exc()
    
    return state

def analyze_capabilities(static_results: Dict[str, Any], binary_functionality: str) -> Dict[str, Any]:
    """
    Analyze binary capabilities using LLM
    
    Args:
        static_results: Static analysis results
        binary_functionality: Description of the binary's functionality
        
    Returns:
        Dictionary containing capabilities analysis
    """
    system_prompt = """You are a binary analysis expert specializing in determining the capabilities of binary files.
    Analyze the provided information and identify the key capabilities of the binary."""
    
    # Prepare data for analysis
    analysis_data = {
        "binary_info": static_results.get("file_info", {}),
        "imports": static_results.get("imports", []),
        "strings": static_results.get("strings", {}),
        "binary_functionality": binary_functionality
    }
    
    user_prompt = f"""Analyze the following binary analysis data and determine the capabilities of the binary:
    
    {json.dumps(analysis_data, indent=2)}
    
    The binary is described as: "{binary_functionality}"
    
    Provide a comprehensive analysis of the binary's capabilities, including:
    1. Core functionality
    2. Network capabilities
    3. File system operations
    4. Process manipulation
    5. Persistence mechanisms
    6. Anti-analysis techniques
    7. Other notable capabilities
    
    Return a JSON object with these categories and your findings."""
    
    try:
        # Get capabilities analysis from LLM
        capabilities = llm_handler.get_json_response(system_prompt, user_prompt)
        return capabilities
    except Exception as e:
        print(f"Error during capabilities analysis: {str(e)}")
        return {
            "core_functionality": "Unknown - analysis failed",
            "network_capabilities": [],
            "file_system_operations": [],
            "process_manipulation": [],
            "persistence_mechanisms": [],
            "anti_analysis_techniques": [],
            "other_capabilities": [],
            "error": str(e)
        }

def answer_question(state: Dict[str, Any], question: str) -> str:
    """
    Answer a question about the binary
    
    Args:
        state: Current workflow state
        question: User's question
        
    Returns:
        Answer to the question
    """
    system_prompt = """You are a binary analysis expert chatbot. Answer the user's question about the analyzed binary
    based on the provided analysis results. Be concise, accurate, and helpful."""
    
    # Prepare context for the chatbot
    static_results = state.get("static_analysis_results", {})
    capabilities = state.get("capabilities", {})
    
    context_data = {
        "binary_info": static_results.get("file_info", {}),
        "imports": static_results.get("imports", []),
        "strings": static_results.get("strings", {}),
        "capabilities": capabilities,
        "binary_functionality": state.get("binary_functionality", "")
    }
    
    user_prompt = f"""The user asked: "{question}"
    
    Here is the binary analysis data to help you answer:
    
    {json.dumps(context_data, indent=2)}
    
    Provide a helpful response to the user's question based on this data."""
    
    try:
        # Get response from LLM
        response = llm_handler.query(system_prompt, user_prompt)
        return response
    except Exception as e:
        return f"Error processing your question: {str(e)}"

if __name__ == "__main__":
    if len(sys.argv) < 4:
        print("Usage: python simple_workflow.py <binary_path> <binary_functionality> <goal> [question]")
        sys.exit(1)
    
    binary_path = sys.argv[1]
    binary_functionality = sys.argv[2]
    goal = sys.argv[3]
    question = sys.argv[4] if len(sys.argv) > 4 else None
    
    result = run_workflow(binary_path, binary_functionality, goal, question)
    
    # Print the final messages
    for message in result.get("messages", []):
        if message["type"] == "ai":
            print(f"AI: {message['content']}")
        elif message["type"] == "human":
            print(f"Human: {message['content']}")
    
    # Save results to file
    output_file = "simple_workflow_result.json"
    with open(output_file, "w") as f:
        json.dump(result, f, indent=2)
    
    print(f"Results saved to {output_file}")
