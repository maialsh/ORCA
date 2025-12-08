#!/usr/bin/env python3
"""
Debug script for BinSleuth workflow
"""
import os
import sys
import json
from pathlib import Path

# Add the current directory to the Python path
current_dir = os.path.dirname(os.path.abspath(__file__))
sys.path.insert(0, current_dir)

# Import workflow module
import workflow

def main():
    """Main function"""
    # Set DEBUG environment variable
    os.environ['DEBUG'] = '1'
    
    # Check if OpenAI API key is set
    if not os.environ.get('OPENAI_API_KEY'):
        print("Error: OPENAI_API_KEY environment variable is not set")
        print("Please set it before running this script")
        sys.exit(1)
    
    # Define test parameters
    binary_path = "samples/nslookupbin"
    binary_functionality = "Network utility binary, nslookup"
    goal = "capabilities"
    
    # Check if binary exists
    if not Path(binary_path).exists():
        print(f"Error: Binary file not found: {binary_path}")
        sys.exit(1)
    
    print(f"Starting debug analysis of {binary_path}...")
    print(f"Functionality: {binary_functionality}")
    print(f"Goal: {goal}")
    print("\nThis may take some time. Please wait...\n")
    
    try:
        # Run the workflow
        state = workflow.run_workflow(
            binary_path=binary_path,
            binary_functionality=binary_functionality,
            goal=goal
        )
        
        # Print state
        print("\n=== Workflow State ===\n")
        print(f"Binary: {state.get('binary_path')}")
        print(f"Functionality: {state.get('binary_functionality')}")
        print(f"Goal: {state.get('goal')}")
        print(f"Plan: {state.get('plan')}")
        print(f"Current step: {state.get('current_step')}")
        print(f"Completed steps: {state.get('completed_steps')}")
        
        # Save results
        output_file = "debug_result.json"
        
        # Create a serializable version of the state
        serializable_state = {
            "binary_path": state.get("binary_path"),
            "binary_functionality": state.get("binary_functionality"),
            "goal": state.get("goal"),
            "plan": state.get("plan"),
            "current_step": state.get("current_step"),
            "completed_steps": state.get("completed_steps"),
            "static_analysis_results": state.get("static_analysis_results"),
            "api_crossrefs_results": state.get("api_crossrefs_results"),
            "api_clustering_results": state.get("api_clustering_results"),
            "capabilities": state.get("capabilities")
        }
        
        # Remove binary_view as it's not serializable
        if "binary_view" in serializable_state:
            del serializable_state["binary_view"]
        
        # Save to file
        with open(output_file, 'w') as f:
            json.dump(serializable_state, f, indent=2)
        
        print(f"\nResults saved to {output_file}")
        
    except Exception as e:
        print(f"Error during analysis: {str(e)}")
        import traceback
        traceback.print_exc()
        sys.exit(1)

if __name__ == "__main__":
    main()
