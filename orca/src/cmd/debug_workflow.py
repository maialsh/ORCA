#!/usr/bin/env python3
"""
Debug script for BinSleuth workflow
"""
import os
import sys
import json
from pathlib import Path

# Import workflow module
from workflow import run_workflow, WorkflowState

def main():
    """Main function"""
    # Check command line arguments
    if len(sys.argv) < 2:
        print("Usage: python debug_workflow.py <binary_path>")
        sys.exit(1)
    
    binary_path = Path(sys.argv[1])
    if not binary_path.exists():
        print(f"Error: Binary file not found: {binary_path}")
        sys.exit(1)
    
    # Set up test parameters
    binary_functionality = "Network utility binary, nslookup"
    goal = "capabilities"
    
    print(f"Starting debug analysis of {binary_path}...")
    print(f"Functionality: {binary_functionality}")
    print(f"Goal: {goal}")
    
    try:
        # Enable debug logging
        os.environ['DEBUG'] = '1'
        
        # Run the workflow with verbose output
        print("\nRunning workflow with verbose output...")
        state = run_workflow(
            binary_path=str(binary_path),
            binary_functionality=binary_functionality,
            goal=goal
        )
        
        # Print detailed state information
        print("\n=== Workflow State Details ===\n")
        
        # Print basic info
        print(f"Binary: {state.get('binary_path')}")
        print(f"Functionality: {state.get('binary_functionality')}")
        print(f"Goal: {state.get('goal')}")
        
        # Print plan
        print(f"\nPlan: {state.get('plan')}")
        print(f"Current step: {state.get('current_step')}")
        
        # Print completed steps
        completed_steps = state.get("completed_steps", [])
        print(f"Completed steps: {completed_steps}")
        
        # Check for errors in each step
        print("\n=== Analysis Results ===\n")
        
        # Static analysis
        if state.get("static_analysis_results"):
            print("Static analysis: SUCCESS")
            if "error" in state.get("static_analysis_results", {}):
                print(f"  Error: {state['static_analysis_results']['error']}")
        else:
            print("Static analysis: FAILED or NOT RUN")
        
        # API cross-references
        if state.get("api_crossrefs_results"):
            print("API cross-references: SUCCESS")
        else:
            print("API cross-references: FAILED or NOT RUN")
        
        # API clustering
        if state.get("api_clustering_results"):
            print("API clustering: SUCCESS")
        else:
            print("API clustering: FAILED or NOT RUN")
        
        # Capabilities
        if state.get("capabilities"):
            print("Capabilities analysis: SUCCESS")
        else:
            print("Capabilities analysis: FAILED or NOT RUN")
        
        # Save detailed state to file
        output_file = "debug_state.json"
        
        # Create a serializable version of the state
        def clean_for_json(obj):
            if isinstance(obj, dict):
                return {k: clean_for_json(v) for k, v in obj.items() if k != "binary_view" and k != "messages"}
            elif isinstance(obj, list):
                return [clean_for_json(item) for item in obj]
            elif hasattr(obj, '__dict__'):
                return str(obj)  # Convert objects to string representation
            else:
                return obj
        
        # Clean the state for JSON serialization
        serializable_state = clean_for_json(state)
        
        # Save to file
        with open(output_file, 'w') as f:
            json.dump(serializable_state, f, indent=2)
        
        print(f"\nDetailed state saved to {output_file}")
        
    except Exception as e:
        print(f"Error during debug analysis: {str(e)}")
        import traceback
        traceback.print_exc()
        sys.exit(1)

if __name__ == "__main__":
    main()
