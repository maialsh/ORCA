#!/usr/bin/env python3
"""
Simple test script for ORCA workflow
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
        print("Usage: python simple_test_workflow.py <binary_path>")
        sys.exit(1)
    
    binary_path = Path(sys.argv[1])
    if not binary_path.exists():
        print(f"Error: Binary file not found: {binary_path}")
        sys.exit(1)
    
    # Set up test parameters
    binary_functionality = "Network utility binary, nslookup"
    goal = "capabilities"
    
    print(f"Starting analysis of {binary_path}...")
    print(f"Functionality: {binary_functionality}")
    print(f"Goal: {goal}")
    
    # Enable debug logging
    os.environ['DEBUG'] = '1'
    
    try:
        # Initialize state manually
        state = WorkflowState(
            binary_path=str(binary_path),
            binary_functionality=binary_functionality,
            goal=goal,
            binary_view=None,
            static_analysis_results=None,
            api_crossrefs_results=None,
            api_clustering_results=None,
            dynamic_analysis_results=None,
            plan=["static_analysis", "api_crossrefs", "api_clustering", "capabilities_analysis", "generate_summary"],
            current_step=0,
            completed_steps=[],
            capabilities=None,
            malware_analysis_results=None,
            messages=[]
        )
        
        print("\nInitial state created with plan.")
        
        # Call static analysis agent directly
        from workflow import static_analysis_agent
        print("\nCalling static analysis agent directly...")
        
        result = static_analysis_agent(state)
        
        print("\nStatic analysis agent result:")
        print(f"Current step: {result.get('current_step')}")
        print(f"Completed steps: {result.get('completed_steps')}")
        print(f"Static analysis results available: {result.get('static_analysis_results') is not None}")
        
        if result.get('static_analysis_results') and 'error' in result.get('static_analysis_results'):
            print(f"Error: {result.get('static_analysis_results').get('error')}")
        
        # Save results to file
        output_file = "simple_test_result.json"
        
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
        serializable_result = clean_for_json(result)
        
        # Save to file
        with open(output_file, 'w') as f:
            json.dump(serializable_result, f, indent=2)
        
        print(f"\nResults saved to {output_file}")
        
    except Exception as e:
        print(f"Error during test: {str(e)}")
        import traceback
        traceback.print_exc()
        sys.exit(1)

if __name__ == "__main__":
    main()
