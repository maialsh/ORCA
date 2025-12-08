#!/usr/bin/env python3
"""
Minimal test script to verify the fix for the 'malware_analysis' state key issue
"""
import sys
import json
from workflow import WorkflowState

def main():
    """Test the workflow state"""
    try:
        # Create a simple state
        state = WorkflowState(
            binary_path="test_path",
            binary_functionality="test functionality",
            goal="capabilities",
            binary_view=None,
            static_analysis_results=None,
            api_crossrefs_results=None,
            api_clustering_results=None,
            dynamic_analysis_results=None,
            plan=None,
            current_step=None,
            completed_steps=[],
            capabilities=None,
            malware_analysis_results={"test": "data"},
            messages=[]
        )
        
        # Print the state
        print("Successfully created WorkflowState with malware_analysis_results")
        
        # Test serialization
        serializable_state = {
            "binary_path": state.get("binary_path"),
            "binary_functionality": state.get("binary_functionality"),
            "goal": state.get("goal"),
            "static_analysis_results": state.get("static_analysis_results"),
            "api_crossrefs_results": state.get("api_crossrefs_results"),
            "api_clustering_results": state.get("api_clustering_results"),
            "dynamic_analysis_results": state.get("dynamic_analysis_results"),
            "capabilities": state.get("capabilities"),
            "malware_analysis_results": state.get("malware_analysis_results"),
            "completed_steps": state.get("completed_steps")
        }
        
        # Serialize to JSON
        json_str = json.dumps(serializable_state, indent=2)
        print("\nSuccessfully serialized state to JSON:")
        print(json_str)
        
        # Deserialize from JSON
        deserialized_state = json.loads(json_str)
        print("\nSuccessfully deserialized state from JSON")
        
        # Verify malware_analysis_results key
        if "malware_analysis_results" in deserialized_state:
            print("malware_analysis_results key exists in deserialized state")
            print(f"Value: {deserialized_state['malware_analysis_results']}")
        else:
            print("ERROR: malware_analysis_results key missing from deserialized state")
        
        print("\nTest successful!")
        return 0
    except Exception as e:
        print(f"Error during test: {str(e)}")
        import traceback
        traceback.print_exc()
        return 1

if __name__ == "__main__":
    sys.exit(main())
