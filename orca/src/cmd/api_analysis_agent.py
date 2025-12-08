"""
API Analysis Agent for BinSleuth
Analyzes the connection between APIs and the user's goal/description
Filters APIs based on their usage in the binary, focusing on those with code cross-references
"""
import os
import sys
import json
import signal
from typing import List, Dict, Any, Set, Optional, Tuple
from pathlib import Path

# Check for Binary Ninja API
BINARY_NINJA_PATH = "/Applications/Binary Ninja.app/Contents/Resources/python"
if os.path.exists(BINARY_NINJA_PATH):
    sys.path.insert(0, BINARY_NINJA_PATH)
else:
    print(f"Warning: Binary Ninja python API not found in expected folder: {BINARY_NINJA_PATH}")
    print("Will attempt to continue, but some functionality may be limited.")

# Import Binary Ninja components
from binaryninja import BinaryView, SymbolType

# Import BinSleuth modules
from api_crossrefs import ApiCrossReferenceTool
from api_clustering import FunctionClusteringTool
from llm_module import llm_handler
from config import config
from state import AnalysisState


class ApiAnalysisAgent:
    """
    Agent that analyzes the connection between APIs and the user's goal/description
    Filters APIs based on their usage in the binary, focusing on those with code cross-references
    """
    def __init__(self, llm_model: Optional[str] = None, llm_api_base: Optional[str] = None):
        """
        Initialize the API analysis agent
        
        Args:
            llm_model: Optional override for LLM model
            llm_api_base: Optional override for LLM API base URL
        """
        # Use config or override with parameters
        self.llm_model = llm_model or config.get('llm.model')
        self.llm_api_base = llm_api_base or config.get('llm.api_base')
        
        # Create a custom LLM handler if model or API base is specified
        if llm_model or llm_api_base:
            from llm_module import LLMHandler
            self.custom_llm_handler = LLMHandler(model=llm_model, api_base=llm_api_base)
        else:
            self.custom_llm_handler = None

    def analyze(self, state: AnalysisState) -> AnalysisState:
        """
        Analyze the connection between APIs and the user's goal/description
        
        Args:
            state: The current analysis state
            
        Returns:
            Updated analysis state with filtered APIs and functions
        """
        if os.environ.get('DEBUG'):
            print("API Analysis Agent: Starting analysis")
        
        # Check if we have the necessary data
        if not state.get("binary_view"):
            if os.environ.get('DEBUG'):
                print("API Analysis Agent: Binary view not available")
            return state
        
        try:
            # Get the binary view
            binary_view = state.get("binary_view")
            
            # Get imports from static analysis
            imports = state.get("imports", [])
            
            # Get functions from static analysis
            functions = state.get("functions", [])
            
            # Initialize API cross-reference tool
            api_tool = ApiCrossReferenceTool(binary_view)
            
            # Analyze API cross-references for all imports
            api_crossrefs_results = api_tool.batch_analyze(imports)
            
            # Get the list of APIs that have code cross-references
            referenced_apis = set(api_crossrefs_results.keys())
            
            if os.environ.get('DEBUG'):
                print(f"API Analysis Agent: Found {len(referenced_apis)} APIs with code cross-references")
            
            # Filter functions to only include those that reference APIs
            filtered_functions = self._filter_functions_with_api_refs(functions, api_crossrefs_results)
            
            if os.environ.get('DEBUG'):
                print(f"API Analysis Agent: Filtered to {len(filtered_functions)} functions with API references")
            
            # Analyze the relevance of APIs to the user's goal and description
            api_relevance = self._analyze_api_relevance(
                referenced_apis, 
                state.get("goal", ""), 
                state.get("binary_functionality", "")
            )
            
            # Update the state with the filtered APIs and functions
            updated_state = {
                **state,
                "api_crossrefs_results": api_crossrefs_results,
                "referenced_apis": list(referenced_apis),
                "filtered_functions": filtered_functions,
                "api_relevance": api_relevance
            }
            
            return updated_state
            
        except Exception as e:
            error_msg = f"Error during API analysis: {str(e)}"
            if os.environ.get('DEBUG'):
                print(f"API Analysis Agent failed: {error_msg}")
                import traceback
                traceback.print_exc()
            
            # Return the original state if an error occurs
            return state

    def _filter_functions_with_api_refs(
        self, 
        functions: List[Dict[str, Any]], 
        api_crossrefs: Dict[str, List[Dict[str, Any]]]
    ) -> List[Dict[str, Any]]:
        """
        Filter functions to only include those that reference APIs
        
        Args:
            functions: List of functions from static analysis
            api_crossrefs: Dictionary of API cross-references
            
        Returns:
            Filtered list of functions that reference APIs
        """
        if not functions or not api_crossrefs:
            return []
        
        # Create a set of function names that reference APIs
        function_names_with_refs = set()
        
        # Collect all function names that reference APIs
        for api, refs in api_crossrefs.items():
            for api_info in refs:
                for ref in api_info.get("references", []):
                    function_names_with_refs.add(ref.get("function"))
        
        # Filter functions to only include those that reference APIs
        filtered_functions = [
            func for func in functions 
            if func.get("name") in function_names_with_refs
        ]
        
        return filtered_functions

    def _analyze_api_relevance(
        self, 
        apis: Set[str], 
        goal: str, 
        binary_functionality: str
    ) -> Dict[str, Dict[str, Any]]:
        """
        Analyze the relevance of APIs to the user's goal and description
        Process APIs in batches to avoid token limits and handle errors gracefully
        
        Args:
            apis: Set of API names
            goal: The user's analysis goal
            binary_functionality: Description of the binary's functionality
            
        Returns:
            Dictionary mapping API names to relevance information
        """
        if not apis:
            return {}
        
        # Use custom handler if specified, otherwise use global handler
        handler = self.custom_llm_handler if self.custom_llm_handler else llm_handler
        
        # Convert to list and process in batches to avoid token limits
        api_list = list(apis)
        batch_size = 10  # Reduce batch size to avoid timeouts
        api_relevance = {}
        
        if os.environ.get('DEBUG'):
            print(f"Processing {len(api_list)} APIs in batches of {batch_size}")
        
        # Process APIs in batches
        for i in range(0, len(api_list), batch_size):
            batch = api_list[i:i + batch_size]
            batch_result = self._analyze_api_batch(batch, goal, binary_functionality, handler)
            api_relevance.update(batch_result)
        
        return api_relevance
    
    def _analyze_api_batch(
        self, 
        api_batch: List[str], 
        goal: str, 
        binary_functionality: str,
        handler
    ) -> Dict[str, Dict[str, Any]]:
        """
        Analyze a batch of APIs for relevance using LLM first, fallback to defaults only on error
        
        Args:
            api_batch: List of API names to analyze
            goal: The user's analysis goal
            binary_functionality: Description of the binary's functionality
            handler: LLM handler to use
            
        Returns:
            Dictionary mapping API names to relevance information
        """
        if os.environ.get('DEBUG'):
            print(f"Starting LLM analysis for batch of {len(api_batch)} APIs")
        
        # Prepare prompt for LLM - try LLM analysis first
        system_prompt = """You are a binary analysis expert specializing in API analysis.
        Analyze the provided APIs and determine their relevance to the user's goal and the binary's functionality.
        Return a valid JSON object with the exact format specified."""
        
        user_prompt = f"""APIs: {api_batch}
Goal: {goal}
Functionality: {binary_functionality}

Analyze each API's relevance (0-10 scores). Return JSON:
{{
    "api1": {{"goal_relevance": 7, "functionality_relevance": 8, "purpose": "Brief description", "requires_further_analysis": true, "reason": "Security relevant"}},
    "api2": {{"goal_relevance": 5, "functionality_relevance": 6, "purpose": "Brief description", "requires_further_analysis": false, "reason": ""}}
}}"""
        
        # Try LLM analysis first with timeout handling
        try:
            if os.environ.get('DEBUG'):
                print(f"Sending LLM request for API batch analysis...")
            
            # Add timeout to prevent hanging
            import signal
            
            def timeout_handler(signum, frame):
                raise TimeoutError("LLM request timed out")
            
            # Set a 30 second timeout for each LLM request
            old_handler = signal.signal(signal.SIGALRM, timeout_handler)
            signal.alarm(30)
            
            try:
                llm_result = handler.get_json_response(system_prompt, user_prompt)
            finally:
                signal.alarm(0)  # Cancel the alarm
                signal.signal(signal.SIGALRM, old_handler)  # Restore original handler
            
            if os.environ.get('DEBUG'):
                print(f"LLM response received: {type(llm_result)}")
                if isinstance(llm_result, dict):
                    print(f"LLM analyzed {len(llm_result)} APIs")
            
            # Validate LLM result structure
            if isinstance(llm_result, dict) and llm_result:
                validated_result = {}
                for api in api_batch:
                    if api in llm_result and isinstance(llm_result[api], dict):
                        api_analysis = llm_result[api]
                        # Validate required fields are present
                        required_fields = ["goal_relevance", "functionality_relevance", "purpose"]
                        if all(field in api_analysis for field in required_fields):
                            validated_result[api] = {
                                "goal_relevance": int(api_analysis.get("goal_relevance", 5)),
                                "functionality_relevance": int(api_analysis.get("functionality_relevance", 5)),
                                "purpose": str(api_analysis.get("purpose", "API function")),
                                "requires_further_analysis": bool(api_analysis.get("requires_further_analysis", False)),
                                "reason": str(api_analysis.get("reason", ""))
                            }
                        else:
                            if os.environ.get('DEBUG'):
                                print(f"API {api} missing required fields, using default")
                            validated_result[api] = self._get_default_api_analysis(api)
                    else:
                        if os.environ.get('DEBUG'):
                            print(f"API {api} not in LLM result or malformed, using default")
                        validated_result[api] = self._get_default_api_analysis(api)
                
                if os.environ.get('DEBUG'):
                    print(f"Successfully validated LLM analysis for {len(validated_result)} APIs")
                
                return validated_result
            else:
                if os.environ.get('DEBUG'):
                    print(f"LLM result invalid format: {llm_result}")
                raise ValueError(f"LLM returned invalid format: {type(llm_result)}")
            
        except Exception as e:
            if os.environ.get('DEBUG'):
                print(f"LLM analysis failed: {str(e)}")
                import traceback
                traceback.print_exc()
            
            # Fallback to intelligent defaults only on LLM failure
            print(f"Warning: LLM API analysis failed ({str(e)}), using intelligent defaults")
            return {api: self._get_default_api_analysis(api, f"LLM analysis failed: {str(e)}") for api in api_batch}
    
    def _get_default_api_analysis(self, api_name: str, error_reason: str = None) -> Dict[str, Any]:
        """
        Get default analysis for an API when LLM analysis fails
        Provide better defaults based on common API patterns
        
        Args:
            api_name: Name of the API
            error_reason: Optional error reason
            
        Returns:
            Default analysis dictionary
        """
        # Provide smarter defaults based on API name patterns
        api_lower = api_name.lower()
        
        # Network related APIs
        if any(net_api in api_lower for net_api in ['socket', 'bind', 'listen', 'connect', 'send', 'recv', 'inet']):
            return {
                "goal_relevance": 8,
                "functionality_relevance": 8,
                "purpose": "Network communication function",
                "requires_further_analysis": True,
                "reason": "Network API - relevant for security analysis"
            }
        
        # File I/O APIs  
        elif any(file_api in api_lower for file_api in ['fopen', 'fread', 'fwrite', 'fgets', 'fprintf', 'sprintf']):
            return {
                "goal_relevance": 7,
                "functionality_relevance": 7,
                "purpose": "File I/O or string formatting function",
                "requires_further_analysis": True,
                "reason": "File operations - relevant for capability analysis"
            }
        
        # System/process APIs
        elif any(sys_api in api_lower for sys_api in ['exec', 'system', 'fork', 'kill', 'signal', 'fcntl']):
            return {
                "goal_relevance": 9,
                "functionality_relevance": 8,
                "purpose": "System or process control function",
                "requires_further_analysis": True,
                "reason": "System API - high security relevance"
            }
        
        # String manipulation
        elif any(str_api in api_lower for str_api in ['str', 'mem', 'cmp']):
            return {
                "goal_relevance": 5,
                "functionality_relevance": 6,
                "purpose": "String or memory manipulation function",
                "requires_further_analysis": False,
                "reason": ""
            }
        
        # Time/date APIs
        elif any(time_api in api_lower for time_api in ['time', 'date', 'sleep']):
            return {
                "goal_relevance": 4,
                "functionality_relevance": 5,
                "purpose": "Time or date related function",
                "requires_further_analysis": False,
                "reason": ""
            }
        
        # Default case
        else:
            return {
                "goal_relevance": 5,
                "functionality_relevance": 5,
                "purpose": "General purpose function",
                "requires_further_analysis": False,
                "reason": error_reason or "Standard library function"
            }


def analyze_apis(state: AnalysisState) -> AnalysisState:
    """
    Convenience function to analyze APIs without creating an agent instance
    
    Args:
        state: The current analysis state
        
    Returns:
        Updated analysis state with filtered APIs and functions
    """
    agent = ApiAnalysisAgent(
        llm_model=config.get('llm.model'),
        llm_api_base=config.get('llm.api_base')
    )
    return agent.analyze(state)
