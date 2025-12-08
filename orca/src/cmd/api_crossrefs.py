import json
import os
import sys
from typing import List, Dict, Any, Set
from langgraph.prebuilt import ToolNode, tools_condition

# Check for Binary Ninja API
BINARY_NINJA_PATH = "/Applications/Binary Ninja.app/Contents/Resources/python"
if not os.path.exists(BINARY_NINJA_PATH):
    print(f"Binary Ninja python API not found in expected folder: {BINARY_NINJA_PATH}")
    sys.exit(1)
sys.path.insert(0, BINARY_NINJA_PATH)
from binaryninja import BinaryView, load, SymbolType

class ApiCrossReferenceTool:
    """
    A tool for cross-referencing API functions and providing detailed analysis.
    Optimized to efficiently find and deduplicate API references within functions.
    Only returns imports that have actual code references to the binary.
    """
    def __init__(self, bv: BinaryView):
        """
        Initialize the tool with a BinaryView object.
        
        Args:
            bv: The BinaryView object representing the binary.
        """
        self.bv = bv
        self.api_crossrefs_cache = {}  # Cache for storing analyzed results
        
        # Safely update analysis if binary view is valid
        if self.bv is not None:
            try:
                self.bv.update_analysis_and_wait()
            except Exception as e:
                print(f"Warning: Could not update binary analysis: {e}")

    def analyze_api_crossrefs(self, api_name: str) -> List[Dict[str, Any]]:
        """
        Analyze a binary for cross-references to a specific API function.
        Optimized to deduplicate references within the same function.
        
        Args:
            api_name: The name of the API function to search for.
            
        Returns:
            A list of dictionaries containing cross-reference information grouped by API.
            Returns an empty list if no references are found.
        """
        # Check cache first
        if api_name in self.api_crossrefs_cache:
            return self.api_crossrefs_cache[api_name]
            
        # Track unique function references for each API
        api_to_functions = {}
        has_references = False
        
        # Check if binary view is valid
        if self.bv is None:
            self.api_crossrefs_cache[api_name] = []
            return []
            
        # Process each function in the binary
        functions = getattr(self.bv, 'functions', None)
        if functions is None:
            self.api_crossrefs_cache[api_name] = []
            return []
        
        try:
            for func in functions:
                if func is None:
                    continue
                    
                # Track APIs found in this function to avoid duplicates
                function_apis = {}
                
                # Safely get the low-level IL
                try:
                    low_level_il = getattr(func, 'low_level_il', None)
                    if low_level_il is None:
                        continue
                        
                    # Analyze the function's low-level IL
                    for block in low_level_il:
                        if block is None:
                            continue
                            
                        for instr in block:
                            if instr is None:
                                continue
                                
                            # Look for call instructions
                            if (hasattr(instr, 'operation') and instr.operation and
                                hasattr(instr.operation, 'name') and instr.operation.name == "LLIL_CALL" and 
                                hasattr(instr, 'dest') and instr.dest and
                                hasattr(instr.dest, 'operation') and instr.dest.operation and
                                hasattr(instr.dest.operation, 'name') and instr.dest.operation.name == "LLIL_CONST_PTR"):
                                
                                call_addr = getattr(instr.dest, 'constant', None)
                                if call_addr is None:
                                    continue
                                    
                                sym = self.bv.get_symbol_at(call_addr)
                                
                                # Check if the symbol exists and matches the API name
                                if sym and hasattr(sym, 'name') and sym.name and api_name in sym.name:
                                    # If we haven't seen this API in this function yet, record it
                                    if sym.name not in function_apis:
                                        function_apis[sym.name] = {
                                            "function": getattr(func, 'name', 'unknown'),
                                            "start_addr": hex(getattr(func, 'start', 0)),
                                            "end_addr": hex(getattr(func, 'highest_address', 0)),
                                            "callsites": []
                                        }
                                    
                                    # Add this specific callsite
                                    instr_addr = getattr(instr, 'address', 0)
                                    function_apis[sym.name]["callsites"].append(hex(instr_addr))
                                    has_references = True
                                    
                except Exception as e:
                    # Skip this function if there's an error analyzing it
                    continue
                
                # Add the function references to our results
                for api, func_info in function_apis.items():
                    api_to_functions.setdefault(api, []).append(func_info)
                    
        except Exception as e:
            # If there's an error processing functions, return empty list
            self.api_crossrefs_cache[api_name] = []
            return []
        
        # Format the results
        output_data = [
            {"api_name": api, "references": refs} 
            for api, refs in api_to_functions.items()
        ]
        
        # Cache the results
        self.api_crossrefs_cache[api_name] = output_data
        
        # Only return data if references were found
        return output_data if has_references else []

    def batch_analyze(self, api_names: List[str]) -> Dict[str, List[Dict[str, Any]]]:
        """
        Efficiently analyze multiple API functions for cross-references.
        Only returns imports that have actual code references to the binary.
        
        Args:
            api_names: A list of API function names to search for.
            
        Returns:
            A dictionary with API names as keys and lists of cross-reference information as values.
            Only includes APIs that have actual references in the code.
        """
        results = {}
        referenced_apis = set()  # Track APIs that have actual references
        
        # Check if binary view is valid
        if self.bv is None:
            return results
        
        # Process all APIs in one pass through the binary if there are multiple APIs
        if len(api_names) > 1:
            # Create a set for faster lookups
            api_set = set(api_names)
            
            # Track unique function references for each API
            api_to_functions = {api: {} for api in api_names}
            
            # Process each function in the binary once
            functions = getattr(self.bv, 'functions', None)
            if functions is None:
                return results
            
            try:
                for func in functions:
                    if func is None:
                        continue
                        
                    # Track APIs found in this function
                    function_apis = {}
                    
                    # Safely get the low-level IL
                    try:
                        low_level_il = getattr(func, 'low_level_il', None)
                        if low_level_il is None:
                            continue
                            
                        # Analyze the function's low-level IL
                        for block in low_level_il:
                            if block is None:
                                continue
                                
                            for instr in block:
                                if instr is None:
                                    continue
                                    
                                # Look for call instructions
                                if (hasattr(instr, 'operation') and instr.operation and
                                    hasattr(instr.operation, 'name') and instr.operation.name == "LLIL_CALL" and 
                                    hasattr(instr, 'dest') and instr.dest and
                                    hasattr(instr.dest, 'operation') and instr.dest.operation and
                                    hasattr(instr.dest.operation, 'name') and instr.dest.operation.name == "LLIL_CONST_PTR"):
                                    
                                    call_addr = getattr(instr.dest, 'constant', None)
                                    if call_addr is None:
                                        continue
                                        
                                    sym = self.bv.get_symbol_at(call_addr)
                                    
                                    # Check if the symbol exists and matches any of our target APIs
                                    if sym and hasattr(sym, 'name') and sym.name:
                                        for api in api_set:
                                            if api in sym.name:
                                                # If we haven't seen this API in this function yet, record it
                                                if sym.name not in function_apis:
                                                    function_apis[sym.name] = {
                                                        "function": getattr(func, 'name', 'unknown'),
                                                        "start_addr": hex(getattr(func, 'start', 0)),
                                                        "end_addr": hex(getattr(func, 'highest_address', 0)),
                                                        "callsites": []
                                                    }
                                                
                                                # Add this specific callsite
                                                instr_addr = getattr(instr, 'address', 0)
                                                function_apis[sym.name]["callsites"].append(hex(instr_addr))
                                                # Mark this API as referenced
                                                referenced_apis.add(api)
                                                
                    except Exception as e:
                        # Skip this function if there's an error analyzing it
                        continue
                    # Add the function references to our results
                    for api, func_info in function_apis.items():
                        for target_api in api_names:
                            if target_api in api:
                                api_to_functions.setdefault(target_api, {}).setdefault(api, []).append(func_info)
            except Exception as e:
                # If there's an error processing functions, return empty results
                return results
            
            # Format the results - only include APIs with references
            for api in api_names:
                if api in referenced_apis:
                    results[api] = [
                        {"api_name": specific_api, "references": refs}
                        for specific_api, refs in api_to_functions.get(api, {}).items()
                    ]
                    # Cache the results
                    self.api_crossrefs_cache[api] = results[api]
        else:
            # If only one API, use the single API method
            for api_name in api_names:
                api_results = self.analyze_api_crossrefs(api_name)
                if api_results:  # Only include if there are references
                    results[api_name] = api_results
                    referenced_apis.add(api_name)
        
        # Return a dictionary of only the APIs that have references
        return results
    
    def get_function_containing_address(self, address: int) -> Dict[str, Any]:
        """
        Get information about the function containing a specific address.
        
        Args:
            address: The address to find the containing function for.
            
        Returns:
            A dictionary with function information or None if not found.
        """
        func = self.bv.get_function_at(address)
        if func:
            return {
                "function": func.name,
                "start_addr": hex(func.start),
                "end_addr": hex(func.highest_address)
            }
        return None
