"""
Binary Analyzer Module

A comprehensive Binary Ninja-based analysis module for ELF and PE binaries.
Provides functionality for call graph generation, API analysis, and function relationship mapping.
"""

import os
import sys
from typing import Dict, List, Optional, Set, Tuple, Any
from dataclasses import dataclass
import json

# Binary Ninja setup
BINARY_NINJA_PATH = "/Applications/Binary Ninja.app/Contents/Resources/python"
if os.path.exists(BINARY_NINJA_PATH):
    sys.path.insert(0, BINARY_NINJA_PATH)
else:
    print(f"Warning: Binary Ninja python API not found in expected folder: {BINARY_NINJA_PATH}")
    print("Will attempt to continue, but some functionality may be limited.")

try:
    import binaryninja as bn
    from binaryninja import BinaryView, Function, BasicBlock, MediumLevelILInstruction
    from binaryninja.enums import SymbolType, InstructionTextTokenType
except ImportError as e:
    print(f"Error importing Binary Ninja: {e}")
    print("Binary Ninja functionality will be limited.")


@dataclass
class FunctionInfo:
    """Data class to hold function information"""
    name: str
    address: int
    size: int
    assembly_instructions: List[str]
    calls_to: List[str]
    called_by: List[str]


@dataclass
class CallGraphNode:
    """Data class for call graph nodes"""
    function_name: str
    address: int
    callers: List[str]
    callees: List[str]


class BinaryAnalyzer:
    """
    A comprehensive binary analysis class using Binary Ninja.
    
    Supports ELF and PE binary formats and provides:
    - Call graph generation
    - API function analysis
    - Function relationship mapping
    - Assembly instruction extraction
    """
    
    def __init__(self, binary_path: str):
        """
        Initialize the binary analyzer.
        
        Args:
            binary_path (str): Path to the binary file to analyze
        """
        self.binary_path = binary_path
        self.bv: Optional[BinaryView] = None
        self.functions: Dict[str, Function] = {}
        self.call_graph: Dict[str, CallGraphNode] = {}
        self._load_binary()
    
    def _load_binary(self) -> bool:
        """
        Load and analyze the binary file.
        
        Returns:
            bool: True if successful, False otherwise
        """
        try:
            print(f"Loading binary: {self.binary_path}")
            self.bv = bn.load(str(self.binary_path))
            
            if self.bv is None:
                print(f"Error: Failed to load binary {self.binary_path}")
                return False
            
            print("Performing analysis...")
            self.bv.update_analysis_and_wait()
            
            # Build function dictionary for quick lookup
            for func in self.bv.functions:
                self.functions[func.name] = func
            
            print(f"Analysis complete. Found {len(self.functions)} functions.")
            return True
            
        except Exception as e:
            print(f"Error loading binary: {e}")
            return False
    
    def generate_call_graph(self) -> Dict[str, CallGraphNode]:
        """
        Generate a complete call graph for the binary.
        
        Returns:
            Dict[str, CallGraphNode]: Call graph with function names as keys
        """
        if not self.bv:
            print("Error: Binary not loaded")
            return {}
        
        print("Generating call graph...")
        call_graph = {}
        
        for func in self.bv.functions:
            callers = []
            callees = []
            
            # Find functions that call this function
            for caller_ref in func.caller_sites:
                caller_func = caller_ref.function
                if caller_func and caller_func.name not in callers:
                    callers.append(caller_func.name)
            
            # Find functions called by this function
            for callee_ref in func.callees:
                if callee_ref.name not in callees:
                    callees.append(callee_ref.name)
            
            call_graph[func.name] = CallGraphNode(
                function_name=func.name,
                address=func.start,
                callers=callers,
                callees=callees
            )
        
        self.call_graph = call_graph
        print(f"Call graph generated with {len(call_graph)} nodes.")
        return call_graph
    
    def find_api_function(self, api_name: str) -> Optional[FunctionInfo]:
        """
        Find a specific API function and return its information including assembly.
        
        Args:
            api_name (str): Name of the API function to find (e.g., 'strcpy', 'malloc')
        
        Returns:
            Optional[FunctionInfo]: Function information if found, None otherwise
        """
        if not self.bv:
            print("Error: Binary not loaded")
            return None
        
        # Search for the function by name (exact match and partial match)
        target_function = None
        
        # First try exact match
        if api_name in self.functions:
            target_function = self.functions[api_name]
        else:
            # Try partial match (case-insensitive)
            for func_name, func in self.functions.items():
                if api_name.lower() in func_name.lower():
                    target_function = func
                    break
        
        if not target_function:
            print(f"API function '{api_name}' not found in binary")
            return None
        
        return self._extract_function_info(target_function)
    
    def get_connected_functions(self, function_name: str) -> Dict[str, FunctionInfo]:
        """
        Get all functions directly connected to the specified function.
        
        Args:
            function_name (str): Name of the function to analyze
        
        Returns:
            Dict[str, FunctionInfo]: Dictionary of connected functions with their assembly
        """
        if not self.bv:
            print("Error: Binary not loaded")
            return {}
        
        if function_name not in self.functions:
            print(f"Function '{function_name}' not found in binary")
            return {}
        
        target_function = self.functions[function_name]
        connected_functions = {}
        
        # Get functions called by this function (callees)
        for callee in target_function.callees:
            if callee.name in self.functions:
                func_info = self._extract_function_info(self.functions[callee.name])
                if func_info:
                    connected_functions[f"callee_{callee.name}"] = func_info
        
        # Get functions that call this function (callers)
        for caller_ref in target_function.caller_sites:
            caller_func = caller_ref.function
            if caller_func and caller_func.name in self.functions:
                func_info = self._extract_function_info(caller_func)
                if func_info:
                    connected_functions[f"caller_{caller_func.name}"] = func_info
        
        print(f"Found {len(connected_functions)} functions connected to '{function_name}'")
        return connected_functions
    
    def _extract_function_info(self, function: Function) -> Optional[FunctionInfo]:
        """
        Extract detailed information from a Binary Ninja Function object.
        
        Args:
            function (Function): Binary Ninja Function object
        
        Returns:
            Optional[FunctionInfo]: Extracted function information
        """
        try:
            assembly_instructions = []
            
            # Extract assembly instructions
            for block in function.basic_blocks:
                for instruction in block:
                    # Get the disassembly text
                    disasm_text = ""
                    for token in instruction.tokens:
                        disasm_text += token.text
                    
                    assembly_instructions.append(f"0x{instruction.address:x}: {disasm_text}")
            
            # Get function calls
            calls_to = [callee.name for callee in function.callees]
            called_by = []
            
            for caller_ref in function.caller_sites:
                caller_func = caller_ref.function
                if caller_func:
                    called_by.append(caller_func.name)
            
            return FunctionInfo(
                name=function.name,
                address=function.start,
                size=len(function),
                assembly_instructions=assembly_instructions,
                calls_to=calls_to,
                called_by=called_by
            )
            
        except Exception as e:
            print(f"Error extracting function info for {function.name}: {e}")
            return None
    
    def get_function_assembly(self, function_name: str) -> List[str]:
        """
        Get assembly instructions for a specific function.
        
        Args:
            function_name (str): Name of the function
        
        Returns:
            List[str]: List of assembly instructions
        """
        if function_name not in self.functions:
            print(f"Function '{function_name}' not found")
            return []
        
        func_info = self._extract_function_info(self.functions[function_name])
        return func_info.assembly_instructions if func_info else []
    
    def search_api_usage(self, api_name: str) -> List[Tuple[str, List[str]]]:
        """
        Search for usage of a specific API across all functions.
        
        Args:
            api_name (str): API name to search for
        
        Returns:
            List[Tuple[str, List[str]]]: List of (function_name, call_locations)
        """
        if not self.bv:
            print("Error: Binary not loaded")
            return []
        
        usage_locations = []
        
        for func_name, func in self.functions.items():
            call_locations = []
            
            # Check if this function calls the API
            for callee in func.callees:
                if api_name.lower() in callee.name.lower():
                    # Find the specific call sites
                    for block in func.basic_blocks:
                        for instruction in block:
                            disasm_text = "".join(token.text for token in instruction.tokens)
                            if api_name.lower() in disasm_text.lower():
                                call_locations.append(f"0x{instruction.address:x}: {disasm_text}")
            
            if call_locations:
                usage_locations.append((func_name, call_locations))
        
        return usage_locations
    
    def export_call_graph(self, output_file: str, format_type: str = "json") -> bool:
        """
        Export the call graph to a file.
        
        Args:
            output_file (str): Output file path
            format_type (str): Export format ('json', 'dot', 'txt')
        
        Returns:
            bool: True if successful, False otherwise
        """
        if not self.call_graph:
            self.generate_call_graph()
        
        try:
            if format_type.lower() == "json":
                # Convert to JSON-serializable format
                json_data = {}
                for name, node in self.call_graph.items():
                    json_data[name] = {
                        "address": hex(node.address),
                        "callers": node.callers,
                        "callees": node.callees
                    }
                
                with open(output_file, 'w') as f:
                    json.dump(json_data, f, indent=2)
            
            elif format_type.lower() == "dot":
                # Export as Graphviz DOT format
                with open(output_file, 'w') as f:
                    f.write("digraph CallGraph {\n")
                    f.write("  rankdir=TB;\n")
                    f.write("  node [shape=box];\n\n")
                    
                    for name, node in self.call_graph.items():
                        for callee in node.callees:
                            f.write(f'  "{name}" -> "{callee}";\n')
                    
                    f.write("}\n")
            
            elif format_type.lower() == "txt":
                # Export as plain text
                with open(output_file, 'w') as f:
                    for name, node in self.call_graph.items():
                        f.write(f"Function: {name} (0x{node.address:x})\n")
                        f.write(f"  Callers: {', '.join(node.callers) if node.callers else 'None'}\n")
                        f.write(f"  Callees: {', '.join(node.callees) if node.callees else 'None'}\n")
                        f.write("\n")
            
            print(f"Call graph exported to {output_file}")
            return True
            
        except Exception as e:
            print(f"Error exporting call graph: {e}")
            return False
    
    def get_binary_info(self) -> Dict[str, Any]:
        """
        Get general information about the loaded binary.
        
        Returns:
            Dict[str, Any]: Binary information
        """
        if not self.bv:
            return {}
        
        return {
            "file_path": self.binary_path,
            "architecture": str(self.bv.arch),
            "platform": str(self.bv.platform),
            "entry_point": hex(self.bv.entry_point),
            "function_count": len(self.bv.functions),
            "file_type": self.bv.view_type,
            "sections": [section.name for section in self.bv.sections.values()],
            "symbols": len(self.bv.symbols)
        }
    
    def close(self):
        """Clean up resources."""
        if self.bv:
            self.bv = None
        self.functions.clear()
        self.call_graph.clear()


def main():
    """Example usage of the BinaryAnalyzer class."""
    if len(sys.argv) != 2:
        print("Usage: python binary_analyzer.py <binary_file>")
        sys.exit(1)
    
    binary_path = sys.argv[1]
    
    # Initialize analyzer
    analyzer = BinaryAnalyzer(binary_path)
    
    # Get binary info
    print("\n=== Binary Information ===")
    info = analyzer.get_binary_info()
    for key, value in info.items():
        print(f"{key}: {value}")
    
    # Generate call graph
    print("\n=== Generating Call Graph ===")
    call_graph = analyzer.generate_call_graph()
    
    # Example: Search for strcpy API
    print("\n=== Searching for strcpy API ===")
    strcpy_info = analyzer.find_api_function("strcpy")
    if strcpy_info:
        print(f"Found strcpy at 0x{strcpy_info.address:x}")
        print(f"Assembly instructions ({len(strcpy_info.assembly_instructions)} lines):")
        for instruction in strcpy_info.assembly_instructions[:10]:  # Show first 10 lines
            print(f"  {instruction}")
        if len(strcpy_info.assembly_instructions) > 10:
            print(f"  ... and {len(strcpy_info.assembly_instructions) - 10} more lines")
    
    # Example: Get connected functions for main
    print("\n=== Functions connected to 'main' ===")
    connected = analyzer.get_connected_functions("main")
    for conn_name, func_info in connected.items():
        print(f"{conn_name}: {func_info.name} at 0x{func_info.address:x}")
    
    # Export call graph
    print("\n=== Exporting Call Graph ===")
    analyzer.export_call_graph("call_graph.json", "json")
    analyzer.export_call_graph("call_graph.dot", "dot")
    
    # Clean up
    analyzer.close()


if __name__ == "__main__":
    main()
