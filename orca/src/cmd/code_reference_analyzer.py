"""
Code Reference Analyzer Module for BinSleuth
Finds code references of strings in binary and retrieves function context and assembly
"""
import os
import sys
import re
from typing import List, Dict, Any, Optional, Tuple, Set
from collections import defaultdict

# Check for Binary Ninja API
BINARY_NINJA_PATH = "/Applications/Binary Ninja.app/Contents/Resources/python"
if os.path.exists(BINARY_NINJA_PATH):
    sys.path.insert(0, BINARY_NINJA_PATH)
    try:
        from binaryninja import BinaryView, Function, BasicBlock
        BINARY_NINJA_AVAILABLE = True
    except ImportError:
        BINARY_NINJA_AVAILABLE = False
        print("Warning: Binary Ninja API not available")
else:
    BINARY_NINJA_AVAILABLE = False
    print("Warning: Binary Ninja not found")

from llm_module import llm_handler


class CodeReferenceAnalyzer:
    """
    Analyzer that finds code references of strings in binary files,
    retrieves the containing function, and provides assembly context.
    """
    
    def __init__(self, binary_view: Optional[Any] = None):
        """
        Initialize the code reference analyzer
        
        Args:
            binary_view: Binary Ninja BinaryView object
        """
        self.binary_view = binary_view
        self.string_cache = {}  # Cache for string search results
        self.function_cache = {}  # Cache for function analysis results
        
        if not BINARY_NINJA_AVAILABLE:
            print("Warning: Binary Ninja not available. Limited functionality.")
    
    def find_string_references(self, search_string: str, case_sensitive: bool = False) -> List[Dict[str, Any]]:
        """
        Find all code references to a specific string in the binary
        
        Args:
            search_string: String to search for
            case_sensitive: Whether to perform case-sensitive search
            
        Returns:
            List of dictionaries containing reference information:
            [
                {
                    "string": str,
                    "address": str,
                    "function_name": str,
                    "function_start": str,
                    "function_end": str,
                    "context": str,
                    "assembly": str,
                    "instruction_context": List[str],
                    "data_references": List[str],
                    "usage_type": str
                }
            ]
        """
        if not self.binary_view or not BINARY_NINJA_AVAILABLE:
            return self._fallback_string_search(search_string)
        
        # Check cache first
        cache_key = f"{search_string}:{case_sensitive}"
        if cache_key in self.string_cache:
            return self.string_cache[cache_key]
        
        results = []
        
        try:
            # Search for string in binary data
            string_refs = self._find_string_in_binary(search_string, case_sensitive)
            
            for string_addr, string_data in string_refs:
                # Find cross-references to this string
                xrefs = self.binary_view.get_code_refs(string_addr)
                
                for xref in xrefs:
                    # Get the function containing this reference
                    func = self.binary_view.get_function_at(xref)
                    if not func:
                        # Try to find containing function
                        funcs = self.binary_view.get_functions_containing(xref)
                        if funcs:
                            func = funcs[0]
                    
                    if func:
                        # Analyze the reference context
                        ref_info = self._analyze_string_reference(
                            search_string, string_addr, xref, func, string_data
                        )
                        if ref_info:
                            results.append(ref_info)
            
            # Cache the results
            self.string_cache[cache_key] = results
            
        except Exception as e:
            print(f"Error finding string references: {e}")
            return self._fallback_string_search(search_string)
        
        return results
    
    def _find_string_in_binary(self, search_string: str, case_sensitive: bool = False) -> List[Tuple[int, str]]:
        """
        Find occurrences of a string in the binary data
        
        Args:
            search_string: String to search for
            case_sensitive: Whether to perform case-sensitive search
            
        Returns:
            List of tuples (address, actual_string_data)
        """
        results = []
        
        if not case_sensitive:
            search_string = search_string.lower()
        
        # Search in defined strings
        for string_ref in self.binary_view.strings:
            string_data = str(string_ref)
            compare_data = string_data if case_sensitive else string_data.lower()
            
            if search_string in compare_data:
                results.append((string_ref.start, string_data))
        
        # Also search in raw data sections
        for section in self.binary_view.sections.values():
            if section.semantics.name in ['ReadOnlyDataSectionSemantics', 'ReadWriteDataSectionSemantics']:
                try:
                    section_data = self.binary_view.read(section.start, section.length)
                    if section_data:
                        # Convert to string and search
                        try:
                            text_data = section_data.decode('utf-8', errors='ignore')
                            compare_data = text_data if case_sensitive else text_data.lower()
                            
                            if search_string in compare_data:
                                # Find the exact offset
                                offset = compare_data.find(search_string)
                                if offset != -1:
                                    addr = section.start + offset
                                    # Extract the actual string around this location
                                    start_idx = max(0, offset - 50)
                                    end_idx = min(len(text_data), offset + len(search_string) + 50)
                                    context_string = text_data[start_idx:end_idx]
                                    results.append((addr, context_string))
                        except UnicodeDecodeError:
                            continue
                except Exception:
                    continue
        
        return results
    
    def _analyze_string_reference(self, search_string: str, string_addr: int, ref_addr: int, 
                                function: Any, string_data: str) -> Optional[Dict[str, Any]]:
        """
        Analyze a specific string reference within a function
        
        Args:
            search_string: Original search string
            string_addr: Address where string is stored
            ref_addr: Address of the reference to the string
            function: Binary Ninja Function object
            string_data: Actual string data found
            
        Returns:
            Dictionary with reference analysis or None if analysis fails
        """
        try:
            # Get instruction at reference address
            instruction_text = ""
            instruction_context = []
            
            # Get disassembly around the reference
            disasm_lines = []
            start_addr = max(function.start, ref_addr - 32)
            end_addr = min(function.highest_address, ref_addr + 32)
            
            for addr in range(start_addr, end_addr, 4):  # Assume 4-byte instructions
                try:
                    disasm = self.binary_view.get_disassembly(addr)
                    if disasm:
                        marker = " --> " if addr == ref_addr else "     "
                        disasm_lines.append(f"{marker}{addr:08x}: {disasm}")
                        
                        if addr == ref_addr:
                            instruction_text = disasm
                        
                        # Get context around the reference
                        if abs(addr - ref_addr) <= 16:
                            instruction_context.append(f"{addr:08x}: {disasm}")
                except:
                    continue
            
            # Determine usage type
            usage_type = self._determine_usage_type(instruction_text, function)
            
            # Get function assembly (limited to reasonable size)
            function_assembly = self._get_function_assembly(function, max_lines=50)
            
            # Get data references
            data_refs = []
            try:
                for ref in self.binary_view.get_data_refs(string_addr):
                    data_refs.append(f"0x{ref:08x}")
            except:
                pass
            
            return {
                "string": search_string,
                "found_string": string_data,
                "address": f"0x{ref_addr:08x}",
                "string_address": f"0x{string_addr:08x}",
                "function_name": function.name,
                "function_start": f"0x{function.start:08x}",
                "function_end": f"0x{function.highest_address:08x}",
                "function_size": function.highest_address - function.start,
                "context": f"Referenced in function {function.name} at instruction: {instruction_text}",
                "assembly": "\n".join(disasm_lines),
                "function_assembly": function_assembly,
                "instruction_context": instruction_context,
                "data_references": data_refs,
                "usage_type": usage_type,
                "instruction": instruction_text
            }
            
        except Exception as e:
            print(f"Error analyzing string reference: {e}")
            return None
    
    def _determine_usage_type(self, instruction: str, function: Any) -> str:
        """
        Determine how the string is being used based on the instruction
        
        Args:
            instruction: Assembly instruction text
            function: Binary Ninja Function object
            
        Returns:
            Usage type description
        """
        if not instruction:
            return "unknown"
        
        instruction_lower = instruction.lower()
        
        # Common usage patterns
        if any(op in instruction_lower for op in ['call', 'jmp']):
            return "function_call"
        elif any(op in instruction_lower for op in ['mov', 'lea']):
            return "data_access"
        elif any(op in instruction_lower for op in ['push']):
            return "parameter_passing"
        elif any(op in instruction_lower for op in ['cmp', 'test']):
            return "comparison"
        elif any(op in instruction_lower for op in ['add', 'sub', 'xor', 'or', 'and']):
            return "arithmetic_operation"
        else:
            return "other"
    
    def _get_function_assembly(self, function: Any, max_lines: int = 50) -> str:
        """
        Get assembly code for a function
        
        Args:
            function: Binary Ninja Function object
            max_lines: Maximum number of assembly lines to return
            
        Returns:
            Assembly code as string
        """
        try:
            assembly_lines = []
            line_count = 0
            
            for block in function.basic_blocks:
                if line_count >= max_lines:
                    assembly_lines.append("... (truncated)")
                    break
                
                for addr in range(block.start, block.end, 4):  # Assume 4-byte instructions
                    if line_count >= max_lines:
                        break
                    
                    try:
                        disasm = self.binary_view.get_disassembly(addr)
                        if disasm:
                            assembly_lines.append(f"{addr:08x}: {disasm}")
                            line_count += 1
                    except:
                        continue
            
            return "\n".join(assembly_lines)
            
        except Exception as e:
            return f"Error getting function assembly: {e}"
    
    def _fallback_string_search(self, search_string: str) -> List[Dict[str, Any]]:
        """
        Fallback string search when Binary Ninja is not available
        
        Args:
            search_string: String to search for
            
        Returns:
            Limited search results
        """
        return [{
            "string": search_string,
            "address": "unknown",
            "function_name": "unknown",
            "function_start": "unknown",
            "function_end": "unknown",
            "context": "Binary Ninja not available - limited analysis",
            "assembly": "Not available",
            "instruction_context": [],
            "data_references": [],
            "usage_type": "unknown"
        }]
    
    def analyze_string_usage_with_llm(self, string_ref: Dict[str, Any]) -> Dict[str, Any]:
        """
        Use LLM to analyze how a string is used in the code
        
        Args:
            string_ref: String reference information from find_string_references
            
        Returns:
            LLM analysis results
        """
        if not string_ref.get("assembly"):
            return {"analysis": "No assembly code available for analysis"}
        
        system_prompt = """You are a reverse engineering expert analyzing assembly code to understand how strings are used.
        
        Analyze the provided assembly code and string reference to determine:
        1. How the string is being used (parameter, comparison, data access, etc.)
        2. The purpose of the function containing the string
        3. Any security implications
        4. Potential malicious behavior indicators
        
        Be specific about the assembly instructions and their purpose."""
        
        user_prompt = f"""Analyze this string reference in assembly code:
        
        String: "{string_ref.get('string', 'unknown')}"
        Function: {string_ref.get('function_name', 'unknown')}
        Instruction: {string_ref.get('instruction', 'unknown')}
        Usage Type: {string_ref.get('usage_type', 'unknown')}
        
        Assembly Context:
        {string_ref.get('assembly', 'Not available')}
        
        Function Assembly (partial):
        {string_ref.get('function_assembly', 'Not available')[:1000]}
        
        Provide a detailed analysis of:
        1. How this string is being used
        2. The function's apparent purpose
        3. Any security concerns or suspicious behavior
        4. Technical details about the assembly instructions
        """
        
        try:
            analysis = llm_handler.query(system_prompt, user_prompt)
            return {
                "analysis": analysis,
                "string": string_ref.get('string'),
                "function": string_ref.get('function_name'),
                "usage_type": string_ref.get('usage_type')
            }
        except Exception as e:
            return {
                "analysis": f"LLM analysis failed: {str(e)}",
                "error": str(e)
            }
    
    def find_all_string_references_in_function(self, function_name: str) -> List[Dict[str, Any]]:
        """
        Find all string references within a specific function
        
        Args:
            function_name: Name of the function to analyze
            
        Returns:
            List of string references in the function
        """
        if not self.binary_view or not BINARY_NINJA_AVAILABLE:
            return []
        
        # Find the function
        target_function = None
        for func in self.binary_view.functions:
            if func.name == function_name:
                target_function = func
                break
        
        if not target_function:
            return []
        
        results = []
        
        try:
            # Analyze all instructions in the function
            for block in target_function.basic_blocks:
                for addr in range(block.start, block.end, 4):
                    try:
                        # Get instruction
                        disasm = self.binary_view.get_disassembly(addr)
                        if not disasm:
                            continue
                        
                        # Check for data references in this instruction
                        refs = self.binary_view.get_data_refs_from(addr)
                        for ref_addr in refs:
                            # Check if this reference points to a string
                            string_data = self._get_string_at_address(ref_addr)
                            if string_data:
                                ref_info = {
                                    "string": string_data,
                                    "address": f"0x{addr:08x}",
                                    "string_address": f"0x{ref_addr:08x}",
                                    "function_name": function_name,
                                    "instruction": disasm,
                                    "usage_type": self._determine_usage_type(disasm, target_function)
                                }
                                results.append(ref_info)
                    except:
                        continue
        except Exception as e:
            print(f"Error analyzing function {function_name}: {e}")
        
        return results
    
    def _get_string_at_address(self, address: int) -> Optional[str]:
        """
        Get string data at a specific address
        
        Args:
            address: Address to check for string data
            
        Returns:
            String data if found, None otherwise
        """
        try:
            # Check if there's a string reference at this address
            for string_ref in self.binary_view.strings:
                if string_ref.start <= address < string_ref.start + string_ref.length:
                    return str(string_ref)
            
            # Try to read as null-terminated string
            max_length = 256
            data = self.binary_view.read(address, max_length)
            if data:
                # Find null terminator
                null_pos = data.find(b'\x00')
                if null_pos > 0:
                    try:
                        return data[:null_pos].decode('utf-8', errors='ignore')
                    except:
                        pass
            
            return None
        except:
            return None
    
    def get_function_string_summary(self, function_name: str) -> Dict[str, Any]:
        """
        Get a summary of all strings used in a function
        
        Args:
            function_name: Name of the function to analyze
            
        Returns:
            Summary of string usage in the function
        """
        string_refs = self.find_all_string_references_in_function(function_name)
        
        if not string_refs:
            return {
                "function_name": function_name,
                "string_count": 0,
                "strings": [],
                "summary": "No strings found in function"
            }
        
        # Categorize strings
        categories = defaultdict(list)
        for ref in string_refs:
            usage_type = ref.get('usage_type', 'unknown')
            categories[usage_type].append(ref['string'])
        
        # Generate summary
        summary = f"Function '{function_name}' references {len(string_refs)} strings:\n"
        for category, strings in categories.items():
            summary += f"- {category}: {len(strings)} strings\n"
        
        return {
            "function_name": function_name,
            "string_count": len(string_refs),
            "strings": [ref['string'] for ref in string_refs],
            "string_references": string_refs,
            "categories": dict(categories),
            "summary": summary
        }
    
    def search_strings_by_pattern(self, pattern: str, regex: bool = False) -> List[Dict[str, Any]]:
        """
        Search for strings matching a pattern
        
        Args:
            pattern: Pattern to search for
            regex: Whether to treat pattern as regex
            
        Returns:
            List of matching string references
        """
        if not self.binary_view or not BINARY_NINJA_AVAILABLE:
            return []
        
        results = []
        
        try:
            if regex:
                compiled_pattern = re.compile(pattern, re.IGNORECASE)
            
            for string_ref in self.binary_view.strings:
                string_data = str(string_ref)
                
                match = False
                if regex:
                    match = compiled_pattern.search(string_data) is not None
                else:
                    match = pattern.lower() in string_data.lower()
                
                if match:
                    # Find references to this string
                    refs = self.find_string_references(string_data, case_sensitive=True)
                    results.extend(refs)
        
        except Exception as e:
            print(f"Error searching strings by pattern: {e}")
        
        return results


def analyze_string_references(binary_view: Any, search_string: str) -> List[Dict[str, Any]]:
    """
    Convenience function to analyze string references
    
    Args:
        binary_view: Binary Ninja BinaryView object
        search_string: String to search for
        
    Returns:
        List of string reference analysis results
    """
    analyzer = CodeReferenceAnalyzer(binary_view)
    return analyzer.find_string_references(search_string)


if __name__ == "__main__":
    # Example usage (requires Binary Ninja)
    print("Code Reference Analyzer")
    print("This module requires Binary Ninja to be installed and available.")
    
    if BINARY_NINJA_AVAILABLE:
        print("Binary Ninja API is available.")
    else:
        print("Binary Ninja API is not available - functionality will be limited.")
