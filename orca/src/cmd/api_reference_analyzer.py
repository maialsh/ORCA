"""
API Reference Analyzer Module for BinSleuth
Finds API references in binary, retrieves assembly context, and provides LLM analysis
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
        from binaryninja import BinaryView, Function, BasicBlock, SymbolType
        BINARY_NINJA_AVAILABLE = True
    except ImportError:
        BINARY_NINJA_AVAILABLE = False
        print("Warning: Binary Ninja API not available")
else:
    BINARY_NINJA_AVAILABLE = False
    print("Warning: Binary Ninja not found")

from llm_module import llm_handler


class ApiReferenceAnalyzer:
    """
    Analyzer that finds API references in binary files,
    retrieves the containing function and assembly context,
    and provides LLM-based analysis of API usage.
    """
    
    def __init__(self, binary_view: Optional[Any] = None):
        """
        Initialize the API reference analyzer
        
        Args:
            binary_view: Binary Ninja BinaryView object
        """
        self.binary_view = binary_view
        self.api_cache = {}  # Cache for API search results
        self.function_cache = {}  # Cache for function analysis results
        
        if not BINARY_NINJA_AVAILABLE:
            print("Warning: Binary Ninja not available. Limited functionality.")
    
    def find_api_references(self, api_name: str, exact_match: bool = False) -> List[Dict[str, Any]]:
        """
        Find all references to a specific API in the binary
        
        Args:
            api_name: Name of the API to search for
            exact_match: Whether to require exact name match or allow partial matches
            
        Returns:
            List of dictionaries containing API reference information:
            [
                {
                    "api_name": str,
                    "found_symbol": str,
                    "address": str,
                    "function_name": str,
                    "function_start": str,
                    "function_end": str,
                    "usage_context": str,
                    "assembly": str,
                    "function_assembly": str,
                    "call_context": List[str],
                    "parameters": List[str],
                    "llm_analysis": str
                }
            ]
        """
        if not self.binary_view or not BINARY_NINJA_AVAILABLE:
            return self._fallback_api_search(api_name)
        
        # Check cache first
        cache_key = f"{api_name}:{exact_match}"
        if cache_key in self.api_cache:
            return self.api_cache[cache_key]
        
        results = []
        
        try:
            # Find API symbols
            api_symbols = self._find_api_symbols(api_name, exact_match)
            
            for symbol in api_symbols:
                # Ensure symbol has required attributes
                if not hasattr(symbol, 'address') or not hasattr(symbol, 'name'):
                    print(f"Warning: Symbol missing required attributes: {symbol}")
                    continue
                
                try:
                    # Find cross-references to this API
                    xrefs = self.binary_view.get_code_refs(symbol.address)
                    
                    for xref in xrefs:
                        # Get the function containing this reference
                        func = self.binary_view.get_function_at(xref)
                        if not func:
                            # Try to find containing function
                            funcs = self.binary_view.get_functions_containing(xref)
                            if funcs:
                                func = funcs[0]
                        
                        if func:
                            # Analyze the API reference context
                            ref_info = self._analyze_api_reference(
                                api_name, symbol, xref, func
                            )
                            if ref_info:
                                results.append(ref_info)
                except Exception as symbol_error:
                    print(f"Error processing symbol {getattr(symbol, 'name', 'unknown')}: {symbol_error}")
                    continue
            
            # Cache the results
            self.api_cache[cache_key] = results
            
        except Exception as e:
            print(f"Error finding API references: {e}")
            return self._fallback_api_search(api_name)
        
        return results
    
    def _find_api_symbols(self, api_name: str, exact_match: bool = False) -> List[Any]:
        """
        Find symbols matching the API name
        
        Args:
            api_name: API name to search for
            exact_match: Whether to require exact match
            
        Returns:
            List of matching symbols
        """
        matching_symbols = []
        
        try:
            # Handle different ways Binary Ninja might structure symbols
            symbols_collection = self.binary_view.symbols
            
            # If symbols is a dict-like object with values()
            if hasattr(symbols_collection, 'values'):
                symbol_values = symbols_collection.values()
            else:
                symbol_values = symbols_collection
            
            for symbol_item in symbol_values:
                # Handle case where symbol_item might be a list or single symbol
                symbols_to_check = []
                
                if isinstance(symbol_item, list):
                    symbols_to_check.extend(symbol_item)
                else:
                    symbols_to_check.append(symbol_item)
                
                for symbol in symbols_to_check:
                    # Ensure we have a valid symbol object with required attributes
                    if not hasattr(symbol, 'type') or not hasattr(symbol, 'name'):
                        continue
                        
                    # Check if symbol is a function or import
                    if symbol.type in [SymbolType.FunctionSymbol, SymbolType.ImportedFunctionSymbol]:
                        if exact_match:
                            if symbol.name == api_name:
                                matching_symbols.append(symbol)
                        else:
                            if api_name.lower() in symbol.name.lower():
                                matching_symbols.append(symbol)
                                
        except Exception as e:
            print(f"Error in _find_api_symbols: {e}")
            # Fallback: try iterating through symbols differently
            try:
                for symbol in self.binary_view.symbols:
                    if hasattr(symbol, 'type') and hasattr(symbol, 'name'):
                        if symbol.type in [SymbolType.FunctionSymbol, SymbolType.ImportedFunctionSymbol]:
                            if exact_match:
                                if symbol.name == api_name:
                                    matching_symbols.append(symbol)
                            else:
                                if api_name.lower() in symbol.name.lower():
                                    matching_symbols.append(symbol)
            except Exception as e2:
                print(f"Fallback symbol iteration also failed: {e2}")
        
        return matching_symbols
    
    def _get_instruction_context(self, ref_addr: int, function: Any, context_size: int = 10) -> List[Tuple[int, str]]:
        """
        Get instruction context around a reference address using proper Binary Ninja methods
        
        Args:
            ref_addr: Address of the reference
            function: Function containing the reference
            context_size: Number of instructions before and after to include
            
        Returns:
            List of tuples (address, disassembly)
        """
        context_instructions = []
        
        try:
            # Find the basic block containing the reference
            target_block = None
            for block in function.basic_blocks:
                if block.start <= ref_addr < block.end:
                    target_block = block
                    break
            
            if not target_block:
                # Fallback: try to get instruction at reference address only
                try:
                    disasm = self.binary_view.get_disassembly(ref_addr)
                    if disasm:
                        context_instructions.append((ref_addr, disasm))
                except:
                    pass
                return context_instructions
            
            # Get instructions from the block using proper instruction iteration
            instructions_found = []
            
            # Try to get all instructions in the block
            try:
                current_addr = target_block.start
                while current_addr < target_block.end:
                    try:
                        disasm = self.binary_view.get_disassembly(current_addr)
                        if disasm:
                            instructions_found.append((current_addr, disasm))
                        
                        # Get instruction length to move to next instruction
                        try:
                            instruction_length = self.binary_view.get_instruction_length(current_addr)
                            if instruction_length > 0:
                                current_addr += instruction_length
                            else:
                                # Fallback: assume minimum instruction size
                                current_addr += 1
                        except:
                            current_addr += 1
                            
                    except:
                        current_addr += 1
                        if current_addr >= target_block.end:
                            break
            except Exception as e:
                print(f"Error iterating instructions: {e}")
            
            # If we couldn't get instructions properly, try a simpler approach
            if not instructions_found:
                # Try to get some instructions around the reference using smaller steps
                start_range = max(target_block.start, ref_addr - (context_size * 4))
                end_range = min(target_block.end, ref_addr + (context_size * 4))
                
                for addr in range(start_range, end_range, 1):  # Try every byte
                    try:
                        disasm = self.binary_view.get_disassembly(addr)
                        if disasm and disasm.strip():  # Only add non-empty disassembly
                            instructions_found.append((addr, disasm))
                            if len(instructions_found) >= context_size * 2:
                                break
                    except:
                        continue
            
            # Find the reference instruction in our list and get context around it
            ref_index = -1
            for i, (addr, _) in enumerate(instructions_found):
                if addr == ref_addr:
                    ref_index = i
                    break
            
            if ref_index >= 0:
                # Get context around the reference
                start_idx = max(0, ref_index - context_size)
                end_idx = min(len(instructions_found), ref_index + context_size + 1)
                context_instructions = instructions_found[start_idx:end_idx]
            else:
                # If we couldn't find the exact reference, include what we found
                context_instructions = instructions_found[:context_size * 2]
                
        except Exception as e:
            print(f"Error getting instruction context: {e}")
            # Final fallback: try to get just the reference instruction
            try:
                disasm = self.binary_view.get_disassembly(ref_addr)
                if disasm:
                    context_instructions.append((ref_addr, disasm))
            except:
                pass
        
        return context_instructions
    
    def _analyze_api_reference(self, api_name: str, symbol: Any, ref_addr: int, 
                             function: Any) -> Optional[Dict[str, Any]]:
        """
        Analyze a specific API reference within a function
        
        Args:
            api_name: Original API name searched for
            symbol: Binary Ninja Symbol object for the API
            ref_addr: Address of the reference to the API
            function: Binary Ninja Function object containing the reference
            
        Returns:
            Dictionary with API reference analysis or None if analysis fails
        """
        try:
            # Get instruction at reference address
            instruction_text = ""
            call_context = []
            
            # Get instruction at the reference address first
            try:
                instruction_text = self.binary_view.get_disassembly(ref_addr)
                if not instruction_text:
                    instruction_text = "Unable to get instruction"
            except Exception as e:
                instruction_text = f"Error getting instruction: {e}"
            
            # Get context around the reference using proper instruction iteration
            context_instructions = self._get_instruction_context(ref_addr, function, context_size=10)
            
            disasm_lines = []
            for addr, disasm in context_instructions:
                try:
                    marker = " --> " if addr == ref_addr else "     "
                    disasm_lines.append(f"{marker}{addr:08x}: {disasm}")
                    
                    # Get context around the API call (within 32 bytes)
                    if abs(addr - ref_addr) <= 32:
                        call_context.append(f"{addr:08x}: {disasm}")
                except Exception as e:
                    continue
            
            # Analyze parameters and calling convention
            parameters = self._analyze_api_parameters(ref_addr, function)
            
            # Get function assembly (limited to reasonable size)
            function_assembly = self._get_function_assembly(function, max_lines=100)
            
            # Determine usage context
            usage_context = self._determine_api_usage_context(instruction_text, function, symbol)
            
            # Perform LLM analysis of the API usage
            llm_analysis = self._analyze_api_usage_with_llm(
                api_name, symbol.name, instruction_text, call_context, 
                function.name, parameters
            )
            
            return {
                "api_name": api_name,
                "found_symbol": symbol.name,
                "symbol_type": str(symbol.type),
                "address": f"0x{ref_addr:08x}",
                "symbol_address": f"0x{symbol.address:08x}",
                "function_name": function.name,
                "function_start": f"0x{function.start:08x}",
                "function_end": f"0x{function.highest_address:08x}",
                "function_size": function.highest_address - function.start,
                "usage_context": usage_context,
                "assembly": "\n".join(disasm_lines),
                "function_assembly": function_assembly,
                "call_context": call_context,
                "parameters": parameters,
                "instruction": instruction_text,
                "llm_analysis": llm_analysis
            }
            
        except Exception as e:
            print(f"Error analyzing API reference: {e}")
            return None
    
    def _analyze_api_parameters(self, ref_addr: int, function: Any) -> List[str]:
        """
        Analyze parameters being passed to the API call
        
        Args:
            ref_addr: Address of the API reference
            function: Function containing the reference
            
        Returns:
            List of parameter information
        """
        parameters = []
        
        try:
            # Get instructions before the call using proper instruction context
            context_instructions = self._get_instruction_context(ref_addr, function, context_size=8)
            
            # Find the reference instruction and get instructions before it
            ref_index = -1
            for i, (addr, _) in enumerate(context_instructions):
                if addr == ref_addr:
                    ref_index = i
                    break
            
            if ref_index > 0:
                # Analyze instructions before the call
                for i in range(max(0, ref_index - 5), ref_index):
                    addr, disasm = context_instructions[i]
                    try:
                        disasm_lower = disasm.lower()
                        
                        # Look for common parameter setup patterns
                        if any(op in disasm_lower for op in ['push', 'mov', 'lea', 'load']):
                            # Check if this might be setting up a parameter
                            if any(reg in disasm_lower for reg in ['eax', 'ebx', 'ecx', 'edx', 'esi', 'edi', 'r8', 'r9', 'r10', 'r11']):
                                parameters.append(f"{addr:08x}: {disasm}")
                        
                        # Look for immediate values that might be parameters
                        if re.search(r'0x[0-9a-fA-F]+', disasm):
                            parameters.append(f"{addr:08x}: {disasm}")
                    except:
                        continue
                        
        except Exception as e:
            print(f"Error analyzing API parameters: {e}")
        
        return parameters[-5:]  # Return last 5 parameter setup instructions
    
    def _determine_api_usage_context(self, instruction: str, function: Any, symbol: Any) -> str:
        """
        Determine the context in which the API is being used
        
        Args:
            instruction: Assembly instruction calling the API
            function: Function containing the call
            symbol: API symbol being called
            
        Returns:
            Usage context description
        """
        if not instruction:
            return "unknown"
        
        instruction_lower = instruction.lower()
        api_name = symbol.name.lower()
        
        # Analyze based on API name patterns
        if any(pattern in api_name for pattern in ['create', 'open']):
            return "resource_creation"
        elif any(pattern in api_name for pattern in ['read', 'write', 'copy', 'cpy']):
            return "data_access"
        elif any(pattern in api_name for pattern in ['close', 'delete', 'destroy']):
            return "resource_cleanup"
        elif any(pattern in api_name for pattern in ['connect', 'send', 'recv']):
            return "network_communication"
        elif any(pattern in api_name for pattern in ['alloc', 'malloc', 'free']):
            return "memory_management"
        elif any(pattern in api_name for pattern in ['thread', 'process']):
            return "process_management"
        elif any(pattern in api_name for pattern in ['reg', 'key']):
            return "registry_access"
        elif any(pattern in api_name for pattern in ['crypt', 'hash']):
            return "cryptographic_operation"
        else:
            # Analyze based on instruction type
            if 'call' in instruction_lower:
                return "function_call"
            elif 'jmp' in instruction_lower:
                return "function_jump"
            else:
                return "other"
    
    def _get_function_assembly(self, function: Any, max_lines: int = 400) -> str:
        """
        Get assembly code for a function using proper Binary Ninja methods
        
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
                
                # Add block header
                assembly_lines.append(f"# Block {block.start:08x}-{block.end:08x}")
                line_count += 1
                
                # Get instructions from the block using proper iteration
                current_addr = block.start
                while current_addr < block.end and line_count < max_lines:
                    try:
                        disasm = self.binary_view.get_disassembly(current_addr)
                        if disasm:
                            assembly_lines.append(f"{current_addr:08x}: {disasm}")
                            line_count += 1
                        
                        # Get instruction length to move to next instruction
                        try:
                            instruction_length = self.binary_view.get_instruction_length(current_addr)
                            if instruction_length > 0:
                                current_addr += instruction_length
                            else:
                                current_addr += 1  # Fallback
                        except:
                            current_addr += 1  # Fallback
                            
                    except:
                        current_addr += 1
                        if current_addr >= block.end:
                            break
            
            return "\n".join(assembly_lines)
            
        except Exception as e:
            return f"Error getting function assembly: {e}"
    
    def _analyze_api_usage_with_llm(self, api_name: str, symbol_name: str, instruction: str,
                                  call_context: List[str], function_name: str, 
                                  parameters: List[str]) -> str:
        """
        Use LLM to analyze how an API is being used
        
        Args:
            api_name: Original API name searched for
            symbol_name: Actual symbol name found
            instruction: Assembly instruction calling the API
            call_context: Assembly context around the call
            function_name: Name of the function containing the call
            parameters: Parameter setup instructions
            
        Returns:
            LLM analysis of the API usage
        """
        system_prompt = """You are a reverse engineering expert analyzing API usage in assembly code.
        
        Analyze the provided API call and assembly context to determine:
        1. The purpose of the API call
        2. How parameters are being set up
        3. The role of this API call in the overall function
        4. Any security implications or suspicious behavior
        5. Common use cases for this API
        
        Be specific about the assembly instructions and their purpose."""
        
        user_prompt = f"""Analyze this API call in assembly code:
        
        API: {symbol_name} (searched for: {api_name})
        Function: {function_name}
        Call Instruction: {instruction}
        
        Call Context (assembly around the API call):
        {chr(10).join(call_context)}
        
        Parameter Setup Instructions:
        {chr(10).join(parameters) if parameters else "No parameter setup detected"}
        
        Provide a detailed analysis of:
        1. What this API does and its typical use cases
        2. How parameters are being prepared for this call
        3. The purpose of this API call within the function
        4. Any security concerns or suspicious usage patterns
        5. Technical details about the calling convention and assembly
        """
        
        try:
            analysis = llm_handler.query(system_prompt, user_prompt)
            return analysis
        except Exception as e:
            return f"LLM analysis failed: {str(e)}"
    
    def _fallback_api_search(self, api_name: str) -> List[Dict[str, Any]]:
        """
        Fallback API search when Binary Ninja is not available
        
        Args:
            api_name: API name to search for
            
        Returns:
            Limited search results
        """
        return [{
            "api_name": api_name,
            "found_symbol": api_name,
            "address": "unknown",
            "function_name": "unknown",
            "function_start": "unknown",
            "function_end": "unknown",
            "usage_context": "Binary Ninja not available - limited analysis",
            "assembly": "Not available",
            "function_assembly": "Not available",
            "call_context": [],
            "parameters": [],
            "llm_analysis": "Analysis not available without Binary Ninja"
        }]
    
    def analyze_function(self, function_name: str) -> Optional[Dict[str, Any]]:
        """
        Analyze all API calls within a specific function
        
        Args:
            function_name: Name of the function to analyze
            
        Returns:
            Dictionary with function analysis including all API calls
        """
        if not self.binary_view or not BINARY_NINJA_AVAILABLE:
            return None
        
        # Check cache first
        if function_name in self.function_cache:
            return self.function_cache[function_name]
        
        # Find the function
        target_function = None
        for func in self.binary_view.functions:
            if func.name == function_name:
                target_function = func
                break
        
        if not target_function:
            return None
        
        try:
            # Get function information
            function_info = {
                "function_name": function_name,
                "start_address": f"0x{target_function.start:08x}",
                "end_address": f"0x{target_function.highest_address:08x}",
                "size": target_function.highest_address - target_function.start,
                "apis_used": [],
                "api_calls": [],
                "assembly": self._get_function_assembly(target_function),
                "llm_analysis": ""
            }
            
            # Find all API calls in the function using proper instruction iteration
            api_calls = []
            apis_used = set()
            
            for block in target_function.basic_blocks:
                current_addr = block.start
                while current_addr < block.end:
                    try:
                        # Check for call instructions
                        disasm = self.binary_view.get_disassembly(current_addr)
                        if disasm and 'call' in disasm.lower():
                            # Get the target of the call
                            refs = self.binary_view.get_code_refs_from(current_addr)
                            for ref in refs:
                                # Check if this is a call to an API
                                symbol = self.binary_view.get_symbol_at(ref)
                                if symbol and symbol.type in [SymbolType.FunctionSymbol, SymbolType.ImportedFunctionSymbol]:
                                    apis_used.add(symbol.name)
                                    
                                    # Analyze this specific API call
                                    api_ref = self._analyze_api_reference(
                                        symbol.name, symbol, current_addr, target_function
                                    )
                                    if api_ref:
                                        api_calls.append(api_ref)
                        
                        # Move to next instruction
                        try:
                            instruction_length = self.binary_view.get_instruction_length(current_addr)
                            if instruction_length > 0:
                                current_addr += instruction_length
                            else:
                                current_addr += 1
                        except:
                            current_addr += 1
                            
                    except:
                        current_addr += 1
                        if current_addr >= block.end:
                            break
            
            function_info["apis_used"] = list(apis_used)
            function_info["api_calls"] = api_calls
            
            # Get LLM analysis of the entire function
            if api_calls:
                function_info["llm_analysis"] = self._analyze_function_with_llm(function_info)
            
            # Cache the result
            self.function_cache[function_name] = function_info
            
            return function_info
            
        except Exception as e:
            print(f"Error analyzing function {function_name}: {e}")
            return None
    
    def _analyze_function_with_llm(self, function_info: Dict[str, Any]) -> str:
        """
        Use LLM to analyze the overall purpose and behavior of a function
        
        Args:
            function_info: Function information including API calls
            
        Returns:
            LLM analysis of the function
        """
        system_prompt = """You are a reverse engineering expert analyzing a function's behavior based on its API calls and assembly code.
        
        Analyze the provided function information to determine:
        1. The overall purpose of the function
        2. The sequence of operations being performed
        3. Any security implications or suspicious behavior
        4. The function's role in the larger program
        5. Potential malicious activities
        
        Focus on the API calls and their sequence to understand the function's behavior."""
        
        # Prepare API call summary
        api_summary = []
        for api_call in function_info.get("api_calls", []):
            api_summary.append(f"- {api_call['found_symbol']} at {api_call['address']}")
            api_summary.append(f"  Context: {api_call['usage_context']}")
            api_summary.append(f"  Instruction: {api_call['instruction']}")
        
        user_prompt = f"""Analyze this function and its API usage:
        
        Function: {function_info['function_name']}
        Size: {function_info['size']} bytes
        Address Range: {function_info['start_address']} - {function_info['end_address']}
        
        APIs Used: {', '.join(function_info.get('apis_used', []))}
        
        API Call Details:
        {chr(10).join(api_summary)}
        
        Assembly Code (partial):
        {function_info.get('assembly', 'Not available')[:2000]}
        
        Provide a comprehensive analysis of:
        1. The function's primary purpose and functionality
        2. The sequence of operations and their significance
        3. Any security concerns or suspicious behavior patterns
        4. How this function might fit into the larger program
        5. Potential impact if this is malicious code
        """
        
        try:
            analysis = llm_handler.query(system_prompt, user_prompt)
            return analysis
        except Exception as e:
            return f"LLM function analysis failed: {str(e)}"
    
    def find_functions_using_api(self, api_name: str) -> List[str]:
        """
        Find all functions that use a specific API
        
        Args:
            api_name: API name to search for
            
        Returns:
            List of function names that use the API
        """
        api_refs = self.find_api_references(api_name)
        function_names = list(set(ref["function_name"] for ref in api_refs))
        return function_names
    
    def get_api_usage_summary(self, api_name: str) -> Dict[str, Any]:
        """
        Get a comprehensive summary of how an API is used across the binary
        
        Args:
            api_name: API name to analyze
            
        Returns:
            Summary of API usage
        """
        api_refs = self.find_api_references(api_name)
        
        if not api_refs:
            return {
                "api_name": api_name,
                "usage_count": 0,
                "functions": [],
                "usage_contexts": [],
                "summary": f"API '{api_name}' not found in binary"
            }
        
        # Analyze usage patterns
        functions = list(set(ref["function_name"] for ref in api_refs))
        contexts = list(set(ref["usage_context"] for ref in api_refs))
        
        # Generate summary
        summary = f"API '{api_name}' is used {len(api_refs)} times across {len(functions)} functions.\n"
        summary += f"Usage contexts: {', '.join(contexts)}\n"
        summary += f"Functions using this API: {', '.join(functions)}"
        
        return {
            "api_name": api_name,
            "usage_count": len(api_refs),
            "functions": functions,
            "usage_contexts": contexts,
            "api_references": api_refs,
            "summary": summary
        }


def analyze_api_references(binary_view: Any, api_name: str) -> List[Dict[str, Any]]:
    """
    Convenience function to analyze API references
    
    Args:
        binary_view: Binary Ninja BinaryView object
        api_name: API name to search for
        
    Returns:
        List of API reference analysis results
    """
    analyzer = ApiReferenceAnalyzer(binary_view)
    return analyzer.find_api_references(api_name)


if __name__ == "__main__":
    # Example usage (requires Binary Ninja)
    print("API Reference Analyzer")
    print("This module requires Binary Ninja to be installed and available.")
    
    if BINARY_NINJA_AVAILABLE:
        print("Binary Ninja API is available.")
    else:
        print("Binary Ninja API is not available - functionality will be limited.")
