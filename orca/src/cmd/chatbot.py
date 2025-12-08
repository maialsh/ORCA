"""
Enhanced Chatbot Module for ORCA
Provides comprehensive interactive chat interface with deep context from analysis results
Integrates with the workflow system to use all analysis data as knowledge base
"""
import json
import os
import re
from typing import Dict, List, Any, Optional
from pathlib import Path

from llm_module import llm_handler
from enhanced_string_analysis import EnhancedStringAnalyzer
from code_reference_analyzer import CodeReferenceAnalyzer
from api_reference_analyzer import ApiReferenceAnalyzer
from api_crossrefs import ApiCrossReferenceTool


class ORCAChatbot:
    """
    Interactive chatbot for binary analysis with comprehensive context from all analysis modules.
    Uses the complete analysis results as knowledge base instead of just strings.
    """
    
    def __init__(self, analysis_context: Optional[Dict[str, Any]] = None):
        """
        Initialize the chatbot with comprehensive analysis context
        
        Args:
            analysis_context: Dictionary containing complete analysis results from workflow
        """
        self.analysis_context = analysis_context or {}
        self.conversation_history = []
        self.string_analyzer = EnhancedStringAnalyzer()
        self.code_ref_analyzer = None
        self.api_ref_analyzer = None
        self.api_crossref_tool = None
        
        # Initialize analyzers if binary view is available
        if self.analysis_context.get("binary_view"):
            try:
                self.code_ref_analyzer = CodeReferenceAnalyzer(self.analysis_context["binary_view"])
                self.api_ref_analyzer = ApiReferenceAnalyzer(self.analysis_context["binary_view"])
                self.api_crossref_tool = ApiCrossReferenceTool(self.analysis_context["binary_view"])
            except Exception as e:
                print(f"Warning: Could not initialize reference analyzers: {e}")
    
    def update_context(self, new_context: Dict[str, Any]):
        """
        Update the analysis context with new results
        
        Args:
            new_context: New analysis context to merge
        """
        self.analysis_context.update(new_context)
        
        # Update analyzers if binary view becomes available
        if self.analysis_context.get("binary_view") and not self.code_ref_analyzer:
            try:
                self.code_ref_analyzer = CodeReferenceAnalyzer(self.analysis_context["binary_view"])
                self.api_ref_analyzer = ApiReferenceAnalyzer(self.analysis_context["binary_view"])
                self.api_crossref_tool = ApiCrossReferenceTool(self.analysis_context["binary_view"])
            except Exception as e:
                print(f"Warning: Could not initialize reference analyzers: {e}")
    
    def chat(self, user_message: str) -> str:
        """
        Process user message and return chatbot response using comprehensive analysis context
        
        Args:
            user_message: User's question or message
            
        Returns:
            Chatbot response
        """
        # Add user message to history
        self.conversation_history.append({"role": "user", "content": user_message})
        
        # Check for specific commands or queries first
        response = self._process_specific_commands(user_message)
        
        # If no specific command matched, use general LLM processing with full context
        if not response:
            response = self._process_general_query(user_message)
        
        # Add response to history
        self.conversation_history.append({"role": "assistant", "content": response})
        
        return response
    
    def _process_specific_commands(self, message: str) -> Optional[str]:
        """
        Process specific commands that require special handling
        
        Args:
            message: User message to process
            
        Returns:
            Response if a specific command was matched, None otherwise
        """
        message_lower = message.lower()
        
        # Handle specific commands
        if "find string" in message_lower or "search string" in message_lower:
            return self._handle_string_search(message)
        elif "find api" in message_lower or "search api" in message_lower:
            return self._handle_api_search(message)
        elif self._is_api_usage_query(message_lower):
            # Handle "how is API used" type questions by routing to find_api pipeline
            return self._handle_api_usage_query(message)
        elif "analyze function" in message_lower or "function analysis" in message_lower:
            return self._handle_function_analysis(message)
        elif "list functions" in message_lower or "show functions" in message_lower:
            return self._handle_list_functions()
        elif "list apis" in message_lower or "show apis" in message_lower:
            return self._handle_list_apis()
        elif "suspicious strings" in message_lower:
            return self._handle_suspicious_strings()
        elif "cross reference" in message_lower or "xref" in message_lower:
            return self._handle_cross_reference_query(message)
        elif "help" in message_lower or "commands" in message_lower:
            return self._handle_help_query()
        
        return None
    
    def _process_general_query(self, message: str) -> str:
        """
        Process general queries using LLM with comprehensive analysis context
        
        Args:
            message: User message
            
        Returns:
            LLM-generated response
        """
        # Prepare comprehensive context for LLM
        context_summary = self._prepare_comprehensive_context()
        
        system_prompt = """You are ORCA, an expert binary analysis assistant with access to comprehensive 
        analysis results from static analysis, API analysis, string analysis, and other security analysis modules.
        
        You have detailed knowledge about the binary including:
        - File information and metadata
        - Imported and exported functions with cross-references
        - String analysis results categorized by type
        - API clustering and behavior analysis
        - Function analysis with behavior patterns
        - Capabilities and potential malware indicators
        - Dynamic analysis results (if available)
        - Binary summary and security assessment
        
        Answer the user's question based on the provided analysis context. Be helpful, accurate, and provide 
        specific details when available. If you don't have enough information to answer a question, say so clearly.
        
        You can help with:
        - Explaining binary capabilities and functionality
        - Identifying suspicious or malicious behavior
        - Finding specific strings, APIs, or functions
        - Analyzing code patterns and security implications
        - Providing recommendations for further analysis
        - Cross-referencing APIs and functions
        - Explaining the purpose of specific functions or code sections
        - Comparing declared functionality with actual capabilities
        """
        
        user_prompt = f"""Comprehensive Analysis Context:
{context_summary}

Conversation History:
{self._format_conversation_history()}

User Question: {message}

Please provide a helpful and detailed response based on the comprehensive analysis context."""
        
        try:
            response = llm_handler.query(system_prompt, user_prompt)
            return response
        except Exception as e:
            return f"I apologize, but I encountered an error processing your question: {str(e)}"
    
    def _prepare_comprehensive_context(self) -> str:
        """
        Prepare a comprehensive summary of all analysis results for the LLM
        
        Returns:
            Formatted comprehensive context summary
        """
        summary_parts = []
        
        # Basic file information
        static_results = self.analysis_context.get("static_analysis_results", {})
        if static_results.get("file_info"):
            file_info = static_results["file_info"]
            summary_parts.append("=== FILE INFORMATION ===")
            summary_parts.append(f"File: {file_info.get('name', 'Unknown')}")
            summary_parts.append(f"Path: {file_info.get('path', 'Unknown')}")
            summary_parts.append(f"Size: {file_info.get('size', 'Unknown')} bytes")
            summary_parts.append(f"SHA256: {file_info.get('sha256', 'Unknown')}")
            summary_parts.append(f"Type: {file_info.get('type', 'Unknown')}")
            summary_parts.append("")
        
        # Binary purpose and goal
        if self.analysis_context.get("binary_functionality"):
            summary_parts.append("=== BINARY PURPOSE ===")
            summary_parts.append(f"Declared Functionality: {self.analysis_context['binary_functionality']}")
            summary_parts.append(f"Analysis Goal: {self.analysis_context.get('goal', 'Unknown')}")
            summary_parts.append("")
        
        # Static analysis results
        if static_results:
            summary_parts.append("=== STATIC ANALYSIS ===")
            
            # Imports
            if static_results.get("imports"):
                imports = static_results["imports"]
                summary_parts.append(f"Imported Functions ({len(imports)} total):")
                if len(imports) <= 15:
                    for imp in imports:
                        summary_parts.append(f"  - {imp}")
                else:
                    for imp in imports[:15]:
                        summary_parts.append(f"  - {imp}")
                    summary_parts.append(f"  ... and {len(imports)-15} more")
                summary_parts.append("")
            
            # Exports
            if static_results.get("exports"):
                exports = static_results["exports"]
                summary_parts.append(f"Exported Functions ({len(exports)} total):")
                for exp in exports[:10]:  # Show first 10
                    summary_parts.append(f"  - {exp}")
                if len(exports) > 10:
                    summary_parts.append(f"  ... and {len(exports)-10} more")
                summary_parts.append("")
            
            # Strings analysis
            if static_results.get("strings"):
                strings_data = static_results["strings"]
                summary_parts.append("String Analysis:")
                for category, strings in strings_data.items():
                    if isinstance(strings, list) and strings:
                        summary_parts.append(f"  {category.title()} ({len(strings)} items):")
                        for s in strings[:5]:  # Show first 5 per category
                            summary_parts.append(f"    - {s}")
                        if len(strings) > 5:
                            summary_parts.append(f"    ... and {len(strings)-5} more")
                summary_parts.append("")
            
            # Functions with behavior
            if static_results.get("functions"):
                functions = static_results["functions"]
                summary_parts.append(f"Functions ({len(functions)} total):")
                
                # Show functions with interesting behavior
                interesting_functions = []
                for func in functions[:15]:  # Limit for context
                    if func.get("behavior"):
                        behavior_types = [b.get("type", "unknown") for b in func["behavior"]]
                        interesting_functions.append(f"{func.get('name', 'unknown')} - behaviors: {', '.join(set(behavior_types))}")
                    else:
                        interesting_functions.append(f"{func.get('name', 'unknown')} - no special behavior detected")
                
                for func_desc in interesting_functions:
                    summary_parts.append(f"  - {func_desc}")
                
                if len(functions) > 15:
                    summary_parts.append(f"  ... and {len(functions)-15} more functions")
                summary_parts.append("")
        
        # API Cross-references
        api_crossrefs = self.analysis_context.get("api_crossrefs_results", {})
        if api_crossrefs:
            summary_parts.append("=== API CROSS-REFERENCES ===")
            summary_parts.append(f"APIs with cross-references: {len(api_crossrefs)}")
            
            # Show sample API cross-references
            for api_name, xref_data in list(api_crossrefs.items())[:5]:
                summary_parts.append(f"  {api_name}:")
                if isinstance(xref_data, dict):
                    if xref_data.get("cross_references"):
                        summary_parts.append(f"    Cross-references: {len(xref_data['cross_references'])}")
                    if xref_data.get("analysis"):
                        summary_parts.append(f"    Analysis: {xref_data['analysis'][:100]}...")
            
            if len(api_crossrefs) > 5:
                summary_parts.append(f"  ... and {len(api_crossrefs)-5} more APIs")
            summary_parts.append("")
        
        # API Clustering
        api_clustering = self.analysis_context.get("api_clustering_results", {})
        if api_clustering.get("clusters"):
            summary_parts.append("=== API CLUSTERS ===")
            for i, cluster in enumerate(api_clustering["clusters"][:5]):  # Show first 5 clusters
                summary_parts.append(f"Cluster {i+1}: {cluster.get('name', 'Unknown')}")
                summary_parts.append(f"  Description: {cluster.get('description', 'No description')}")
                summary_parts.append(f"  APIs ({len(cluster.get('apis', []))}): {', '.join(cluster.get('apis', [])[:5])}")
                if len(cluster.get('apis', [])) > 5:
                    summary_parts.append(f"    ... and {len(cluster.get('apis', []))-5} more")
                summary_parts.append(f"  Security Assessment: {cluster.get('security_assessment', 'Unknown')}")
                summary_parts.append(f"  Potential Usage: {cluster.get('potential_usage', 'Unknown')}")
                summary_parts.append("")
        
        # API Analysis
        api_analysis = self.analysis_context.get("api_analysis_results", {})
        if api_analysis:
            summary_parts.append("=== API ANALYSIS ===")
            summary_parts.append(f"Referenced APIs: {len(api_analysis.get('referenced_apis', []))}")
            summary_parts.append(f"Functions with API calls: {len(api_analysis.get('filtered_functions', []))}")
            
            if api_analysis.get("api_relevance"):
                summary_parts.append("API Relevance Analysis:")
                for api, relevance in list(api_analysis["api_relevance"].items())[:5]:
                    summary_parts.append(f"  {api}: {relevance}")
            summary_parts.append("")
        
        # Capabilities
        capabilities = self.analysis_context.get("capabilities", {})
        if capabilities:
            summary_parts.append("=== CAPABILITIES ===")
            for category, items in capabilities.items():
                if items and category != "error":
                    if isinstance(items, list) and items:
                        summary_parts.append(f"{category.replace('_', ' ').title()}:")
                        for item in items[:5]:  # Show first 5 items
                            summary_parts.append(f"  - {item}")
                        if len(items) > 5:
                            summary_parts.append(f"  ... and {len(items)-5} more")
                    elif isinstance(items, str):
                        summary_parts.append(f"{category.replace('_', ' ').title()}: {items}")
            summary_parts.append("")
        
        # Malware analysis
        malware_analysis = self.analysis_context.get("malware_analysis_results", {})
        if malware_analysis:
            summary_parts.append("=== MALWARE ANALYSIS ===")
            summary_parts.append(f"Classification: {malware_analysis.get('classification', 'Unknown')}")
            summary_parts.append(f"Threat Level: {malware_analysis.get('threat_level', 'Unknown')}")
            summary_parts.append(f"Confidence: {malware_analysis.get('confidence_level', 0)}%")
            
            if malware_analysis.get("malicious_indicators"):
                summary_parts.append("Malicious Indicators:")
                for indicator in malware_analysis["malicious_indicators"][:5]:
                    summary_parts.append(f"  - {indicator}")
                if len(malware_analysis["malicious_indicators"]) > 5:
                    summary_parts.append(f"  ... and {len(malware_analysis['malicious_indicators'])-5} more")
            
            if malware_analysis.get("suspicious_behaviors"):
                summary_parts.append("Suspicious Behaviors:")
                for behavior in malware_analysis["suspicious_behaviors"][:5]:
                    summary_parts.append(f"  - {behavior}")
                if len(malware_analysis["suspicious_behaviors"]) > 5:
                    summary_parts.append(f"  ... and {len(malware_analysis['suspicious_behaviors'])-5} more")
            summary_parts.append("")
        
        # Binary summary
        binary_summary = self.analysis_context.get("binary_summary_results", {})
        if binary_summary and binary_summary.get("summary"):
            summary_parts.append("=== BINARY SUMMARY ===")
            summary_text = binary_summary["summary"]
            if len(summary_text) > 800:
                summary_parts.append(summary_text[:800] + "...")
            else:
                summary_parts.append(summary_text)
            summary_parts.append("")
        
        # Final summary
        final_summary = self.analysis_context.get("final_summary", {})
        if final_summary:
            summary_parts.append("=== FINAL ANALYSIS SUMMARY ===")
            if final_summary.get("executive_summary"):
                summary_parts.append(f"Executive Summary: {final_summary['executive_summary']}")
            if final_summary.get("security_assessment"):
                summary_parts.append(f"Security Assessment: {final_summary['security_assessment']}")
            summary_parts.append("")
        
        # Dynamic analysis
        dynamic_results = self.analysis_context.get("dynamic_analysis_results", {})
        if dynamic_results and not dynamic_results.get("error"):
            summary_parts.append("=== DYNAMIC ANALYSIS ===")
            if dynamic_results.get("suspicious_syscalls"):
                summary_parts.append(f"Suspicious System Calls ({len(dynamic_results['suspicious_syscalls'])}):")
                for syscall in dynamic_results["suspicious_syscalls"][:5]:
                    summary_parts.append(f"  - {syscall}")
                if len(dynamic_results["suspicious_syscalls"]) > 5:
                    summary_parts.append(f"  ... and {len(dynamic_results['suspicious_syscalls'])-5} more")
            summary_parts.append("")
        
        return "\n".join(summary_parts) if summary_parts else "No comprehensive analysis context available."
    
    def _handle_string_search(self, message: str) -> str:
        """
        Handle string search queries using both static analysis and reference analyzer
        
        Args:
            message: User message containing string search request
            
        Returns:
            Response with string search results
        """
        # Extract string from message
        search_string = self._extract_quoted_text(message)
        if not search_string:
            # Try to extract without quotes
            words = message.split()
            for i, word in enumerate(words):
                if word.lower() in ["string", "strings"] and i + 1 < len(words):
                    search_string = words[i + 1]
                    break
        
        if not search_string:
            return "Please specify the string you want to search for. Example: 'find string \"example\"'"
        
        results = []
        
        # Search in static analysis strings
        static_results = self.analysis_context.get("static_analysis_results", {})
        strings_data = static_results.get("strings", {})
        
        for category, strings_list in strings_data.items():
            if isinstance(strings_list, list):
                for s in strings_list:
                    if search_string.lower() in s.lower():
                        results.append(f"Found in {category}: '{s}'")
        
        # Search using reference analyzer if available
        if self.code_ref_analyzer:
            try:
                ref_results = self.code_ref_analyzer.find_string_references(search_string)
                if ref_results:
                    results.append("\nCode References:")
                    for result in ref_results:
                        results.append(f"  Function: {result['function_name']} at {result['address']}")
                        results.append(f"  Context: {result['context']}")
            except Exception as e:
                results.append(f"Error in reference analysis: {str(e)}")
        
        if results:
            return f"Search results for '{search_string}':\n\n" + "\n".join(results)
        else:
            return f"No references found for string '{search_string}' in the binary analysis results."
    
    def _handle_api_search(self, message: str) -> str:
        """
        Handle API search queries using comprehensive analysis including cross-references,
        enhanced assembly analysis, and LLM insights for instructions before and after API calls
        
        Args:
            message: User message containing API search request
            
        Returns:
            Response with comprehensive API search results including enhanced assembly analysis
        """
        # Extract API name from message
        api_name = self._extract_quoted_text(message)
        if not api_name:
            words = message.split()
            for i, word in enumerate(words):
                if word.lower() in ["api", "apis"] and i + 1 < len(words):
                    api_name = words[i + 1]
                    break
        
        if not api_name:
            return "Please specify the API you want to search for. Example: 'find api \"malloc\"'"
        
        # Check if we have cached analysis for this API
        cached_analysis = self._get_cached_api_analysis(api_name)
        if cached_analysis:
            return self._format_cached_api_analysis(api_name, cached_analysis)
        
        results = []
        
        # 1. Search in static analysis imports first
        static_results = self.analysis_context.get("static_analysis_results", {})
        imports = static_results.get("imports", [])
        
        matching_imports = [imp for imp in imports if api_name.lower() in imp.lower()]
        if matching_imports:
            results.append(f"=== IMPORT ANALYSIS ===")
            results.append(f"Found {len(matching_imports)} matching imports:")
            for imp in matching_imports:
                results.append(f"  - {imp}")
            results.append("")
        
        # 2. Use ApiCrossReferenceTool to get code references
        crossref_results = []
        if self.api_crossref_tool:
            try:
                # Get cross-references using the ApiCrossReferenceTool
                crossref_data = self.api_crossref_tool.analyze_api_crossrefs(api_name)
                if crossref_data:
                    results.append(f"=== CODE CROSS-REFERENCES ===")
                    results.append(f"Found {len(crossref_data)} API variants with code references:")
                    
                    for api_data in crossref_data:
                        api_variant = api_data.get("api_name", "Unknown")
                        references = api_data.get("references", [])
                        
                        results.append(f"\nAPI: {api_variant}")
                        results.append(f"  Functions using this API: {len(references)}")
                        
                        for ref in references[:3]:  # Show first 3 functions
                            func_name = ref.get("function", "Unknown")
                            start_addr = ref.get("start_addr", "Unknown")
                            callsites = ref.get("callsites", [])
                            
                            results.append(f"    - Function: {func_name} ({start_addr})")
                            results.append(f"      Call sites: {len(callsites)} locations")
                            if callsites:
                                results.append(f"      Addresses: {', '.join(callsites[:3])}")
                                if len(callsites) > 3:
                                    results.append(f"        ... and {len(callsites)-3} more")
                        
                        if len(references) > 3:
                            results.append(f"    ... and {len(references)-3} more functions")
                    
                    # Store for detailed analysis
                    crossref_results = crossref_data
                    results.append("")
                else:
                    results.append(f"=== CODE CROSS-REFERENCES ===")
                    results.append(f"No code references found for API '{api_name}' in the binary.")
                    results.append("")
            except Exception as e:
                results.append(f"Error in cross-reference analysis: {str(e)}")
                results.append("")
        
        # 3. Enhanced assembly analysis with before/after API call context
        enhanced_analysis = self._perform_enhanced_assembly_analysis(api_name, crossref_results)
        if enhanced_analysis:
            results.extend(enhanced_analysis)
        
        # 4. Search in existing API cross-references from analysis context
        api_crossrefs = self.analysis_context.get("api_crossrefs_results", {})
        if api_crossrefs:
            matching_crossrefs = []
            for api, xref_data in api_crossrefs.items():
                if api_name.lower() in api.lower():
                    matching_crossrefs.append((api, xref_data))
            
            if matching_crossrefs:
                results.append(f"=== STORED CROSS-REFERENCE DATA ===")
                for api, xref_data in matching_crossrefs[:3]:  # Show first 3
                    results.append(f"API: {api}")
                    if isinstance(xref_data, dict):
                        if xref_data.get("cross_references"):
                            results.append(f"  Stored cross-references: {len(xref_data['cross_references'])}")
                        if xref_data.get("analysis"):
                            analysis_text = xref_data['analysis']
                            results.append(f"  Stored analysis: {analysis_text[:200]}...")
                    results.append("")
        
        # 5. Cache the comprehensive analysis results
        comprehensive_analysis = {
            "imports": matching_imports,
            "crossref_data": crossref_results,
            "enhanced_analysis": enhanced_analysis,
            "timestamp": str(os.path.getmtime(__file__)) if os.path.exists(__file__) else "unknown"
        }
        self._cache_api_analysis(api_name, comprehensive_analysis)
        
        # 6. Provide summary and recommendations
        if results:
            results.append(f"=== SUMMARY ===")
            total_refs = len(crossref_results) if crossref_results else 0
            if total_refs > 0:
                results.append(f"API '{api_name}' is actively used in the binary with {total_refs} code references.")
                results.append(f"Enhanced assembly analysis reveals detailed usage patterns and calling conventions.")
                results.append(f"LLM analysis provides insights into instructions before and after API calls.")
            else:
                results.append(f"API '{api_name}' was found in imports but no active code references were detected.")
                results.append(f"This could indicate the API is imported but not used, or used through indirect calls.")
            
            return f"Comprehensive API Analysis for '{api_name}':\n\n" + "\n".join(results)
        else:
            return f"No references found for API '{api_name}' in the binary analysis results.\n\nThe API may not be imported or used by this binary."
    
    def _handle_function_analysis(self, message: str) -> str:
        """
        Handle function analysis queries
        
        Args:
            message: User message containing function analysis request
            
        Returns:
            Response with function analysis
        """
        # Extract function name from message
        function_name = self._extract_quoted_text(message)
        if not function_name:
            words = message.split()
            for i, word in enumerate(words):
                if word.lower() == "function" and i + 1 < len(words):
                    function_name = words[i + 1]
                    break
        
        if not function_name:
            return "Please specify the function you want to analyze. Example: 'analyze function \"main\"'"
        
        # Search in static analysis functions
        static_results = self.analysis_context.get("static_analysis_results", {})
        functions = static_results.get("functions", [])
        
        matching_functions = []
        for func in functions:
            if function_name.lower() in func.get("name", "").lower():
                matching_functions.append(func)
        
        if not matching_functions:
            return f"Function '{function_name}' not found in the static analysis results."
        
        results = []
        for func in matching_functions[:3]:  # Limit to 3 matches
            results.append(f"Function: {func.get('name', 'Unknown')}")
            results.append(f"  Address: {func.get('address', 'Unknown')}")
            results.append(f"  Size: {func.get('size', 'Unknown')} bytes")
            
            if func.get("callers"):
                results.append(f"  Called by: {', '.join(func['callers'][:5])}")
            
            if func.get("callees"):
                results.append(f"  Calls: {', '.join(func['callees'][:5])}")
            
            if func.get("behavior"):
                behavior_types = [b.get("type", "unknown") for b in func["behavior"]]
                results.append(f"  Behavior patterns: {', '.join(set(behavior_types))}")
                
                # Show some behavior details
                for behavior in func["behavior"][:3]:
                    results.append(f"    - {behavior.get('type', 'unknown')}: {behavior.get('instruction', 'N/A')}")
            
            results.append("")
        
        # Use API reference analyzer if available
        if self.api_ref_analyzer:
            try:
                detailed_analysis = self.api_ref_analyzer.analyze_function(function_name)
                if detailed_analysis:
                    results.append("Detailed Analysis:")
                    results.append(f"  APIs used: {', '.join(detailed_analysis.get('apis_used', []))}")
                    if detailed_analysis.get('llm_analysis'):
                        results.append(f"  LLM Analysis: {detailed_analysis['llm_analysis'][:300]}...")
            except Exception as e:
                results.append(f"Error in detailed analysis: {str(e)}")
        
        return "\n".join(results)
    
    def _handle_list_functions(self) -> str:
        """
        Handle requests to list functions in the binary
        
        Returns:
            Response with function list
        """
        static_results = self.analysis_context.get("static_analysis_results", {})
        functions = static_results.get("functions", [])
        
        if not functions:
            return "No functions found in static analysis results."
        
        response = [f"Functions Found ({len(functions)} total):"]
        
        # Show first 20 functions with details
        for i, func in enumerate(functions[:20]):
            name = func.get("name", f"function_{i}")
            address = func.get("address", "unknown")
            size = func.get("size", "unknown")
            
            func_line = f"  {name} (Address: {address}, Size: {size})"
            
            # Add behavior info if available
            if func.get("behavior"):
                behavior_types = [b.get("type", "unknown") for b in func["behavior"]]
                unique_behaviors = list(set(behavior_types))
                if unique_behaviors:
                    func_line += f" - Behaviors: {', '.join(unique_behaviors)}"
            
            response.append(func_line)
        
        if len(functions) > 20:
            response.append(f"\n... and {len(functions) - 20} more functions.")
            response.append("Use 'analyze function <name>' to get detailed analysis of a specific function.")
        
        return "\n".join(response)
    
    def _handle_list_apis(self) -> str:
        """
        Handle requests to list APIs used by the binary
        
        Returns:
            Response with API list
        """
        static_results = self.analysis_context.get("static_analysis_results", {})
        imports = static_results.get("imports", [])
        
        if not imports:
            return "No APIs/imports found in static analysis results."
        
        response = [f"APIs/Imports Found ({len(imports)} total):"]
        
        # Group APIs by category using clustering results if available
        api_clustering = self.analysis_context.get("api_clustering_results", {})
        if api_clustering.get("clusters"):
            response.append("\nGrouped by functionality:")
            for cluster in api_clustering["clusters"]:
                cluster_name = cluster.get("name", "Unknown")
                cluster_apis = cluster.get("apis", [])
                security = cluster.get("security_assessment", "unknown")
                
                response.append(f"\n{cluster_name} ({security}):")
                for api in cluster_apis[:10]:  # Show first 10 per cluster
                    response.append(f"  - {api}")
                if len(cluster_apis) > 10:
                    response.append(f"  ... and {len(cluster_apis)-10} more")
        else:
            # Show ungrouped list
            for api in imports[:30]:  # Show first 30
                response.append(f"  - {api}")
            if len(imports) > 30:
                response.append(f"  ... and {len(imports)-30} more")
        
        response.append("\nUse 'find api <name>' to find where a specific API is used in the code.")
        
        return "\n".join(response)
    
    def _handle_suspicious_strings(self) -> str:
        """
        Handle queries about suspicious strings using enhanced string analysis
        
        Returns:
            Response with suspicious strings analysis
        """
        static_results = self.analysis_context.get("static_analysis_results", {})
        strings_data = static_results.get("strings", {})
        
        if not strings_data:
            return "No strings found in static analysis results for suspicious string analysis."
        
        # Collect all strings
        all_strings = []
        for category, strings_list in strings_data.items():
            if isinstance(strings_list, list):
                all_strings.extend(strings_list)
        
        if not all_strings:
            return "No strings found to analyze for suspicious patterns."
        
        try:
            # Analyze for suspicious strings
            suspicious_results = self.string_analyzer.find_suspicious_strings(all_strings)
            
            if not any(suspicious_results.get("suspicious_strings", {}).values()):
                return "No suspicious strings indicating malicious behavior were found."
            
            response = ["Suspicious Strings Analysis:"]
            response.append(f"Risk Score: {suspicious_results.get('risk_score', 0)}/100")
            
            if suspicious_results.get("summary"):
                response.append(f"\nSummary: {suspicious_results['summary']}")
            
            # Display suspicious strings by category
            for category, strings in suspicious_results.get("suspicious_strings", {}).items():
                if strings:
                    response.append(f"\n{category.replace('_', ' ').title()}:")
                    for string_info in strings[:5]:  # Show first 5 per category
                        response.append(f"  - '{string_info['string']}'")
                        response.append(f"    Reason: {string_info['reason']}")
                        response.append(f"    Risk Level: {string_info['risk_level']}")
                    if len(strings) > 5:
                        response.append(f"  ... and {len(strings)-5} more")
            
            return "\n".join(response)
            
        except Exception as e:
            return f"Error analyzing suspicious strings: {str(e)}"
    
    def _handle_cross_reference_query(self, message: str) -> str:
        """
        Handle cross-reference queries
        
        Args:
            message: User message containing cross-reference request
            
        Returns:
            Response with cross-reference information
        """
        # Extract what to cross-reference from message
        target = self._extract_quoted_text(message)
        if not target:
            words = message.split()
            for i, word in enumerate(words):
                if word.lower() in ["xref", "reference", "cross"] and i + 1 < len(words):
                    target = words[i + 1]
                    break
        
        if not target:
            return "Please specify what you want to cross-reference. Example: 'cross reference \"CreateFile\"'"
        
        results = []
        
        # Check API cross-references
        api_crossrefs = self.analysis_context.get("api_crossrefs_results", {})
        for api, xref_data in api_crossrefs.items():
            if target.lower() in api.lower():
                results.append(f"\nAPI Cross-references for '{api}':")
                if isinstance(xref_data, dict):
                    if xref_data.get("cross_references"):
                        results.append(f"  Found {len(xref_data['cross_references'])} cross-references")
                        for xref in xref_data["cross_references"][:5]:
                            results.append(f"    - {xref}")
                        if len(xref_data["cross_references"]) > 5:
                            results.append(f"    ... and {len(xref_data['cross_references'])-5} more")
                    
                    if xref_data.get("analysis"):
                        results.append(f"  Analysis: {xref_data['analysis'][:200]}...")
        
        # Use reference analyzers if available
        if self.api_ref_analyzer:
            try:
                api_refs = self.api_ref_analyzer.find_api_references(target)
                if api_refs:
                    results.append(f"\nDetailed Cross-references for '{target}':")
                    for ref in api_refs[:3]:  # Show first 3
                        results.append(f"  Function: {ref['function_name']} at {ref['address']}")
                        results.append(f"  Context: {ref['usage_context']}")
                        if ref.get('instruction'):
                            results.append(f"  Instruction: {ref['instruction']}")
            except Exception as e:
                results.append(f"Error in API reference analysis: {str(e)}")
        
        if self.code_ref_analyzer:
            try:
                string_refs = self.code_ref_analyzer.find_string_references(target)
                if string_refs:
                    results.append(f"\nString Cross-references for '{target}':")
                    for ref in string_refs[:3]:  # Show first 3
                        results.append(f"  Function: {ref['function_name']} at {ref['address']}")
                        results.append(f"  Context: {ref['context']}")
            except Exception as e:
                results.append(f"Error in string reference analysis: {str(e)}")
        
        if results:
            return f"Cross-reference results for '{target}':\n" + "\n".join(results)
        else:
            return f"No cross-references found for '{target}' in the analysis results."
    
    def _handle_help_query(self) -> str:
        """
        Handle help queries showing available commands
        
        Returns:
            Help text with available commands
        """
        help_text = """ORCA Chatbot - Available Commands:

SPECIFIC COMMANDS:
• find string "text" - Search for specific strings in the binary
• find api "name" - Search for specific API usage
• analyze function "name" - Get detailed analysis of a function
• list functions - Show all functions found in the binary
• list apis - Show all APIs/imports used by the binary
• suspicious strings - Find strings that might indicate malicious behavior
• cross reference "item" - Find cross-references for APIs or strings
• help - Show this help message

GENERAL QUERIES:
You can also ask general questions about the binary analysis, such as:
• "What does this binary do?"
• "Is this binary malicious?"
• "What network capabilities does this have?"
• "What files does this access?"
• "Explain the main functionality"
• "What are the security implications?"

ANALYSIS CONTEXT:
I have access to comprehensive analysis results including:
- Static analysis (functions, imports, exports, strings)
- API clustering and cross-references
- Malware analysis and threat assessment
- Capabilities analysis
- Binary summary and security assessment
- Dynamic analysis results (if available)

Feel me ask specific questions about any aspect of the binary analysis!"""
        
        return help_text
    
    def _is_api_usage_query(self, message_lower: str) -> bool:
        """
        Check if the message is asking about how an API is used
        
        Args:
            message_lower: Lowercase user message
            
        Returns:
            True if this is an API usage query
        """
        api_usage_patterns = [
            "how is",
            "how does",
            "how are",
            "usage of",
            "used by",
            "using",
            "utilizes",
            "calls to",
            "calling",
            "invokes",
            "invocation of"
        ]
        
        api_indicators = [
            "api",
            "function",
            "call",
            "method"
        ]
        
        # Check if message contains usage patterns and API indicators
        has_usage_pattern = any(pattern in message_lower for pattern in api_usage_patterns)
        has_api_indicator = any(indicator in message_lower for indicator in api_indicators)
        
        return has_usage_pattern and has_api_indicator
    
    def _handle_api_usage_query(self, message: str) -> str:
        """
        Handle queries about how APIs are used by routing to the find_api pipeline
        
        Args:
            message: User message asking about API usage
            
        Returns:
            Response with API usage analysis
        """
        # Extract API name from the usage query
        api_name = self._extract_api_from_usage_query(message)
        
        if not api_name:
            return ("I understand you're asking about API usage, but I need to know which specific API. "
                   "Please specify the API name. Example: 'How is CreateFile used?' or 'How does malloc work?'")
        
        # Use the enhanced find_api pipeline to analyze usage
        return self._handle_api_search(f'find api "{api_name}"')
    
    def _extract_api_from_usage_query(self, message: str) -> Optional[str]:
        """
        Extract API name from a usage query
        
        Args:
            message: User message asking about API usage
            
        Returns:
            API name if found, None otherwise
        """
        # First try quoted text
        quoted_api = self._extract_quoted_text(message)
        if quoted_api:
            return quoted_api
        
        # Try to find API name patterns in the message
        words = message.split()
        
        # Look for patterns like "how is CreateFile used"
        for i, word in enumerate(words):
            if word.lower() in ["is", "does", "are"] and i + 1 < len(words):
                potential_api = words[i + 1]
                # Check if it looks like an API name (starts with capital or contains common API patterns)
                if (potential_api[0].isupper() or 
                    any(pattern in potential_api.lower() for pattern in ['create', 'get', 'set', 'open', 'close', 'read', 'write', 'malloc', 'free'])):
                    return potential_api
        
        # Look for patterns like "usage of CreateFile"
        for i, word in enumerate(words):
            if word.lower() in ["of", "for"] and i + 1 < len(words):
                potential_api = words[i + 1]
                if (potential_api[0].isupper() or 
                    any(pattern in potential_api.lower() for pattern in ['create', 'get', 'set', 'open', 'close', 'read', 'write', 'malloc', 'free'])):
                    return potential_api
        
        # Look for common API names in the message
        common_apis = [
            'CreateFile', 'ReadFile', 'WriteFile', 'CloseHandle', 'OpenProcess',
            'VirtualAlloc', 'VirtualProtect', 'LoadLibrary', 'GetProcAddress',
            'RegOpenKey', 'RegSetValue', 'RegQueryValue', 'malloc', 'free', 'calloc',
            'strcpy', 'strcat', 'sprintf', 'printf', 'scanf', 'fopen', 'fclose',
            'socket', 'connect', 'send', 'recv', 'bind', 'listen', 'accept'
        ]
        
        message_lower = message.lower()
        for api in common_apis:
            if api.lower() in message_lower:
                return api
        
        return None
    
    def _extract_quoted_text(self, message: str) -> Optional[str]:
        """
        Extract text within quotes from a message
        
        Args:
            message: Message to extract quoted text from
            
        Returns:
            Quoted text if found, None otherwise
        """
        # Try double quotes first
        match = re.search(r'"([^"]+)"', message)
        if match:
            return match.group(1)
        
        # Try single quotes
        match = re.search(r"'([^']+)'", message)
        if match:
            return match.group(1)
        
        return None
    
    def _perform_enhanced_assembly_analysis(self, api_name: str, crossref_results: List[Dict[str, Any]]) -> List[str]:
        """
        Perform enhanced assembly analysis with detailed before/after API call context
        
        Args:
            api_name: API name being analyzed
            crossref_results: Cross-reference results from ApiCrossReferenceTool
            
        Returns:
            List of formatted analysis results
        """
        results = []
        
        if not self.api_ref_analyzer or not crossref_results:
            return results
        
        try:
            # Get detailed API references with assembly context
            detailed_refs = self.api_ref_analyzer.find_api_references(api_name)
            
            if detailed_refs:
                results.append(f"=== ENHANCED ASSEMBLY ANALYSIS ===")
                results.append(f"Detailed analysis of {len(detailed_refs)} API references with before/after context:")
                
                for i, ref in enumerate(detailed_refs[:5]):  # Show first 5 detailed references
                    results.append(f"\n[Enhanced Reference {i+1}]")
                    results.append(f"  API Symbol: {ref.get('found_symbol', 'Unknown')}")
                    results.append(f"  Function: {ref.get('function_name', 'Unknown')}")
                    results.append(f"  Address: {ref.get('address', 'Unknown')}")
                    results.append(f"  Usage Context: {ref.get('usage_context', 'Unknown')}")
                    
                    # Enhanced assembly context analysis
                    assembly_context = self._analyze_assembly_before_after(ref)
                    if assembly_context:
                        results.extend(assembly_context)
                    
                    # Show parameter setup with enhanced analysis
                    if ref.get('parameters'):
                        results.append(f"  Parameter Setup Analysis:")
                        param_analysis = self._analyze_parameter_setup(ref['parameters'])
                        results.extend(param_analysis)
                    
                    # Enhanced LLM analysis focusing on before/after instructions
                    enhanced_llm = self._get_enhanced_llm_analysis(ref, api_name)
                    if enhanced_llm:
                        results.append(f"  Enhanced LLM Analysis (Before/After Context):")
                        results.append(f"    {enhanced_llm[:400]}...")
                        if len(enhanced_llm) > 400:
                            results.append(f"    ... (full analysis available)")
                
                if len(detailed_refs) > 5:
                    results.append(f"\n... and {len(detailed_refs)-5} more enhanced references")
                
                results.append("")
                
                # Function-level enhanced analysis
                functions_using_api = list(set(ref.get('function_name', '') for ref in detailed_refs))
                if functions_using_api and functions_using_api[0]:
                    results.append(f"=== FUNCTION-LEVEL ENHANCED ANALYSIS ===")
                    results.append(f"Enhanced analysis of functions utilizing '{api_name}':")
                    
                    for func_name in functions_using_api[:3]:  # Analyze first 3 functions
                        if func_name and func_name != 'Unknown':
                            try:
                                func_analysis = self._get_enhanced_function_analysis(func_name, api_name)
                                if func_analysis:
                                    results.extend(func_analysis)
                            except Exception as func_error:
                                results.append(f"  Error in enhanced function analysis for {func_name}: {func_error}")
                    
                    if len(functions_using_api) > 3:
                        results.append(f"\n... and {len(functions_using_api)-3} more functions with enhanced analysis available")
            else:
                results.append(f"=== ENHANCED ASSEMBLY ANALYSIS ===")
                results.append(f"No detailed assembly references found for enhanced analysis of API '{api_name}'.")
                results.append("")
                
        except Exception as e:
            results.append(f"Error in enhanced assembly analysis: {str(e)}")
            results.append("")
        
        return results
    
    def _analyze_assembly_before_after(self, ref: Dict[str, Any]) -> List[str]:
        """
        Analyze assembly instructions before and after the API call
        
        Args:
            ref: API reference data containing assembly context
            
        Returns:
            List of formatted analysis results
        """
        results = []
        
        try:
            assembly = ref.get('assembly', '')
            if not assembly:
                return results
            
            assembly_lines = assembly.split('\n')
            api_call_line = -1
            
            # Find the API call instruction
            for i, line in enumerate(assembly_lines):
                if '-->' in line:  # Marker for the API call
                    api_call_line = i
                    break
            
            if api_call_line >= 0:
                results.append(f"  Assembly Context Analysis:")
                
                # Analyze instructions before the API call
                before_instructions = assembly_lines[max(0, api_call_line-5):api_call_line]
                if before_instructions:
                    results.append(f"    Instructions BEFORE API call:")
                    for line in before_instructions:
                        if line.strip():
                            results.append(f"      {line}")
                            # Analyze specific instruction patterns
                            instruction_analysis = self._analyze_instruction_pattern(line)
                            if instruction_analysis:
                                results.append(f"        → {instruction_analysis}")
                
                # Show the API call itself
                if api_call_line < len(assembly_lines):
                    api_line = assembly_lines[api_call_line]
                    results.append(f"    API CALL:")
                    results.append(f"      {api_line}")
                
                # Analyze instructions after the API call
                after_instructions = assembly_lines[api_call_line+1:api_call_line+6]
                if after_instructions:
                    results.append(f"    Instructions AFTER API call:")
                    for line in after_instructions:
                        if line.strip():
                            results.append(f"      {line}")
                            # Analyze specific instruction patterns
                            instruction_analysis = self._analyze_instruction_pattern(line)
                            if instruction_analysis:
                                results.append(f"        → {instruction_analysis}")
            
        except Exception as e:
            results.append(f"    Error analyzing assembly context: {str(e)}")
        
        return results
    
    def _analyze_instruction_pattern(self, instruction_line: str) -> Optional[str]:
        """
        Analyze a specific assembly instruction for patterns
        
        Args:
            instruction_line: Assembly instruction line
            
        Returns:
            Analysis of the instruction pattern or None
        """
        if not instruction_line.strip():
            return None
        
        instruction = instruction_line.lower()
        
        # Parameter setup patterns
        if 'push' in instruction:
            return "Parameter being pushed onto stack"
        elif 'mov' in instruction and any(reg in instruction for reg in ['eax', 'ebx', 'ecx', 'edx']):
            return "Register being set up (likely parameter)"
        elif 'lea' in instruction:
            return "Loading effective address (likely string/buffer parameter)"
        elif 'xor' in instruction and instruction.count('eax') == 2:
            return "Zeroing register (likely NULL parameter)"
        
        # Return value handling patterns
        elif 'test' in instruction and 'eax' in instruction:
            return "Testing return value for success/failure"
        elif 'cmp' in instruction and 'eax' in instruction:
            return "Comparing return value against expected value"
        elif 'jz' in instruction or 'je' in instruction:
            return "Conditional jump based on zero/equal result"
        elif 'jnz' in instruction or 'jne' in instruction:
            return "Conditional jump based on non-zero/not-equal result"
        
        # Memory operations
        elif 'mov' in instruction and '[' in instruction:
            return "Memory access operation"
        elif 'add esp' in instruction or 'sub esp' in instruction:
            return "Stack cleanup/allocation"
        
        return None
    
    def _analyze_parameter_setup(self, parameters: List[str]) -> List[str]:
        """
        Analyze parameter setup instructions for patterns
        
        Args:
            parameters: List of parameter setup instructions
            
        Returns:
            List of formatted parameter analysis
        """
        results = []
        
        for i, param in enumerate(parameters):
            param_analysis = f"    Parameter {i+1}: {param}"
            
            # Analyze the parameter instruction
            if 'push' in param.lower():
                if '0' in param or 'null' in param.lower():
                    param_analysis += " → NULL parameter"
                elif any(reg in param.lower() for reg in ['eax', 'ebx', 'ecx', 'edx']):
                    param_analysis += " → Register value parameter"
                else:
                    param_analysis += " → Immediate value parameter"
            elif 'mov' in param.lower():
                param_analysis += " → Register setup for parameter"
            elif 'lea' in param.lower():
                param_analysis += " → Address/pointer parameter"
            
            results.append(param_analysis)
        
        return results
    
    def _get_enhanced_llm_analysis(self, ref: Dict[str, Any], api_name: str) -> str:
        """
        Get enhanced LLM analysis focusing on before/after API call context
        
        Args:
            ref: API reference data
            api_name: API name being analyzed
            
        Returns:
            Enhanced LLM analysis
        """
        system_prompt = """You are a reverse engineering expert specializing in assembly code analysis.
        
        Focus specifically on analyzing the assembly instructions BEFORE and AFTER API calls to understand:
        1. How parameters are being prepared and passed to the API
        2. How the return value is being handled and checked
        3. The calling convention being used
        4. Error handling patterns
        5. Security implications of the parameter setup and return value handling
        6. Common attack patterns or defensive programming practices
        
        Pay special attention to the sequence of instructions and their purpose in the API calling context."""
        
        # Extract before/after context from assembly
        assembly = ref.get('assembly', '')
        before_after_context = ""
        
        if assembly:
            lines = assembly.split('\n')
            api_line = -1
            for i, line in enumerate(lines):
                if '-->' in line:
                    api_line = i
                    break
            
            if api_line >= 0:
                before_lines = lines[max(0, api_line-5):api_line]
                after_lines = lines[api_line:api_line+6]
                before_after_context = "BEFORE API CALL:\n" + "\n".join(before_lines)
                before_after_context += "\n\nAFTER API CALL:\n" + "\n".join(after_lines)
        
        user_prompt = f"""Analyze this API call with focus on before/after assembly context:
        
        API: {ref.get('found_symbol', api_name)}
        Function: {ref.get('function_name', 'Unknown')}
        Usage Context: {ref.get('usage_context', 'Unknown')}
        
        Assembly Context (Before/After API call):
        {before_after_context}
        
        Parameter Setup:
        {chr(10).join(ref.get('parameters', []))}
        
        Provide detailed analysis focusing on:
        1. Parameter preparation sequence and calling convention
        2. Return value handling and error checking patterns
        3. Security implications of the parameter setup
        4. Any defensive programming or attack patterns
        5. How this fits into the overall function logic
        6. Potential vulnerabilities or security concerns
        """
        
        try:
            analysis = llm_handler.query(system_prompt, user_prompt)
            return analysis
        except Exception as e:
            return f"Enhanced LLM analysis failed: {str(e)}"
    
    def _get_enhanced_function_analysis(self, func_name: str, api_name: str) -> List[str]:
        """
        Get enhanced function-level analysis focusing on API usage patterns
        
        Args:
            func_name: Function name to analyze
            api_name: API being analyzed
            
        Returns:
            List of formatted enhanced function analysis
        """
        results = []
        
        try:
            func_analysis = self.api_ref_analyzer.analyze_function(func_name)
            if func_analysis:
                results.append(f"\nEnhanced Function Analysis: {func_name}")
                results.append(f"  Address Range: {func_analysis.get('start_address', 'Unknown')} - {func_analysis.get('end_address', 'Unknown')}")
                results.append(f"  Size: {func_analysis.get('size', 'Unknown')} bytes")
                
                apis_used = func_analysis.get('apis_used', [])
                if apis_used:
                    results.append(f"  All APIs Used: {', '.join(apis_used[:8])}")
                    if len(apis_used) > 8:
                        results.append(f"    ... and {len(apis_used)-8} more")
                
                # Enhanced analysis of API call patterns within the function
                api_calls = func_analysis.get('api_calls', [])
                api_specific_calls = [call for call in api_calls if api_name.lower() in call.get('found_symbol', '').lower()]
                
                if api_specific_calls:
                    results.append(f"  {api_name} Usage Pattern in Function:")
                    for i, call in enumerate(api_specific_calls[:3]):
                        results.append(f"    Call {i+1}: {call.get('address', 'Unknown')}")
                        results.append(f"      Context: {call.get('usage_context', 'Unknown')}")
                        results.append(f"      Instruction: {call.get('instruction', 'Unknown')}")
                
                # Enhanced LLM analysis for function-level API usage
                if func_analysis.get('llm_analysis'):
                    func_llm = func_analysis['llm_analysis']
                    results.append(f"  Function-Level API Usage Analysis:")
                    sentences = func_llm.split('. ')
                    for sentence in sentences[:3]:  # Show first 3 sentences
                        if sentence.strip():
                            results.append(f"    {sentence.strip()}.")
                    if len(sentences) > 3:
                        results.append(f"    ... (complete analysis available)")
        
        except Exception as e:
            results.append(f"  Error in enhanced function analysis: {str(e)}")
        
        return results
    
    def _get_cached_api_analysis(self, api_name: str) -> Optional[Dict[str, Any]]:
        """
        Get cached API analysis if available
        
        Args:
            api_name: API name to look up
            
        Returns:
            Cached analysis data or None
        """
        # Check if we have cached analysis in the analysis context
        cached_apis = self.analysis_context.get("cached_api_analyses", {})
        return cached_apis.get(api_name.lower())
    
    def _cache_api_analysis(self, api_name: str, analysis_data: Dict[str, Any]):
        """
        Cache API analysis results for future use
        
        Args:
            api_name: API name
            analysis_data: Analysis data to cache
        """
        if "cached_api_analyses" not in self.analysis_context:
            self.analysis_context["cached_api_analyses"] = {}
        
        self.analysis_context["cached_api_analyses"][api_name.lower()] = analysis_data
    
    def _format_cached_api_analysis(self, api_name: str, cached_data: Dict[str, Any]) -> str:
        """
        Format cached API analysis for display
        
        Args:
            api_name: API name
            cached_data: Cached analysis data
            
        Returns:
            Formatted cached analysis
        """
        results = [f"Using cached analysis for API '{api_name}':\n"]
        
        # Show imports
        imports = cached_data.get("imports", [])
        if imports:
            results.append(f"=== CACHED IMPORT ANALYSIS ===")
            results.append(f"Found {len(imports)} matching imports:")
            for imp in imports:
                results.append(f"  - {imp}")
            results.append("")
        
        # Show cross-reference data
        crossref_data = cached_data.get("crossref_data", [])
        if crossref_data:
            results.append(f"=== CACHED CROSS-REFERENCES ===")
            results.append(f"Found {len(crossref_data)} API variants with code references:")
            
            for api_data in crossref_data:
                api_variant = api_data.get("api_name", "Unknown")
                references = api_data.get("references", [])
                
                results.append(f"\nAPI: {api_variant}")
                results.append(f"  Functions using this API: {len(references)}")
                
                for ref in references[:2]:  # Show first 2 functions from cache
                    func_name = ref.get("function", "Unknown")
                    start_addr = ref.get("start_addr", "Unknown")
                    callsites = ref.get("callsites", [])
                    
                    results.append(f"    - Function: {func_name} ({start_addr})")
                    results.append(f"      Call sites: {len(callsites)} locations")
                
                if len(references) > 2:
                    results.append(f"    ... and {len(references)-2} more functions")
            results.append("")
        
        # Show enhanced analysis summary
        enhanced_analysis = cached_data.get("enhanced_analysis", [])
        if enhanced_analysis:
            results.append(f"=== CACHED ENHANCED ANALYSIS ===")
            results.append("Enhanced assembly analysis available from cache.")
            results.append("Key findings from previous analysis:")
            
            # Extract key insights from cached enhanced analysis
            for line in enhanced_analysis[:10]:  # Show first 10 lines
                if "Enhanced Reference" in line or "Parameter" in line or "LLM Analysis" in line:
                    results.append(f"  {line}")
            
            if len(enhanced_analysis) > 10:
                results.append(f"  ... and {len(enhanced_analysis)-10} more analysis lines")
            results.append("")
        
        # Show cache timestamp
        timestamp = cached_data.get("timestamp", "unknown")
        results.append(f"=== CACHE INFO ===")
        results.append(f"Analysis cached at: {timestamp}")
        results.append("Use 'find api <name>' again to refresh the analysis.")
        
        return "\n".join(results)
    
    def _format_conversation_history(self) -> str:
        """
        Format conversation history for LLM context
        
        Returns:
            Formatted conversation history
        """
        if not self.conversation_history:
            return "No previous conversation."
        
        # Show last 5 exchanges to keep context manageable
        recent_history = self.conversation_history[-10:]  # Last 10 messages (5 exchanges)
        
        formatted = []
        for entry in recent_history:
            role = entry["role"].title()
            content = entry["content"]
            # Truncate very long messages
            if len(content) > 500:
                content = content[:500] + "..."
            formatted.append(f"{role}: {content}")
        
        return "\n".join(formatted)
    
    def get_conversation_summary(self) -> Dict[str, Any]:
        """
        Get a summary of the current conversation
        
        Returns:
            Dictionary with conversation statistics and summary
        """
        total_messages = len(self.conversation_history)
        user_messages = len([msg for msg in self.conversation_history if msg["role"] == "user"])
        assistant_messages = len([msg for msg in self.conversation_history if msg["role"] == "assistant"])
        
        # Get recent topics discussed
        recent_topics = []
        for msg in self.conversation_history[-6:]:  # Last 6 messages
            if msg["role"] == "user":
                content = msg["content"].lower()
                if "string" in content:
                    recent_topics.append("string analysis")
                elif "api" in content:
                    recent_topics.append("API analysis")
                elif "function" in content:
                    recent_topics.append("function analysis")
                elif "malicious" in content or "suspicious" in content:
                    recent_topics.append("malware analysis")
                elif "help" in content:
                    recent_topics.append("help")
        
        return {
            "total_messages": total_messages,
            "user_messages": user_messages,
            "assistant_messages": assistant_messages,
            "recent_topics": list(set(recent_topics)),
            "has_analysis_context": bool(self.analysis_context),
            "available_analyzers": {
                "string_analyzer": self.string_analyzer is not None,
                "code_ref_analyzer": self.code_ref_analyzer is not None,
                "api_ref_analyzer": self.api_ref_analyzer is not None
            }
        }
    
    def clear_conversation(self):
        """
        Clear the conversation history
        """
        self.conversation_history = []
    
    def save_conversation(self, filepath: str):
        """
        Save conversation history to file
        
        Args:
            filepath: Path to save the conversation
        """
        try:
            conversation_data = {
                "conversation_history": self.conversation_history,
                "analysis_context_summary": {
                    "has_static_analysis": "static_analysis_results" in self.analysis_context,
                    "has_api_crossrefs": "api_crossrefs_results" in self.analysis_context,
                    "has_api_clustering": "api_clustering_results" in self.analysis_context,
                    "has_malware_analysis": "malware_analysis_results" in self.analysis_context,
                    "has_capabilities": "capabilities" in self.analysis_context,
                    "binary_functionality": self.analysis_context.get("binary_functionality", "Unknown")
                },
                "conversation_summary": self.get_conversation_summary(),
                "timestamp": str(os.path.getmtime(__file__))
            }
            
            with open(filepath, 'w') as f:
                json.dump(conversation_data, f, indent=2)
            
            print(f"Conversation saved to {filepath}")
        except Exception as e:
            print(f"Error saving conversation: {e}")
    
    def load_conversation(self, filepath: str) -> bool:
        """
        Load conversation history from file
        
        Args:
            filepath: Path to load the conversation from
            
        Returns:
            True if successful, False otherwise
        """
        try:
            with open(filepath, 'r') as f:
                data = json.load(f)
                self.conversation_history = data.get("conversation_history", [])
                return True
        except Exception as e:
            print(f"Error loading conversation: {e}")
            return False
    
    def interactive_chat(self):
        """
        Start an interactive chat session
        """
        print("ORCA Interactive Chatbot")
        print("=" * 40)
        print("Type 'help' for available commands")
        print("Type 'quit' or 'exit' to end the session")
        print("Type 'clear' to clear conversation history")
        print("=" * 40)
        
        # Show context summary if available
        if self.analysis_context:
            print(f"\nAnalysis Context Available:")
            if self.analysis_context.get("binary_functionality"):
                print(f"Binary Purpose: {self.analysis_context['binary_functionality']}")
            
            static_results = self.analysis_context.get("static_analysis_results", {})
            if static_results:
                imports_count = len(static_results.get("imports", []))
                functions_count = len(static_results.get("functions", []))
                print(f"Static Analysis: {functions_count} functions, {imports_count} imports")
            
            print()
        
        while True:
            try:
                user_input = input("\nYou: ").strip()
                
                if not user_input:
                    continue
                
                if user_input.lower() in ['quit', 'exit', 'bye']:
                    print("\nGoodbye! Chat session ended.")
                    break
                
                if user_input.lower() == 'clear':
                    self.clear_conversation()
                    print("Conversation history cleared.")
                    continue
                
                if user_input.lower() == 'summary':
                    summary = self.get_conversation_summary()
                    print(f"\nConversation Summary:")
                    print(f"Total messages: {summary['total_messages']}")
                    print(f"Recent topics: {', '.join(summary['recent_topics']) if summary['recent_topics'] else 'None'}")
                    continue
                
                # Get chatbot response
                response = self.chat(user_input)
                print(f"\nORCA: {response}")
                
            except KeyboardInterrupt:
                print("\n\nChat session interrupted. Goodbye!")
                break
            except Exception as e:
                print(f"\nError: {e}")
                print("Please try again or type 'help' for available commands.")


def create_chatbot_with_context(analysis_context: Dict[str, Any]) -> OrcaChatbot:
    """
    Convenience function to create a chatbot with analysis context
    
    Args:
        analysis_context: Complete analysis results from workflow
        
    Returns:
        Configured OrcaChatbot instance
    """
    return OrcaChatbot(analysis_context)


if __name__ == "__main__":
    # Example usage
    print("ORCA Enhanced Chatbot")
    print("This chatbot provides interactive analysis of binary files using comprehensive context.")
    
    # Create a chatbot with sample context
    sample_context = {
        "binary_functionality": "File compression utility",
        "goal": "Analyze compression software for security vulnerabilities",
        "static_analysis_results": {
            "file_info": {
                "name": "sample.exe",
                "size": 1024000,
                "type": "PE32 executable"
            },
            "imports": ["CreateFileA", "ReadFile", "WriteFile", "CloseHandle"],
            "functions": [
                {"name": "main", "address": "0x401000", "size": 256},
                {"name": "compress_data", "address": "0x401100", "size": 512}
            ],
            "strings": {
                "file_paths": ["C:\\temp\\", "output.zip"],
                "error_messages": ["File not found", "Compression failed"]
            }
        }
    }
    
    chatbot = OrcaChatbot(sample_context)
    
    # Example queries
    test_queries = [
        "What does this binary do?",
        "list functions",
        "find api CreateFile",
        "help"
    ]
    
    print("\nTesting chatbot with sample queries:")
    for query in test_queries:
        print(f"\nUser: {query}")
        response = chatbot.chat(query)
        print(f"ORCA: {response[:200]}...")  # Truncate for display
    
    print("\nTo start interactive mode, call chatbot.interactive_chat()")
