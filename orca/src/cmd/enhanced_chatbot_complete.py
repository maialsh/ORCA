"""
Enhanced Chatbot Module for ORCA - Complete Implementation
Implements comprehensive interactive chat interface with advanced workflows:
1. List APIs used with state and static analysis context
2. API usage analysis with cross-references and ASM instruction analysis
3. Function analysis with ASM retrieval and LLM analysis
4. General malware analysis and vulnerability research support
5. Comprehensive error handling
"""
import json
import os
import re
import traceback
from typing import Dict, List, Any, Optional, Tuple
from pathlib import Path

from llm_module import llm_handler
from enhanced_string_analysis import EnhancedStringAnalyzer
from code_reference_analyzer import CodeReferenceAnalyzer
from api_reference_analyzer import ApiReferenceAnalyzer
from api_crossrefs import ApiCrossReferenceTool
from state import AnalysisState


class EnhancedOrcaChatbot:
    """
    Enhanced interactive chatbot for binary analysis with comprehensive workflows.
    Implements advanced API analysis, function analysis, and malware research capabilities.
    """
    
    def __init__(self, analysis_context: Optional[Dict[str, Any]] = None, 
                 analysis_state: Optional[AnalysisState] = None):
        """
        Initialize the enhanced chatbot with comprehensive analysis context
        
        Args:
            analysis_context: Dictionary containing complete analysis results from workflow
            analysis_state: AnalysisState object containing binary view and analysis data
        """
        self.analysis_context = analysis_context or {}
        self.analysis_state = analysis_state
        self.conversation_history = []
        self.error_log = []
        
        # Initialize analyzers
        self.string_analyzer = None
        self.code_ref_analyzer = None
        self.api_ref_analyzer = None
        self.api_crossref_tool = None
        
        # Initialize analyzers with proper error handling
        self._initialize_analyzers()
    
    def _initialize_analyzers(self):
        """Initialize all analyzers with comprehensive error handling"""
        try:
            self.string_analyzer = EnhancedStringAnalyzer()
        except Exception as e:
            self._log_error("string_analyzer", e)
        
        # Get binary view from either analysis_state or analysis_context
        binary_view = None
        if self.analysis_state and hasattr(self.analysis_state, 'binary_view'):
            binary_view = self.analysis_state.binary_view
        elif self.analysis_context.get("binary_view"):
            binary_view = self.analysis_context["binary_view"]
        
        if binary_view:
            try:
                self.code_ref_analyzer = CodeReferenceAnalyzer(binary_view)
            except Exception as e:
                self._log_error("code_ref_analyzer", e)
            
            try:
                self.api_ref_analyzer = ApiReferenceAnalyzer(binary_view)
            except Exception as e:
                self._log_error("api_ref_analyzer", e)
            
            try:
                self.api_crossref_tool = ApiCrossReferenceTool(binary_view)
            except Exception as e:
                self._log_error("api_crossref_tool", e)
        else:
            self._log_error("binary_view", "Binary view not available in analysis context or state")
    
    def _log_error(self, component: str, error: Exception):
        """Log errors for debugging and user feedback"""
        error_info = {
            "component": component,
            "error": str(error),
            "traceback": traceback.format_exc()
        }
        self.error_log.append(error_info)
        print(f"Warning: Failed to initialize {component}: {error}")
    
    def chat(self, user_message: str) -> str:
        """
        Process user message and return chatbot response with enhanced workflows
        
        Args:
            user_message: User's question or message
            
        Returns:
            Chatbot response
        """
        try:
            # Add user message to history
            self.conversation_history.append({"role": "user", "content": user_message})
            
            # Process the message with enhanced workflows
            response = self._process_enhanced_workflows(user_message)
            
            # If no specific workflow matched, use general processing
            if not response:
                response = self._process_general_query(user_message)
            
            # Add response to history
            self.conversation_history.append({"role": "assistant", "content": response})
            
            return response
            
        except Exception as e:
            error_response = f"I encountered an error processing your request: {str(e)}"
            self._log_error("chat_processing", e)
            self.conversation_history.append({"role": "assistant", "content": error_response})
            return error_response
    
    def _process_enhanced_workflows(self, message: str) -> Optional[str]:
        """
        Process enhanced workflows as specified in requirements
        
        Args:
            message: User message to process
            
        Returns:
            Response if a workflow was matched, None otherwise
        """
        message_lower = message.lower()
        
        try:
            # Workflow 1: List APIs used
            if self._is_list_apis_query(message_lower):
                return self._handle_list_apis_workflow()
            
            # Workflow 2: How particular API is being used
            elif self._is_api_usage_query(message_lower):
                return self._handle_api_usage_workflow(message)
            
            # Workflow 3: Function analysis
            elif self._is_function_analysis_query(message_lower):
                return self._handle_function_analysis_workflow(message)
            
            # Workflow 4: General malware analysis and vulnerability research
            elif self._is_malware_analysis_query(message_lower):
                return self._handle_malware_analysis_workflow(message)
            
            # Enhanced specific commands
            elif "find string" in message_lower or "search string" in message_lower:
                return self._handle_enhanced_string_search(message)
            elif "cross reference" in message_lower or "xref" in message_lower:
                return self._handle_enhanced_cross_reference(message)
            elif "suspicious" in message_lower and "string" in message_lower:
                return self._handle_suspicious_strings_analysis()
            elif "help" in message_lower or "commands" in message_lower:
                return self._handle_enhanced_help()
            
        except Exception as e:
            self._log_error("workflow_processing", e)
            return f"Error processing workflow: {str(e)}"
        
        return None
    
    def _is_list_apis_query(self, message_lower: str) -> bool:
        """Check if user is asking for list of APIs used"""
        patterns = [
            "list apis", "show apis", "what apis", "which apis",
            "list api", "show api", "apis used", "api used",
            "imported functions", "imports", "list imports"
        ]
        return any(pattern in message_lower for pattern in patterns)
    
    def _is_api_usage_query(self, message_lower: str) -> bool:
        """Check if user is asking how a particular API is being used"""
        usage_patterns = [
            "how is", "how does", "how are", "usage of", "used by",
            "using", "utilizes", "calls to", "calling", "invokes",
            "how to use", "explain", "analyze api", "api analysis"
        ]
        api_indicators = ["api", "function", "call", "method"]
        
        has_usage_pattern = any(pattern in message_lower for pattern in usage_patterns)
        has_api_indicator = any(indicator in message_lower for indicator in api_indicators)
        
        return has_usage_pattern and has_api_indicator
    
    def _is_function_analysis_query(self, message_lower: str) -> bool:
        """Check if user is requesting function analysis"""
        patterns = [
            "analyze function", "function analysis", "examine function",
            "study function", "investigate function", "function details",
            "function behavior", "what does function", "function purpose"
        ]
        return any(pattern in message_lower for pattern in patterns)
    
    def _is_malware_analysis_query(self, message_lower: str) -> bool:
        """Check if user is asking about malware analysis or vulnerability research"""
        patterns = [
            "malware", "malicious", "virus", "trojan", "backdoor",
            "vulnerability", "exploit", "security", "threat",
            "suspicious", "dangerous", "harmful", "attack",
            "penetration", "reverse engineering", "binary analysis"
        ]
        return any(pattern in message_lower for pattern in patterns)
    
    def _handle_list_apis_workflow(self) -> str:
        """
        Workflow 1: List APIs used with state and static analysis context
        """
        try:
            results = ["=== APIs USED IN BINARY ===\n"]
            
            # Get APIs from static analysis results
            static_results = self.analysis_context.get("static_analysis_results", {})
            imports = static_results.get("imports", [])
            
            # Get APIs from analysis state if available
            if self.analysis_state:
                state_imports = getattr(self.analysis_state, 'imports', [])
                if state_imports:
                    imports.extend(state_imports)
                    imports = list(set(imports))  # Remove duplicates
            
            if not imports:
                return "No APIs/imports found in the analysis results."
            
            results.append(f"Total APIs/Imports Found: {len(imports)}\n")
            
            # Group APIs using clustering if available
            api_clustering = self.analysis_context.get("api_clustering_results", {})
            if api_clustering and api_clustering.get("clusters"):
                results.append("=== APIS GROUPED BY FUNCTIONALITY ===\n")
                
                for cluster in api_clustering["clusters"]:
                    cluster_name = cluster.get("name", "Unknown")
                    cluster_apis = cluster.get("apis", [])
                    security = cluster.get("security_assessment", "unknown")
                    description = cluster.get("description", "No description")
                    
                    results.append(f"📁 {cluster_name} ({security.upper()})")
                    results.append(f"   Description: {description}")
                    results.append(f"   APIs ({len(cluster_apis)}):")
                    
                    for api in cluster_apis[:10]:  # Show first 10 per cluster
                        results.append(f"     • {api}")
                    if len(cluster_apis) > 10:
                        results.append(f"     ... and {len(cluster_apis)-10} more")
                    results.append("")
                
                # Show unclustered APIs
                clustered_apis = set()
                for cluster in api_clustering["clusters"]:
                    clustered_apis.update(cluster.get("apis", []))
                
                unclustered = [api for api in imports if api not in clustered_apis]
                if unclustered:
                    results.append("📁 UNCLUSTERED APIS")
                    for api in unclustered[:20]:  # Show first 20
                        results.append(f"     • {api}")
                    if len(unclustered) > 20:
                        results.append(f"     ... and {len(unclustered)-20} more")
            else:
                # Show ungrouped list with categories
                results.append("=== ALL APIS (ALPHABETICAL) ===\n")
                
                # Categorize APIs by common patterns
                categories = {
                    "File Operations": [],
                    "Network Operations": [],
                    "Memory Management": [],
                    "Process/Thread": [],
                    "Registry": [],
                    "Cryptography": [],
                    "System Info": [],
                    "Other": []
                }
                
                for api in sorted(imports):
                    api_lower = api.lower()
                    categorized = False
                    
                    if any(pattern in api_lower for pattern in ['file', 'read', 'write', 'open', 'close', 'create']):
                        categories["File Operations"].append(api)
                        categorized = True
                    elif any(pattern in api_lower for pattern in ['socket', 'connect', 'send', 'recv', 'net', 'http']):
                        categories["Network Operations"].append(api)
                        categorized = True
                    elif any(pattern in api_lower for pattern in ['alloc', 'malloc', 'free', 'heap', 'virtual']):
                        categories["Memory Management"].append(api)
                        categorized = True
                    elif any(pattern in api_lower for pattern in ['process', 'thread', 'create', 'terminate']):
                        categories["Process/Thread"].append(api)
                        categorized = True
                    elif any(pattern in api_lower for pattern in ['reg', 'key', 'registry']):
                        categories["Registry"].append(api)
                        categorized = True
                    elif any(pattern in api_lower for pattern in ['crypt', 'hash', 'encrypt', 'decrypt']):
                        categories["Cryptography"].append(api)
                        categorized = True
                    elif any(pattern in api_lower for pattern in ['get', 'system', 'info', 'version']):
                        categories["System Info"].append(api)
                        categorized = True
                    
                    if not categorized:
                        categories["Other"].append(api)
                
                for category, apis in categories.items():
                    if apis:
                        results.append(f"📁 {category} ({len(apis)} APIs)")
                        for api in apis[:15]:  # Show first 15 per category
                            results.append(f"     • {api}")
                        if len(apis) > 15:
                            results.append(f"     ... and {len(apis)-15} more")
                        results.append("")
            
            # Add context from state
            if self.analysis_state:
                results.append("=== ANALYSIS STATE CONTEXT ===")
                results.append(f"File: {getattr(self.analysis_state, 'name', 'Unknown')}")
                results.append(f"Size: {getattr(self.analysis_state, 'size', 'Unknown')} bytes")
                results.append(f"Type: {getattr(self.analysis_state, 'file_type', 'Unknown')}")
                results.append(f"Executable: {getattr(self.analysis_state, 'is_executable', 'Unknown')}")
                results.append("")
            
            # Add usage instructions
            results.append("=== NEXT STEPS ===")
            results.append("• Use 'how is <API_NAME> used?' to analyze specific API usage")
            results.append("• Use 'analyze function <FUNCTION_NAME>' for function-level analysis")
            results.append("• Use 'suspicious' to find potentially malicious indicators")
            
            return "\n".join(results)
            
        except Exception as e:
            self._log_error("list_apis_workflow", e)
            return f"Error listing APIs: {str(e)}"
    
    def _handle_api_usage_workflow(self, message: str) -> str:
        """
        Workflow 2: How particular API is being used with cross-references and ASM analysis
        """
        try:
            # Extract API name from message
            api_name = self._extract_api_name_from_message(message)
            if not api_name:
                return ("I need to know which specific API you want to analyze. "
                       "Please specify the API name. Example: 'How is CreateFile used?'")
            
            results = [f"=== COMPREHENSIVE API USAGE ANALYSIS: {api_name} ===\n"]
            
            # Step 1: Use API cross-references to get code references
            crossref_data = []
            if self.api_crossref_tool:
                try:
                    crossref_data = self.api_crossref_tool.analyze_api_crossrefs(api_name)
                    if crossref_data:
                        results.append("🔍 CROSS-REFERENCE ANALYSIS")
                        results.append(f"Found {len(crossref_data)} API variants with code references:\n")
                        
                        for api_data in crossref_data:
                            api_variant = api_data.get("api_name", "Unknown")
                            references = api_data.get("references", [])
                            
                            results.append(f"📍 API: {api_variant}")
                            results.append(f"   Functions using this API: {len(references)}")
                            
                            for ref in references[:3]:  # Show first 3 functions
                                func_name = ref.get("function", "Unknown")
                                start_addr = ref.get("start_addr", "Unknown")
                                callsites = ref.get("callsites", [])
                                
                                results.append(f"   • Function: {func_name} ({start_addr})")
                                results.append(f"     Call sites: {len(callsites)} locations")
                                if callsites:
                                    results.append(f"     Addresses: {', '.join(callsites[:3])}")
                            
                            if len(references) > 3:
                                results.append(f"   ... and {len(references)-3} more functions")
                            results.append("")
                    else:
                        results.append("🔍 CROSS-REFERENCE ANALYSIS")
                        results.append("No code references found for this API.\n")
                except Exception as e:
                    self._log_error("crossref_analysis", e)
                    results.append(f"Cross-reference analysis failed: {str(e)}\n")
            
            # Step 2: Get all functions using the API
            functions_using_api = []
            if crossref_data:
                for api_data in crossref_data:
                    for ref in api_data.get("references", []):
                        func_name = ref.get("function", "")
                        if func_name and func_name not in functions_using_api:
                            functions_using_api.append(func_name)
            
            # Step 3: Retrieve ASM instructions for all functions using the API
            if functions_using_api and self.api_ref_analyzer:
                results.append("🔧 ASSEMBLY INSTRUCTION ANALYSIS")
                results.append(f"Analyzing ASM instructions for {len(functions_using_api)} functions:\n")
                
                for func_name in functions_using_api[:5]:  # Limit to 5 functions
                    try:
                        func_analysis = self.api_ref_analyzer.analyze_function(func_name)
                        if func_analysis:
                            results.append(f"📋 Function: {func_name}")
                            results.append(f"   Address: {func_analysis.get('start_address', 'Unknown')} - {func_analysis.get('end_address', 'Unknown')}")
                            results.append(f"   Size: {func_analysis.get('size', 'Unknown')} bytes")
                            
                            # Show ASM instructions (limited)
                            assembly = func_analysis.get('assembly', '')
                            if assembly:
                                asm_lines = assembly.split('\n')[:20]  # First 20 lines
                                results.append("   ASM Instructions (sample):")
                                for line in asm_lines:
                                    if line.strip():
                                        results.append(f"     {line}")
                                if len(assembly.split('\n')) > 20:
                                    results.append("     ... (truncated)")
                            
                            # Show API calls in this function
                            api_calls = func_analysis.get('api_calls', [])
                            api_specific_calls = [call for call in api_calls 
                                                if api_name.lower() in call.get('found_symbol', '').lower()]
                            
                            if api_specific_calls:
                                results.append(f"   {api_name} Usage in Function:")
                                for call in api_specific_calls[:3]:
                                    results.append(f"     • Address: {call.get('address', 'Unknown')}")
                                    results.append(f"       Context: {call.get('usage_context', 'Unknown')}")
                                    results.append(f"       Instruction: {call.get('instruction', 'Unknown')}")
                            
                            results.append("")
                    except Exception as e:
                        self._log_error(f"function_analysis_{func_name}", e)
                        results.append(f"   Error analyzing function {func_name}: {str(e)}\n")
                
                if len(functions_using_api) > 5:
                    results.append(f"... and {len(functions_using_api)-5} more functions with ASM analysis available\n")
            
            # Step 4: LLM analysis of API usage based on ASM instructions
            if functions_using_api and self.api_ref_analyzer:
                results.append("🤖 LLM ANALYSIS OF API USAGE")
                try:
                    # Get detailed API references for LLM analysis
                    api_refs = self.api_ref_analyzer.find_api_references(api_name)
                    if api_refs:
                        # Prepare comprehensive context for LLM
                        llm_context = self._prepare_api_llm_context(api_name, api_refs, crossref_data)
                        llm_analysis = self._get_comprehensive_api_analysis(api_name, llm_context)
                        
                        results.append(llm_analysis)
                    else:
                        results.append("No detailed API references found for LLM analysis.")
                except Exception as e:
                    self._log_error("llm_api_analysis", e)
                    results.append(f"LLM analysis failed: {str(e)}")
            
            # Step 5: Security implications and recommendations
            results.append("\n🛡️ SECURITY ASSESSMENT")
            security_assessment = self._assess_api_security(api_name, functions_using_api)
            results.append(security_assessment)
            
            return "\n".join(results)
            
        except Exception as e:
            self._log_error("api_usage_workflow", e)
            return f"Error analyzing API usage: {str(e)}"
    
    def _handle_function_analysis_workflow(self, message: str) -> str:
        """
        Workflow 3: Function analysis with ASM retrieval and LLM analysis
        """
        try:
            # Extract function name from message
            function_name = self._extract_function_name_from_message(message)
            if not function_name:
                return ("I need to know which specific function you want to analyze. "
                       "Please specify the function name. Example: 'analyze function main'")
            
            results = [f"=== COMPREHENSIVE FUNCTION ANALYSIS: {function_name} ===\n"]
            
            # Step 1: Find matching functions in the binary
            matching_functions = self._find_matching_functions(function_name)
            
            if not matching_functions:
                results.append(f"❌ No functions matching '{function_name}' found in the binary.")
                results.append("\nAvailable functions (sample):")
                
                # Show some available functions
                static_results = self.analysis_context.get("static_analysis_results", {})
                functions = static_results.get("functions", [])
                for func in functions[:10]:
                    results.append(f"   • {func.get('name', 'unknown')}")
                if len(functions) > 10:
                    results.append(f"   ... and {len(functions)-10} more")
                
                return "\n".join(results)
            
            results.append(f"✅ Found {len(matching_functions)} matching function(s):\n")
            
            # Step 2: Analyze each matching function
            for i, func_match in enumerate(matching_functions[:3]):  # Limit to 3 matches
                results.append(f"📋 Function Match {i+1}: {func_match['name']}")
                results.append(f"   Address: {func_match.get('address', 'Unknown')}")
                results.append(f"   Size: {func_match.get('size', 'Unknown')} bytes")
                
                # Step 3: Retrieve ASM instructions using specific module
                if self.api_ref_analyzer:
                    try:
                        func_analysis = self.api_ref_analyzer.analyze_function(func_match['name'])
                        if func_analysis:
                            # Show function details
                            results.append(f"   Full Address Range: {func_analysis.get('start_address', 'Unknown')} - {func_analysis.get('end_address', 'Unknown')}")
                            
                            # Show APIs used by this function
                            apis_used = func_analysis.get('apis_used', [])
                            if apis_used:
                                results.append(f"   APIs Used ({len(apis_used)}): {', '.join(apis_used[:10])}")
                                if len(apis_used) > 10:
                                    results.append(f"     ... and {len(apis_used)-10} more")
                            
                            # Show ASM instructions
                            assembly = func_analysis.get('assembly', '')
                            if assembly:
                                results.append("\n   🔧 ASSEMBLY INSTRUCTIONS:")
                                asm_lines = assembly.split('\n')
                                
                                # Show first 30 lines of assembly
                                for line in asm_lines[:30]:
                                    if line.strip():
                                        results.append(f"     {line}")
                                
                                if len(asm_lines) > 30:
                                    results.append(f"     ... ({len(asm_lines)-30} more lines)")
                            
                            # Step 4: LLM analysis of the function
                            results.append("\n   🤖 LLM ANALYSIS:")
                            llm_analysis = func_analysis.get('llm_analysis', '')
                            if llm_analysis:
                                # Format LLM analysis nicely
                                analysis_lines = llm_analysis.split('\n')
                                for line in analysis_lines:
                                    if line.strip():
                                        results.append(f"     {line.strip()}")
                            else:
                                # Generate new LLM analysis if not available
                                try:
                                    new_analysis = self._generate_function_llm_analysis(func_match['name'], func_analysis)
                                    analysis_lines = new_analysis.split('\n')
                                    for line in analysis_lines:
                                        if line.strip():
                                            results.append(f"     {line.strip()}")
                                except Exception as e:
                                    results.append(f"     LLM analysis failed: {str(e)}")
                        else:
                            results.append("   ❌ Could not retrieve detailed function analysis")
                    except Exception as e:
                        self._log_error(f"function_asm_analysis_{func_match['name']}", e)
                        results.append(f"   Error retrieving ASM: {str(e)}")
                
                # Show behavior patterns if available
                if func_match.get('behavior'):
                    results.append("\n   🎯 BEHAVIOR PATTERNS:")
                    for behavior in func_match['behavior'][:5]:
                        behavior_type = behavior.get('type', 'unknown')
                        instruction = behavior.get('instruction', 'N/A')
                        results.append(f"     • {behavior_type}: {instruction}")
                
                results.append("")
            
            if len(matching_functions) > 3:
                results.append(f"... and {len(matching_functions)-3} more matching functions")
            
            # Step 5: Security and malware analysis
            results.append("🛡️ SECURITY ASSESSMENT")
            security_assessment = self._assess_function_security(matching_functions)
            results.append(security_assessment)
            
            return "\n".join(results)
            
        except Exception as e:
            self._log_error("function_analysis_workflow", e)
            return f"Error analyzing function: {str(e)}"
    
    def _handle_malware_analysis_workflow(self, message: str) -> str:
        """
        Workflow 4: General malware analysis and vulnerability research
        """
        try:
            results = ["=== MALWARE ANALYSIS & VULNERABILITY RESEARCH ===\n"]
            
            # Use all analysis results as context
            comprehensive_context = self._prepare_malware_analysis_context()
            
            # Determine specific aspect of malware analysis requested
            message_lower = message.lower()
            
            if "classification" in message_lower or "type" in message_lower:
                results.append("🏷️ MALWARE CLASSIFICATION")
                classification = self._get_malware_classification(comprehensive_context)
                results.append(classification)
                
            elif "behavior" in message_lower or "capability" in message_lower:
                results.append("🎯 BEHAVIORAL ANALYSIS")
                behavior_analysis = self._get_behavior_analysis(comprehensive_context)
                results.append(behavior_analysis)
                
            elif "vulnerability" in message_lower or "exploit" in message_lower:
                results.append("🔍 VULNERABILITY ASSESSMENT")
                vuln_analysis = self._get_vulnerability_analysis(comprehensive_context)
                results.append(vuln_analysis)
                
            elif "threat" in message_lower or "risk" in message_lower:
                results.append("⚠️ THREAT ASSESSMENT")
                threat_analysis = self._get_threat_analysis(comprehensive_context)
                results.append(threat_analysis)
                
            else:
                # General malware analysis
                results.append("🔬 COMPREHENSIVE MALWARE ANALYSIS")
                general_analysis = self._get_general_malware_analysis(comprehensive_context)
                results.append(general_analysis)
            
            # Add specific indicators if available
            malware_results = self.analysis_context.get("malware_analysis_results", {})
            if malware_results:
                results.append("\n📊 ANALYSIS RESULTS SUMMARY")
                results.append(f"Classification: {malware_results.get('classification', 'Unknown')}")
                results.append(f"Threat Level: {malware_results.get('threat_level', 'Unknown')}")
                results.append(f"Confidence: {malware_results.get('confidence_level', 0)}%")
                
                if malware_results.get('malicious_indicators'):
                    results.append("\n🚨 MALICIOUS INDICATORS:")
                    for indicator in malware_results['malicious_indicators'][:10]:
                        results.append(f"   • {indicator}")
                
                if malware_results.get('suspicious_behaviors'):
                    results.append("\n⚠️ SUSPICIOUS BEHAVIORS:")
                    for behavior in malware_results['suspicious_behaviors'][:10]:
                        results.append(f"   • {behavior}")
            
            # Add recommendations
            results.append("\n💡 RECOMMENDATIONS")
            recommendations = self._get_analysis_recommendations(comprehensive_context)
            results.append(recommendations)
            
            return "\n".join(results)
            
        except Exception as e:
            self._log_error("malware_analysis_workflow", e)
            return f"Error in malware analysis: {str(e)}"
    
    def _extract_api_name_from_message(self, message: str) -> Optional[str]:
        """Extract API name from user message"""
        # Try quoted text first
        quoted_match = re.search(r'["\']([^"\']+)["\']', message)
        if quoted_match:
            return quoted_match.group(1)
        
        # Try common patterns
        patterns = [
            r'how (?:is|does|are) (\w+)',
            r'usage of (\w+)',
            r'analyze api (\w+)',
            r'api (\w+)',
            r'function (\w+)'
        ]
        
        for pattern in patterns:
            match = re.search(pattern, message.lower())
            if match:
                return match.group(1)
        
        return None
    
    def _extract_function_name_from_message(self, message: str) -> Optional[str]:
        """Extract function name from user message"""
        quoted_match = re.search(r'["\']([^"\'\']+)["\']', message)
        if quoted_match:
            return quoted_match.group(1)
        
        patterns = [
            r'analyze function (\w+)',
            r'function (\w+)',
            r'examine (\w+)',
            r'study (\w+)'
        ]
        
        for pattern in patterns:
            match = re.search(pattern, message.lower())
            if match:
                return match.group(1)
        
        return None
    
    def _find_matching_functions(self, function_name: str) -> List[Dict[str, Any]]:
        """Find functions matching the given name"""
        static_results = self.analysis_context.get("static_analysis_results", {})
        functions = static_results.get("functions", [])
        
        matching_functions = []
        for func in functions:
            if function_name.lower() in func.get("name", "").lower():
                matching_functions.append(func)
        
        return matching_functions
    
    def _prepare_api_llm_context(self, api_name: str, api_refs: List[Dict[str, Any]], crossref_data: List[Dict[str, Any]]) -> str:
        """Prepare comprehensive context for API LLM analysis"""
        context_parts = []
        context_parts.append(f"API Analysis Context for: {api_name}")
        context_parts.append(f"Number of references found: {len(api_refs)}")
        
        if crossref_data:
            context_parts.append("\nCross-reference Summary:")
            for api_data in crossref_data:
                api_variant = api_data.get("api_name", "Unknown")
                references = api_data.get("references", [])
                context_parts.append(f"  {api_variant}: {len(references)} function references")
        
        context_parts.append("\nDetailed API References:")
        for i, ref in enumerate(api_refs[:5]):
            context_parts.append(f"  Reference {i+1}:")
            context_parts.append(f"    Function: {ref.get('function_name', 'Unknown')}")
            context_parts.append(f"    Address: {ref.get('address', 'Unknown')}")
            context_parts.append(f"    Context: {ref.get('usage_context', 'Unknown')}")
            if ref.get('assembly'):
                context_parts.append(f"    Assembly: {ref['assembly'][:200]}...")
        
        return "\n".join(context_parts)
    
    def _get_comprehensive_api_analysis(self, api_name: str, llm_context: str) -> str:
        """Get comprehensive API analysis using LLM"""
        system_prompt = """You are an expert binary analysis assistant specializing in API usage analysis.
        
        Analyze the provided API usage context and provide comprehensive insights about:
        1. How the API is being used in the binary
        2. The purpose and functionality it serves
        3. Security implications of its usage
        4. Common patterns or unusual usage
        5. Potential vulnerabilities or security concerns
        
        Be specific and technical in your analysis."""
        
        user_prompt = f"""Analyze the usage of API '{api_name}' based on this context:
        
        {llm_context}
        
        Provide a comprehensive analysis of how this API is being used."""
        
        try:
            response = llm_handler.query(system_prompt, user_prompt)
            return response
        except Exception as e:
            return f"LLM analysis failed: {str(e)}"
    
    def _assess_api_security(self, api_name: str, functions_using_api: List[str]) -> str:
        """Assess security implications of API usage"""
        security_assessment = []
        
        dangerous_apis = {
            'CreateFile': 'File creation/access - check for path traversal vulnerabilities',
            'WriteFile': 'File writing - potential for data corruption or unauthorized writes',
            'VirtualAlloc': 'Memory allocation - could indicate shellcode injection',
            'LoadLibrary': 'Dynamic library loading - potential DLL hijacking',
            'RegSetValue': 'Registry modification - system configuration changes',
            'CreateProcess': 'Process creation - potential for privilege escalation',
            'socket': 'Network communication - check for unauthorized connections',
            'recv': 'Network data reception - potential buffer overflow risks'
        }
        
        api_lower = api_name.lower()
        for dangerous_api, risk_desc in dangerous_apis.items():
            if dangerous_api.lower() in api_lower:
                security_assessment.append(f"⚠️ Security Risk: {risk_desc}")
                break
        
        if not security_assessment:
            security_assessment.append("✅ No immediate security concerns identified for this API")
        
        security_assessment.append(f"Functions using this API: {len(functions_using_api)}")
        security_assessment.append("Recommendation: Review usage context and parameter validation")
        
        return "\n".join(security_assessment)
    
    def _generate_function_llm_analysis(self, function_name: str, func_analysis: Dict[str, Any]) -> str:
        """Generate LLM analysis for a function"""
        system_prompt = """You are an expert reverse engineer analyzing binary functions.
        
        Provide detailed analysis of the function including:
        1. Purpose and functionality
        2. APIs and system calls used
        3. Behavior patterns and logic flow
        4. Security implications
        5. Potential vulnerabilities
        
        Be technical and specific in your analysis."""
        
        apis_used = func_analysis.get('apis_used', [])
        assembly = func_analysis.get('assembly', '')
        
        user_prompt = f"""Analyze function '{function_name}' with this information:
        
        APIs Used: {', '.join(apis_used) if apis_used else 'None detected'}
        Assembly Code: {assembly[:500] if assembly else 'Not available'}...
        
        Provide comprehensive analysis of this function."""
        
        try:
            response = llm_handler.query(system_prompt, user_prompt)
            return response
        except Exception as e:
            return f"Function analysis failed: {str(e)}"
    
    def _assess_function_security(self, matching_functions: List[Dict[str, Any]]) -> str:
        """Assess security implications of functions"""
        security_assessment = []
        total_functions = len(matching_functions)
        security_assessment.append(f"Analyzed {total_functions} matching function(s)")
        
        suspicious_behaviors = []
        for func in matching_functions:
            behaviors = func.get('behavior', [])
            for behavior in behaviors:
                behavior_type = behavior.get('type', '')
                if any(pattern in behavior_type.lower() for pattern in ['inject', 'hook', 'modify', 'encrypt']):
                    suspicious_behaviors.append(f"{func.get('name', 'unknown')}: {behavior_type}")
        
        if suspicious_behaviors:
            security_assessment.append("⚠️ Suspicious behaviors detected:")
            for behavior in suspicious_behaviors[:5]:
                security_assessment.append(f"  - {behavior}")
        else:
            security_assessment.append("✅ No immediately suspicious behaviors detected")
        
        security_assessment.append("Recommendation: Review function implementation and calling patterns")
        return "\n".join(security_assessment)
    
    def _prepare_malware_analysis_context(self) -> str:
        """Prepare comprehensive context for malware analysis"""
        context_parts = []
        
        static_results = self.analysis_context.get("static_analysis_results", {})
        if static_results:
            context_parts.append("Static Analysis Results Available")
            
            imports = static_results.get("imports", [])
            if imports:
                context_parts.append(f"Imports: {len(imports)} APIs")
                high_risk_apis = [api for api in imports if any(risk in api.lower() for risk in ['virtual', 'process', 'thread', 'registry', 'crypto'])]
                if high_risk_apis:
                    context_parts.append(f"High-risk APIs: {', '.join(high_risk_apis[:10])}")
        
        capabilities = self.analysis_context.get("capabilities", {})
        if capabilities:
            context_parts.append("\nCapabilities Analysis:")
            for category, items in capabilities.items():
                if items and isinstance(items, list):
                    context_parts.append(f"  {category}: {len(items)} items")
        
        malware_results = self.analysis_context.get("malware_analysis_results", {})
        if malware_results:
            context_parts.append("\nExisting Malware Analysis:")
            context_parts.append(f"Classification: {malware_results.get('classification', 'Unknown')}")
            context_parts.append(f"Threat Level: {malware_results.get('threat_level', 'Unknown')}")
        
        return "\n".join(context_parts) if context_parts else "Limited analysis context available"
    
    def _get_malware_classification(self, context: str) -> str:
        """Get malware classification analysis"""
        system_prompt = """You are a malware analysis expert. Classify the binary based on the provided analysis context.
        
        Provide classification including:
        1. Malware family (if applicable)
        2. Type (trojan, virus, worm, etc.)
        3. Confidence level
        4. Key indicators supporting the classification
        """
        
        user_prompt = f"""Classify this binary based on analysis context:
        
        {context}
        
        Provide detailed malware classification."""
        
        try:
            response = llm_handler.query(system_prompt, user_prompt)
            return response
        except Exception as e:
            return f"Classification analysis failed: {str(e)}"
    
    def _get_behavior_analysis(self, context: str) -> str:
        """Get behavioral analysis"""
        system_prompt = """You are a behavioral analysis expert. Analyze the binary's behavior patterns.
        
        Focus on:
        1. System interactions
        2. Network behavior
        3. File system operations
        4. Registry modifications
        5. Process/thread activities
        """
        
        user_prompt = f"""Analyze behavioral patterns based on:
        
        {context}
        
        Provide comprehensive behavioral analysis."""
        
        try:
            response = llm_handler.query(system_prompt, user_prompt)
            return response
        except Exception as e:
            return f"Behavioral analysis failed: {str(e)}"
    
    def _get_vulnerability_analysis(self, context: str) -> str:
        """Get vulnerability analysis"""
        system_prompt = """You are a vulnerability research expert. Identify potential vulnerabilities and exploits.
        
        Analyze for:
        1. Buffer overflow vulnerabilities
        2. Injection attacks
        3. Privilege escalation
        4. Memory corruption issues
        5. Logic flaws
        """
        
        user_prompt = f"""Identify vulnerabilities based on:
        
        {context}
        
        Provide detailed vulnerability assessment."""
        
        try:
            response = llm_handler.query(system_prompt, user_prompt)
            return response
        except Exception as e:
            return f"Vulnerability analysis failed: {str(e)}"
    
    def _get_threat_analysis(self, context: str) -> str:
        """Get threat analysis"""
        system_prompt = """You are a threat intelligence analyst. Assess the threat level and potential impact.
        
        Evaluate:
        1. Threat severity
        2. Potential targets
        3. Attack vectors
        4. Mitigation strategies
        5. IOCs (Indicators of Compromise)
        """
        
        user_prompt = f"""Assess threat level based on:
        
        {context}
        
        Provide comprehensive threat analysis."""
        
        try:
            response = llm_handler.query(system_prompt, user_prompt)
            return response
        except Exception as e:
            return f"Threat analysis failed: {str(e)}"
    
    def _get_general_malware_analysis(self, context: str) -> str:
        """Get general malware analysis"""
        system_prompt = """You are a comprehensive malware analyst. Provide overall assessment of the binary.
        
        Include:
        1. General assessment
        2. Key findings
        3. Risk level
        4. Recommendations
        5. Further analysis suggestions
        """
        
        user_prompt = f"""Provide general malware analysis based on:
        
        {context}
        
        Give comprehensive overview and assessment."""
        
        try:
            response = llm_handler.query(system_prompt, user_prompt)
            return response
        except Exception as e:
            return f"General malware analysis failed: {str(e)}"
    
    def _get_analysis_recommendations(self, context: str) -> str:
        """Get analysis recommendations"""
        recommendations = [
            "🔍 Further Analysis Recommendations:",
            "• Perform dynamic analysis in a sandboxed environment",
            "• Monitor network traffic during execution",
            "• Analyze file system and registry changes",
            "• Check for persistence mechanisms",
            "• Validate with multiple antivirus engines",
            "• Review strings for additional IOCs",
            "• Analyze any embedded resources or payloads"
        ]
        return "\n".join(recommendations)
    
    def _handle_enhanced_string_search(self, message: str) -> str:
        """Handle enhanced string search with comprehensive analysis"""
        search_string = self._extract_quoted_text(message)
        if not search_string:
            words = message.split()
            for i, word in enumerate(words):
                if word.lower() in ["string", "strings"] and i + 1 < len(words):
                    search_string = words[i + 1]
                    break
        
        if not search_string:
            return "Please specify the string you want to search for. Example: 'find string \"example\"'"
        
        results = []
        static_results = self.analysis_context.get("static_analysis_results", {})
        strings_data = static_results.get("strings", {})
        
        found_strings = []
        for category, strings_list in strings_data.items():
            if isinstance(strings_list, list):
                for s in strings_list:
                    if search_string.lower() in s.lower():
                        found_strings.append((category, s))
        
        if found_strings:
            results.append(f"=== STRING SEARCH RESULTS FOR '{search_string}' ===")
            results.append(f"Found {len(found_strings)} matching strings:\n")
            
            for category, string in found_strings:
                results.append(f"Category: {category}")
                results.append(f"String: '{string}'")
                results.append("")
        else:
            results.append(f"No strings matching '{search_string}' found in static analysis.")
        
        return "\n".join(results)
    
    def _handle_enhanced_cross_reference(self, message: str) -> str:
        """Handle enhanced cross-reference analysis"""
        target = self._extract_quoted_text(message)
        if not target:
            words = message.split()
            for i, word in enumerate(words):
                if word.lower() in ["xref", "reference", "cross"] and i + 1 < len(words):
                    target = words[i + 1]
                    break
        
        if not target:
            return "Please specify what you want to cross-reference. Example: 'cross reference \"CreateFile\"'"
        
        results = [f"=== ENHANCED CROSS-REFERENCE ANALYSIS FOR '{target}' ==="]
        
        if self.api_crossref_tool:
            try:
                crossref_data = self.api_crossref_tool.analyze_api_crossrefs(target)
                if crossref_data:
                    results.append(f"\nFound {len(crossref_data)} cross-reference matches:")
                    for api_data in crossref_data:
                        api_name = api_data.get("api_name", "Unknown")
                        references = api_data.get("references", [])
                        results.append(f"\n{api_name}: {len(references)} references")
                        for ref in references[:3]:
                            func_name = ref.get("function", "Unknown")
                            results.append(f"  - Function: {func_name}")
                else:
                    results.append(f"\nNo cross-references found for '{target}'.")
            except Exception as e:
                results.append(f"\nError in cross-reference analysis: {str(e)}")
        else:
            results.append(f"\nCross-reference tool not available.")
        
        return "\n".join(results)
    
    def _handle_suspicious_strings_analysis(self) -> str:
        """Handle suspicious strings analysis"""
        static_results = self.analysis_context.get("static_analysis_results", {})
        strings_data = static_results.get("strings", {})
        
        if not strings_data:
            return "No strings available for suspicious analysis."
        
        all_strings = []
        for category, strings_list in strings_data.items():
            if isinstance(strings_list, list):
                all_strings.extend(strings_list)
        
        if not all_strings:
            return "No strings found to analyze."
        
        try:
            results = self.string_analyzer.find_suspicious_strings(all_strings)
            
            response = ["=== SUSPICIOUS STRINGS ANALYSIS ==="]
            response.append(f"Risk Score: {results.get('risk_score', 0)}/100")
            response.append(f"\nSummary: {results.get('summary', 'No summary available')}")
            
            suspicious_strings = results.get("suspicious_strings", {})
            for category, strings in suspicious_strings.items():
                if strings:
                    response.append(f"\n{category.replace('_', ' ').title()}:")
                    for string_info in strings[:5]:
                        response.append(f"  - '{string_info['string']}'")
                        response.append(f"    Reason: {string_info['reason']}")
                        response.append(f"    Risk: {string_info['risk_level']}")
            
            return "\n".join(response)
            
        except Exception as e:
            return f"Error in suspicious strings analysis: {str(e)}"
    
    def _handle_enhanced_help(self) -> str:
        """Handle enhanced help queries"""
        help_text = """=== ENHANCED ORCA CHATBOT HELP ===
        
        ENHANCED WORKFLOWS:
        • 'list apis' - Show all APIs used with clustering and analysis
        • 'how is <API> used?' - Comprehensive API usage analysis with ASM
        • 'analyze function <name>' - Detailed function analysis with LLM insights
        • 'malware analysis' - Security assessment and threat analysis
        
        SPECIFIC COMMANDS:
        • 'find string "text"' - Enhanced string search with context
        • 'cross reference "item"' - Advanced cross-reference analysis
        • 'suspicious strings' - Find potentially malicious string patterns
        • 'help' - Show this help message
        
        GENERAL QUERIES:
        Ask natural language questions about:
        • Binary capabilities and functionality
        • Security implications and threats
        • API usage patterns and behaviors
        • Malware classification and analysis
        • Vulnerability assessment
        
        ENHANCED FEATURES:
        ✓ Assembly instruction analysis with before/after context
        ✓ LLM-powered insights for complex analysis
        ✓ Cross-reference analysis with code context
        ✓ Comprehensive security assessment
        ✓ Advanced string pattern recognition
        ✓ Function-level behavioral analysis
        
        The enhanced chatbot provides deep technical analysis with expert-level insights!"""
        
        return help_text
    
    def _extract_quoted_text(self, message: str) -> Optional[str]:
        """Extract text within quotes from a message"""
        match = re.search(r'"([^"]+)"', message)
        if match:
            return match.group(1)
        
        match = re.search(r"'([^']+)'", message)
        if match:
            return match.group(1)
        
        return None
    
    def _process_general_query(self, message: str) -> str:
        """Process general queries using LLM with comprehensive analysis context"""
        context_summary = self._prepare_comprehensive_context()
        
        system_prompt = """You are ORCA Enhanced, an expert binary analysis assistant with access to comprehensive
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
        - Enhanced assembly analysis with before/after API call context
        - LLM-powered insights for complex analysis patterns
        
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
        - Advanced assembly analysis and calling conventions
        - Vulnerability assessment and threat analysis
        """
        
        user_prompt = f"""Comprehensive Enhanced Analysis Context:
        {context_summary}
        
        Conversation History:
        {self._format_conversation_history()}
        
        User Question: {message}
        
        Please provide a helpful and detailed response based on the comprehensive enhanced analysis context."""
        
        try:
            response = llm_handler.query(system_prompt, user_prompt)
            return response
        except Exception as e:
            return f"I apologize, but I encountered an error processing your question: {str(e)}"
    
    def _prepare_comprehensive_context(self) -> str:
        """Prepare a comprehensive summary of all analysis results for the LLM"""
        summary_parts = []
        
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
        
        if self.analysis_context.get("binary_functionality"):
            summary_parts.append("=== BINARY PURPOSE ===")
            summary_parts.append(f"Declared Functionality: {self.analysis_context['binary_functionality']}")
            summary_parts.append(f"Analysis Goal: {self.analysis_context.get('goal', 'Unknown')}")
            summary_parts.append("")
        
        if static_results:
            summary_parts.append("=== STATIC ANALYSIS ===")
            
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
            
            if static_results.get("functions"):
                functions = static_results["functions"]
                summary_parts.append(f"Functions ({len(functions)} total):")
                
                for func in functions[:10]:
                    if func.get("behavior"):
                        behavior_types = [b.get("type", "unknown") for b in func["behavior"]]
                        summary_parts.append(f"  - {func.get('name', 'unknown')} - behaviors: {', '.join(set(behavior_types))}")
                    else:
                        summary_parts.append(f"  - {func.get('name', 'unknown')} - no special behavior detected")
                
                if len(functions) > 10:
                    summary_parts.append(f"  ... and {len(functions)-10} more functions")
                summary_parts.append("")
        
        capabilities = self.analysis_context.get("capabilities", {})
        if capabilities:
            summary_parts.append("=== CAPABILITIES ===")
            for category, items in capabilities.items():
                if items and category != "error":
                    if isinstance(items, list) and items:
                        summary_parts.append(f"{category.replace('_', ' ').title()}:")
                        for item in items[:5]:
                            summary_parts.append(f"  - {item}")
                        if len(items) > 5:
                            summary_parts.append(f"  ... and {len(items)-5} more")
                    elif isinstance(items, str):
                        summary_parts.append(f"{category.replace('_', ' ').title()}: {items}")
            summary_parts.append("")
        
        return "\n".join(summary_parts) if summary_parts else "No comprehensive analysis context available."
    
    def _format_conversation_history(self) -> str:
        """Format conversation history for LLM context"""
        if not self.conversation_history:
            return "No previous conversation."
        
        recent_history = self.conversation_history[-10:]
        
        formatted = []
        for entry in recent_history:
            role = entry["role"].title()
            content = entry["content"]
            if len(content) > 500:
                content = content[:500] + "..."
            formatted.append(f"{role}: {content}")
        
        return "\n".join(formatted)
