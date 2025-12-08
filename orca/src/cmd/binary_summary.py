"""
Binary Summary Module for BinSleuth
Generates comprehensive summaries of binary files based on analysis results
Identifies suspicious APIs that don't match the binary's declared functionality
"""
import os
import json
import sys
from typing import Dict, List, Any, Optional, Set, Tuple
from pathlib import Path

# Try to load credentials from AGENTCONFIG if available
try:
    if 'AGENTCONFIG' in os.environ:
        creds = json.load(open(os.environ['AGENTCONFIG']))
        os.environ['OPENAI_API_KEY'] = creds['OPENAI_API_KEY']
    else:
        print("Warning: AGENTCONFIG environment variable not set. Using default configuration.")
except Exception as e:
    print(f"Warning: Failed to load credentials from AGENTCONFIG: {str(e)}")

# Import LLM handler
from llm_module import llm_handler

class BinarySummaryGenerator:
    """
    Generates comprehensive summaries of binary files based on analysis results
    Identifies suspicious APIs that don't match the binary's declared functionality
    """
    
    def __init__(self):
        """Initialize the summary generator"""
        # Common categories of binary functionality
        self.binary_categories = {
            "utility": [
                "calculator", "text editor", "file manager", "archive tool", 
                "converter", "system utility"
            ],
            "network": [
                "web browser", "email client", "ftp client", "network scanner",
                "packet analyzer", "vpn client", "ssh client"
            ],
            "security": [
                "antivirus", "firewall", "password manager", "encryption tool",
                "security scanner", "authentication tool"
            ],
            "system": [
                "device driver", "system service", "daemon", "scheduler",
                "process manager", "system monitor"
            ],
            "multimedia": [
                "media player", "image viewer", "audio editor", "video editor",
                "screen recorder", "streaming tool"
            ],
            "development": [
                "compiler", "interpreter", "debugger", "ide", "build tool",
                "version control", "code analyzer"
            ]
        }
        
        # Suspicious API combinations by binary category
        self.suspicious_api_combinations = {
            "utility": [
                {"apis": ["socket", "connect", "bind"], "reason": "Network functionality in utility tool"},
                {"apis": ["exec", "system", "popen"], "reason": "Command execution in utility tool"},
                {"apis": ["chroot", "setuid", "setgid"], "reason": "Privilege operations in utility tool"}
            ],
            "network": [
                {"apis": ["ptrace", "dlopen"], "reason": "Process manipulation in network tool"},
                {"apis": ["setuid", "setgid", "chroot"], "reason": "Privilege escalation in network tool"}
            ],
            "security": [
                {"apis": ["memfd_create", "mmap", "mprotect"], "reason": "Memory manipulation in security tool"}
            ],
            "system": [
                {"apis": ["encrypt", "decrypt", "base64"], "reason": "Cryptographic operations in system tool"}
            ],
            "multimedia": [
                {"apis": ["socket", "connect", "bind"], "reason": "Network functionality in multimedia tool"},
                {"apis": ["setuid", "setgid", "chroot"], "reason": "Privilege operations in multimedia tool"}
            ],
            "development": [
                {"apis": ["setuid", "setgid", "chroot"], "reason": "Privilege operations in development tool"}
            ]
        }
    
    def generate_summary(self, 
                        analysis_results: Dict[str, Any], 
                        binary_functionality: str,
                        binary_path: Optional[str] = None) -> Dict[str, Any]:
        """
        Generate a comprehensive summary of the binary based on analysis results
        
        Args:
            analysis_results: Dictionary containing analysis results
            binary_functionality: Description of the binary's intended functionality
            binary_path: Optional path to the binary file
            
        Returns:
            Dictionary containing the summary
        """
        # Extract key information from analysis results
        file_info = analysis_results.get("file_info", {})
        imports = analysis_results.get("imports", [])
        strings = analysis_results.get("strings", {})
        api_crossrefs = analysis_results.get("api_crossrefs_results", {})
        api_clusters = analysis_results.get("api_clustering_results", {})
        
        # Identify suspicious APIs based on binary functionality
        suspicious_apis = self._identify_suspicious_apis(imports, binary_functionality, api_crossrefs)
        
        # Prepare data for LLM summary
        summary_data = {
            "binary_info": file_info,
            "binary_functionality": binary_functionality,
            "imports_summary": self._summarize_imports(imports, api_crossrefs, api_clusters),
            "strings_summary": self._summarize_strings(strings),
            "suspicious_apis": suspicious_apis
        }
        
        # Generate summary using LLM
        llm_summary = self._generate_llm_summary(summary_data)
        
        # Combine all results
        return {
            "binary_info": file_info,
            "binary_functionality": binary_functionality,
            "imports_summary": summary_data["imports_summary"],
            "strings_summary": summary_data["strings_summary"],
            "suspicious_apis": suspicious_apis,
            "summary": llm_summary
        }
    
    def _identify_suspicious_apis(self, 
                                imports: List[str], 
                                binary_functionality: str,
                                api_crossrefs: Dict[str, Any]) -> List[Dict[str, Any]]:
        """
        Identify suspicious APIs that don't match the binary's declared functionality
        
        Args:
            imports: List of imported APIs
            binary_functionality: Description of the binary's intended functionality
            api_crossrefs: Dictionary containing API cross-reference information
            
        Returns:
            List of suspicious APIs with reasons
        """
        suspicious_apis = []
        
        # Determine the binary category based on functionality description
        binary_category = self._determine_binary_category(binary_functionality)
        
        # Get suspicious API combinations for this category
        category_suspicious_apis = self.suspicious_api_combinations.get(binary_category, [])
        
        # Check for suspicious API combinations
        for combo in category_suspicious_apis:
            apis = combo["apis"]
            reason = combo["reason"]
            
            # Check if all APIs in the combination are present and referenced
            if all(any(api in imp for imp in imports) for api in apis):
                # Verify these APIs are actually referenced in the code
                referenced_apis = set()
                for api_name, references in api_crossrefs.items():
                    if references:  # If there are references to this API
                        referenced_apis.add(api_name)
                
                # Only include if the APIs are actually referenced
                matching_apis = [api for api in apis if any(api in ref_api for ref_api in referenced_apis)]
                if matching_apis:
                    suspicious_apis.append({
                        "apis": matching_apis,
                        "reason": reason,
                        "severity": "high" if len(matching_apis) == len(apis) else "medium"
                    })
        
        # Use LLM to identify additional suspicious APIs
        llm_suspicious_apis = self._identify_suspicious_apis_with_llm(imports, binary_functionality, api_crossrefs)
        
        # Combine results
        for api in llm_suspicious_apis:
            if not any(api["apis"] == existing["apis"] for existing in suspicious_apis):
                suspicious_apis.append(api)
        
        return suspicious_apis
    
    def _determine_binary_category(self, binary_functionality: str) -> str:
        """
        Determine the category of the binary based on its functionality description
        
        Args:
            binary_functionality: Description of the binary's intended functionality
            
        Returns:
            Category of the binary
        """
        binary_functionality = binary_functionality.lower()
        
        for category, keywords in self.binary_categories.items():
            if any(keyword in binary_functionality for keyword in keywords):
                return category
        
        # Default to utility if no match
        return "utility"
    
    def _summarize_imports(self, 
                          imports: List[str], 
                          api_crossrefs: Dict[str, Any],
                          api_clusters: Dict[str, Any]) -> Dict[str, Any]:
        """
        Summarize imported APIs
        
        Args:
            imports: List of imported APIs
            api_crossrefs: Dictionary containing API cross-reference information
            api_clusters: Dictionary containing API clustering information
            
        Returns:
            Dictionary containing import summary
        """
        # Count imports by category
        import_categories = {
            "network": 0,
            "filesystem": 0,
            "process": 0,
            "memory": 0,
            "crypto": 0,
            "ui": 0,
            "other": 0
        }
        
        # Network-related APIs
        network_apis = ["socket", "connect", "bind", "listen", "accept", "recv", "send", "gethostbyname"]
        
        # Filesystem-related APIs
        filesystem_apis = ["open", "read", "write", "close", "unlink", "mkdir", "rmdir", "stat"]
        
        # Process-related APIs
        process_apis = ["fork", "exec", "system", "popen", "kill", "wait", "exit"]
        
        # Memory-related APIs
        memory_apis = ["malloc", "free", "realloc", "mmap", "munmap", "memcpy", "memset"]
        
        # Crypto-related APIs
        crypto_apis = ["crypt", "encrypt", "decrypt", "md5", "sha", "aes", "des", "ssl", "tls"]
        
        # UI-related APIs
        ui_apis = ["gtk", "qt", "window", "dialog", "button", "display", "screen"]
        
        # Count imports by category
        for imp in imports:
            imp_lower = imp.lower()
            
            if any(api in imp_lower for api in network_apis):
                import_categories["network"] += 1
            elif any(api in imp_lower for api in filesystem_apis):
                import_categories["filesystem"] += 1
            elif any(api in imp_lower for api in process_apis):
                import_categories["process"] += 1
            elif any(api in imp_lower for api in memory_apis):
                import_categories["memory"] += 1
            elif any(api in imp_lower for api in crypto_apis):
                import_categories["crypto"] += 1
            elif any(api in imp_lower for api in ui_apis):
                import_categories["ui"] += 1
            else:
                import_categories["other"] += 1
        
        # Get most referenced APIs
        most_referenced_apis = []
        for api_name, references in api_crossrefs.items():
            if references:
                ref_count = sum(len(ref.get("references", [])) for ref in references)
                most_referenced_apis.append({"api": api_name, "references": ref_count})
        
        # Sort by reference count
        most_referenced_apis = sorted(most_referenced_apis, key=lambda x: x["references"], reverse=True)[:10]
        
        # Extract API clusters
        api_cluster_summary = []
        for cluster in api_clusters.get("clusters", []):
            api_cluster_summary.append({
                "name": cluster.get("name", "Unknown"),
                "description": cluster.get("description", ""),
                "security_assessment": cluster.get("security_assessment", "unknown"),
                "api_count": len(cluster.get("apis", []))
            })
        
        return {
            "total_imports": len(imports),
            "categories": import_categories,
            "most_referenced_apis": most_referenced_apis,
            "api_clusters": api_cluster_summary
        }
    
    def _summarize_strings(self, strings: Dict[str, List[str]]) -> Dict[str, Any]:
        """
        Summarize strings found in the binary
        
        Args:
            strings: Dictionary containing categorized strings
            
        Returns:
            Dictionary containing string summary
        """
        # Count strings by category
        string_counts = {category: len(items) for category, items in strings.items() if isinstance(items, list)}
        
        # Identify potentially interesting strings
        interesting_strings = {
            "urls": strings.get("urls", [])[:10],
            "ip_addresses": strings.get("ip_addresses", [])[:10],
            "domains": strings.get("domains", [])[:10],
            "paths": strings.get("paths", [])[:10],
            "suspicious": strings.get("suspicious", [])[:10]
        }
        
        return {
            "counts": string_counts,
            "interesting_strings": interesting_strings
        }
    
    def _identify_suspicious_apis_with_llm(self, 
                                         imports: List[str], 
                                         binary_functionality: str,
                                         api_crossrefs: Dict[str, Any]) -> List[Dict[str, Any]]:
        """
        Use LLM to identify suspicious APIs based on binary functionality
        
        Args:
            imports: List of imported APIs
            binary_functionality: Description of the binary's intended functionality
            api_crossrefs: Dictionary containing API cross-reference information
            
        Returns:
            List of suspicious APIs with reasons
        """
        # Prepare data for LLM
        referenced_imports = []
        for api_name, references in api_crossrefs.items():
            if references:  # If there are references to this API
                referenced_imports.append(api_name)
        
        # Only analyze if we have referenced imports
        if not referenced_imports:
            return []
        
        # Prepare prompt for LLM
        system_prompt = """You are a binary analysis expert specializing in identifying suspicious API usage.
        Analyze the provided APIs and binary functionality to identify APIs that don't match the expected functionality."""
        
        user_prompt = f"""Analyze these APIs that are referenced in a binary:
        
        Referenced APIs:
        {json.dumps(referenced_imports, indent=2)}
        
        Binary's declared functionality:
        {binary_functionality}
        
        Identify any APIs or combinations of APIs that seem suspicious or don't match the declared functionality.
        For each suspicious API or combination, provide:
        1. The API name(s)
        2. A reason why it's suspicious given the binary's functionality
        3. A severity level (low, medium, high)
        
        Return your analysis as a JSON array of objects with "apis" (array), "reason" (string), and "severity" (string) fields.
        Only include truly suspicious APIs that don't match the functionality - don't force findings if nothing is suspicious.
        """
        
        try:
            # Get response from LLM
            response = llm_handler.get_json_response(system_prompt, user_prompt)
            
            # Extract suspicious APIs
            if isinstance(response, list):
                return response
            elif isinstance(response, dict) and "suspicious_apis" in response:
                return response["suspicious_apis"]
            else:
                return []
        except Exception as e:
            print(f"Error identifying suspicious APIs with LLM: {str(e)}")
            return []
    
    def _generate_llm_summary(self, summary_data: Dict[str, Any]) -> str:
        """
        Generate a comprehensive summary of the binary using LLM
        
        Args:
            summary_data: Dictionary containing summary data
            
        Returns:
            String containing the summary
        """
        # Prepare prompt for LLM
        system_prompt = """You are a binary analysis expert. Create a comprehensive summary of the analyzed binary
        based on the provided analysis results. Focus on the binary's purpose, capabilities, and any suspicious findings."""
        
        user_prompt = f"""Generate a comprehensive summary for this binary:
        
        {json.dumps(summary_data, indent=2)}
        
        Include:
        1. Basic file information
        2. Assessment of whether the binary's behavior matches its declared functionality
        3. Key capabilities identified from imports and strings
        4. Suspicious APIs or behaviors
        5. Overall risk assessment
        
        Format the summary in a clear, structured manner with sections and bullet points where appropriate.
        """
        
        try:
            # Get response from LLM
            return llm_handler.query(system_prompt, user_prompt)
        except Exception as e:
            print(f"Error generating LLM summary: {str(e)}")
            return "Error generating summary. Please check the analysis results manually."


# Main execution
if __name__ == "__main__":
    if len(sys.argv) < 3:
        print("Usage: python binary_summary.py <analysis_results_file> <binary_functionality>")
        sys.exit(1)
        
    # Load analysis results
    with open(sys.argv[1], 'r') as f:
        analysis_results = json.load(f)
    
    binary_functionality = sys.argv[2]
    
    # Generate summary
    summary_generator = BinarySummaryGenerator()
    summary = summary_generator.generate_summary(analysis_results, binary_functionality)
    
    # Print summary
    print(json.dumps(summary, indent=2))
