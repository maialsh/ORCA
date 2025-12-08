"""
Enhanced String Analysis Module for BinSleuth
Detects suspicious strings that might indicate backdoor or trojan behavior
"""
import re
import json
import os
from typing import List, Dict, Any, Optional, Set, Tuple
from collections import defaultdict

from llm_module import llm_handler
from smart_string_analysis import SmartStringAnalyzer, SmartStringValidator


class EnhancedStringAnalyzer:
    """
    Enhanced string analyzer that can detect suspicious strings indicating
    backdoor, trojan, or other malicious behavior.
    """
    
    def __init__(self, use_llm: bool = True):
        """
        Initialize the enhanced string analyzer
        
        Args:
            use_llm: Whether to use LLM for advanced analysis
        """
        self.use_llm = use_llm
        self.smart_analyzer = SmartStringAnalyzer(use_llm=use_llm)
        self.validator = SmartStringValidator(use_llm=use_llm)
        
        # Define suspicious string patterns
        self.suspicious_patterns = {
            "backdoor_indicators": [
                r"\b(?:backdoor|rootkit|keylogger|stealer|trojan)\b",
                r"\b(?:hidden|secret|covert|stealth)\b",
                r"\b(?:inject|hook|patch|modify)\b",
                r"\b(?:bypass|evade|disable|kill)\b",
                r"\b(?:persistence|startup|autorun)\b",
                r"\b(?:privilege|escalate|admin|root)\b",
                r"\b(?:remote|shell|cmd|command)\b",
                r"\b(?:download|upload|exfiltrate|steal)\b"
            ],
            "network_indicators": [
                r"\b(?:c2|cnc|command.?control)\b",
                r"\b(?:beacon|heartbeat|checkin)\b",
                r"\b(?:proxy|tunnel|redirect)\b",
                r"\b(?:bot|zombie|slave)\b",
                r"\b(?:ddos|flood|attack)\b",
                r"(?:tcp|udp|http|https)://",
                r"\b(?:port|socket|connect|bind)\b"
            ],
            "crypto_indicators": [
                r"\b(?:encrypt|decrypt|cipher|crypto)\b",
                r"\b(?:key|password|secret|token)\b",
                r"\b(?:hash|md5|sha|aes|rsa)\b",
                r"\b(?:base64|encode|decode)\b",
                r"\b(?:xor|rot|obfuscate)\b"
            ],
            "evasion_indicators": [
                r"\b(?:antivirus|av|defender|firewall)\b",
                r"\b(?:sandbox|vm|virtual|debug)\b",
                r"\b(?:analysis|reverse|disasm)\b",
                r"\b(?:hide|mask|cloak|disguise)\b",
                r"\b(?:polymorphic|metamorphic|packer)\b"
            ],
            "persistence_indicators": [
                r"\b(?:registry|hkey|regedit)\b",
                r"\b(?:service|daemon|driver)\b",
                r"\b(?:startup|autostart|boot)\b",
                r"\b(?:schedule|task|cron)\b",
                r"\b(?:dll|library|module)\b"
            ],
            "data_theft_indicators": [
                r"\b(?:password|credential|login)\b",
                r"\b(?:browser|chrome|firefox|edge)\b",
                r"\b(?:wallet|bitcoin|crypto)\b",
                r"\b(?:document|file|data)\b",
                r"\b(?:screenshot|keylog|clipboard)\b"
            ]
        }
        
        # Define high-risk keywords
        self.high_risk_keywords = {
            "exploit", "vulnerability", "zero.?day", "payload", "shellcode",
            "malware", "virus", "worm", "ransomware", "spyware",
            "botnet", "c2", "command.?control", "backdoor", "rootkit",
            "keylogger", "stealer", "trojan", "rat", "remote.?access"
        }
        
        # Define suspicious file extensions and paths
        self.suspicious_paths = {
            "system_paths": [
                r"\\system32\\", r"\\syswow64\\", r"\\windows\\",
                r"/usr/bin/", r"/bin/", r"/sbin/", r"/etc/"
            ],
            "temp_paths": [
                r"\\temp\\", r"\\tmp\\", r"%temp%", r"/tmp/",
                r"\\appdata\\", r"\\roaming\\"
            ],
            "suspicious_extensions": [
                r"\.(?:exe|dll|sys|bat|cmd|ps1|vbs|js|jar|scr)$"
            ]
        }
    
    def find_suspicious_strings(self, strings: List[str]) -> Dict[str, Any]:
        """
        Analyze strings to find suspicious patterns indicating malicious behavior
        
        Args:
            strings: List of strings to analyze
            
        Returns:
            Dictionary containing suspicious strings analysis:
            {
                "suspicious_strings": {
                    "backdoor_indicators": [],
                    "network_indicators": [],
                    "crypto_indicators": [],
                    "evasion_indicators": [],
                    "persistence_indicators": [],
                    "data_theft_indicators": []
                },
                "high_risk_strings": [],
                "suspicious_paths": [],
                "encoded_strings": [],
                "summary": str,
                "risk_score": int
            }
        """
        results = {
            "suspicious_strings": defaultdict(list),
            "high_risk_strings": [],
            "suspicious_paths": [],
            "encoded_strings": [],
            "summary": "",
            "risk_score": 0
        }
        
        # Track processed strings to avoid duplicates
        processed_strings = set()
        
        for string_value in strings:
            if not isinstance(string_value, str) or len(string_value) < 3:
                continue
            
            # Skip if already processed
            if string_value in processed_strings:
                continue
            processed_strings.add(string_value)
            
            # Check against suspicious patterns
            self._check_suspicious_patterns(string_value, results)
            
            # Check for high-risk keywords
            self._check_high_risk_keywords(string_value, results)
            
            # Check for suspicious paths
            self._check_suspicious_paths(string_value, results)
            
            # Check for encoded strings
            self._check_encoded_strings(string_value, results)
        
        # Use LLM for additional analysis if enabled
        if self.use_llm and any(results["suspicious_strings"].values()):
            llm_analysis = self._analyze_with_llm(results)
            results["summary"] = llm_analysis.get("summary", "")
            results["risk_score"] = llm_analysis.get("risk_score", 0)
        else:
            # Calculate basic risk score
            results["risk_score"] = self._calculate_risk_score(results)
            results["summary"] = self._generate_basic_summary(results)
        
        # Convert defaultdict to regular dict
        results["suspicious_strings"] = dict(results["suspicious_strings"])
        
        return results
    
    def _check_suspicious_patterns(self, string_value: str, results: Dict[str, Any]):
        """
        Check string against suspicious patterns
        
        Args:
            string_value: String to check
            results: Results dictionary to update
        """
        string_lower = string_value.lower()
        
        for category, patterns in self.suspicious_patterns.items():
            for pattern in patterns:
                if re.search(pattern, string_lower, re.IGNORECASE):
                    # Determine risk level based on pattern
                    risk_level = self._determine_risk_level(pattern, category)
                    
                    string_info = {
                        "string": string_value,
                        "pattern": pattern,
                        "reason": f"Matches {category.replace('_', ' ')} pattern",
                        "risk_level": risk_level,
                        "context": self._get_string_context(string_value)
                    }
                    
                    results["suspicious_strings"][category].append(string_info)
                    break  # Only match first pattern per category
    
    def _check_high_risk_keywords(self, string_value: str, results: Dict[str, Any]):
        """
        Check string against high-risk keywords
        
        Args:
            string_value: String to check
            results: Results dictionary to update
        """
        string_lower = string_value.lower()
        
        for keyword in self.high_risk_keywords:
            if re.search(keyword, string_lower, re.IGNORECASE):
                string_info = {
                    "string": string_value,
                    "keyword": keyword,
                    "reason": f"Contains high-risk keyword: {keyword}",
                    "risk_level": "high",
                    "context": self._get_string_context(string_value)
                }
                
                results["high_risk_strings"].append(string_info)
                break  # Only match first keyword
    
    def _check_suspicious_paths(self, string_value: str, results: Dict[str, Any]):
        """
        Check string for suspicious file paths
        
        Args:
            string_value: String to check
            results: Results dictionary to update
        """
        for category, patterns in self.suspicious_paths.items():
            for pattern in patterns:
                if re.search(pattern, string_value, re.IGNORECASE):
                    string_info = {
                        "string": string_value,
                        "pattern": pattern,
                        "reason": f"Suspicious {category.replace('_', ' ')}",
                        "risk_level": "medium" if "temp" in category else "high",
                        "context": self._get_string_context(string_value)
                    }
                    
                    results["suspicious_paths"].append(string_info)
                    break
    
    def _check_encoded_strings(self, string_value: str, results: Dict[str, Any]):
        """
        Check for potentially encoded or obfuscated strings
        
        Args:
            string_value: String to check
            results: Results dictionary to update
        """
        # Check for base64-like strings
        if len(string_value) >= 16 and re.match(r'^[A-Za-z0-9+/=]+$', string_value):
            # Calculate entropy to determine if it's likely encoded
            entropy = self._calculate_entropy(string_value)
            if entropy > 4.5:  # High entropy suggests encoding
                string_info = {
                    "string": string_value,
                    "encoding": "base64-like",
                    "reason": f"High entropy ({entropy:.2f}) suggests encoding",
                    "risk_level": "medium",
                    "context": self._get_string_context(string_value)
                }
                
                results["encoded_strings"].append(string_info)
        
        # Check for hex-encoded strings
        elif len(string_value) >= 16 and re.match(r'^[0-9a-fA-F]+$', string_value):
            string_info = {
                "string": string_value,
                "encoding": "hexadecimal",
                "reason": "Appears to be hex-encoded data",
                "risk_level": "low",
                "context": self._get_string_context(string_value)
            }
            
            results["encoded_strings"].append(string_info)
        
        # Check for XOR-like patterns (repeated characters)
        elif len(string_value) >= 8:
            char_freq = defaultdict(int)
            for char in string_value:
                char_freq[char] += 1
            
            # If a single character appears more than 50% of the time, might be XOR
            max_freq = max(char_freq.values())
            if max_freq / len(string_value) > 0.5:
                string_info = {
                    "string": string_value,
                    "encoding": "possible XOR",
                    "reason": f"Character repetition suggests XOR encoding",
                    "risk_level": "medium",
                    "context": self._get_string_context(string_value)
                }
                
                results["encoded_strings"].append(string_info)
    
    def _determine_risk_level(self, pattern: str, category: str) -> str:
        """
        Determine risk level based on pattern and category
        
        Args:
            pattern: Regex pattern that matched
            category: Category of the pattern
            
        Returns:
            Risk level string
        """
        high_risk_patterns = [
            "backdoor", "rootkit", "trojan", "inject", "bypass",
            "privilege", "escalate", "c2", "cnc", "command.?control"
        ]
        
        medium_risk_patterns = [
            "hidden", "secret", "encrypt", "decrypt", "antivirus",
            "sandbox", "registry", "service"
        ]
        
        pattern_lower = pattern.lower()
        
        if any(hrp in pattern_lower for hrp in high_risk_patterns):
            return "high"
        elif any(mrp in pattern_lower for mrp in medium_risk_patterns):
            return "medium"
        else:
            return "low"
    
    def _get_string_context(self, string_value: str) -> str:
        """
        Get context information about a string
        
        Args:
            string_value: String to get context for
            
        Returns:
            Context description
        """
        # Basic context based on string characteristics
        if string_value.startswith(('http://', 'https://')):
            return "URL"
        elif '\\' in string_value or '/' in string_value:
            return "File path"
        elif '@' in string_value and '.' in string_value:
            return "Email address"
        elif re.match(r'^\d{1,3}\.\d{1,3}\.\d{1,3}\.\d{1,3}', string_value):
            return "IP address"
        elif len(string_value) >= 32 and re.match(r'^[a-fA-F0-9]+$', string_value):
            return "Hash or key"
        else:
            return "General string"
    
    def _calculate_entropy(self, string_value: str) -> float:
        """
        Calculate Shannon entropy of a string
        
        Args:
            string_value: String to calculate entropy for
            
        Returns:
            Entropy value
        """
        import math
        
        if not string_value:
            return 0.0
        
        # Count character frequencies
        char_counts = defaultdict(int)
        for char in string_value:
            char_counts[char] += 1
        
        # Calculate entropy
        entropy = 0.0
        length = len(string_value)
        
        for count in char_counts.values():
            probability = count / length
            entropy -= probability * math.log2(probability)
        
        return entropy
    
    def _calculate_risk_score(self, results: Dict[str, Any]) -> int:
        """
        Calculate overall risk score based on findings
        
        Args:
            results: Analysis results
            
        Returns:
            Risk score (0-100)
        """
        score = 0
        
        # Score based on suspicious strings
        for category, strings in results["suspicious_strings"].items():
            for string_info in strings:
                risk_level = string_info.get("risk_level", "low")
                if risk_level == "high":
                    score += 15
                elif risk_level == "medium":
                    score += 10
                else:
                    score += 5
        
        # Score based on high-risk strings
        score += len(results["high_risk_strings"]) * 20
        
        # Score based on suspicious paths
        for path_info in results["suspicious_paths"]:
            risk_level = path_info.get("risk_level", "low")
            if risk_level == "high":
                score += 10
            else:
                score += 5
        
        # Score based on encoded strings
        score += len(results["encoded_strings"]) * 3
        
        # Cap at 100
        return min(score, 100)
    
    def _generate_basic_summary(self, results: Dict[str, Any]) -> str:
        """
        Generate a basic summary of findings
        
        Args:
            results: Analysis results
            
        Returns:
            Summary string
        """
        total_suspicious = sum(len(strings) for strings in results["suspicious_strings"].values())
        high_risk_count = len(results["high_risk_strings"])
        suspicious_paths_count = len(results["suspicious_paths"])
        encoded_count = len(results["encoded_strings"])
        risk_score = results.get("risk_score", 0)
        
        if risk_score >= 70:
            risk_level = "HIGH"
        elif risk_score >= 40:
            risk_level = "MEDIUM"
        elif risk_score >= 20:
            risk_level = "LOW"
        else:
            risk_level = "MINIMAL"
        
        summary = f"Risk Level: {risk_level} (Score: {risk_score}/100)\n\n"
        summary += f"Found {total_suspicious} suspicious string patterns, "
        summary += f"{high_risk_count} high-risk keywords, "
        summary += f"{suspicious_paths_count} suspicious paths, "
        summary += f"and {encoded_count} potentially encoded strings.\n\n"
        
        if risk_score >= 50:
            summary += "This binary shows significant indicators of malicious behavior. "
            summary += "Manual analysis is strongly recommended."
        elif risk_score >= 20:
            summary += "This binary shows some suspicious characteristics. "
            summary += "Further investigation may be warranted."
        else:
            summary += "This binary shows minimal suspicious characteristics based on string analysis."
        
        return summary
    
    def _analyze_with_llm(self, results: Dict[str, Any]) -> Dict[str, Any]:
        """
        Use LLM to analyze suspicious strings and provide insights
        
        Args:
            results: Current analysis results
            
        Returns:
            LLM analysis results
        """
        # Prepare data for LLM
        suspicious_data = {
            "suspicious_patterns": dict(results["suspicious_strings"]),
            "high_risk_strings": results["high_risk_strings"],
            "suspicious_paths": results["suspicious_paths"],
            "encoded_strings": results["encoded_strings"]
        }
        
        system_prompt = """You are a malware analysis expert specializing in string analysis. 
        Analyze the provided suspicious strings and determine the likelihood of malicious behavior.
        
        Focus on:
        1. Patterns that indicate backdoor or trojan functionality
        2. Network communication capabilities
        3. Persistence mechanisms
        4. Evasion techniques
        5. Data theft capabilities
        
        Provide a risk assessment and summary."""
        
        user_prompt = f"""Analyze these suspicious strings found in a binary:
        
        {json.dumps(suspicious_data, indent=2)}
        
        Provide a JSON response with:
        1. "summary": A detailed analysis of the findings and their implications
        2. "risk_score": An integer from 0-100 indicating the overall risk level
        3. "threat_indicators": A list of specific threat indicators found
        4. "recommendations": Suggested next steps for analysis
        """
        
        try:
            response = llm_handler.get_json_response(system_prompt, user_prompt)
            return response
        except Exception as e:
            print(f"LLM analysis failed: {e}")
            return {
                "summary": self._generate_basic_summary(results),
                "risk_score": self._calculate_risk_score(results),
                "threat_indicators": [],
                "recommendations": ["Manual analysis recommended due to LLM analysis failure"]
            }
    
    def save_suspicious_strings(self, results: Dict[str, Any], filepath: str):
        """
        Save suspicious strings analysis to file
        
        Args:
            results: Analysis results to save
            filepath: Path to save the results
        """
        try:
            # Prepare data for saving
            save_data = {
                "analysis_timestamp": str(os.path.getmtime(__file__)),
                "suspicious_strings_analysis": results,
                "metadata": {
                    "total_suspicious": sum(len(strings) for strings in results["suspicious_strings"].values()),
                    "risk_score": results.get("risk_score", 0),
                    "analysis_version": "1.0"
                }
            }
            
            with open(filepath, 'w') as f:
                json.dump(save_data, f, indent=2)
            
            print(f"Suspicious strings analysis saved to {filepath}")
        except Exception as e:
            print(f"Error saving suspicious strings analysis: {e}")
    
    def load_suspicious_strings(self, filepath: str) -> Optional[Dict[str, Any]]:
        """
        Load suspicious strings analysis from file
        
        Args:
            filepath: Path to load the results from
            
        Returns:
            Loaded analysis results or None if failed
        """
        try:
            with open(filepath, 'r') as f:
                data = json.load(f)
                return data.get("suspicious_strings_analysis")
        except Exception as e:
            print(f"Error loading suspicious strings analysis: {e}")
            return None


def analyze_strings_for_threats(strings: List[str], use_llm: bool = True) -> Dict[str, Any]:
    """
    Convenience function to analyze strings for threat indicators
    
    Args:
        strings: List of strings to analyze
        use_llm: Whether to use LLM for analysis
        
    Returns:
        Analysis results
    """
    analyzer = EnhancedStringAnalyzer(use_llm=use_llm)
    return analyzer.find_suspicious_strings(strings)


if __name__ == "__main__":
    # Example usage
    test_strings = [
        "CreateRemoteThread",
        "backdoor_access",
        "C:\\Windows\\System32\\evil.exe",
        "http://malicious-c2.com/beacon",
        "keylogger_data",
        "bypass_antivirus",
        "inject_payload",
        "steal_passwords",
        "hidden_service",
        "encrypt_files",
        "AKIA1234567890ABCDEF",  # AWS key-like
        "aGVsbG8gd29ybGQ=",  # base64
        "normal_string_here",
        "legitimate_function"
    ]
    
    print("Analyzing test strings for suspicious patterns...")
    results = analyze_strings_for_threats(test_strings)
    
    print(f"\nRisk Score: {results['risk_score']}/100")
    print(f"\nSummary:\n{results['summary']}")
    
    print(f"\nSuspicious Strings Found:")
    for category, strings in results["suspicious_strings"].items():
        if strings:
            print(f"\n{category.replace('_', ' ').title()}:")
            for string_info in strings:
                print(f"  - {string_info['string']} ({string_info['risk_level']} risk)")
                print(f"    Reason: {string_info['reason']}")
