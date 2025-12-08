import re
import json
import os
import string
import ipaddress
from typing import List, Dict, Optional, Tuple, Set
from tenacity import retry, stop_after_attempt, wait_exponential
import hashlib
import sys

# Try to load credentials from AGENTCONFIG if available
try:
    if 'AGENTCONFIG' in os.environ:
        creds = json.load(open(os.environ['AGENTCONFIG']))
        os.environ['OPENAI_API_KEY'] = creds['OPENAI_API_KEY']
    else:
        print("Warning: AGENTCONFIG environment variable not set. Using default configuration.")
except Exception as e:
    print(f"Warning: Failed to load credentials from AGENTCONFIG: {str(e)}")

# Import OpenAI client
try:
    from openai import OpenAI
    client = OpenAI()
except ImportError:
    print("Warning: OpenAI package not installed. LLM functionality will be limited.")
    client = None

def analyze_binary_strings(strings: List[str], use_llm: bool = True, llm_threshold: int = 50, analyze_files: bool = True) -> Dict[str, List[str]]:
    """
    Analyze binary strings to extract security-relevant artifacts.
    Only saves valid words, URLs, IP addresses, and other relevant data.
    
    Args:
        strings: List of extracted strings from binary
        use_llm: Whether to use LLM for advanced analysis
        llm_threshold: Minimum number of strings before using sampling for LLM
        analyze_files: Whether to analyze found file paths
    
    Returns:
        Dictionary containing categorized artifacts:
        {
            "apis": [],
            "hashes": [],
            "keys": [],
            "paths": [],
            "verified_paths": {},  # Paths that exist with their summaries
            "urls": [],
            "registry": [],
            "ip_addresses": [],
            "domains": [],
            "suspicious": [],
            "code_summaries": {}  # File content summaries
        }
    """
    results = {
        "apis": [],
        "hashes": [],
        "keys": [],
        "paths": [],
        "verified_paths": {},
        "urls": [],
        "registry": [],
        "ip_addresses": [],
        "domains": [],
        "suspicious": [],
        "code_summaries": {}
    }

    # Pre-compile all regex patterns
    patterns = {
        "win32_apis": re.compile(r'\b(?:Create|Open|Close|Read|Write|Delete|Set|Get|Find|Enum|Reg)[A-Za-z]+\b'),
        "linux_apis": re.compile(r'\b(?:sys_|_syscall|socket|open|read|write|exec|fork|ioctl|mmap)\b'),
        "hashes": re.compile(r'\b[A-Fa-f0-9]{16,}\b'),
        "keys": re.compile(r'\b(?:[A-Za-z0-9+/=]{32,}|[A-Fa-f0-9]{32,}|[0-9a-f]{8}-[0-9a-f]{4}-[0-9a-f]{4}-[0-9a-f]{4}-[0-9a-f]{12})\b'),
        "paths": re.compile(r'(?:[a-zA-Z]:\\\\|/|\./|\.\./)(?:[^/\0\n\r]+[/\\])+[^/\0\n\r]*'),
        "urls": re.compile(r'https?://(?:[-\w.]|(?:%[\da-fA-F]{2}))+[/\w .?=&%-]*'),
        "registry": re.compile(r'HKEY_[A-Z_]+\\[\\\w-]+(?:\\[\\\w-]+)*'),
        "ip_addresses": re.compile(r'\b\d{1,3}\.\d{1,3}\.\d{1,3}\.\d{1,3}(?::\d+)?\b'),
        "domains": re.compile(r'\b(?:[a-zA-Z0-9-]+\.)+[a-zA-Z]{2,}\b'),
        "suspicious": re.compile(r'\b(?:secret|key|password|admin|backdoor|exploit|vulnerability|malware|inject|payload)\b', re.I),
        "valid_words": re.compile(r'\b[a-zA-Z]{3,}\b')  # Words with at least 3 letters
    }

    # First pass with regex
    for s in strings:
        if not isinstance(s, str) or len(s) < 3:
            continue

        # Check for Windows APIs
        if matches := patterns["win32_apis"].findall(s):
            results["apis"].extend(matches)

        # Check for Linux APIs
        if matches := patterns["linux_apis"].findall(s):
            results["apis"].extend(matches)

        # Check for hashes - validate they are proper hashes
        if matches := patterns["hashes"].findall(s):
            for match in matches:
                if _is_likely_hash(match):
                    results["hashes"].append(match)

        # Check for keys - validate they are proper keys
        if matches := patterns["keys"].findall(s):
            for match in matches:
                if _is_likely_key(match):
                    results["keys"].append(match)

        # Check for paths - with enhanced verification
        if matches := patterns["paths"].findall(s):
            for path in matches:
                # Only add paths that look valid
                if _is_valid_path(path):
                    results["paths"].append(path)
                    if analyze_files:
                        verified = verify_and_analyze_path(path)
                        if verified:
                            results["verified_paths"][path] = verified
                            if "summary" in verified:
                                results["code_summaries"][path] = verified["summary"]

        # Check for URLs - validate they are proper URLs
        if matches := patterns["urls"].findall(s):
            for match in matches:
                if _is_valid_url(match):
                    results["urls"].append(match)

        # Check for registry keys
        if matches := patterns["registry"].findall(s):
            results["registry"].extend(matches)

        # Check for IP addresses - validate they are proper IP addresses
        if matches := patterns["ip_addresses"].findall(s):
            for match in matches:
                ip_part = match.split(':')[0]  # Remove port if present
                if _is_valid_ip(ip_part):
                    results["ip_addresses"].append(match)

        # Check for domains - validate they are proper domains
        if matches := patterns["domains"].findall(s):
            for match in matches:
                if _is_valid_domain(match):
                    results["domains"].append(match)

        # Check for suspicious terms
        if matches := patterns["suspicious"].findall(s):
            results["suspicious"].extend(matches)

    # Deduplicate results (except for verified_paths and code_summaries)
    for key in [k for k in results if k not in ["verified_paths", "code_summaries"]]:
        results[key] = list(set(results[key]))

    # Smart LLM analysis for remaining strings
    if use_llm and client:
        # Only analyze strings that weren't categorized and might be meaningful
        remaining_strings = [
            s for s in strings 
            if len(s) >= 3 and 
            not any(s in results[key] for key in results if key not in ["verified_paths", "code_summaries"]) and
            not any(pattern.search(s) for pattern in patterns.values()) and
            _is_meaningful_string(s)
        ]

        if remaining_strings:
            # If too many strings, sample the most interesting ones
            if len(remaining_strings) > llm_threshold:
                remaining_strings = sorted(
                    remaining_strings,
                    key=lambda x: (
                        -len(x),
                        sum(c.isupper() for c in x),
                        sum(c in '_-/\\@#$%^&*' for c in x)
                    )
                )[:llm_threshold]

            llm_results = _analyze_strings_with_llm(remaining_strings)
            
            # Merge LLM results - only add items that pass validation
            for category, items in llm_results.items():
                if category in results:
                    # Validate each item before adding
                    if category == "urls":
                        items = [item for item in items if _is_valid_url(item)]
                    elif category == "ip_addresses":
                        items = [item for item in items if _is_valid_ip(item.split(':')[0])]
                    elif category == "domains":
                        items = [item for item in items if _is_valid_domain(item)]
                    elif category == "paths":
                        items = [item for item in items if _is_valid_path(item)]
                    
                    # Add validated items
                    results[category].extend(items)
                    results[category] = list(set(results[category]))

    return results

def _is_meaningful_string(s: str) -> bool:
    """
    Check if a string is meaningful and worth analyzing.
    Filters out random character sequences, compiler artifacts, etc.
    
    Args:
        s: String to check
        
    Returns:
        True if the string is meaningful, False otherwise
    """
    # Skip strings that are too short
    if len(s) < 3:
        return False
        
    # Skip strings with too many non-printable characters
    printable_ratio = sum(c in string.printable for c in s) / len(s)
    if printable_ratio < 0.8:
        return False
    
    # Skip strings that are just repeated characters
    if len(set(s)) < 3:
        return False
    
    # Skip strings that are just numbers
    if s.isdigit():
        return False
    
    # Skip common compiler artifacts and debug strings
    compiler_artifacts = [
        "GCC:", "__PRETTY_FUNCTION__", "__func__", "clang", 
        "LLVM", "0x", "0X", "\\x", "\\u", "\\U"
    ]
    if any(artifact in s for artifact in compiler_artifacts):
        return False
    
    return True

def _is_valid_url(url: str) -> bool:
    """
    Validate if a string is a proper URL
    
    Args:
        url: URL string to validate
        
    Returns:
        True if valid URL, False otherwise
    """
    try:
        # Basic URL validation
        return url.startswith(('http://', 'https://')) and '.' in url
    except:
        return False
        
def _is_valid_ip(ip: str) -> bool:
    """
    Validate if a string is a proper IP address
    
    Args:
        ip: IP address string to validate
        
    Returns:
        True if valid IP, False otherwise
    """
    try:
        # Split the IP into octets
        octets = ip.split('.')
        if len(octets) != 4:
            return False
            
        # Check each octet is a valid number between 0-255
        for octet in octets:
            if not octet.isdigit():
                return False
            if int(octet) < 0 or int(octet) > 255:
                return False
                
        return True
    except:
        return False
        
def _is_valid_domain(domain: str) -> bool:
    """
    Validate if a string is a proper domain name
    
    Args:
        domain: Domain string to validate
        
    Returns:
        True if valid domain, False otherwise
    """
    try:
        # Basic domain validation
        parts = domain.split('.')
        return len(parts) >= 2 and all(part.isalnum() or '-' in part for part in parts)
    except:
        return False
        
def _is_valid_path(path: str) -> bool:
    """
    Validate if a string is a proper file path
    
    Args:
        path: Path string to validate
        
    Returns:
        True if valid path, False otherwise
    """
    # Check for common path patterns
    if re.match(r'^[a-zA-Z]:\\', path):  # Windows path
        return True
    if path.startswith('/'):  # Unix absolute path
        return True
    if path.startswith('./') or path.startswith('../'):  # Unix relative path
        return True
    
    # Check for path-like structure
    parts = re.split(r'[/\\]', path)
    return len(parts) >= 2 and all(len(part) > 0 for part in parts if part)

def verify_and_analyze_path(path: str) -> Optional[Dict]:
    """
    Verify if path exists and analyze its contents if possible
    
    Args:
        path: Path to verify and analyze
        
    Returns:
        Dictionary with:
        {
            "exists": bool,
            "type": "file|directory|other",
            "size": int,
            "readable": bool,
            "content_sample": str,  # First 1KB if readable
            "summary": str  # LLM summary if applicable
        }
    """
    try:
        # Normalize path (handle relative paths, symlinks, etc.)
        abs_path = os.path.abspath(os.path.expanduser(path))

        # Basic security check - don't allow paths outside current directory
        if not abs_path.startswith(os.getcwd()):
            return None

        result = {}
        if os.path.exists(abs_path):
            result["exists"] = True

            if os.path.isfile(abs_path):
                result["type"] = "file"
                result["size"] = os.path.getsize(abs_path)

                # Try to read the file (first 1KB)
                try:
                    with open(abs_path, 'r', encoding='utf-8', errors='ignore') as f:
                        sample = f.read(1024)
                        result["content_sample"] = sample
                        result["readable"] = True

                        # Only summarize certain file types
                        if abs_path.endswith(('.c', '.cpp', '.h', '.py', '.js', '.java', '.sh', '.php')):
                            result["summary"] = summarize_code_with_llm(sample, abs_path)
                except (IOError, PermissionError):
                    result["readable"] = False

            elif os.path.isdir(abs_path):
                result["type"] = "directory"
                try:
                    result["size"] = sum(os.path.getsize(os.path.join(abs_path, f)) 
                                for f in os.listdir(abs_path) 
                                if os.path.isfile(os.path.join(abs_path, f)))
                except (IOError, PermissionError):
                    result["size"] = 0

            return result
    except Exception as e:
        print(f"Error verifying path {path}: {e}")

    return None

@retry(stop=stop_after_attempt(3), wait=wait_exponential(multiplier=1, min=4, max=10))
def summarize_code_with_llm(code_sample: str, filepath: str) -> str:
    """
    Use LLM to summarize code file contents
    
    Args:
        code_sample: Sample of code to summarize
        filepath: Path to the file
        
    Returns:
        Summary of the code
    """
    if not client:
        return ""
        
    try:
        prompt = f"""Analyze this code sample from {filepath} and provide a concise summary:
        
        Code:
        {code_sample}

        Provide a summary that includes:
        1. The apparent purpose of the code
        2. Any interesting functions or features
        3. Potential security implications
        4. Key variables or data structures
        
        Keep the summary under 100 words.
        """

        response = client.chat.completions.create(
            model="gpt-4-turbo",
            messages=[{"role": "user", "content": prompt}],
            temperature=0.1,
            max_tokens=200
        )

        return response.choices[0].message.content.strip()
    except Exception as e:
        print(f"LLM code summarization failed: {e}")
        return ""

@retry(stop=stop_after_attempt(3), wait=wait_exponential(multiplier=1, min=4, max=10))
def _analyze_strings_with_llm(strings: List[str]) -> Dict[str, List[str]]:
    """
    Use LLM to analyze strings that didn't match regex patterns
    
    Args:
        strings: List of strings to analyze
        
    Returns:
        Dictionary of categorized strings
    """
    if not client:
        return {}
        
    try:
        prompt = f"""Analyze these strings from a binary file and categorize them:
        
        Strings:
        {json.dumps(strings, indent=2)}

        Categories to use (return JSON format):
        - apis: Windows/Linux API calls
        - hashes: Cryptographic hashes
        - keys: Encryption keys, API keys, UUIDs
        - paths: File system paths
        - urls: Web URLs
        - registry: Windows registry keys
        - ip_addresses: IP addresses
        - domains: Domain names
        - suspicious: Malicious indicators

        For each string, provide the most specific category possible.
        Only return strings that fit these categories.
        Discard any strings that don't clearly fit into one of these categories.
        """

        response = client.chat.completions.create(
            model="gpt-4-turbo",
            messages=[{"role": "user", "content": prompt}],
            temperature=0.1,
            max_tokens=2000,
            response_format={"type": "json_object"}
        )

        return json.loads(response.choices[0].message.content)
    except Exception as e:
        print(f"LLM analysis failed: {e}")
        return {}

def _is_likely_hash(s: str) -> bool:
    """
    Check if string is likely a cryptographic hash
    
    Args:
        s: String to check
        
    Returns:
        True if likely a hash, False otherwise
    """
    if len(s) not in [32, 40, 64, 128]:  # Common hash lengths
        return False

    hex_digits = set("0123456789abcdefABCDEF")
    return all(c in hex_digits for c in s)

def _is_likely_key(s: str) -> bool:
    """
    Check if string is likely an encryption key
    
    Args:
        s: String to check
        
    Returns:
        True if likely a key, False otherwise
    """
    if len(s) < 16:
        return False

    # Check for high entropy
    entropy = _calculate_entropy(s)
    return entropy > 3.5

def _calculate_entropy(s: str) -> float:
    """
    Calculate Shannon entropy of a string
    
    Args:
        s: String to calculate entropy for
        
    Returns:
        Entropy value
    """
    entropy = 0.0
    size = len(s)
    freq = {}

    for c in s:
        freq[c] = freq.get(c, 0) + 1

    for count in freq.values():
        p = float(count) / size
        entropy -= p * math.log2(p)

    return entropy

# Import math for entropy calculation
import math
