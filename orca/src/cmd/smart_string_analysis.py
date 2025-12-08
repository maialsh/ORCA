"""
Smart String Analysis Module for BinSleuth
Uses LLM to filter and validate strings, domains, URLs, and IP addresses
"""
import re
import json
import os
import ipaddress
import socket
import tldextract
import validators
from typing import List, Dict, Any, Optional, Union, Tuple, Set
from urllib.parse import urlparse

from llm_module import llm_handler
from string_analysis import (
    _is_valid_url, _is_valid_ip, _is_valid_domain, _is_valid_path,
    _is_meaningful_string, _is_likely_hash, _is_likely_key
)

class SmartStringValidator:
    """
    Advanced string validator that uses LLM to determine if strings are valid
    and categorize them appropriately.
    """
    
    def __init__(self, use_llm: bool = True, confidence_threshold: float = 0.7):
        """
        Initialize the smart string validator
        
        Args:
            use_llm: Whether to use LLM for validation
            confidence_threshold: Minimum confidence score to consider a validation result valid
        """
        self.use_llm = use_llm
        self.confidence_threshold = confidence_threshold
        self.cache = {}  # Cache for validation results
        
    def validate_string(self, string_value: str, string_type: Optional[str] = None) -> Dict[str, Any]:
        """
        Validate a string and determine if it's valid based on its type
        
        Args:
            string_value: The string to validate
            string_type: Optional type hint (url, domain, ip, path, hash, key, etc.)
            
        Returns:
            Dictionary with validation results:
            {
                "valid": bool,
                "type": str,  # Detected type if valid
                "confidence": float,  # Confidence score
                "reason": str,  # Reason for validation result
                "metadata": {}  # Additional metadata about the string
            }
        """
        # Check cache first
        cache_key = f"{string_value}:{string_type or 'auto'}"
        if cache_key in self.cache:
            return self.cache[cache_key]
        
        # Initialize result
        result = {
            "valid": False,
            "type": string_type or "unknown",
            "confidence": 0.0,
            "reason": "",
            "metadata": {}
        }
        
        # Skip empty or very short strings
        if not string_value or len(string_value) < 3:
            result["reason"] = "String is too short"
            self.cache[cache_key] = result
            return result
        
        # If type is provided, use specific validation
        if string_type:
            if string_type == "url":
                return self.validate_url(string_value)
            elif string_type == "domain":
                return self.validate_domain(string_value)
            elif string_type == "ip":
                return self.validate_ip(string_value)
            elif string_type == "path":
                return self.validate_path(string_value)
            elif string_type == "hash":
                return self.validate_hash(string_value)
            elif string_type == "key":
                return self.validate_key(string_value)
        
        # Auto-detect type and validate
        detected_type = self._detect_string_type(string_value)
        result["type"] = detected_type
        
        if detected_type == "url":
            result = self.validate_url(string_value)
        elif detected_type == "domain":
            result = self.validate_domain(string_value)
        elif detected_type == "ip":
            result = self.validate_ip(string_value)
        elif detected_type == "path":
            result = self.validate_path(string_value)
        elif detected_type == "hash":
            result = self.validate_hash(string_value)
        elif detected_type == "key":
            result = self.validate_key(string_value)
        elif detected_type == "email":
            result = self.validate_email(string_value)
        else:
            # For general strings, use LLM if enabled
            if self.use_llm:
                llm_result = self._validate_with_llm(string_value)
                result.update(llm_result)
            else:
                result["valid"] = _is_meaningful_string(string_value)
                result["confidence"] = 0.8 if result["valid"] else 0.2
                result["reason"] = "Basic validation" if result["valid"] else "Not a meaningful string"
        
        # Cache the result
        self.cache[cache_key] = result
        return result
    
    def validate_url(self, url: str) -> Dict[str, Any]:
        """
        Validate if a string is a proper URL
        
        Args:
            url: URL string to validate
            
        Returns:
            Validation result dictionary
        """
        result = {
            "valid": False,
            "type": "url",
            "confidence": 0.0,
            "reason": "",
            "metadata": {}
        }
        
        # Basic validation
        if not url.startswith(('http://', 'https://')):
            result["reason"] = "URL must start with http:// or https://"
            return result
        
        # Use validators library for initial check
        if validators.url(url):
            result["valid"] = True
            result["confidence"] = 0.9
            result["reason"] = "Valid URL format"
            
            # Extract and validate domain part
            parsed_url = urlparse(url)
            domain = parsed_url.netloc
            
            # Remove port if present
            if ':' in domain:
                domain = domain.split(':')[0]
            
            domain_result = self.validate_domain(domain)
            result["metadata"]["domain"] = domain
            result["metadata"]["domain_valid"] = domain_result["valid"]
            result["metadata"]["path"] = parsed_url.path
            result["metadata"]["query"] = parsed_url.query
            
            # If domain is invalid, reduce confidence
            if not domain_result["valid"]:
                result["confidence"] = 0.6
                result["reason"] += ", but domain validation failed"
        else:
            # Fall back to basic validation
            basic_valid = _is_valid_url(url)
            if basic_valid:
                result["valid"] = True
                result["confidence"] = 0.7
                result["reason"] = "Basic URL validation passed"
            else:
                result["reason"] = "Invalid URL format"
        
        # Use LLM for additional validation if confidence is low
        if self.use_llm and result["confidence"] < 0.8:
            llm_result = self._validate_with_llm(url, "url")
            
            # Only update if LLM has higher confidence
            if llm_result["confidence"] > result["confidence"]:
                result.update(llm_result)
                # Keep metadata from our validation
                result["metadata"].update(llm_result.get("metadata", {}))
        
        return result
    
    def validate_domain(self, domain: str) -> Dict[str, Any]:
        """
        Validate if a string is a proper domain name
        
        Args:
            domain: Domain string to validate
            
        Returns:
            Validation result dictionary
        """
        result = {
            "valid": False,
            "type": "domain",
            "confidence": 0.0,
            "reason": "",
            "metadata": {}
        }
        
        # Skip if too short or contains invalid characters
        if len(domain) < 3 or ' ' in domain:
            result["reason"] = "Domain is too short or contains spaces"
            return result
        
        # Use validators library
        if validators.domain(domain):
            result["valid"] = True
            result["confidence"] = 0.9
            result["reason"] = "Valid domain format"
            
            # Extract domain parts
            extract_result = tldextract.extract(domain)
            result["metadata"]["subdomain"] = extract_result.subdomain
            result["metadata"]["domain"] = extract_result.domain
            result["metadata"]["suffix"] = extract_result.suffix
            
            # Check if TLD is valid
            if not extract_result.suffix:
                result["valid"] = False
                result["confidence"] = 0.4
                result["reason"] = "Invalid or missing TLD"
            
            # Try DNS resolution if valid format
            if result["valid"]:
                try:
                    socket.gethostbyname(domain)
                    result["metadata"]["resolvable"] = True
                    result["confidence"] = 0.95
                except socket.error:
                    result["metadata"]["resolvable"] = False
                    # Still valid, just not resolvable
        else:
            # Fall back to basic validation
            basic_valid = _is_valid_domain(domain)
            if basic_valid:
                result["valid"] = True
                result["confidence"] = 0.7
                result["reason"] = "Basic domain validation passed"
            else:
                result["reason"] = "Invalid domain format"
        
        # Use LLM for additional validation if confidence is low
        if self.use_llm and result["confidence"] < 0.8:
            llm_result = self._validate_with_llm(domain, "domain")
            
            # Only update if LLM has higher confidence
            if llm_result["confidence"] > result["confidence"]:
                result.update(llm_result)
                # Keep metadata from our validation
                result["metadata"].update(llm_result.get("metadata", {}))
        
        return result
    
    def validate_ip(self, ip: str) -> Dict[str, Any]:
        """
        Validate if a string is a proper IP address
        
        Args:
            ip: IP address string to validate
            
        Returns:
            Validation result dictionary
        """
        result = {
            "valid": False,
            "type": "ip",
            "confidence": 0.0,
            "reason": "",
            "metadata": {}
        }
        
        # Handle IP:port format
        ip_part = ip
        port = None
        if ':' in ip:
            parts = ip.split(':')
            if len(parts) == 2 and parts[1].isdigit():
                ip_part = parts[0]
                port = int(parts[1])
                result["metadata"]["port"] = port
        
        # Try ipaddress module for validation
        try:
            ip_obj = ipaddress.ip_address(ip_part)
            result["valid"] = True
            result["confidence"] = 0.95
            result["reason"] = f"Valid {ip_obj.__class__.__name__}"
            
            # Add metadata
            result["metadata"]["version"] = "IPv4" if isinstance(ip_obj, ipaddress.IPv4Address) else "IPv6"
            result["metadata"]["is_private"] = ip_obj.is_private
            result["metadata"]["is_global"] = ip_obj.is_global
            result["metadata"]["is_multicast"] = ip_obj.is_multicast
            
            # Check if it's a special address
            if ip_obj.is_loopback:
                result["metadata"]["is_special"] = "loopback"
            elif ip_obj.is_link_local:
                result["metadata"]["is_special"] = "link_local"
            elif ip_obj.is_reserved:
                result["metadata"]["is_special"] = "reserved"
            
            # Validate port if present
            if port is not None:
                if 1 <= port <= 65535:
                    result["metadata"]["valid_port"] = True
                else:
                    result["metadata"]["valid_port"] = False
                    result["confidence"] = 0.7
                    result["reason"] += ", but port is invalid"
        except ValueError:
            # Fall back to basic validation
            basic_valid = _is_valid_ip(ip_part)
            if basic_valid:
                result["valid"] = True
                result["confidence"] = 0.7
                result["reason"] = "Basic IP validation passed"
                result["metadata"]["version"] = "IPv4"
            else:
                result["reason"] = "Invalid IP format"
        
        # Use LLM for additional validation if confidence is low
        if self.use_llm and result["confidence"] < 0.8:
            llm_result = self._validate_with_llm(ip, "ip")
            
            # Only update if LLM has higher confidence
            if llm_result["confidence"] > result["confidence"]:
                result.update(llm_result)
                # Keep metadata from our validation
                result["metadata"].update(llm_result.get("metadata", {}))
        
        return result
    
    def validate_path(self, path: str) -> Dict[str, Any]:
        """
        Validate if a string is a proper file path
        
        Args:
            path: Path string to validate
            
        Returns:
            Validation result dictionary
        """
        result = {
            "valid": False,
            "type": "path",
            "confidence": 0.0,
            "reason": "",
            "metadata": {}
        }
        
        # Basic validation
        basic_valid = _is_valid_path(path)
        if basic_valid:
            result["valid"] = True
            result["confidence"] = 0.8
            result["reason"] = "Valid path format"
            
            # Determine path type
            if re.match(r'^[a-zA-Z]:\\', path):
                result["metadata"]["os"] = "windows"
                result["metadata"]["is_absolute"] = True
            elif path.startswith('/'):
                result["metadata"]["os"] = "unix"
                result["metadata"]["is_absolute"] = True
            elif path.startswith('./') or path.startswith('../'):
                result["metadata"]["os"] = "unix"
                result["metadata"]["is_absolute"] = False
            else:
                result["metadata"]["is_absolute"] = False
            
            # Extract file extension if present
            if '.' in os.path.basename(path):
                result["metadata"]["extension"] = os.path.splitext(path)[1]
        else:
            result["reason"] = "Invalid path format"
        
        # Use LLM for additional validation if confidence is low
        if self.use_llm and result["confidence"] < 0.8:
            llm_result = self._validate_with_llm(path, "path")
            
            # Only update if LLM has higher confidence
            if llm_result["confidence"] > result["confidence"]:
                result.update(llm_result)
                # Keep metadata from our validation
                result["metadata"].update(llm_result.get("metadata", {}))
        
        return result
    
    def validate_hash(self, hash_str: str) -> Dict[str, Any]:
        """
        Validate if a string is a proper cryptographic hash
        
        Args:
            hash_str: Hash string to validate
            
        Returns:
            Validation result dictionary
        """
        result = {
            "valid": False,
            "type": "hash",
            "confidence": 0.0,
            "reason": "",
            "metadata": {}
        }
        
        # Basic validation
        if _is_likely_hash(hash_str):
            result["valid"] = True
            
            # Determine hash type based on length
            hash_length = len(hash_str)
            if hash_length == 32:
                result["metadata"]["hash_type"] = "MD5"
                result["confidence"] = 0.9
            elif hash_length == 40:
                result["metadata"]["hash_type"] = "SHA1"
                result["confidence"] = 0.9
            elif hash_length == 64:
                result["metadata"]["hash_type"] = "SHA256"
                result["confidence"] = 0.9
            elif hash_length == 128:
                result["metadata"]["hash_type"] = "SHA512"
                result["confidence"] = 0.9
            else:
                result["metadata"]["hash_type"] = "Unknown"
                result["confidence"] = 0.7
            
            result["reason"] = f"Valid {result['metadata'].get('hash_type', 'hash')} format"
        else:
            result["reason"] = "Invalid hash format"
        
        # Use LLM for additional validation if confidence is low
        if self.use_llm and result["confidence"] < 0.8:
            llm_result = self._validate_with_llm(hash_str, "hash")
            
            # Only update if LLM has higher confidence
            if llm_result["confidence"] > result["confidence"]:
                result.update(llm_result)
                # Keep metadata from our validation
                result["metadata"].update(llm_result.get("metadata", {}))
        
        return result
    
    def validate_key(self, key_str: str) -> Dict[str, Any]:
        """
        Validate if a string is a proper key (API key, encryption key, etc.)
        
        Args:
            key_str: Key string to validate
            
        Returns:
            Validation result dictionary
        """
        result = {
            "valid": False,
            "type": "key",
            "confidence": 0.0,
            "reason": "",
            "metadata": {}
        }
        
        # Basic validation
        if _is_likely_key(key_str):
            result["valid"] = True
            result["confidence"] = 0.8
            result["reason"] = "Valid key format"
            
            # Try to determine key type
            if re.match(r'^[0-9a-f]{8}-[0-9a-f]{4}-[0-9a-f]{4}-[0-9a-f]{4}-[0-9a-f]{12}$', key_str, re.I):
                result["metadata"]["key_type"] = "UUID"
                result["confidence"] = 0.95
            elif re.match(r'^sk-[A-Za-z0-9]{48}$', key_str):
                result["metadata"]["key_type"] = "OpenAI API Key"
                result["confidence"] = 0.95
            elif re.match(r'^AKIA[0-9A-Z]{16}$', key_str):
                result["metadata"]["key_type"] = "AWS Access Key ID"
                result["confidence"] = 0.95
            elif re.match(r'^[A-Za-z0-9+/=]{40}$', key_str):
                result["metadata"]["key_type"] = "AWS Secret Access Key"
                result["confidence"] = 0.9
            elif re.match(r'^[A-Za-z0-9_-]{39}$', key_str):
                result["metadata"]["key_type"] = "Google API Key"
                result["confidence"] = 0.9
            else:
                result["metadata"]["key_type"] = "Unknown"
        else:
            result["reason"] = "Invalid key format"
        
        # Use LLM for additional validation if confidence is low
        if self.use_llm and result["confidence"] < 0.8:
            llm_result = self._validate_with_llm(key_str, "key")
            
            # Only update if LLM has higher confidence
            if llm_result["confidence"] > result["confidence"]:
                result.update(llm_result)
                # Keep metadata from our validation
                result["metadata"].update(llm_result.get("metadata", {}))
        
        return result
    
    def validate_email(self, email: str) -> Dict[str, Any]:
        """
        Validate if a string is a proper email address
        
        Args:
            email: Email string to validate
            
        Returns:
            Validation result dictionary
        """
        result = {
            "valid": False,
            "type": "email",
            "confidence": 0.0,
            "reason": "",
            "metadata": {}
        }
        
        # Use validators library
        if validators.email(email):
            result["valid"] = True
            result["confidence"] = 0.9
            result["reason"] = "Valid email format"
            
            # Extract domain part
            domain = email.split('@')[-1]
            result["metadata"]["domain"] = domain
            
            # Validate domain
            domain_result = self.validate_domain(domain)
            result["metadata"]["domain_valid"] = domain_result["valid"]
            
            # If domain is invalid, reduce confidence
            if not domain_result["valid"]:
                result["confidence"] = 0.6
                result["reason"] += ", but domain validation failed"
        else:
            # Basic regex validation
            if re.match(r'^[a-zA-Z0-9._%+-]+@[a-zA-Z0-9.-]+\.[a-zA-Z]{2,}$', email):
                result["valid"] = True
                result["confidence"] = 0.7
                result["reason"] = "Basic email validation passed"
                
                # Extract domain part
                domain = email.split('@')[-1]
                result["metadata"]["domain"] = domain
            else:
                result["reason"] = "Invalid email format"
        
        # Use LLM for additional validation if confidence is low
        if self.use_llm and result["confidence"] < 0.8:
            llm_result = self._validate_with_llm(email, "email")
            
            # Only update if LLM has higher confidence
            if llm_result["confidence"] > result["confidence"]:
                result.update(llm_result)
                # Keep metadata from our validation
                result["metadata"].update(llm_result.get("metadata", {}))
        
        return result
    
    def _detect_string_type(self, string_value: str) -> str:
        """
        Detect the type of a string based on its format
        
        Args:
            string_value: String to analyze
            
        Returns:
            Detected string type
        """
        # URL detection
        if string_value.startswith(('http://', 'https://')):
            return "url"
        
        # IP address detection
        if re.match(r'^\d{1,3}\.\d{1,3}\.\d{1,3}\.\d{1,3}(:\d+)?$', string_value):
            return "ip"
        
        # Email detection
        if '@' in string_value and '.' in string_value.split('@')[-1]:
            return "email"
        
        # Path detection
        if re.match(r'^[a-zA-Z]:\\', string_value) or string_value.startswith('/') or \
           string_value.startswith('./') or string_value.startswith('../'):
            return "path"
        
        # Hash detection
        if _is_likely_hash(string_value):
            return "hash"
        
        # Key detection
        if _is_likely_key(string_value):
            return "key"
        
        # Domain detection - check after others to avoid false positives
        if '.' in string_value and not ' ' in string_value:
            parts = string_value.split('.')
            if len(parts) >= 2 and all(re.match(r'^[a-zA-Z0-9-]+$', part) for part in parts):
                return "domain"
        
        return "general"
    
    def _validate_with_llm(self, string_value: str, string_type: Optional[str] = None) -> Dict[str, Any]:
        """
        Use LLM to validate a string
        
        Args:
            string_value: String to validate
            string_type: Optional type hint
            
        Returns:
            Validation result dictionary
        """
        type_prompt = f" as a {string_type}" if string_type else ""
        
        system_prompt = """You are a string validation expert. Analyze the provided string and determine if it's valid
        based on its format and content. Provide a confidence score and reasoning."""
        
        user_prompt = f"""Analyze this string{type_prompt} and determine if it's valid:
        
        String: {string_value}
        
        Return a JSON object with:
        1. "valid": boolean indicating if the string is valid
        2. "type": the detected type of string (url, domain, ip, path, hash, key, email, general)
        3. "confidence": a score between 0.0 and 1.0 indicating your confidence
        4. "reason": a brief explanation of your decision
        5. "metadata": any additional information about the string (e.g., for URLs: domain, path, etc.)
        """
        
        try:
            response = llm_handler.get_json_response(system_prompt, user_prompt)
            
            # Ensure required fields are present
            result = {
                "valid": response.get("valid", False),
                "type": response.get("type", string_type or "general"),
                "confidence": response.get("confidence", 0.5),
                "reason": response.get("reason", "LLM validation"),
                "metadata": response.get("metadata", {})
            }
            
            return result
        except Exception as e:
            print(f"LLM validation failed: {e}")
            
            # Return a basic result on failure
            return {
                "valid": _is_meaningful_string(string_value),
                "type": string_type or "general",
                "confidence": 0.5,
                "reason": "LLM validation failed, using basic validation",
                "metadata": {}
            }


class SmartStringAnalyzer:
    """
    Advanced string analyzer that uses LLM to filter and categorize strings
    from binary files or other sources.
    """
    
    def __init__(self, use_llm: bool = True, batch_size: int = 50):
        """
        Initialize the smart string analyzer
        
        Args:
            use_llm: Whether to use LLM for analysis
            batch_size: Number of strings to analyze in each LLM batch
        """
        self.use_llm = use_llm
        self.batch_size = batch_size
        self.validator = SmartStringValidator(use_llm=use_llm)
    
    def analyze_strings(self, strings: List[str]) -> Dict[str, Any]:
        """
        Analyze a list of strings and categorize them
        
        Args:
            strings: List of strings to analyze
            
        Returns:
            Dictionary with categorized strings:
            {
                "valid": {
                    "urls": [],
                    "domains": [],
                    "ip_addresses": [],
                    "paths": [],
                    "emails": [],
                    "hashes": [],
                    "keys": [],
                    "general": []
                },
                "invalid": {
                    "urls": [],
                    "domains": [],
                    "ip_addresses": [],
                    "paths": [],
                    "emails": [],
                    "hashes": [],
                    "keys": [],
                    "general": []
                },
                "metadata": {
                    "string_id": {
                        "validation_result": {}
                    }
                }
            }
        """
        result = {
            "valid": {
                "urls": [],
                "domains": [],
                "ip_addresses": [],
                "paths": [],
                "emails": [],
                "hashes": [],
                "keys": [],
                "general": []
            },
            "invalid": {
                "urls": [],
                "domains": [],
                "ip_addresses": [],
                "paths": [],
                "emails": [],
                "hashes": [],
                "keys": [],
                "general": []
            },
            "metadata": {}
        }
        
        # Filter out empty or very short strings
        filtered_strings = [s for s in strings if isinstance(s, str) and len(s) >= 3]
        
        # First pass: use regex and basic validation
        for string_id, s in enumerate(filtered_strings):
            # Skip if not meaningful
            if not _is_meaningful_string(s):
                continue
            
            # Validate the string
            validation_result = self.validator.validate_string(s)
            
            # Store metadata
            result["metadata"][string_id] = {
                "validation_result": validation_result
            }
            
            # Categorize based on validation result
            string_type = validation_result["type"]
            if string_type not in result["valid"]:
                string_type = "general"
            
            # Add to appropriate category
            if validation_result["valid"] and validation_result["confidence"] >= self.validator.confidence_threshold:
                result["valid"][string_type].append(s)
            else:
                result["invalid"][string_type].append(s)
        
        # Second pass: use LLM for batch analysis of uncategorized strings
        if self.use_llm:
            # Get strings that weren't confidently categorized
            uncertain_strings = []
            uncertain_ids = []
            
            for string_id, metadata in result["metadata"].items():
                validation_result = metadata["validation_result"]
                if validation_result["confidence"] < self.validator.confidence_threshold:
                    string_id = int(string_id)
                    if string_id < len(filtered_strings):
                        uncertain_strings.append(filtered_strings[string_id])
                        uncertain_ids.append(string_id)
            
            # Process in batches
            for i in range(0, len(uncertain_strings), self.batch_size):
                batch = uncertain_strings[i:i+self.batch_size]
                batch_ids = uncertain_ids[i:i+self.batch_size]
                
                # Analyze batch with LLM
                batch_results = self._analyze_batch_with_llm(batch)
                
                # Update results
                for j, batch_result in enumerate(batch_results):
                    string_id = batch_ids[j]
                    string_value = batch[j]
                    
                    # Update metadata
                    result["metadata"][string_id]["validation_result"] = batch_result
                    
                    # Recategorize
                    string_type = batch_result["type"]
                    if string_type not in result["valid"]:
                        string_type = "general"
                    
                    # Remove from previous category if present
                    for category in ["valid", "invalid"]:
                        for type_key in result[category]:
                            if string_value in result[category][type_key]:
                                result[category][type_key].remove(string_value)
                    
                    # Add to new category
                    if batch_result["valid"] and batch_result["confidence"] >= self.validator.confidence_threshold:
                        result["valid"][string_type].append(string_value)
                    else:
                        result["invalid"][string_type].append(string_value)
        
        # Deduplicate results
        for category in ["valid", "invalid"]:
            for type_key in result[category]:
                result[category][type_key] = list(set(result[category][type_key]))
        
        return result
    
    def _analyze_batch_with_llm(self, strings: List[str]) -> List[Dict[str, Any]]:
        """
        Use LLM to analyze a batch of strings
        
        Args:
            strings: List of strings to analyze
            
        Returns:
            List of validation results for each string
        """
        system_prompt = """You are a string validation expert. Analyze the provided strings and determine if each is valid
        based on its format and content. Provide a confidence score and reasoning for each."""
        
        user_prompt = f"""Analyze these strings and determine if each is valid:
        
        Strings:
        {json.dumps(strings, indent=2)}
        
        For each string, return a JSON object with:
        1. "valid": boolean indicating if the string is valid
        2. "type": the detected type of string (url, domain, ip, path, hash, key, email, general)
        3. "confidence": a score between 0.0 and 1.0 indicating your confidence
        4. "reason": a brief explanation of your decision
        5. "metadata": any additional information about the string
        
        Return a JSON array with one object per string, in the same order as the input strings.
        """
        
        try:
            response = llm_handler.get_json_response(system_prompt, user_prompt)
            
            # Handle different response formats
            if isinstance(response, list):
                results = response
            elif "results" in response:
                results = response["results"]
            else:
                # Create a default response for each string
                results = []
                for s in strings:
                    string_type = self.validator._detect_string_type(s)
                    results.append({
                        "valid": _is_meaningful_string(s),
                        "type": string_type,
                        "confidence": 0.5,
                        "reason": "Default validation due to LLM response format issue",
                        "metadata": {}
                    })
            
            # Ensure we have a result for each string
            if len(results) < len(strings):
                # Pad with default results
                for i in range(len(results), len(strings)):
                    s = strings[i]
                    string_type = self.validator._detect_string_type(s)
                    results.append({
                        "valid": _is_meaningful_string(s),
                        "type": string_type,
                        "confidence": 0.5,
                        "reason": "Default validation (missing from LLM response)",
                        "metadata": {}
                    })
            
            return results[:len(strings)]  # Ensure we don't return more results than strings
            
        except Exception as e:
            print(f"LLM batch analysis failed: {e}")
            
            # Return basic results on failure
            results = []
            for s in strings:
                string_type = self.validator._detect_string_type(s)
                results.append({
                    "valid": _is_meaningful_string(s),
                    "type": string_type,
                    "confidence": 0.5,
                    "reason": f"LLM batch analysis failed: {str(e)}",
                    "metadata": {}
                })
            
            return results


def filter_valid_strings(strings: List[str], use_llm: bool = True) -> Dict[str, List[str]]:
    """
    Filter a list of strings into valid and invalid categories
    
    Args:
        strings: List of strings to filter
        use_llm: Whether to use LLM for validation
        
    Returns:
        Dictionary with valid and invalid strings by category
    """
    analyzer = SmartStringAnalyzer(use_llm=use_llm)
    return analyzer.analyze_strings(strings)


def filter_valid_urls(urls: List[str], use_llm: bool = True) -> Tuple[List[str], List[str]]:
    """
    Filter a list of URLs into valid and invalid categories
    
    Args:
        urls: List of URLs to filter
        use_llm: Whether to use LLM for validation
        
    Returns:
        Tuple of (valid_urls, invalid_urls)
    """
    validator = SmartStringValidator(use_llm=use_llm)
    valid_urls = []
    invalid_urls = []
    
    for url in urls:
        result = validator.validate_url(url)
        if result["valid"] and result["confidence"] >= validator.confidence_threshold:
            valid_urls.append(url)
        else:
            invalid_urls.append(url)
    
    return valid_urls, invalid_urls


def filter_valid_domains(domains: List[str], use_llm: bool = True) -> Tuple[List[str], List[str]]:
    """
    Filter a list of domains into valid and invalid categories
    
    Args:
        domains: List of domains to filter
        use_llm: Whether to use LLM for validation
        
    Returns:
        Tuple of (valid_domains, invalid_domains)
    """
    validator = SmartStringValidator(use_llm=use_llm)
    valid_domains = []
    invalid_domains = []
    
    for domain in domains:
        result = validator.validate_domain(domain)
        if result["valid"] and result["confidence"] >= validator.confidence_threshold:
            valid_domains.append(domain)
        else:
            invalid_domains.append(domain)
    
    return valid_domains, invalid_domains


def filter_valid_ips(ips: List[str], use_llm: bool = True) -> Tuple[List[str], List[str]]:
    """
    Filter a list of IP addresses into valid and invalid categories
    
    Args:
        ips: List of IP addresses to filter
        use_llm: Whether to use LLM for validation
        
    Returns:
        Tuple of (valid_ips, invalid_ips)
    """
    validator = SmartStringValidator(use_llm=use_llm)
    valid_ips = []
    invalid_ips = []
    
    for ip in ips:
        result = validator.validate_ip(ip)
        if result["valid"] and result["confidence"] >= validator.confidence_threshold:
            valid_ips.append(ip)
        else:
            invalid_ips.append(ip)
    
    return valid_ips, invalid_ips


def get_string_validation_details(string_value: str, string_type: Optional[str] = None, use_llm: bool = True) -> Dict[str, Any]:
    """
    Get detailed validation information for a string
    
    Args:
        string_value: String to validate
        string_type: Optional type hint
        use_llm: Whether to use LLM for validation
        
    Returns:
        Validation result dictionary
    """
    validator = SmartStringValidator(use_llm=use_llm)
    return validator.validate_string(string_value, string_type)


if __name__ == "__main__":
    # Example usage
    test_strings = [
        "https://www.example.com/path?query=value",
        "invalid-url",
        "example.com",
        "not a domain",
        "192.168.1.1",
        "999.999.999.999",
        "/usr/local/bin/python",
        "C:\\Windows\\System32\\cmd.exe",
        "5f4dcc3b5aa765d61d8327deb882cf99",  # MD5 hash
        "api_key_12345",
        "sk-1234567890abcdefghijklmnopqrstuvwxyzABCDEFGHIJKLMN",  # OpenAI-like API key
        "user@example.com",
        "This is just a regular string with no special meaning."
    ]
    
    print("Analyzing test strings...")
    results = filter_valid_strings(test_strings)
    
    print("\nValid strings:")
    for category, strings in results["valid"].items():
        if strings:
            print(f"  {category}:")
            for s in strings:
                print(f"    - {s}")
    
    print("\nInvalid strings:")
    for category, strings in results["invalid"].items():
        if strings:
            print(f"  {category}:")
            for s in strings:
                print(f"    - {s}")
    
    # Example of getting detailed validation for a specific string
    print("\nDetailed validation for a URL:")
    url = "https://www.example.com/path?query=value"
    details = get_string_validation_details(url, "url")
    print(json.dumps(details, indent=2))