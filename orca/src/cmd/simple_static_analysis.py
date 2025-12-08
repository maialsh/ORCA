"""
Simple Static Analysis Module for BinSleuth
Provides basic binary analysis without requiring Binary Ninja
"""
import os
import subprocess
import hashlib
import sys
import re
import time
import json
from pathlib import Path
from typing import Dict, List, Any, Optional

class SimpleStaticAnalyzer:
    """
    Simple static analysis for binary files without Binary Ninja dependency
    """
    def __init__(self):
        """Initialize the analyzer"""
        # Minimum string length for extraction
        self.min_string_length = 4
        
        # Regex for identifying normal words or sentences
        self.normal_text_pattern = re.compile(r'^[A-Za-z0-9\s.,;:!?\'"-_()[\]{}@#$%^&*+=<>/\\|~`]+$')
        
        # Regex for identifying library files
        self.library_file_pattern = re.compile(r'.*\.(so|dylib|dll|a|lib|framework)(\.\d+)*$', re.IGNORECASE)

    def analyze(self, file_path: Path) -> Dict[str, Any]:
        """
        Main analysis entry point
        
        Args:
            file_path: Path to the binary file
            
        Returns:
            Dictionary containing analysis results
        """
        if not file_path.exists():
            raise FileNotFoundError(f"File not found: {file_path}")
        
        # Initialize results structure
        results = {
            "file_info": self._get_file_info(file_path),
            "strings": self._extract_and_analyze_strings(file_path),
            "imports": self._extract_imports(file_path),
            "exports": [],
            "sections": [],
            "functions": [],
            "behavior": {},
            "linux_checks": {},
            "analysis_summary": {}
        }
        
        return results

    def _get_file_info(self, file_path: Path) -> Dict[str, Any]:
        """
        Get comprehensive file information
        
        Args:
            file_path: Path to the binary file
            
        Returns:
            Dictionary containing file information
        """
        # Calculate file hash
        with open(file_path, "rb") as f:
            file_hash = hashlib.sha256(f.read()).hexdigest()
        
        # Get file type using 'file' command
        file_type = subprocess.run(
            ['file', str(file_path)],
            capture_output=True, text=True
        ).stdout.strip()
        
        # Get file permissions
        permissions = oct(os.stat(file_path).st_mode)[-3:]
        
        # Check if file is executable
        is_executable = os.access(file_path, os.X_OK)
        
        return {
            "path": str(file_path),
            "name": file_path.name,
            "size": os.path.getsize(file_path),
            "sha256": file_hash,
            "md5": self._get_md5(file_path),
            "type": file_type,
            "permissions": permissions,
            "is_executable": is_executable,
            "created": time.ctime(os.path.getctime(file_path)),
            "modified": time.ctime(os.path.getmtime(file_path))
        }
    
    def _get_md5(self, file_path: Path) -> str:
        """
        Calculate MD5 hash of a file
        
        Args:
            file_path: Path to the file
            
        Returns:
            MD5 hash as a string
        """
        with open(file_path, "rb") as f:
            return hashlib.md5(f.read()).hexdigest()
    
    def _extract_and_analyze_strings(self, file_path: Path) -> Dict[str, List[str]]:
        """
        Extract and analyze strings from the binary
        
        Args:
            file_path: Path to the binary file
            
        Returns:
            Dictionary containing categorized strings
        """
        # Extract strings using the 'strings' command
        try:
            strings_output = subprocess.run(
                ['strings', '-n', str(self.min_string_length), str(file_path)],
                capture_output=True, text=True
            ).stdout.strip().split('\n')
        except Exception as e:
            print(f"Error extracting strings: {str(e)}")
            strings_output = []
        
        return self._string_analysis(strings_output)
    
    def _string_analysis(self, strings: List[str]) -> Dict[str, List[str]]:
        """
        Analyze strings extracted from the binary
        
        Args:
            strings: List of strings extracted from the binary
            
        Returns:
            Dictionary containing categorized strings
        """
        results = {
            "apis": [],
            "urls": [],
            "registry": [],
            "ip_addresses": [],
            "domains": [],
            "library_paths": [],
            "commands": [],
            "emails": [],
            "suspicious": [],
            "user_agents": [],
        }
        
        # Regex patterns for various types of strings
        patterns = {
            "win32_apis": re.compile(r'\b(?:Create|Open|Close|Read|Write|Delete|Set|Get|Find|Enum|Reg)[A-Za-z]+\b'),
            "linux_apis": re.compile(r'\b(?:sys_|_syscall|socket|open|read|write|exec|fork|ioctl|mmap)\b'),
            "urls": re.compile(r'https?://(?:[-\w.]|(?:%[\da-fA-F]{2}))+[/\w .?=&%-]*'),
            "registry": re.compile(r'HKEY_[A-Z_]+\\[\\\w-]+(?:\\[\\\w-]+)*'),
            "ip_addresses": re.compile(r'\b\d{1,3}\.\d{1,3}\.\d{1,3}\.\d{1,3}(?::\d+)?\b'),
            "domains": re.compile(r'\b(?:[a-zA-Z0-9-]+\.)+[a-zA-Z]{2,}\b'),
            "paths": re.compile(r'(?:[a-zA-Z]:\\\\|/|\./|\.\./)(?:[^/\0\n\r]+[/\\])+[^/\0\n\r]*'),
            "emails": re.compile(r'\b[A-Za-z0-9._%+-]+@[A-Za-z0-9.-]+\.[A-Z|a-z]{2,}\b'),
            "commands": re.compile(r'\b(?:cmd\.exe|powershell|bash|sh|python|perl|ruby|wget|curl|nc|netcat)\b.*'),
            "user_agents": re.compile(r'Mozilla/\d\.\d|Chrome/\d+|Safari/\d+|Firefox/\d+|MSIE \d+|Opera/\d+'),
            "suspicious": re.compile(r'\b(?:secret|key|password|admin|backdoor|exploit|vulnerability|malware|inject|payload|shell|root|admin|hack|crack|bypass)\b', re.I)
        }
        
        # Analyze each string
        for s in strings:
            if not isinstance(s, str) or len(s) < 3:
                continue
                
            # Only process strings that look like normal text
            if self.normal_text_pattern.match(s):
                
                # Check for Windows APIs
                if matches := patterns["win32_apis"].findall(s):
                    results["apis"].extend(matches)
    
                # Check for Linux APIs
                if matches := patterns["linux_apis"].findall(s):
                    results["apis"].extend(matches)
    
                # Check for URLs
                if matches := patterns["urls"].findall(s):
                    results["urls"].extend(matches)
    
                # Check for registry keys
                if matches := patterns["registry"].findall(s):
                    results["registry"].extend(matches)
    
                # Check for IP addresses
                if matches := patterns["ip_addresses"].findall(s):
                    results["ip_addresses"].extend(matches)
    
                # Check for domains
                if matches := patterns["domains"].findall(s):
                    results["domains"].extend(matches)
                    
                # Check for emails
                if matches := patterns["emails"].findall(s):
                    results["emails"].extend(matches)
                    
                # Check for commands
                if matches := patterns["commands"].findall(s):
                    results["commands"].extend(matches)
                    
                # Check for user agents
                if matches := patterns["user_agents"].findall(s):
                    results["user_agents"].extend(matches)
                    
                # Check for suspicious strings
                if matches := patterns["suspicious"].findall(s):
                    results["suspicious"].extend(matches)
            
            # Check for library paths separately (these might not match normal text pattern)
            if matches := patterns["paths"].findall(s):
                for path in matches:
                    if self.library_file_pattern.match(path):
                        results["library_paths"].append(path)
                
        # Remove duplicates while preserving order
        for key in results:
            if isinstance(results[key], list):
                results[key] = list(dict.fromkeys(results[key]))
                
        return results
    
    def _extract_imports(self, file_path: Path) -> List[str]:
        """
        Extract imported symbols using 'nm' command
        
        Args:
            file_path: Path to the binary file
            
        Returns:
            List of imported symbol names
        """
        imports = []
        
        try:
            # Try using 'nm' command to extract symbols
            nm_output = subprocess.run(
                ['nm', '-D', str(file_path)],
                capture_output=True, text=True
            ).stdout.strip()
            
            # Parse nm output
            for line in nm_output.split('\n'):
                if 'U ' in line:  # Undefined symbols are imports
                    parts = line.strip().split(' ')
                    if len(parts) >= 2:
                        symbol = parts[-1]
                        imports.append(symbol)
        except Exception as e:
            print(f"Error extracting imports: {str(e)}")
        
        return imports
