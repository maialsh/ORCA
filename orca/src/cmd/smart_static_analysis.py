"""
Smart Static Analysis Module for BinSleuth
Utilizes Binary Ninja API to extract features from binary files
and uses LLM to enhance analysis capabilities
"""
import os
import subprocess
import hashlib
import sys
import re
import time
import math
import json
import platform
from itertools import islice
from typing import List, Dict, Any, Iterable, Optional, Tuple, Set
from pathlib import Path

# Check for Binary Ninja API
BINARY_NINJA_PATH = "/Applications/Binary Ninja.app/Contents/Resources/python"
if os.path.exists(BINARY_NINJA_PATH):
    sys.path.insert(0, BINARY_NINJA_PATH)
else:
    print(f"Warning: Binary Ninja python API not found in expected folder: {BINARY_NINJA_PATH}")
    print("Will attempt to continue, but some functionality may be limited.")

# Import Binary Ninja components
import binaryninja as bn
from binaryninja import BinaryView, SymbolType, Section, SectionSemantics

# Import BinSleuth modules
from utils import batched, _clean_json
from config import config
from llm_module import llm_handler
from sandbox import DockerSandbox


class SmartStaticAnalyzer:
    """
    Enhanced static analysis for binary files with LLM integration
    Extracts and analyzes features from binary files using Binary Ninja API
    """
    def __init__(self, llm_model: Optional[str] = None, llm_api_base: Optional[str] = None):
        """
        Initialize the analyzer with configuration
        
        Args:
            llm_model: Optional override for LLM model
            llm_api_base: Optional override for LLM API base URL
        """
        # Use config or override with parameters
        self.llm_model = llm_model or config.get('llm.model')
        self.temp_all_strings = []
        self.llm_api_base = llm_api_base or config.get('llm.api_base')
        
        # Load behavior patterns from config
        self.core_patterns = config.get('behavior_patterns', {})
        
        # Additional pattern lists
        self.backdoor_indicators = [
            "backdoor", "shell", "rootkit", "hidden", "secret",
            "password", "login", "command", "connect_back",
            "reverse_shell", "bind_shell", "port_knocking",
            "telnet", "netcat", "nc", "socat", "tunnel"
        ]
        
        self.linux_persistence_locations = [
            "/etc/rc.local", "/etc/cron.", "/etc/systemd/",
            "~/.bashrc", "~/.profile", "~/.config/autostart",
            "/etc/init.d/", "/etc/profile.d/", "/lib/systemd/",
            "/usr/lib/systemd/", "/etc/xdg/autostart/", 
            "/var/spool/cron/", "/etc/crontab", "/etc/anacrontab"
        ]
        
        # Cache for LLM-generated patterns
        self.llm_pattern_cache = {}
        
        # Minimum string length for extraction
        self.min_string_length = config.get('analysis.extract_strings_min_length', 4)
        
        # Regex for identifying normal words or sentences
        self.normal_text_pattern = re.compile(r'^[A-Za-z0-9\s.,;:!?\'"-_()[\]{}@#$%^&*+=<>/\\|~`]+$')
        
        # Regex for identifying library files
        self.library_file_pattern = re.compile(r'.*\.(so|dylib|dll|a|lib|framework)(\.\d+)*$', re.IGNORECASE)

    def analyze(self, file_path: Path, use_llm: bool = True) -> Dict[str, Any]:
        """
        Main analysis entry point with LLM integration
        
        Args:
            file_path: Path to the binary file
            use_llm: Whether to use LLM for enhanced analysis
            
        Returns:
            Dictionary containing analysis results
        """
        if not file_path.exists():
            raise FileNotFoundError(f"File not found: {file_path}")
        
        # Initialize results structure
        results = {
            "file_info": self._get_file_info(file_path),
            "strings": {},
            "imports": [],
            "exports": [],
            "sections": [],
            "functions": [],
            "behavior": {},
            "linux_checks": {},
            "analysis_summary": {}
        }
        
        try:
            with bn.load(str(file_path)) as bv:
                # Extract basic features
                bv.update_analysis_and_wait()
                strings = self._extract_strings(bv)
                results["strings"] = self._string_analysis(strings)
                results["imports"] = self._clean_import_names(self._get_imports(bv))
                results["exports"] = self._get_exports(bv)
                results["sections"] = self._get_sections(bv)
                results["functions"] = self._analyze_functions(bv)
                results["bv"] = bv
                
                # Get behavior patterns (from LLM if enabled)
                if use_llm:
                    results["behavior"] = self._get_llm_behavior_patterns()
                else:
                    results["behavior"] = self.core_patterns
                
                # Perform Linux-specific checks
                results["linux_checks"] = self._perform_linux_checks(bv, results)
                
                # LLM-enhanced analysis if enabled
                if use_llm:
                    results["analysis_summary"] = self._perform_llm_analysis(results)
                
        except Exception as e:
            print(f"Analysis failed: {str(e)}")
            results["error"] = f"Analysis failed: {str(e)}"
            
        return results

    def _get_llm_behavior_patterns(self) -> Dict[str, List[str]]:
        """
        Get expanded behavior patterns from LLM
        
        Returns:
            Dictionary of behavior patterns by category
        """
        # Return cached patterns if available
        if "behavior_patterns" in self.llm_pattern_cache:
            return self.llm_pattern_cache["behavior_patterns"]
        
        try:
            # Use the LLM handler to get behavior patterns
            patterns = llm_handler.get_behavior_patterns()
            self.llm_pattern_cache["behavior_patterns"] = patterns
            return patterns
        except Exception as e:
            print(f"LLM pattern generation failed: {str(e)}")
            return self.core_patterns  # Fallback to core patterns

    def _perform_llm_analysis(self, results: Dict[str, Any]) -> Dict[str, Any]:
        """
        Perform LLM-enhanced analysis on extracted features
        Only analyzes imports as per requirements
        
        Args:
            results: Dictionary containing analysis results
            
        Returns:
            Dictionary containing LLM analysis results
        """
        llm_analysis = {}
        
        try:
            # Only analyze imports
            if results.get("imports"):
                print("Analyzing imports with LLM...")
                llm_analysis["imports_analysis"] = llm_handler.analyze_binary_behavior(
                    {"imports": results["imports"]}, "imports"
                )
            
        except Exception as e:
            print(f"LLM analysis failed: {str(e)}")
            llm_analysis["error"] = f"LLM analysis failed: {str(e)}"
        
        return llm_analysis

    def _analyze_functions(self, bv: BinaryView) -> List[Dict]:
        """
        Analyze functions with both algorithmic and LLM-enhanced detection
        
        Args:
            bv: Binary Ninja BinaryView object
            
        Returns:
            List of dictionaries containing function analysis results
        """
        functions = []
        llm_patterns = self._get_llm_behavior_patterns()
        
        # Limit the number of functions to analyze if there are too many
        max_functions = config.get('analysis.max_functions_to_analyze', 1000)
        function_list = list(bv.functions)
        if len(function_list) > max_functions:
            print(f"Limiting analysis to {max_functions} functions out of {len(function_list)}")
            function_list = function_list[:max_functions]
        
        for func in function_list:
            # Get basic function information
            callers = [caller.name for caller in func.callers]
            callees = [callee.name for callee in func.callees]
            
            # Get function parameters and return type if available
            parameters = []
            try:
                for param in func.parameter_vars:
                    parameters.append({
                        "name": param.name,
                        "type": str(param.type) if param.type else "unknown"
                    })
            except:
                pass  # Parameter information might not be available
            
            # Create function info dictionary
            func_info = {
                "name": func.name,
                "address": hex(func.start),
                "size": func.total_bytes,
                "callers": callers,
                "callees": callees,
                "parameters": parameters,
                "is_library_function": func.symbol.type == SymbolType.LibraryFunctionSymbol if func.symbol else False,
                "behavior": self._analyze_function_behavior(func, llm_patterns)
            }
            
            # Add function to results
            functions.append(func_info)
            
        return functions

    def _analyze_function_behavior(self, func, llm_patterns: Dict) -> List[Dict]:
        """
        Enhanced behavior analysis using expanded patterns
        
        Args:
            func: Binary Ninja Function object
            llm_patterns: Dictionary of behavior patterns by category
            
        Returns:
            List of dictionaries containing behavior analysis results
        """
        behavior = []
        
        # Combine core patterns with LLM patterns
        all_patterns = {**self.core_patterns, **llm_patterns}
        
        # Analyze each instruction in the function
        for block in func:
            for insn in block:
                disasm = str(insn)
              
                
                # Check against all patterns
                for category, patterns in all_patterns.items():
                    if any(re.search(pattern, disasm, re.IGNORECASE) for pattern in patterns):
                        behavior.append({
                            "type": category,
                            "instruction": disasm
                        })
                        break  # Only categorize once per instruction
                
                # Check for backdoor indicators
                if any(re.search(indicator, disasm, re.IGNORECASE) for indicator in self.backdoor_indicators):
                    behavior.append({
                        "type": "backdoor",
                        "instruction": disasm
                    })
        
        return behavior

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
        
        # Get ELF information if applicable
        elf_info = self._get_elf_info(file_path)
        
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
            "modified": time.ctime(os.path.getmtime(file_path)),
            "elf_info": elf_info
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
    
    def _get_elf_info(self, file_path: Path) -> Dict[str, Any]:
        """
        Extract comprehensive ELF header information
        
        Args:
            file_path: Path to the ELF file
            
        Returns:
            Dictionary containing ELF information
        """
        elf_info = {
            "header": {},
            "program_headers": [],
            "section_headers": [],
            "dynamic": [],
            "symbols": []
        }
        
        # Check if we're on macOS
        is_macos = platform.system() == "Darwin"
        
        try:
            if is_macos:
                # Use Docker sandbox for macOS
                return self._get_elf_info_docker(file_path)
            else:
                # Use native readelf on Linux
                return self._get_elf_info_native(file_path)
        except Exception as e:
            print(f"Error getting ELF info: {str(e)}")
            return elf_info
            
    def _get_elf_info_native(self, file_path: Path) -> Dict[str, Any]:
        """
        Extract ELF information using native readelf command
        
        Args:
            file_path: Path to the ELF file
            
        Returns:
            Dictionary containing ELF information
        """
        elf_info = {
            "header": {},
            "program_headers": [],
            "section_headers": [],
            "dynamic": [],
            "symbols": []
        }
        
        try:
            # Get ELF header
            header_result = subprocess.run(
                ['readelf', '-h', str(file_path)],
                capture_output=True, text=True
            )
            
            if header_result.returncode == 0:
                for line in header_result.stdout.split('\n'):
                    if ':' in line:
                        key, value = line.split(':', 1)
                        elf_info["header"][key.strip()] = value.strip()
            
            # Get program headers
            ph_result = subprocess.run(
                ['readelf', '-l', str(file_path)],
                capture_output=True, text=True
            )
            
            if ph_result.returncode == 0:
                elf_info["program_headers"] = ph_result.stdout
            
            # Get section headers
            sh_result = subprocess.run(
                ['readelf', '-S', str(file_path)],
                capture_output=True, text=True
            )
            
            if sh_result.returncode == 0:
                elf_info["section_headers"] = sh_result.stdout
            
            # Get dynamic section
            dyn_result = subprocess.run(
                ['readelf', '-d', str(file_path)],
                capture_output=True, text=True
            )
            
            if dyn_result.returncode == 0:
                elf_info["dynamic"] = dyn_result.stdout
            
            # Get symbols
            sym_result = subprocess.run(
                ['readelf', '-s', str(file_path)],
                capture_output=True, text=True
            )
            
            if sym_result.returncode == 0:
                elf_info["symbols"] = sym_result.stdout
            
            return elf_info
        except Exception as e:
            print(f"Error getting ELF info with native readelf: {str(e)}")
            return elf_info
            
    def _get_elf_info_docker(self, file_path: Path) -> Dict[str, Any]:
        """
        Extract ELF information using Docker sandbox with readelf
        
        Args:
            file_path: Path to the ELF file
            
        Returns:
            Dictionary containing ELF information
        """
        elf_info = {
            "header": {},
            "program_headers": [],
            "section_headers": [],
            "dynamic": [],
            "symbols": []
        }
        
        try:
            # Initialize Docker sandbox
            sandbox = DockerSandbox()
            error = sandbox.start(str(file_path))
            
            if error:
                print(f"Error starting Docker sandbox: {error}")
                return elf_info
                
            try:
                # Run readelf commands in Docker container
                
                # Get ELF header
                exit_code, header_output = sandbox.container.exec_run(
                    f"readelf -h /tmp/sample", 
                    privileged=False
                )
                
                if exit_code == 0:
                    header_text = header_output.decode('utf-8', errors='ignore')
                    for line in header_text.split('\n'):
                        if ':' in line:
                            key, value = line.split(':', 1)
                            elf_info["header"][key.strip()] = value.strip()
                
                # Get program headers
                exit_code, ph_output = sandbox.container.exec_run(
                    f"readelf -l /tmp/sample", 
                    privileged=False
                )
                
                if exit_code == 0:
                    elf_info["program_headers"] = ph_output.decode('utf-8', errors='ignore')
                
                # Get section headers
                exit_code, sh_output = sandbox.container.exec_run(
                    f"readelf -S /tmp/sample", 
                    privileged=False
                )
                
                if exit_code == 0:
                    elf_info["section_headers"] = sh_output.decode('utf-8', errors='ignore')
                
                # Get dynamic section
                exit_code, dyn_output = sandbox.container.exec_run(
                    f"readelf -d /tmp/sample", 
                    privileged=False
                )
                
                if exit_code == 0:
                    elf_info["dynamic"] = dyn_output.decode('utf-8', errors='ignore')
                
                # Get symbols
                exit_code, sym_output = sandbox.container.exec_run(
                    f"readelf -s /tmp/sample", 
                    privileged=False
                )
                
                if exit_code == 0:
                    elf_info["symbols"] = sym_output.decode('utf-8', errors='ignore')
                
            finally:
                # Clean up Docker container
                sandbox.cleanup()
                
            return elf_info
            
        except Exception as e:
            print(f"Error getting ELF info with Docker: {str(e)}")
            return elf_info

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
    
    def _extract_strings(self, bv: BinaryView) -> List[str]:
        """
        Extract strings from binary
        
        Args:
            bv: Binary Ninja BinaryView object
            
        Returns:
            List of strings extracted from the binary
        """
        extracted_strings = [string.value for string in bv.strings if len(string.value) >= self.min_string_length]
        self.temp_all_strings = extracted_strings
        return extracted_strings

    def _clean_import_names(self, imports: List[str]) -> List[str]:
        """
        Clean import names by removing leading underscores
        
        Args:
            imports: List of import names
            
        Returns:
            List of cleaned import names
        """
        cleaned_imports = []
        
        for imp in imports:
            # Remove leading underscore if present
            if imp.startswith('_'):
                cleaned_imports.append(imp[1:])
            else:
                cleaned_imports.append(imp)
                
        return cleaned_imports

    def _get_imports(self, bv: BinaryView) -> List[str]:
        """
        Get imported symbols using Binary Ninja API
        
        Args:
            bv: Binary Ninja BinaryView object
            
        Returns:
            List of imported symbol names
        """
        imports = []
        for sym in bv.get_symbols():
            if sym.type in [SymbolType.ImportedFunctionSymbol, 
                          SymbolType.ImportedDataSymbol,
                          SymbolType.LibraryFunctionSymbol]:
                imports.append(sym.name)
        return imports

    def _get_exports(self, bv: BinaryView) -> List[str]:
        """
        Get exported functions using Binary Ninja API
        
        Args:
            bv: Binary Ninja BinaryView object
            
        Returns:
            List of exported symbol names
        """
        exports = []
        for sym in bv.get_symbols():
            if sym.type in [SymbolType.FunctionSymbol, SymbolType.DataSymbol]:
                exports.append(sym.name)
        return exports
    
    def _get_sections(self, bv: BinaryView) -> List[Dict[str, Any]]:
        """
        Get binary sections using Binary Ninja API
        
        Args:
            bv: Binary Ninja BinaryView object
            
        Returns:
            List of dictionaries containing section information
        """
        sections = []
        
        for section in bv.sections.values():
            section_info = {
                "name": section.name,
                "start": hex(section.start),
                "end": hex(section.end),
                "length": section.length,
                "semantics": str(section.semantics),
                "type": str(section.type),
                "align": section.align,
                "entry_size": section.entry_size,
                "is_readable": getattr(section, 'readable', False),
                "is_writable": getattr(section, 'writable', False),
                "is_executable": getattr(section, 'executable', False),
                "is_code": section.semantics == SectionSemantics.ReadOnlyCodeSectionSemantics,
                "is_data": section.semantics in [
                    SectionSemantics.ReadOnlyDataSectionSemantics,
                    SectionSemantics.ReadWriteDataSectionSemantics
                ]
            }
            
            # Calculate entropy if section is not too large
            if section.length <= 10 * 1024 * 1024:  # 10MB limit
                try:
                    data = bv.read(section.start, section.length)
                    section_info["entropy"] = self._calculate_entropy(data)
                except:
                    section_info["entropy"] = None
            else:
                section_info["entropy"] = None
                
            sections.append(section_info)
            
        return sections
    
    def _calculate_entropy(self, data: bytes) -> float:
        """
        Calculate Shannon entropy of data
        
        Args:
            data: Bytes to calculate entropy for
            
        Returns:
            Entropy value (0.0 to 8.0)
        """
        if not data:
            return 0.0
            
        entropy = 0.0
        for x in range(256):
            p_x = float(data.count(x)) / len(data)
            if p_x > 0:
                entropy += - p_x * math.log(p_x, 2)
                
        return entropy

    def _perform_linux_checks(self, bv: BinaryView, results: Dict) -> Dict[str, List[str]]:
        """
        Perform Linux-specific malware checks
        
        Args:
            bv: Binary Ninja BinaryView object
            results: Dictionary containing analysis results
            
        Returns:
            Dictionary containing Linux-specific check results
        """
        checks = {
            "interpreter_hijacking": [],
            "library_injection": [],
            "process_hollowing": [],
            "privilege_escalation": [],
            "persistence_mechanisms": [],
            "anti_debugging": [],
            "network_capabilities": [],
            "file_operations": []
        }
        
        # Extract strings for analysis
        # all_strings = results.get("strings", {}).get("normal_text", [])
        all_strings = self.temp_all_strings
        
        # Interpreter hijacking
        if any("/tmp/" in s or "/dev/shm" in s for s in all_strings):
            checks["interpreter_hijacking"].append("Potential interpreter hijacking in strings")
        
        # Library injection
        if any("LD_PRELOAD" in s for s in all_strings):
            checks["library_injection"].append("LD_PRELOAD referenced in strings")
        
        # Persistence mechanisms
        for location in self.linux_persistence_locations:
            if any(location in s for s in all_strings):
                checks["persistence_mechanisms"].append(f"Persistence location referenced: {location}")
        
        # Network capabilities
        network_indicators = ["socket", "connect", "bind", "listen", "accept", "recv", "send"]
        if any(indicator in s for s in all_strings for indicator in network_indicators):
            checks["network_capabilities"].append("Network-related functions referenced in strings")
        
        # File operations
        file_indicators = ["open", "read", "write", "unlink", "mkdir", "rmdir", "chmod"]
        if any(indicator in s for s in all_strings for indicator in file_indicators):
            checks["file_operations"].append("File operation functions referenced in strings")
        
        # Check functions for Linux-specific behaviors
        for func in results.get("functions", []):
            for behavior in func.get("behavior", []):
                # Privilege escalation
                if behavior["type"] == "privilege_escalation":
                    checks["privilege_escalation"].append(
                        f"Privilege escalation in {func['name']}: {behavior['instruction']}"
                    )
                
                # Anti-debugging
                elif behavior["type"] == "anti_analysis":
                    checks["anti_debugging"].append(
                        f"Anti-analysis in {func['name']}: {behavior['instruction']}"
                    )
                
                # Network capabilities
                elif behavior["type"] == "network":
                    checks["network_capabilities"].append(
                        f"Network operation in {func['name']}: {behavior['instruction']}"
                    )
                
                # File operations
                elif behavior["type"] == "filesystem":
                    checks["file_operations"].append(
                        f"File operation in {func['name']}: {behavior['instruction']}"
                    )
        
        return checks


# Import math module for entropy calculation


# Main execution
if __name__ == "__main__":
    if len(sys.argv) < 2:
        print("Usage: python smart_static_analysis.py <binary_file>")
        sys.exit(1)
        
    analyzer = SmartStaticAnalyzer(llm_model=config.get('llm.model'), llm_api_base=config.get('llm.api_base'))
    results = analyzer.analyze(Path(sys.argv[1]), use_llm=config.get('analysis.enable_llm_analysis', True))
    results['bv'] = str(results['bv']) if 'bv' in results else None
    # Save results to file
    output_file = "results.json"
    with open(output_file, "w") as f:
        json.dump(results, f, indent=2)
    
    print(f"Analysis complete. Results saved to {output_file}")
    print("========================")
