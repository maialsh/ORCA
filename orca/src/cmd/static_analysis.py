import os
import subprocess
import hashlib
import sys
import re
import base64
import codecs
from pathlib import Path
from typing import Dict, List, Optional, Tuple
if not os.path.exists("/Applications/Binary Ninja.app/Contents/Resources/python"):
    print(f"Binary Ninja python API not found in expected folder")
    sys.exit(1)
sys.path.insert(0, "/Applications/Binary Ninja.app/Contents/Resources/python")
import binaryninja as bn
from binaryninja import BinaryView, SymbolType

class StaticAnalyzer:
    def __init__(self):
        self.suspicious_patterns = [
            # Network
            "bind", "listen", "accept", "connect", "socket",
            # Command execution
            "system", "exec", "popen", "fork", "spawn",
            # Environment manipulation
            "getenv", "putenv", "setenv",
            # Anti-analysis
            "ptrace", "inotify", "nanosleep",
            # Cryptography
            "crypt", "getpass", "openssl",
            # Dynamic loading
            "dlopen", "dlsym", "dlerror"
        ]
        
        self.backdoor_indicators = [
            "backdoor", "shell", "rootkit", "hidden", "secret",
            "password", "login", "command", "connect_back",
            "reverse_shell", "bind_shell", "port_knocking"
        ]
        
        self.linux_persistence_locations = [
            "/etc/rc.local", "/etc/cron.", "/etc/systemd/",
            "~/.bashrc", "~/.profile", "~/.config/autostart",
            "/etc/init.d/", "/etc/profile.d/"
        ]

    def analyze(self, file_path: Path) -> Dict[str, any]:
        """Main analysis entry point"""
        if not file_path.exists():
            raise FileNotFoundError(f"File not found: {file_path}")
        
        results = {
            "file_info": self._get_file_info(file_path),
            "strings": [],
            "decoded_strings": {},
            "imports": [],
            "exports": [],
            "functions": [],
            "suspicious_functions": [],
            "linux_checks": {},
            "potential_backdoors": []
        }
        
        try:
            with bn.open_view(str(file_path)) as bv:
                results.update({
                    "strings": self._extract_strings(bv),
                    "imports": self._get_imports(bv),
                    "exports": self._get_exports(bv),
                    "functions": self._analyze_functions(bv),
                })
                
                results["decoded_strings"] = self._decode_strings(results["strings"])
                results["suspicious_functions"] = self._find_suspicious_functions(results["functions"])
                results["linux_checks"] = self._perform_linux_checks(bv, results)
                results["potential_backdoors"] = self._detect_backdoors(results)
                
        except Exception as e:
            results["error"] = f"Static analysis failed: {str(e)}"
            
        return results

    def _get_file_info(self, file_path: Path) -> Dict[str, str]:
        """Get basic file information"""
        with open(file_path, "rb") as f:
            file_hash = hashlib.sha256(f.read()).hexdigest()
        
        file_type = subprocess.run(
            ['file', str(file_path)],
            capture_output=True, text=True
        ).stdout.strip()
        
        elf_info = self._get_elf_info(file_path)
        
        return {
            "path": str(file_path),
            "name": file_path.name,
            "size": os.path.getsize(file_path),
            "sha256": file_hash,
            "type": file_type,
            "elf_info": elf_info
        }

    

    def _analyze_function_behavior(self, func) -> List[Dict]:
        """Analyze behavior within a single function"""
        behavior = []
        
        for block in func:
            for insn in block:
                disasm = str(insn)
                
                # Network behavior
                if any(net in disasm for net in ["socket", "bind", "listen", "connect"]):
                    behavior.append({
                        "type": "network",
                        "instruction": disasm,
                        "address": hex(insn.address)
                    })
                
                # File operations
                elif any(file_op in disasm for file_op in ["open", "read", "write", "unlink"]):
                    behavior.append({
                        "type": "file_operation",
                        "instruction": disasm,
                        "address": hex(insn.address)
                    })
                
                # Process manipulation
                elif any(proc in disasm for proc in ["fork", "exec", "kill", "ptrace"]):
                    behavior.append({
                        "type": "process_manipulation",
                        "instruction": disasm,
                        "address": hex(insn.address)
                    })
                
                # Privilege escalation
                elif any(priv in disasm for priv in ["setuid", "setgid", "capset"]):
                    behavior.append({
                        "type": "privilege_escalation",
                        "instruction": disasm,
                        "address": hex(insn.address)
                    })
                
                # Anti-analysis
                elif any(anti in disasm for anti in ["ptrace", "inotify", "nanosleep"]):
                    behavior.append({
                        "type": "anti_analysis",
                        "instruction": disasm,
                        "address": hex(insn.address)
                    })
                
                # Cryptography
                elif any(crypto in disasm for crypto in ["crypt", "md5", "sha1", "aes"]):
                    behavior.append({
                        "type": "cryptography",
                        "instruction": disasm,
                        "address": hex(insn.address)
                    })
        
        return behavior

    def _find_suspicious_functions(self, functions: List[Dict]) -> List[Dict]:
        """Identify suspicious functions based on name and behavior"""
        suspicious = []
        
        for func in functions:
            # Check function name against suspicious patterns
            name_match = any(
                re.search(pattern, func["name"], re.IGNORECASE)
                for pattern in self.suspicious_patterns
            )
            
            # Check for suspicious behaviors
            behavior_match = any(
                behavior["type"] in ["network", "process_manipulation", "privilege_escalation", "anti_analysis"]
                for behavior in func.get("behavior", [])
            )
            
            if name_match or behavior_match:
                suspicious.append(func)
                
        return suspicious

    def _perform_linux_checks(self, bv: BinaryView, results: Dict) -> Dict[str, List[str]]:
        """Perform Linux-specific malware checks"""
        checks = {
            "interpreter_hijacking": [],
            "library_injection": [],
            "process_hollowing": [],
            "privilege_escalation": [],
            "persistence_mechanisms": [],
            "anti_debugging": []
        }
        
        # Check strings for Linux-specific patterns
        strings = results.get("strings", [])
        
        # Interpreter hijacking
        if any("/tmp/" in s or "/dev/shm" in s for s in strings):
            checks["interpreter_hijacking"].append("Potential interpreter hijacking in strings")
        
        # Library injection
        if any("LD_PRELOAD" in s for s in strings):
            checks["library_injection"].append("LD_PRELOAD referenced in strings")
        
        # Persistence mechanisms
        for location in self.linux_persistence_locations:
            if any(location in s for s in strings):
                checks["persistence_mechanisms"].append(f"Persistence location referenced: {location}")
        
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
        
        return checks

    def _detect_backdoors(self, results: Dict) -> List[str]:
        """Detect potential backdoor patterns"""
        indicators = []
        
        # String analysis
        strings = results.get("strings", [])
        for s in strings:
            s_lower = s.lower()
            if any(keyword in s_lower for keyword in self.backdoor_indicators):
                indicators.append(f"Suspicious string: {s}")
        
        # Function analysis
        for func in results.get("suspicious_functions", []):
            # Network functions with no clear reason
            if any(net in func["name"].lower() for net in ["bind", "listen", "accept"]):
                behaviors = [b["type"] for b in func.get("behavior", [])]
                if "network" in behaviors and len(behaviors) < 3:
                    indicators.append(
                        f"Minimal network function {func['name']} with behaviors: {', '.join(behaviors)}"
                    )
        
        # Linux-specific checks
        linux_checks = results.get("linux_checks", {})
        for check_type, findings in linux_checks.items():
            if findings:
                indicators.append(f"Linux {check_type.replace('_', ' ')} findings:")
                indicators.extend(findings[:3])  # Limit to top 3
        
        return indicators