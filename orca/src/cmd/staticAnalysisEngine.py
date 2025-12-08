import os
import sys
if not os.path.exists("/Applications/Binary Ninja.app/Contents/Resources/python"):
    print(f"Binary Ninja python API not found in expected folder")
    sys.exit(1)
sys.path.insert(0, "/Applications/Binary Ninja.app/Contents/Resources/python")
import binaryninja
from binaryninja import BinaryView, Architecture
from typing import Dict, Any, Optional, Tuple
import lief
import capstone
import re
import hashlib
import json
from enum import Enum

class BinaryArchitecture(Enum):
    X86_64 = "x86_64"
    ARM = "arm"
    ARM64 = "aarch64"
    UNKNOWN = "unknown"

class StaticAnalyzer:
    def __init__(self, binary_path: str):
        self.binary_path = binary_path
        self.bv: Optional[BinaryView] = None
        self.lief_binary = None
        self.capstone_engine = None
        self.analysis_results = {}
        self.architecture = BinaryArchitecture.UNKNOWN
        
    def analyze(self) -> Dict[str, Any]:
        """Perform comprehensive static analysis"""
        try:
            self._load_binary()
            self._determine_architecture()
            #self._basic_file_analysis()
            self._binary_ninja_analysis()
            #self._lief_analysis()
            #self._capstone_analysis()
            self._string_analysis()
            self._symbol_analysis()
            self._detect_packing()
            return self.analysis_results
        except Exception as e:
            raise StaticAnalysisError(f"Static analysis failed: {str(e)}")
    
    def _load_binary(self):
        """Load binary using multiple tools"""
        self.bv = binaryninja.BinaryViewType.get_view_of_file(self.binary_path)
        self.lief_binary = lief.parse(self.binary_path)
    
    def _determine_architecture(self):
        """Determine the binary architecture and configure appropriate tools"""
        if not self.bv:
            raise StaticAnalysisError("Binary not loaded")
        
        # Binary Ninja architecture detection
        arch = self.bv.arch
        if arch.name == 'x86_64':
            self.architecture = BinaryArchitecture.X86_64
            self.capstone_engine = capstone.Cs(capstone.CS_ARCH_X86, capstone.CS_MODE_64)
        elif arch.name in ['armv7', 'arm']:
            self.architecture = BinaryArchitecture.ARM
            self.capstone_engine = capstone.Cs(capstone.CS_ARCH_ARM, capstone.CS_MODE_ARM)
        elif arch.name in ['aarch64', 'arm64']:
            self.architecture = BinaryArchitecture.ARM64
            self.capstone_engine = capstone.Cs(capstone.CS_ARCH_ARM64, capstone.CS_MODE_ARM)
        else:
            raise StaticAnalysisError(f"Unsupported architecture: {arch.name}")
        
        self.analysis_results['architecture'] = self.architecture.value
    
    def _binary_ninja_analysis(self):
        """Extract advanced features using Binary Ninja"""
        self.analysis_results['functions'] = []
        
        # Architecture-specific analysis
        if self.architecture in [BinaryArchitecture.X86_64]:
            self._analyze_x64_features()
        elif self.architecture in [BinaryArchitecture.ARM, BinaryArchitecture.ARM64]:
            self._analyze_arm_features()
        
        for func in self.bv.functions:
            fn_info = {
                'name': func.name,
                'start': func.start,
                'calling_convention': str(func.calling_convention),
                'parameters': [str(param) for param in func.parameter_vars],
                'has_loops': func.has_loops,
                'can_return': func.can_return
            }
            self.analysis_results['functions'].append(fn_info)
        
        # Control flow analysis
        self.analysis_results['cfgs'] = {}
        for func in self.bv.functions:
            self.analysis_results['cfgs'][func.name] = self._extract_cfg(func)
    
    def _analyze_x64_features(self):
        """x64-specific analysis"""
        self.analysis_results['x64_specific'] = {
            'plt_entries': self._find_plt_entries(),
            'got_entries': self._find_got_entries(),
            'syscall_sites': self._find_syscall_sites_x64()
        }

    def _extract_cfg(self, func) -> Dict:
        """Extract control flow graph information"""
        cfg = {
            'basic_blocks': [],
            'edges': []
        }
        
        for block in func:
            block_info = {
                'start': block.start,
                'end': block.end,
                'instructions': []
            }
            
            for insn in block:
                block_info['instructions'].append({
                    'address': insn.address,
                    'text': str(insn)
                })
            
            cfg['basic_blocks'].append(block_info)
            
            for edge in block.outgoing_edges:
                cfg['edges'].append({
                    'source': block.start,
                    'target': edge.target.start,
                    'type': str(edge.type)
                })
        
        return cfg
    
    def _analyze_arm_features(self):
        """ARM-specific analysis"""
        self.analysis_results['arm_specific'] = {
            'plt_entries': self._find_plt_entries(),
            'got_entries': self._find_got_entries(),
            'svc_sites': self._find_svc_sites(),
            'thumb_functions': self._find_thumb_functions()
        }
    
    def _find_syscall_sites_x64(self) -> List[int]:
        """Find x64 syscall instructions (0F 05)"""
        syscalls = []
        for segment in self.lief_binary.segments:
            if not segment.is_executable:
                continue
            data = bytes(segment.content)
            for i in range(len(data) - 1):
                if data[i] == 0x0F and data[i+1] == 0x05:
                    syscalls.append(segment.virtual_address + i)
        return syscalls
    
    def _find_svc_sites(self) -> List[int]:
        """Find ARM SVC (supervisor call) instructions"""
        svc_calls = []
        for segment in self.lief_binary.segments:
            if not segment.is_executable:
                continue
            data = bytes(segment.content)
            # ARM mode SVC: 0xEFXXXXXX
            # Thumb mode SVC: 0xDFXX
            # This is simplified - actual analysis should use proper disassembly
            for i in range(len(data) - 3):
                if data[i] == 0xEF:
                    svc_calls.append(segment.virtual_address + i)
            for i in range(len(data) - 1):
                if data[i] == 0xDF:
                    svc_calls.append(segment.virtual_address + i)
        return svc_calls
    
    def _find_thumb_functions(self) -> Dict[str, int]:
        """Identify ARM Thumb functions (T-bit set in address)"""
        thumb_funcs = {}
        for func in self.bv.functions:
            if func.start & 1:
                thumb_funcs[func.name] = func.start
        return thumb_funcs