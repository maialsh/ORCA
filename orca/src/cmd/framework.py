# framework.py
import asyncio
from pathlib import Path
from typing import Dict, Any
from orchestrator import AnalysisOrchestrator, BinaryArchitecture
import logging
import hashlib
import json

class BinaryCapabilityFramework:
    def __init__(self, cache_dir: str = "/tmp/bcaf_cache"):
        self.orchestrator = AnalysisOrchestrator()
        self.cache_dir = Path(cache_dir)
        self.cache_dir.mkdir(exist_ok=True)
        
    async def analyze(self, binary_path: str, use_cache: bool = True) -> Dict[str, Any]:
        """Main entry point for binary analysis"""
        binary_path = Path(binary_path)
        if not binary_path.exists():
            raise FileNotFoundError(f"Binary not found: {binary_path}")
            
        cache_key = self._get_cache_key(binary_path)
        cache_file = self.cache_dir / f"{cache_key}.json"
        
        if use_cache and cache_file.exists():
            logging.info(f"Loading results from cache: {cache_file}")
            return json.loads(cache_file.read_text())
            
        try:
            results = await self.orchestrator.analyze_binary(str(binary_path))
            
            # Add architecture-specific post-processing
            if 'architecture' in results.get('static', {}):
                arch = results['static']['architecture']
                if arch in ['arm', 'aarch64']:
                    results = self._post_process_arm_results(results)
                elif arch == 'x86_64':
                    results = self._post_process_x64_results(results)
            
            if use_cache:
                cache_file.write_text(json.dumps(results, indent=2))
                
            return results
        except Exception as e:
            logging.error(f"Failed to analyze binary {binary_path}: {e}")
            raise
            
    def _post_process_arm_results(self, results: Dict) -> Dict:
        """Add ARM-specific analysis enhancements"""
        if 'arm_specific' in results.get('static', {}):
            arm_data = results['static']['arm_specific']
            # Add Thumb/ARM interworking analysis
            arm_data['interworking'] = self._analyze_arm_interworking(
                arm_data.get('thumb_functions', {}))
        return results
    
    def _post_process_x64_results(self, results: Dict) -> Dict:
        """Add x64-specific analysis enhancements"""
        if 'x64_specific' in results.get('static', {}):
            x64_data = results['static']['x64_specific']
            # Add syscall table mapping
            x64_data['syscall_names'] = self._map_syscall_numbers(
                x64_data.get('syscall_sites', []))
        return results
    
    def _analyze_arm_interworking(self, thumb_funcs: Dict) -> Dict:
        """Analyze ARM/Thumb interworking patterns"""
        return {
            'thumb_count': len(thumb_funcs),
            'potential_switches': []  # Would be populated with actual analysis
        }
    
    def _map_syscall_numbers(self, syscall_sites: List) -> Dict:
        """Map syscall numbers to names"""
        return {
            str(addr): "unknown" for addr in syscall_sites  # Would use syscall table
        }
    
    def _get_cache_key(self, binary_path: Path) -> str:
        """Generate a unique cache key for the binary"""
        file_hash = hashlib.sha256()
        with binary_path.open('rb') as f:
            while chunk := f.read(8192):
                file_hash.update(chunk)
        return file_hash.hexdigest()