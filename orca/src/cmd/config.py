"""
Configuration module for BinSleuth
Contains settings for LLM integration and analysis parameters
"""
import os
import json
from pathlib import Path
from typing import Dict, Any, Optional
creds = json.load(open(os.environ['AGENTCONFIG']))
os.environ['OPENAI_API_KEY'] = creds['OPENAI_API_KEY']
# Default configuration
DEFAULT_CONFIG = {
    # LLM Configuration
    "llm": {
        "provider": "openai",
        "model": "gpt-4o",
        "api_base": None,  # Use default API base
        "api_key": None,   # Will be loaded from environment or config file
        "temperature": 0.1,
        "max_tokens": 2048,  # Reduced from 4096 to avoid rate limits
        "timeout": 60,     # Seconds
        "retry_attempts": 3,
        "max_batch_size": 20,  # Maximum number of items to process in a single batch
        "rate_limit_delay": 5  # Seconds to wait after a rate limit error
    },
    
    # Binary Analysis Configuration
    "analysis": {
        "max_file_size": 50 * 1024 * 1024,  # 50MB
        "extract_strings_min_length": 4,
        "max_functions_to_analyze": 500,  # Reduced from 1000 to avoid token limits
        "sandbox_timeout": 30,  # Seconds
        "enable_dynamic_analysis": False,
        "enable_llm_analysis": True
    },
    
    # Feature Extraction Configuration
    "features": {
        "strings": True,
        "imports": True,
        "exports": True,
        "functions": True,
        "sections": True,
        "headers": True,
        "decoded_strings": True,
        "behavior_patterns": True,
        "linux_specific": True
    },
    
    # Behavior Pattern Categories
    "behavior_patterns": {
        "network": ["socket", "bind", "listen", "accept", "connect", "recv", "send"],
        "process": ["exec", "fork", "spawn", "clone", "kill", "ptrace"],
        "filesystem": ["open", "read", "write", "unlink", "mkdir", "rmdir", "chmod"],
        "privilege": ["setuid", "setgid", "capset", "prctl"],
        "crypto": ["crypt", "md5", "sha1", "aes", "des", "blowfish"],
        "anti_analysis": ["ptrace", "getpid", "gettimeofday", "clock_gettime", "sysinfo"],
        "persistence": ["crontab", "systemd", "init", "rc", "bashrc", "profile"]
    }
}

class Config:
    """Configuration manager for BinSleuth"""
    
    def __init__(self, config_path: Optional[str] = None):
        """
        Initialize configuration
        
        Args:
            config_path: Path to custom config file (optional)
        """
        self.config = DEFAULT_CONFIG.copy()
        
        # Load from config file if provided
        if config_path and os.path.exists(config_path):
            self._load_from_file(config_path)
        
        # Override with environment variables
        self._load_from_env()
    
    def _load_from_file(self, config_path: str) -> None:
        """Load configuration from file"""
        try:
            with open(config_path, 'r') as f:
                user_config = json.load(f)
                
            # Deep merge with default config
            self._deep_merge(self.config, user_config)
        except Exception as e:
            print(f"Error loading config from {config_path}: {str(e)}")
    
    def _load_from_env(self) -> None:
        """Load configuration from environment variables"""
        # LLM API key
        if api_key := os.environ.get('OPENAI_API_KEY'):
            self.config['llm']['api_key'] = api_key
        
        # LLM API base
        if api_base := os.environ.get('OPENAI_API_BASE'):
            self.config['llm']['api_base'] = api_base
        
        # LLM model
        if model := os.environ.get('LLM_MODEL'):
            self.config['llm']['model'] = model
        
        # LLM provider
        if provider := os.environ.get('LLM_PROVIDER'):
            self.config['llm']['provider'] = provider
    
    def _deep_merge(self, target: Dict, source: Dict) -> None:
        """Deep merge two dictionaries"""
        for key, value in source.items():
            if key in target and isinstance(target[key], dict) and isinstance(value, dict):
                self._deep_merge(target[key], value)
            else:
                target[key] = value
    
    def get(self, key: str, default: Any = None) -> Any:
        """Get a configuration value by key"""
        keys = key.split('.')
        result = self.config
        
        for k in keys:
            if isinstance(result, dict) and k in result:
                result = result[k]
            else:
                return default
        
        return result
    
    def set(self, key: str, value: Any) -> None:
        """Set a configuration value by key"""
        keys = key.split('.')
        target = self.config
        
        for i, k in enumerate(keys[:-1]):
            if k not in target:
                target[k] = {}
            target = target[k]
        
        target[keys[-1]] = value
    
    def save(self, config_path: str) -> None:
        """Save configuration to file"""
        try:
            with open(config_path, 'w') as f:
                json.dump(self.config, f, indent=2)
        except Exception as e:
            print(f"Error saving config to {config_path}: {str(e)}")
    
    @property
    def llm_config(self) -> Dict[str, Any]:
        """Get LLM configuration"""
        return self.config['llm']
    
    @property
    def analysis_config(self) -> Dict[str, Any]:
        """Get analysis configuration"""
        return self.config['analysis']
    
    @property
    def features_config(self) -> Dict[str, Any]:
        """Get features configuration"""
        return self.config['features']
    
    @property
    def behavior_patterns(self) -> Dict[str, Any]:
        """Get behavior patterns configuration"""
        return self.config['behavior_patterns']


# Global configuration instance
config = Config()
