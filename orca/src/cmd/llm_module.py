"""
LLM Module for BinSleuth
Handles interactions with language models using LiteLLM
"""
import os
import json
import time
from typing import Dict, List, Any, Optional, Union, Tuple
from pathlib import Path

from litellm import completion
from litellm.exceptions import ServiceUnavailableError, APIError, RateLimitError

from config import config
from utils import _clean_json
from timing_utils import TimingCollector, estimate_openai_cost, estimate_anthropic_cost

# Try to load credentials from AGENTCONFIG if available
try:
    if 'AGENTCONFIG' in os.environ:
        creds = json.load(open(os.environ['AGENTCONFIG']))
        os.environ['OPENAI_API_KEY'] = creds['OPENAI_API_KEY']
    else:
        print("Warning: AGENTCONFIG environment variable not set. Using default configuration.")
except Exception as e:
    print(f"Warning: Failed to load credentials from AGENTCONFIG: {str(e)}")
class LLMHandler:
    """
    Handler for LLM interactions with error handling and retries
    """
    
    def __init__(self, model: Optional[str] = None, api_base: Optional[str] = None):
        """
        Initialize LLM handler
        
        Args:
            model: LLM model to use (defaults to config)
            api_base: API base URL (defaults to config)
        """
        self.model = model or config.get('llm.model')
        self.api_base = api_base or config.get('llm.api_base')
        self.temperature = config.get('llm.temperature', 0.1)
        self.max_tokens = config.get('llm.max_tokens', 2048)
        self.timeout = config.get('llm.timeout', 60)
        self.retry_attempts = config.get('llm.retry_attempts', 3)
        self.max_batch_size = config.get('llm.max_batch_size', 20)
        self.rate_limit_delay = config.get('llm.rate_limit_delay', 5)
        
        # Initialize timing collector
        self.timing_collector = TimingCollector()
        
        # Ensure API key is set
        if not os.environ.get('OPENAI_API_KEY') and config.get('llm.api_key'):
            os.environ['OPENAI_API_KEY'] = config.get('llm.api_key')
    
    def query(self, 
              system_prompt: str, 
              user_prompt: str, 
              response_format: Optional[Dict[str, str]] = None,
              temperature: Optional[float] = None) -> str:
        """
        Send a query to the LLM and get a response
        
        Args:
            system_prompt: System prompt for the LLM
            user_prompt: User prompt for the LLM
            response_format: Optional format specification for the response
            temperature: Optional temperature override
            
        Returns:
            LLM response as a string
        """
        messages = [
            {"role": "system", "content": system_prompt},
            {"role": "user", "content": user_prompt}
        ]
        
        return self.send_messages(messages, response_format, temperature)
    
    def send_messages(self, 
                     messages: List[Dict[str, str]], 
                     response_format: Optional[Dict[str, str]] = None,
                     temperature: Optional[float] = None,
                     request_type: str = "general") -> str:
        """
        Send messages to the LLM with retry logic and metrics tracking
        
        Args:
            messages: List of message dictionaries
            response_format: Optional format specification for the response
            temperature: Optional temperature override
            request_type: Type of request for metrics tracking
            
        Returns:
            LLM response content as a string
        """
        # Start timing the LLM request
        timer_name = f"llm_request_{request_type}_{int(time.time())}"
        self.timing_collector.start_timer(timer_name, {
            "model": self.model,
            "request_type": request_type,
            "message_count": len(messages)
        })
        
        attempts = 0
        last_error = None
        current_max_tokens = self.max_tokens
        current_temperature = temperature or self.temperature
        
        while attempts < self.retry_attempts:
            try:
                print(f"Sending LLM request (attempt {attempts+1}/{self.retry_attempts})")
                start_time = time.time()
                
                response = completion(
                    model=self.model,
                    messages=messages,
                    temperature=current_temperature,
                    max_tokens=current_max_tokens,
                    response_format=response_format,
                    api_base=self.api_base,
                    timeout=self.timeout
                )
                
                # End the timer
                duration = self.timing_collector.end_timer(timer_name)
                
                # Extract token usage if available
                usage = getattr(response, 'usage', None)
                if usage:
                    prompt_tokens = getattr(usage, 'prompt_tokens', 0)
                    completion_tokens = getattr(usage, 'completion_tokens', 0)
                    total_tokens = getattr(usage, 'total_tokens', prompt_tokens + completion_tokens)
                else:
                    # Estimate token usage if not provided
                    prompt_text = " ".join([msg.get("content", "") for msg in messages])
                    response_text = response.choices[0].message.content
                    prompt_tokens = len(prompt_text.split()) * 1.3  # Rough estimation
                    completion_tokens = len(response_text.split()) * 1.3
                    total_tokens = prompt_tokens + completion_tokens
                
                # Calculate cost based on model
                if "gpt" in self.model.lower():
                    cost = estimate_openai_cost(self.model, prompt_tokens, completion_tokens)
                elif "claude" in self.model.lower():
                    cost = estimate_anthropic_cost(self.model, prompt_tokens, completion_tokens)
                else:
                    cost = estimate_openai_cost(self.model, prompt_tokens, completion_tokens)  # Default
                
                # Record LLM usage metrics
                self.timing_collector.record_llm_usage(
                    model=self.model,
                    prompt_tokens=int(prompt_tokens),
                    completion_tokens=int(completion_tokens),
                    total_tokens=int(total_tokens),
                    cost_usd=cost,
                    request_type=request_type,
                    success=True
                )
                
                print(f"LLM request completed in {duration:.2f}s, tokens: {int(total_tokens)}, cost: ${cost:.4f}")
                
                return response.choices[0].message.content
            
            except RateLimitError as e:
                last_error = e
                attempts += 1
                
                # Record failed request
                self.timing_collector.record_llm_usage(
                    model=self.model,
                    prompt_tokens=0,
                    completion_tokens=0,
                    total_tokens=0,
                    cost_usd=0.0,
                    request_type=request_type,
                    success=False,
                    error=f"Rate limit error: {str(e)}"
                )
                
                # More aggressive handling for rate limit errors
                print(f"Rate limit error: {str(e)}")
                
                # Reduce token limit and temperature
                current_max_tokens = int(current_max_tokens * 0.7)
                current_temperature = max(0.0, current_temperature - 0.2)
                
                # Add additional delay for rate limit errors
                wait_time = self.rate_limit_delay * attempts
                print(f"Reducing max_tokens to {current_max_tokens}, temperature to {current_temperature}")
                print(f"Waiting {wait_time} seconds before retry...")
                time.sleep(wait_time)
                
            except (ServiceUnavailableError, APIError) as e:
                last_error = e
                attempts += 1
                
                # Record failed request
                self.timing_collector.record_llm_usage(
                    model=self.model,
                    prompt_tokens=0,
                    completion_tokens=0,
                    total_tokens=0,
                    cost_usd=0.0,
                    request_type=request_type,
                    success=False,
                    error=f"API error: {str(e)}"
                )
                
                # Exponential backoff with jitter
                backoff_time = min(2 ** attempts + (0.1 * attempts), 60)
                print(f"API error: {str(e)}")
                print(f"Retrying in {backoff_time} seconds...")
                time.sleep(backoff_time)
            
            except Exception as e:
                # End timer for failed request
                try:
                    self.timing_collector.end_timer(timer_name)
                except:
                    pass
                
                # Record failed request
                self.timing_collector.record_llm_usage(
                    model=self.model,
                    prompt_tokens=0,
                    completion_tokens=0,
                    total_tokens=0,
                    cost_usd=0.0,
                    request_type=request_type,
                    success=False,
                    error=f"Error: {str(e)}"
                )
                
                # For other errors, fail immediately
                error_msg = f"LLM query failed: {str(e)}"
                print(error_msg)
                raise Exception(error_msg)
        
        # End timer for failed request after all retries
        try:
            self.timing_collector.end_timer(timer_name)
        except:
            pass
        
        # If we've exhausted retries
        error_msg = f"LLM query failed after {self.retry_attempts} attempts. Last error: {str(last_error)}"
        print(error_msg)
        raise Exception(error_msg)
    
    def get_json_response(self, 
                         system_prompt: str, 
                         user_prompt: str, 
                         temperature: Optional[float] = None,
                         request_type: str = "json_query") -> Dict[str, Any]:
        """
        Get a JSON response from the LLM
        
        Args:
            system_prompt: System prompt for the LLM
            user_prompt: User prompt for the LLM
            temperature: Optional temperature override
            request_type: Type of request for metrics tracking
            
        Returns:
            Parsed JSON response as a dictionary
        """
        response_format = {"type": "json_object"}
        
        messages = [
            {"role": "system", "content": system_prompt},
            {"role": "user", "content": user_prompt}
        ]
        
        try:
            response = self.send_messages(messages, response_format, temperature, request_type)
            cleaned_json = _clean_json(response)
            return json.loads(cleaned_json)
        except json.JSONDecodeError:
            # If JSON parsing fails, try again with more explicit instructions
            retry_prompt = f"{user_prompt}\n\nIMPORTANT: Your response MUST be valid JSON."
            retry_messages = [
                {"role": "system", "content": system_prompt},
                {"role": "user", "content": retry_prompt}
            ]
            response = self.send_messages(retry_messages, response_format, temperature, f"{request_type}_retry")
            cleaned_json = _clean_json(response)
            return json.loads(cleaned_json)
    
    def analyze_binary_behavior(self, 
                               binary_info: Dict[str, Any], 
                               feature_type: str) -> Dict[str, Any]:
        """
        Analyze binary behavior using LLM
        
        Args:
            binary_info: Dictionary containing binary information
            feature_type: Type of feature to analyze (e.g., 'strings', 'imports', 'functions')
            
        Returns:
            Analysis results as a dictionary
        """
        system_prompt = """You are a binary analysis expert specializing in malware analysis. 
        Analyze the provided binary features and identify potential malicious behaviors, 
        capabilities, and indicators of compromise."""
        
        # Create a focused prompt based on feature type
        if feature_type == 'strings':
            # Limit the size of strings to analyze
            strings_data = binary_info.get('strings', {})
            # Limit each category to a reasonable number of items
            for category in strings_data:
                if isinstance(strings_data[category], list) and len(strings_data[category]) > 100:
                    strings_data[category] = strings_data[category][:100]
            
            user_prompt = f"""Analyze the following strings extracted from a binary file:
            
            {json.dumps(strings_data, indent=2)}
            
            Identify potential:
            1. Command and control (C2) domains or IP addresses
            2. Encoded or obfuscated commands
            3. File paths that might indicate persistence mechanisms
            4. API functions that suggest malicious capabilities
            5. Passwords, keys, or credentials
            
            Return a JSON object with these categories and your findings."""
            
        elif feature_type == 'imports':
            # Limit the number of imports to analyze
            imports = binary_info.get('imports', [])
            if len(imports) > 200:
                imports = imports[:200]
                
            user_prompt = f"""Analyze the following imported functions from a binary file:
            
            {json.dumps(imports, indent=2)}
            
            Identify potential:
            1. Network communication capabilities
            2. File operations
            3. Process manipulation
            4. Anti-analysis techniques
            5. Privilege escalation methods
            
            Return a JSON object with these categories and your findings."""
            
        elif feature_type == 'functions':
            # Process functions in smaller batches to avoid token limits
            return self._analyze_functions_in_batches(binary_info.get('functions', []), system_prompt)
            
        else:
            # For other types, limit the data size
            limited_info = self._limit_data_size(binary_info)
            user_prompt = f"""Analyze the following binary information:
            
            {json.dumps(limited_info, indent=2)}
            
            Identify potential:
            1. Malicious behaviors or capabilities
            2. Indicators of compromise
            3. Techniques used by the binary
            4. Overall assessment of the binary's purpose
            
            Return a JSON object with these categories and your findings."""
        
        return self.get_json_response(system_prompt, user_prompt)
        
    def _analyze_functions_in_batches(self, functions: List[Dict], system_prompt: str) -> Dict[str, Any]:
        """
        Analyze functions in smaller batches to avoid token limits
        
        Args:
            functions: List of function dictionaries
            system_prompt: System prompt for the LLM
            
        Returns:
            Combined analysis results
        """
        # Limit to a reasonable number of functions for analysis
        max_functions = 200
        if len(functions) > max_functions:
            print(f"Limiting function analysis to {max_functions} functions out of {len(functions)}")
            functions = functions[:max_functions]
        
        # Use batch size from config
        batch_size = min(self.max_batch_size, 20)  # Default to 20 if config value is larger
        results = {
            "suspicious_functions": [],
            "malicious_capabilities": {},
            "function_relationships": [],
            "overall_assessment": ""
        }
        
        total_batches = (len(functions) + batch_size - 1) // batch_size
        print(f"Processing {len(functions)} functions in {total_batches} batches of {batch_size}")
        
        # Process functions in batches
        for i in range(0, len(functions), batch_size):
            batch = functions[i:i+batch_size]
            batch_num = i // batch_size + 1
            
            print(f"Processing batch {batch_num}/{total_batches} ({len(batch)} functions)")
            
            # Simplify function data to reduce token usage
            simplified_batch = []
            for func in batch:
                # Create a simplified version with only essential fields
                simplified_func = {
                    "name": func.get("name", "unknown"),
                    "address": func.get("address", "0x0"),
                    "size": func.get("size", 0),
                }
                
                # Only include non-empty fields that are useful for analysis
                if "behavior" in func and func["behavior"]:
                    simplified_func["behavior"] = func["behavior"]
                
                if "callees" in func and len(func["callees"]) > 0:
                    # Limit the number of callees to reduce tokens
                    simplified_func["callees"] = func["callees"][:10] if len(func["callees"]) > 10 else func["callees"]
                
                if "parameters" in func and func["parameters"]:
                    simplified_func["parameters"] = func["parameters"]
                
                simplified_batch.append(simplified_func)
            
            user_prompt = f"""Analyze the following batch of functions (batch {batch_num} of {total_batches}) from a binary file:
            
            {json.dumps(simplified_batch, indent=2)}
            
            Identify potential:
            1. Suspicious function names or patterns
            2. Functions with unusual behavior
            3. Functions that might implement malicious capabilities
            4. Relationships between suspicious functions
            
            Return a JSON object with these categories and your findings."""
            
            try:
                # Add delay between batches to avoid rate limits
                if i > 0:
                    delay = 2  # 2 second delay between batches
                    print(f"Waiting {delay} seconds before processing next batch...")
                    time.sleep(delay)
                
                batch_result = self.get_json_response(system_prompt, user_prompt)
                
                # Merge results
                if "suspicious_functions" in batch_result:
                    results["suspicious_functions"].extend(batch_result["suspicious_functions"])
                
                if "malicious_capabilities" in batch_result:
                    for capability, details in batch_result.get("malicious_capabilities", {}).items():
                        if capability in results["malicious_capabilities"]:
                            results["malicious_capabilities"][capability].extend(details)
                        else:
                            results["malicious_capabilities"][capability] = details
                
                if "function_relationships" in batch_result:
                    results["function_relationships"].extend(batch_result.get("function_relationships", []))
                
                print(f"Successfully analyzed batch {batch_num}/{total_batches}")
                
            except Exception as e:
                print(f"Error analyzing function batch {batch_num}/{total_batches}: {str(e)}")
                # Continue with next batch instead of failing completely
        
        # Final analysis to summarize all batches
        if results["suspicious_functions"]:
            print("Generating final summary of function analysis...")
            
            # Limit the data sent for summary to avoid token limits
            suspicious_funcs_sample = results["suspicious_functions"][:15]
            capabilities_sample = {}
            for capability, details in results["malicious_capabilities"].items():
                capabilities_sample[capability] = details[:5] if len(details) > 5 else details
            
            summary_prompt = f"""Based on the analysis of {len(functions)} functions, provide an overall assessment 
            of the binary's functionality and potential malicious nature. Here are the key findings:
            
            Suspicious functions (sample): {json.dumps(suspicious_funcs_sample, indent=2)}
            
            Malicious capabilities (sample): {json.dumps(capabilities_sample, indent=2)}
            
            Return a brief overall assessment as a string."""
            
            try:
                summary_result = self.get_json_response(system_prompt, summary_prompt)
                if isinstance(summary_result, dict) and "overall_assessment" in summary_result:
                    results["overall_assessment"] = summary_result["overall_assessment"]
                elif isinstance(summary_result, dict):
                    results["overall_assessment"] = json.dumps(summary_result)
                else:
                    results["overall_assessment"] = str(summary_result)
                print("Successfully generated function analysis summary")
            except Exception as e:
                error_msg = f"Error generating summary: {str(e)}"
                print(error_msg)
                results["overall_assessment"] = error_msg
        
        return results
        
    def _limit_data_size(self, data: Dict[str, Any]) -> Dict[str, Any]:
        """
        Limit the size of data to avoid token limits
        
        Args:
            data: Dictionary containing data to limit
            
        Returns:
            Limited data dictionary
        """
        limited_data = {}
        
        for key, value in data.items():
            if isinstance(value, list):
                # Limit lists to 100 items
                limited_data[key] = value[:100]
            elif isinstance(value, dict):
                # Recursively limit nested dictionaries
                limited_data[key] = self._limit_data_size(value)
            else:
                limited_data[key] = value
                
        return limited_data
    
    def get_behavior_patterns(self) -> Dict[str, List[str]]:
        """
        Get expanded behavior patterns from LLM
        
        Returns:
            Dictionary of behavior patterns by category
        """
        system_prompt = """You are a security analyst. Your task is to provide a list of suspicious 
        API/function patterns in binary files that could indicate malicious behavior."""
        
        user_prompt = """List at least 30 suspicious API/function patterns in Linux and Windows binaries 
        that could indicate malicious behavior, organized by category.
        Include common legitimate functions that could be abused.
        
        Categories should include:
        - network: Network communication functions
        - process: Process creation and manipulation
        - filesystem: File operations
        - privilege: Privilege escalation
        - crypto: Cryptographic operations
        - anti_analysis: Anti-debugging and anti-VM techniques
        - persistence: System persistence mechanisms
        - memory: Memory manipulation
        - registry: Windows registry operations (Windows only)
        - injection: Code/DLL injection techniques
        
        Return as JSON with categories as keys and arrays of function patterns as values."""
        
        try:
            return self.get_json_response(system_prompt, user_prompt)
        except Exception as e:
            print(f"Failed to get behavior patterns from LLM: {str(e)}")
            # Return default patterns from config
            return config.get('behavior_patterns', {})
    
    def analyze_decoded_strings(self, decoded_strings: Dict[str, List[str]]) -> Dict[str, Any]:
        """
        Analyze decoded strings using LLM
        
        Args:
            decoded_strings: Dictionary of decoded strings by encoding type
            
        Returns:
            Analysis results as a dictionary
        """
        system_prompt = """You are a binary analysis expert specializing in malware analysis.
        Analyze the provided decoded strings and identify potential malicious indicators."""
        
        user_prompt = f"""Analyze the following decoded strings from a binary file:
        
        {json.dumps(decoded_strings, indent=2)}
        
        For each decoding method (base64, rot13, hex, xor), identify:
        1. Potential commands or scripts
        2. URLs, domains, or IP addresses
        3. File paths or system locations
        4. Potential passwords or keys
        5. Other suspicious content
        
        Return a JSON object with your analysis for each encoding type."""
        
        return self.get_json_response(system_prompt, user_prompt)
    
    def generate_summary_report(self, analysis_results: Dict[str, Any]) -> str:
        """
        Generate a summary report of the analysis
        
        Args:
            analysis_results: Complete analysis results
            
        Returns:
            Summary report as a string
        """
        system_prompt = """You are a binary analysis expert. Create a concise but comprehensive 
        summary report of the analyzed binary based on the provided analysis results."""
        
        user_prompt = f"""Generate a summary report for the following binary analysis results:
        
        {json.dumps(analysis_results, indent=2)}
        
        Include:
        1. Basic file information
        2. Key capabilities identified
        3. Suspicious behaviors or indicators
        4. Potential malware classification if applicable
        5. Recommendations for further analysis
        
        Format the report in Markdown with appropriate sections and highlights."""
        
        return self.query(system_prompt, user_prompt)
    
    def cluster_api_functions(self, api_list: List[str]) -> Dict[str, Any]:
        """
        Cluster API functions into logical groups based on their purpose
        and provide a detailed analysis of each cluster.
        
        Args:
            api_list: List of API function names to cluster
            
        Returns:
            Dictionary containing clusters of API functions with analysis
        """
        system_prompt = """You are an expert in reverse engineering, Vulnerability Analysis and Malware Analysis."""
        
        user_prompt = f"""I have a list of API functions imported by a binary that I need you to cluster.

        Your task:
        1. Cluster these APIs into logical functional groups based on their purpose
        2. For each cluster, provide:
           - A descriptive name
           - A description of the functionality
           - The libraries these APIs typically come from
           - A security assessment (safe, potentially dangerous, dangerous)
           - Potential usage scenarios (legitimate and malicious)

        IMPORTANT REQUIREMENTS:
        - Include ALL functions from the list in your clustering - do not leave any out
        - Group validation functions (especially those with __chk in their names) together
        - Ensure each function appears in exactly one cluster

        Here's the list of API functions:
        {api_list}

        Return your analysis as a JSON object with the following structure:
        {{
          "clusters": [
            {{
              "name": "Cluster name",
              "description": "Description of what these functions do collectively",
              "apis": ["api1", "api2", ...],
              "libraries": ["library1", "library2", ...],
              "security_assessment": "safe|potentially_dangerous|dangerous",
              "potential_usage": "Description of how these APIs might be used",
            }},
            ...
          ]
        }}
        """
        
        return self.get_json_response(system_prompt, user_prompt, request_type="api_clustering")
    
    def get_timing_metrics(self) -> Dict[str, Any]:
        """
        Get current timing and cost metrics
        
        Returns:
            Dictionary with timing and LLM usage metrics
        """
        return self.timing_collector.get_summary()
    
    def save_metrics(self, filename: str) -> None:
        """
        Save timing and LLM metrics to a file
        
        Args:
            filename: Output filename
        """
        self.timing_collector.save_metrics(filename)
    
    def reset_metrics(self) -> None:
        """
        Reset timing and LLM metrics for a new analysis
        """
        self.timing_collector = TimingCollector()


# Global LLM handler instance
llm_handler = LLMHandler()
