import json
from typing import List, Dict, Any, Optional
from llm_module import llm_handler

class FunctionClusteringTool:
    """
    A tool for clustering API functions into logical groups based on their purpose
    and providing a detailed analysis of each cluster.
    """
    def __init__(self, llm_model: Optional[str] = None, llm_api_base: Optional[str] = None):
        """
        Initialize the clustering tool with LLM model and API base
        
        Args:
            llm_model: Optional model name to override default
            llm_api_base: Optional API base URL to override default
        """
        self.llm_model = llm_model
        self.llm_api_base = llm_api_base
        
        # Create a custom LLM handler if model or API base is specified
        if llm_model or llm_api_base:
            from llm_module import LLMHandler
            self.custom_llm_handler = LLMHandler(model=llm_model, api_base=llm_api_base)
        else:
            self.custom_llm_handler = None

    def analyze_apis(self, api_list: List[str]) -> Dict[str, Any]:
        """
        Analyze a list of API functions and cluster them into functional groups
        
        Args:
            api_list: List of API function names to cluster
            
        Returns:
            Dictionary containing clusters of API functions with analysis
        """
        # Use custom handler if specified, otherwise use global handler
        handler = self.custom_llm_handler if self.custom_llm_handler else llm_handler
        
        # Call the LLM handler's cluster_api_functions method
        return handler.cluster_api_functions(api_list)


def cluster_apis(api_list: List[str], llm_model: Optional[str] = None, llm_api_base: Optional[str] = None) -> Dict[str, Any]:
    """
    Convenience function to cluster API functions without creating a tool instance
    
    Args:
        api_list: List of API function names to cluster
        llm_model: Optional model name to override default
        llm_api_base: Optional API base URL to override default
        
    Returns:
        Dictionary containing clusters of API functions with analysis
    """
    tool = FunctionClusteringTool(llm_model=llm_model, llm_api_base=llm_api_base)
    return tool.analyze_apis(api_list)
