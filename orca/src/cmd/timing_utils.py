"""
Timing and metrics collection utilities for BinSleuth
Tracks analysis performance and LLM usage costs
"""
import time
import json
from datetime import datetime, timezone
from typing import Dict, Any, List, Optional
from dataclasses import dataclass, asdict

@dataclass
class TimingMetric:
    """Individual timing measurement"""
    name: str
    start_time: float
    end_time: Optional[float] = None
    duration: Optional[float] = None
    metadata: Optional[Dict[str, Any]] = None

@dataclass 
class LLMUsageMetric:
    """LLM API usage tracking"""
    model: str
    prompt_tokens: int
    completion_tokens: int
    total_tokens: int
    cost_usd: float
    timestamp: str
    request_type: str
    success: bool = True
    error: Optional[str] = None

class TimingCollector:
    """
    Collects timing metrics and LLM usage data for performance analysis
    """
    
    def __init__(self):
        """Initialize timing collector"""
        self.metrics: Dict[str, TimingMetric] = {}
        self.llm_usage: List[LLMUsageMetric] = []
        self.session_start = time.time()
        self.session_id = datetime.now().strftime("%Y%m%d_%H%M%S")
    
    def start_timer(self, name: str, metadata: Optional[Dict[str, Any]] = None) -> None:
        """
        Start timing a process
        
        Args:
            name: Name of the process being timed
            metadata: Optional metadata about the process
        """
        self.metrics[name] = TimingMetric(
            name=name,
            start_time=time.time(),
            metadata=metadata or {}
        )
    
    def end_timer(self, name: str) -> float:
        """
        End timing a process and calculate duration
        
        Args:
            name: Name of the process being timed
            
        Returns:
            Duration in seconds
        """
        if name not in self.metrics:
            raise ValueError(f"Timer '{name}' was not started")
        
        metric = self.metrics[name]
        metric.end_time = time.time()
        metric.duration = metric.end_time - metric.start_time
        
        return metric.duration
    
    def record_llm_usage(self, 
                        model: str,
                        prompt_tokens: int,
                        completion_tokens: int,
                        total_tokens: int,
                        cost_usd: float,
                        request_type: str,
                        success: bool = True,
                        error: Optional[str] = None) -> None:
        """
        Record LLM API usage for cost tracking
        
        Args:
            model: LLM model name
            prompt_tokens: Number of prompt tokens
            completion_tokens: Number of completion tokens
            total_tokens: Total tokens used
            cost_usd: Cost in USD
            request_type: Type of request (e.g., 'capabilities', 'analysis')
            success: Whether the request was successful
            error: Error message if request failed
        """
        usage = LLMUsageMetric(
            model=model,
            prompt_tokens=prompt_tokens,
            completion_tokens=completion_tokens,
            total_tokens=total_tokens,
            cost_usd=cost_usd,
            timestamp=datetime.now(tz=timezone.utc).isoformat(),
            request_type=request_type,
            success=success,
            error=error
        )
        
        self.llm_usage.append(usage)
    
    def get_summary(self) -> Dict[str, Any]:
        """
        Get comprehensive timing and cost summary
        
        Returns:
            Dictionary with timing and cost metrics
        """
        total_session_time = time.time() - self.session_start
        
        # Calculate timing summary
        timing_summary = {}
        total_measured_time = 0
        
        for name, metric in self.metrics.items():
            if metric.duration is not None:
                timing_summary[name] = {
                    "duration_seconds": round(metric.duration, 3),
                    "duration_minutes": round(metric.duration / 60, 3),
                    "start_time": datetime.fromtimestamp(metric.start_time, tz=timezone.utc).isoformat(),
                    "end_time": datetime.fromtimestamp(metric.end_time, tz=timezone.utc).isoformat() if metric.end_time else None,
                    "metadata": metric.metadata
                }
                total_measured_time += metric.duration
        
        # Calculate LLM usage summary
        llm_summary = {
            "total_requests": len(self.llm_usage),
            "successful_requests": len([u for u in self.llm_usage if u.success]),
            "failed_requests": len([u for u in self.llm_usage if not u.success]),
            "total_tokens": sum(u.total_tokens for u in self.llm_usage),
            "total_prompt_tokens": sum(u.prompt_tokens for u in self.llm_usage),
            "total_completion_tokens": sum(u.completion_tokens for u in self.llm_usage),
            "total_cost_usd": round(sum(u.cost_usd for u in self.llm_usage), 4),
            "models_used": list(set(u.model for u in self.llm_usage)),
            "request_types": list(set(u.request_type for u in self.llm_usage))
        }
        
        # Add per-model breakdown
        model_breakdown = {}
        for usage in self.llm_usage:
            if usage.model not in model_breakdown:
                model_breakdown[usage.model] = {
                    "requests": 0,
                    "tokens": 0,
                    "cost_usd": 0.0
                }
            
            model_breakdown[usage.model]["requests"] += 1
            model_breakdown[usage.model]["tokens"] += usage.total_tokens
            model_breakdown[usage.model]["cost_usd"] += usage.cost_usd
        
        # Round costs in model breakdown
        for model in model_breakdown:
            model_breakdown[model]["cost_usd"] = round(model_breakdown[model]["cost_usd"], 4)
        
        return {
            "session_info": {
                "session_id": self.session_id,
                "total_session_time_seconds": round(total_session_time, 3),
                "total_session_time_minutes": round(total_session_time / 60, 3),
                "total_measured_time_seconds": round(total_measured_time, 3),
                "start_timestamp": datetime.fromtimestamp(self.session_start, tz=timezone.utc).isoformat(),
                "end_timestamp": datetime.now(tz=timezone.utc).isoformat()
            },
            "timing_metrics": timing_summary,
            "llm_usage_summary": llm_summary,
            "llm_model_breakdown": model_breakdown,
            "detailed_llm_usage": [asdict(usage) for usage in self.llm_usage]
        }
    
    def get_current_metrics(self) -> Dict[str, Any]:
        """
        Get current metrics without ending the session
        
        Returns:
            Current timing and LLM metrics
        """
        return self.get_summary()
    
    def save_metrics(self, filename: str) -> None:
        """
        Save metrics to a JSON file
        
        Args:
            filename: Output filename
        """
        metrics = self.get_summary()
        
        with open(filename, 'w') as f:
            json.dump(metrics, f, indent=2)
    
    def merge_with_other_collector(self, other: 'TimingCollector') -> None:
        """
        Merge metrics from another collector
        
        Args:
            other: Another TimingCollector instance
        """
        # Merge timing metrics (avoid duplicates by prefixing)
        for name, metric in other.metrics.items():
            unique_name = f"{other.session_id}_{name}"
            self.metrics[unique_name] = metric
        
        # Merge LLM usage
        self.llm_usage.extend(other.llm_usage)

def estimate_openai_cost(model: str, prompt_tokens: int, completion_tokens: int) -> float:
    """
    Estimate OpenAI API cost based on current pricing
    
    Args:
        model: OpenAI model name
        prompt_tokens: Number of prompt tokens
        completion_tokens: Number of completion tokens
        
    Returns:
        Estimated cost in USD
    """
    # OpenAI pricing (as of 2024)
    pricing = {
        "gpt-4o": {
            "prompt": 0.000015,  # $0.015 per 1K tokens
            "completion": 0.00006  # $0.06 per 1K tokens
        },
        "gpt-4o-mini": {
            "prompt": 0.00000015,  # $0.00015 per 1K tokens
            "completion": 0.0000006  # $0.0006 per 1K tokens
        },
        "gpt-4": {
            "prompt": 0.00003,  # $0.03 per 1K tokens
            "completion": 0.00006  # $0.06 per 1K tokens
        },
        "gpt-3.5-turbo": {
            "prompt": 0.0000015,  # $0.0015 per 1K tokens
            "completion": 0.000002  # $0.002 per 1K tokens
        }
    }
    
    model_pricing = pricing.get(model, pricing.get("gpt-4o"))  # Default to gpt-4o
    
    prompt_cost = (prompt_tokens / 1000) * model_pricing["prompt"]
    completion_cost = (completion_tokens / 1000) * model_pricing["completion"]
    
    return prompt_cost + completion_cost

def estimate_anthropic_cost(model: str, prompt_tokens: int, completion_tokens: int) -> float:
    """
    Estimate Anthropic API cost based on current pricing
    
    Args:
        model: Anthropic model name
        prompt_tokens: Number of prompt tokens
        completion_tokens: Number of completion tokens
        
    Returns:
        Estimated cost in USD
    """
    # Anthropic pricing (as of 2024) 
    pricing = {
        "claude-3-5-sonnet-20241022": {
            "prompt": 0.000003,  # $0.003 per 1K tokens
            "completion": 0.000015  # $0.015 per 1K tokens
        },
        "claude-sonnet-4-20250514": {  # Assuming same as 3.5 sonnet
            "prompt": 0.000003,  # $0.003 per 1K tokens
            "completion": 0.000015  # $0.015 per 1K tokens
        },
        "claude-3-opus-20240229": {
            "prompt": 0.000015,  # $0.015 per 1K tokens
            "completion": 0.000075  # $0.075 per 1K tokens
        },
        "claude-3-haiku-20240307": {
            "prompt": 0.00000025,  # $0.00025 per 1K tokens
            "completion": 0.00000125  # $0.00125 per 1K tokens
        }
    }
    
    model_pricing = pricing.get(model, pricing.get("claude-3-5-sonnet-20241022"))  # Default to 3.5 sonnet
    
    prompt_cost = (prompt_tokens / 1000) * model_pricing["prompt"]
    completion_cost = (completion_tokens / 1000) * model_pricing["completion"]
    
    return prompt_cost + completion_cost

#
