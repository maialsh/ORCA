"""
ORCA LLM Provider — unified interface to LiteLLM with rate limiting,
circuit breaking, retries, structured JSON output, and usage tracking.
"""
from __future__ import annotations
import json, os, time, random, re
from typing import Any, Dict, List, Optional
from orca.core.config import config
from orca.core.llm.rate_limiter import TokenEstimator, RateLimiter, CircuitBreaker


def _clean_json(text: str) -> str:
    """Strip markdown fences and trailing commas from LLM JSON output."""
    text = re.sub(r"```json\s*", "", text)
    text = re.sub(r"```\s*$", "", text)
    text = re.sub(r",\s*([}\]])", r"\1", text)
    return text.strip()


def _extract_json(text: str) -> Optional[Dict[str, Any]]:
    """Try multiple strategies to extract a JSON object from LLM output."""
    cleaned = _clean_json(text)

    # Strategy 1: direct parse
    try:
        return json.loads(cleaned)
    except json.JSONDecodeError:
        pass

    # Strategy 2: find first { ... } block
    start = cleaned.find("{")
    if start >= 0:
        depth = 0
        for i in range(start, len(cleaned)):
            if cleaned[i] == "{":
                depth += 1
            elif cleaned[i] == "}":
                depth -= 1
                if depth == 0:
                    try:
                        return json.loads(cleaned[start:i + 1])
                    except json.JSONDecodeError:
                        break

    # Strategy 3: strip trailing commas more aggressively and retry
    aggressive = re.sub(r",\s*}", "}", cleaned)
    aggressive = re.sub(r",\s*]", "]", aggressive)
    try:
        return json.loads(aggressive)
    except json.JSONDecodeError:
        pass

    return None


# Cost per 1M tokens (USD) — update as pricing changes
MODEL_PRICING = {
    "anthropic/claude-sonnet-4-20250514": {"input": 3.00, "output": 15.00},
    "claude-sonnet-4-20250514": {"input": 3.00, "output": 15.00},
    "anthropic/claude-haiku-4-5-20251001": {"input": 0.80, "output": 4.00},
    "claude-haiku-4-5-20251001": {"input": 0.80, "output": 4.00},
    "anthropic/claude-opus-4-20250514": {"input": 15.00, "output": 75.00},
    "claude-opus-4-20250514": {"input": 15.00, "output": 75.00},
    "gpt-4o": {"input": 2.50, "output": 10.00},
    "gpt-4o-mini": {"input": 0.15, "output": 0.60},
    "gpt-4.1": {"input": 2.00, "output": 8.00},
    "gpt-4.1-mini": {"input": 0.40, "output": 1.60},
}


class LLMProvider:
    """
    Thin wrapper around LiteLLM with resilience features and usage tracking.

    Supports any model string LiteLLM understands:
      anthropic/claude-sonnet-4-20250514, gpt-4o, ollama/llama3, etc.

    Usage tracking is class-level so all instances share the same counters.
    """

    # Class-level usage tracking shared across all instances
    _global_usage = {
        "total_requests": 0,
        "total_input_tokens": 0,
        "total_output_tokens": 0,
        "total_tokens": 0,
        "total_cost_usd": 0.0,
        "per_request": [],
    }

    def __init__(self, model: Optional[str] = None):
        self.model = model or config.get("llm.model")
        self.temperature = config.get("llm.temperature", 0.1)
        self.max_tokens = config.get("llm.max_tokens", 4096)
        self.timeout = config.get("llm.timeout", 120)
        self._retries = config.get("llm.retry_attempts", 7)
        self._rl_delay = config.get("llm.rate_limit_delay", 15)
        self._limiter = RateLimiter(
            config.get("llm.requests_per_minute", 15),
            config.get("llm.min_delay_between_requests", 4.0),
        )
        self._breaker = CircuitBreaker(
            config.get("llm.circuit_breaker_threshold", 5),
            config.get("llm.circuit_breaker_timeout", 90),
        )

    # ── public API ─────────────────────────────────────────────

    def query(self, system: str, user: str, *, temperature: Optional[float] = None) -> str:
        """Send system+user prompt, return raw text response."""
        msgs = [{"role": "system", "content": system}, {"role": "user", "content": user}]
        return self._send(msgs, temperature=temperature)

    def query_json(self, system: str, user: str, *, temperature: Optional[float] = None) -> Dict[str, Any]:
        """Send prompt and parse JSON response (with robust extraction and retry)."""
        raw = self.query(system, user, temperature=temperature)
        parsed = _extract_json(raw)
        if parsed is not None:
            return parsed

        # Retry with explicit JSON instruction
        retry_user = user + "\n\nIMPORTANT: Your response MUST be valid JSON only. No text before or after the JSON object."
        raw = self.query(system, retry_user, temperature=temperature)
        parsed = _extract_json(raw)
        if parsed is not None:
            return parsed

        raise ValueError(f"Could not parse JSON from LLM response: {raw[:200]}")

    @classmethod
    def get_usage(cls) -> Dict[str, Any]:
        """Return accumulated usage statistics (class-level, shared across all instances)."""
        return {
            "total_requests": cls._global_usage["total_requests"],
            "total_input_tokens": cls._global_usage["total_input_tokens"],
            "total_output_tokens": cls._global_usage["total_output_tokens"],
            "total_tokens": cls._global_usage["total_tokens"],
            "total_cost_usd": round(cls._global_usage["total_cost_usd"], 6),
        }

    @classmethod
    def get_usage_per_request(cls) -> List[Dict[str, Any]]:
        """Return per-request usage details."""
        return cls._global_usage["per_request"]

    @classmethod
    def reset_usage(cls):
        """Reset usage counters (call before each binary analysis)."""
        cls._global_usage = {
            "total_requests": 0,
            "total_input_tokens": 0,
            "total_output_tokens": 0,
            "total_tokens": 0,
            "total_cost_usd": 0.0,
            "per_request": [],
        }

    def _estimate_cost(self, input_tokens: int, output_tokens: int) -> float:
        """Estimate cost in USD based on model pricing."""
        pricing = MODEL_PRICING.get(self.model, {})
        if not pricing:
            # Try without provider prefix
            short_model = self.model.split("/")[-1] if "/" in self.model else self.model
            pricing = MODEL_PRICING.get(short_model, {"input": 0, "output": 0})
        input_cost = (input_tokens / 1_000_000) * pricing.get("input", 0)
        output_cost = (output_tokens / 1_000_000) * pricing.get("output", 0)
        return input_cost + output_cost

    # ── internal ───────────────────────────────────────────────

    def _send(self, messages: List[Dict[str, str]], *, temperature: Optional[float] = None) -> str:
        from litellm import completion
        from litellm.exceptions import RateLimitError, ServiceUnavailableError, APIError

        if not self._breaker.can_attempt():
            raise RuntimeError(f"Circuit breaker open: {self._breaker.get_state()}")

        cur_temp = temperature if temperature is not None else self.temperature
        cur_max = self.max_tokens

        for attempt in range(1, self._retries + 1):
            try:
                self._limiter.wait_if_needed()
                resp = completion(
                    model=self.model,
                    messages=messages,
                    temperature=cur_temp,
                    max_tokens=cur_max,
                    timeout=self.timeout,
                )
                self._breaker.record_success()

                # Track usage (class-level, shared across all instances)
                usage = getattr(resp, "usage", None)
                input_tokens = getattr(usage, "prompt_tokens", 0) if usage else 0
                output_tokens = getattr(usage, "completion_tokens", 0) if usage else 0
                total_tokens = input_tokens + output_tokens
                cost = self._estimate_cost(input_tokens, output_tokens)

                LLMProvider._global_usage["total_requests"] += 1
                LLMProvider._global_usage["total_input_tokens"] += input_tokens
                LLMProvider._global_usage["total_output_tokens"] += output_tokens
                LLMProvider._global_usage["total_tokens"] += total_tokens
                LLMProvider._global_usage["total_cost_usd"] += cost
                LLMProvider._global_usage["per_request"].append({
                    "input_tokens": input_tokens,
                    "output_tokens": output_tokens,
                    "total_tokens": total_tokens,
                    "cost_usd": round(cost, 6),
                })

                return resp.choices[0].message.content

            except RateLimitError:
                self._breaker.record_failure()
                cur_max = int(cur_max * 0.7)
                wait = self._rl_delay * attempt + random.uniform(0, self._rl_delay * 0.2)
                time.sleep(wait)

            except (ServiceUnavailableError, APIError):
                self._breaker.record_failure()
                time.sleep(min(2 ** attempt, 60))

            except Exception as exc:
                self._breaker.record_failure()
                raise

        raise RuntimeError(f"LLM query failed after {self._retries} attempts")
