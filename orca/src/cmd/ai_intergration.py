# ai_integration.py
from typing import List, Dict, Any
from openai import AsyncOpenAI

aclient = AsyncOpenAI()
import litellm
from dataclasses import dataclass
import json
from tenacity import retry, stop_after_attempt, wait_exponential

@dataclass
class AnalysisPrompt:
    static_results: Dict[str, Any]

    def to_prompt(self) -> str:
        """Convert analysis results to LLM prompt"""
        prompt = """Analyze the following binary analysis results and determine the capabilities of the binary.
            Static Analysis:
            {static}
            
            Provide a comprehensive report including:
            1. Potential malicious capabilities
            2. Vulnerabilities
            3. Key functions and their purposes
            4. Indicators of Compromise (IOCs)
            5. Suggested further analysis steps
            """.format(
                static=json.dumps(self.static_results, indent=2),)
        return prompt

class AIIntegrator:
    def __init__(self, model: str = "gpt-4-turbo", provider: str = "openai"):
        self.model = model
        self.provider = provider

    @retry(stop=stop_after_attempt(3), wait=wait_exponential(multiplier=1, min=4, max=10))
    async def analyze_binary(self, prompt: AnalysisPrompt) -> Dict[str, Any]:
        """Use LLM to analyze binary capabilities"""
        try:
            if self.provider == "openai":
                response = await aclient.chat.completions.create(model=self.model,
                messages=[{"role": "user", "content": prompt.to_prompt()}],
                temperature=0.3,
                max_tokens=2000)
                return json.loads(response.choices[0].message.content)
            else:
                response = await litellm.acompletion(
                    model=self.model,
                    messages=[{"role": "user", "content": prompt.to_prompt()}],
                    temperature=0.3,
                    max_tokens=2000
                )
                return json.loads(response.choices[0].message.content)
        except Exception as e:
            raise AIAnalysisError(f"AI analysis failed: {str(e)}")

class AIAnalysisError(Exception):
    pass