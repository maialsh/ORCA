# agents/orchestrator.py
from smolagents import Agent, MCP
from typing import Dict, Any, List
import asyncio
from staticAnalysisEngine import StaticAnalyzer
from ai_integration import AnalysisPrompt, AIIntegrator
from concurrent.futures import ThreadPoolExecutor
import logging

class BinaryAnalysisAgent(Agent):
    def __init__(self, binary_path: str):
        super().__init__(name=f"BinaryAnalysisAgent-{binary_path}")
        self.binary_path = binary_path
        self.static_results = None
                                                                                                                                self.llm_analysis = None
        self.executor = ThreadPoolExecutor(max_workers=4)
        
    async def run(self) -> Dict[str, Any]:
        """Orchestrate the analysis workflow"""
        try:
            # Run static analysis
            static_task = asyncio.get_event_loop().run_in_executor(
                self.executor, self._run_static_analysis)
            
            await asyncio.gather(static_task)
            
            # Perform AI analysis
            await self._run_ai_analysis()
            
            return {
                "static": self.static_results,
                "llm_analysis": self.llm_analysis
            }
        except Exception as e:
            logging.error(f"Analysis failed: {e}")
            raise
            
    def _run_static_analysis(self):
        analyzer = StaticAnalyzer(self.binary_path)
        self.static_results = analyzer.analyze()
        
    # def _run_dynamic_analysis(self):
    #     from dynamic_analysis import DynamicAnalyzer
    #     analyzer = DynamicAnalyzer(self.binary_path, timeout=30)
    #     self.dynamic_results = analyzer.analyze()
        
    async def _run_ai_analysis(self):
        prompt = AnalysisPrompt(self.static_results)
        integrator = AIIntegrator()
        self.llm_analysis = await integrator.analyze_binary(prompt)

class AnalysisOrchestrator(MCP):
    def __init__(self):
        super().__init__(name="BinaryAnalysisOrchestrator")
        self.agents = {}
        
    async def analyze_binary(self, binary_path: str) -> Dict[str, Any]:
        """Create and manage an agent for binary analysis"""
        if binary_path in self.agents:
            return self.agents[binary_path].get_results()
            
        agent = BinaryAnalysisAgent(binary_path)
        self.agents[binary_path] = agent
        await self.register_agent(agent)
        return await agent.run()