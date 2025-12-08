from typing import Optional, Type
import os
from pydantic import BaseModel, Field
from langchain_core.tools import tool
from config import config
from smart_static_analysis import SmartStaticAnalysis


class StaticAnalysisInputSchema(BaseModel):
    """Run static analysis on a binary file."""
    file_path: str = Field(description="Path to the binary file")


@tool("static_analysis_tool", args_schema=StaticAnalysisInputSchema)
def static_analysis(file_path: str) -> Dict[str, Any]:
    analyzer = SmartStaticAnalyzer(llm_model=config.get('llm.model'), llm_api_base=config.get('llm.api_base'))
    results = analyzer.analyze(Path(sys.argv[1]), use_llm=config.get('analysis.enable_llm_analysis', True))

