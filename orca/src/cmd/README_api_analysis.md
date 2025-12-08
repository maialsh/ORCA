# API Analysis Agent

The API Analysis Agent is a specialized component of BinSleuth that analyzes the connection between APIs used in a binary and the user's goal/description. It filters APIs based on their usage in the binary, focusing on those with code cross-references.

## Purpose

The primary purpose of the API Analysis Agent is to:

1. Identify APIs that are actually used in the binary (have code cross-references)
2. Filter functions to only include those that reference APIs
3. Analyze the relevance of APIs to the user's goal and the binary's functionality
4. Provide insights into which APIs require further analysis

This helps analysts focus on the most relevant parts of the binary and understand how the APIs relate to the binary's intended functionality.

## Integration with Workflow

The API Analysis Agent is integrated into the BinSleuth workflow and is executed after the API cross-references and API clustering steps. It builds upon the results of these previous steps to provide a more focused analysis.

## Usage

### As Part of the Workflow

When running the BinSleuth workflow, the API Analysis Agent is automatically executed if the user's goal includes "api" or "capabilities". The results are stored in the workflow state and can be accessed by subsequent agents.

```python
# Example of running the workflow with API analysis
from workflow import run_workflow

result = run_workflow(
    binary_path="/path/to/binary",
    binary_functionality="A network utility for file transfer",
    goal="Analyze API capabilities"
)

# Access API analysis results
api_analysis_results = result.get("api_analysis_results", {})
```

### Standalone Usage

The API Analysis Agent can also be used independently of the workflow. This is useful for focused API analysis or for integration into custom analysis pipelines.

```python
from api_analysis_agent import ApiAnalysisAgent
from smart_static_analysis import SmartStaticAnalyzer
from api_crossrefs import ApiCrossReferenceTool
from binaryninja import load
from pathlib import Path

# Perform static analysis
analyzer = SmartStaticAnalyzer()
static_results = analyzer.analyze(Path("/path/to/binary"), use_llm=True)

# Load binary with Binary Ninja
binary_view = load("/path/to/binary")

# Analyze API cross-references
api_tool = ApiCrossReferenceTool(binary_view)
imports = static_results.get("imports", [])
api_crossrefs_results = api_tool.batch_analyze(imports)

# Initialize API Analysis Agent
analysis_agent = ApiAnalysisAgent()

# Prepare state for analysis
analysis_state = {
    "binary_view": binary_view,
    "imports": imports,
    "functions": static_results.get("functions", []),
    "goal": "Analyze network capabilities",
    "binary_functionality": "A network utility for file transfer"
}

# Perform API analysis
result_state = analysis_agent.analyze(analysis_state)

# Access results
referenced_apis = result_state.get("referenced_apis", [])
filtered_functions = result_state.get("filtered_functions", [])
api_relevance = result_state.get("api_relevance", {})
```

### Using the Test Script

A test script is provided to demonstrate how to use the API Analysis Agent:

```bash
python test_api_analysis.py /path/to/binary "Analyze network capabilities" "A network utility for file transfer"
```

The test script performs the following steps:

1. Static analysis to extract imports and functions
2. API cross-reference analysis to find APIs with code references
3. API analysis to filter functions and analyze API relevance
4. Outputs the results to the console and saves them to a JSON file

## Output

The API Analysis Agent produces the following outputs:

1. **referenced_apis**: A list of APIs that have code cross-references in the binary
2. **filtered_functions**: A list of functions that reference APIs
3. **api_relevance**: A dictionary mapping API names to relevance information, including:
   - **goal_relevance**: Relevance score (0-10) to the user's goal
   - **functionality_relevance**: Relevance score (0-10) to the binary's functionality
   - **purpose**: Brief explanation of the API's purpose
   - **requires_further_analysis**: Whether the API requires further analysis
   - **reason**: Reason for further analysis if applicable

## Example Output

```json
{
  "referenced_apis": ["socket", "connect", "send", "recv", "close"],
  "filtered_functions": [
    {
      "name": "establish_connection",
      "address": "0x1000",
      "size": 120,
      "callers": ["main"],
      "callees": ["socket", "connect"]
    },
    {
      "name": "transfer_data",
      "address": "0x1080",
      "size": 200,
      "callers": ["main"],
      "callees": ["send", "recv"]
    }
  ],
  "api_relevance": {
    "socket": {
      "goal_relevance": 9,
      "functionality_relevance": 10,
      "purpose": "Creates a network socket for communication",
      "requires_further_analysis": true,
      "reason": "Core networking API that may reveal connection targets"
    },
    "connect": {
      "goal_relevance": 9,
      "functionality_relevance": 10,
      "purpose": "Connects a socket to a remote address",
      "requires_further_analysis": true,
      "reason": "May reveal malicious connection targets"
    }
  }
}
```

## Implementation Details

The API Analysis Agent is implemented in `api_analysis_agent.py` and consists of the following key components:

1. **ApiAnalysisAgent class**: The main class that performs the analysis
2. **analyze method**: The entry point for the analysis
3. **\_filter_functions_with_api_refs method**: Filters functions to only include those that reference APIs
4. **\_analyze_api_relevance method**: Analyzes the relevance of APIs to the user's goal and the binary's functionality

The agent uses the LLM (Language Learning Model) to analyze the relevance of APIs to the user's goal and the binary's functionality. This provides valuable insights into which APIs are most important for understanding the binary's behavior.
