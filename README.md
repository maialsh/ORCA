# ORCA: Orchestrated Multi-Agent and LLM-Based Reasoning for Static Binary Code Analysis

ORCA is a multi-agent framework that orchestrates Large Language Models and Binary Ninja for static binary code analysis. The system employs specialized agents to perform comprehensive malware analysis and reverse engineering tasks.

## System Overview

ORCA implements an orchestrated multi-agent architecture where each agent is responsible for specific analysis tasks. The framework integrates Binary Ninja's static analysis capabilities with LLM-powered reasoning to provide comprehensive binary analysis.

## Architecture

The system consists of multiple specialized agents coordinated through a supervisor:

- **Supervisor Agent**: Orchestrates the analysis workflow
- **Planning Agent**: Creates dynamic analysis plans based on specified goals
- **Static Analysis Agent**: Performs static analysis using Binary Ninja
- **API Cross-reference Agent**: Analyzes API usage patterns and cross-references
- **API Clustering Agent**: Groups related API functions
- **API Analysis Agent**: Examines API relevance to binary functionality  
- **Capabilities Agent**: Identifies binary capabilities
- **Malware Analysis Agent**: Detects malicious behavior patterns
- **String Analysis Agent**: Analyzes strings for threat indicators
- **Binary Summary Agent**: Generates analysis summaries
- **Chatbot Agent**: Provides interactive querying of analysis results

## Requirements

- Python 3.8+
- Binary Ninja (commercial license required)
- OpenAI API access

## Installation

1. Clone the repository:
```bash
git clone https://github.com/maialsh/ORCA.git
cd ORCA
```

2. Create and activate virtual environment:
```bash
python -m venv venv
source venv/bin/activate  # On Windows: venv\Scripts\activate
```

3. Install dependencies:
```bash
pip install -r orca/requirements.txt
```

4. Configure OpenAI API key:
```bash
export OPENAI_API_KEY="your-api-key"
```

## Usage

### Quick Analysis Example

```bash
# Interactive mode
python orca_cli.py

# Command line mode
python orca_cli.py --binary /path/to/binary --functionality "System utility" --goal "capabilities" --analyze
```

### Interactive CLI

ORCA provides a comprehensive interactive CLI:

```
orca> set_binary /path/to/suspicious_binary.exe
orca> set_functionality "Network utility program"
orca> set_goal "malware analysis"
orca> analyze
```

### Available Commands

- `set_binary <path>` - Set binary file for analysis
- `set_functionality <description>` - Describe the binary's purpose
- `set_goal <goal>` - Set analysis goal (capabilities/malware_analysis)
- `analyze` - Run the multi-agentic analysis workflow
- `chat` - Enter interactive chatbot mode
- `list_apis` - Show all APIs used by the binary
- `api_usage <api>` - Analyze specific API usage
- `malware_check` - Quick malware assessment
- `suspicious_strings` - Analyze suspicious strings
- `status` - Show current analysis status
- `save <filename>` - Save analysis results

### Quick Commands

- `quick_analyze <binary> <description>` - Quick capabilities analysis
- `comprehensive_analyze <binary> <description>` - Full analysis including malware detection

### Web Interface

Launch Streamlit frontend:
```bash
python run_streamlit_frontend.py
```

## Architecture

ORCA uses LangGraph to orchestrate multiple specialized agents:

```
┌─────────────────┐    ┌─────────────────┐    ┌─────────────────┐
│  Supervisor     │───▶│  Planning       │───▶│  Static         │
│  Agent          │    │  Agent          │    │  Analysis       │
└─────────────────┘    └─────────────────┘    └─────────────────┘
                                                       │
                                                       ▼
┌─────────────────┐    ┌─────────────────┐    ┌─────────────────┐
│  API Cross-ref  │◀───│  API Clustering │◀───│  API Analysis   │
│  Agent          │    │  Agent          │    │  Agent          │
└─────────────────┘    └─────────────────┘    └─────────────────┘
         │                       │                       │
         ▼                       ▼                       ▼
┌─────────────────┐    ┌─────────────────┐    ┌─────────────────┐
│  Capabilities   │    │  Malware        │    │  String         │
│  Agent          │    │  Analysis       │    │  Analysis       │
└─────────────────┘    └─────────────────┘    └─────────────────┘
         │                       │                       │
         └───────────────────────┼───────────────────────┘
                                 ▼
         ┌─────────────────┐    ┌─────────────────┐    ┌─────────────────┐
         │  Binary Summary │───▶│  Summary        │───▶│  Chatbot        │
         │  Agent          │    │  Generator      │    │  Agent          │
         └─────────────────┘    └─────────────────┘    └─────────────────┘
```

## Configuration

### Binary Ninja Setup
Ensure Binary Ninja is installed and the Python API is accessible:
```python
# ORCA will automatically detect Binary Ninja at:
# /Applications/Binary Ninja.app/Contents/Resources/python (macOS)
```

### LLM Configuration
Configure in `orca/src/cmd/config.py`:
```python
config = {
    'llm.model': 'gpt-4o',
    'llm.temperature': 0.1,
    'llm.api_base': None  # Use default OpenAI endpoint
}
```

## Output Examples

### Capabilities Analysis
```json
{
  "core_functionality": "Network scanning and enumeration tool",
  "network_capabilities": ["TCP connect scanning", "UDP scanning"],
  "file_system_operations": ["File creation", "Directory traversal"],
  "process_manipulation": ["Process enumeration"],
  "threat_level": "low"
}
```

### Malware Analysis
```json
{
  "classification": "Potentially Unwanted Program",
  "threat_level": "medium", 
  "confidence_level": 75,
  "malicious_indicators": ["Network scanning", "Registry modification"],
  "iocs": ["suspicious_domain.com", "malware.exe"]
}
```

## Interactive Chatbot

After analysis, enter chat mode to explore results:

```
chat> What APIs does this binary use for network communication?
chat> Are there any suspicious strings in this binary?
chat> How does this binary achieve persistence?
chat> Find all functions that handle file operations
```

## System Workflow

The analysis workflow follows this sequence:

1. Binary ingestion and initial static analysis
2. API extraction and cross-reference generation
3. API clustering and relevance analysis
4. Capability identification
5. Malware behavior analysis
6. String analysis for threat indicators
7. Summary generation
8. Interactive analysis interface activation

## Output Format

Analysis results are provided in structured JSON format:

```json
{
  "binary_info": {...},
  "api_analysis": {...},
  "capabilities": [...],
  "malware_indicators": {...},
  "summary": "..."
}
```

## Project Structure

```
ORCA/
├── orca_cli.py              # Main CLI interface
├── orca/                    # Core framework
│   ├── src/cmd/            # Agent implementations
│   │   ├── workflow.py     # Workflow orchestration
│   │   ├── agents.py       # Agent definitions
│   │   └── ...
│   └── requirements.txt
├── streamlit_frontend.py    # Web interface
└── README.md
```

## Contributing

Contributions are welcome. Please open an issue to discuss proposed changes before submitting a pull request.

## License

This project is licensed under the MIT License.
