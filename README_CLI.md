# ORCA CLI Tool

A simplified command-line interface for binary analysis using the ORCA framework.

## Overview

The ORCA CLI tool provides a streamlined way to analyze binary files and determine their capabilities. It utilizes the comprehensive multi-agentic workflow from the ORCA framework to perform static analysis, API analysis, and capability identification.

## Installation

1. Ensure you have Python 3.8+ installed
2. Install the required dependencies for ORCA (see orca/requirements.txt)
3. Set up your OpenAI API key:
   ```bash
   export OPENAI_API_KEY="your-api-key-here"
   ```

## Usage

### Basic Usage

```bash
python orca_cli.py -b <path_to_binary> -f <functionality> -o <results.json>
```

### Parameters

- `-b, --binary`: Path to the binary file to analyze (required)
- `-f, --functionality`: Description of the binary's intended functionality (required)
- `-o, --output`: Output JSON file path for analysis results (required)
- `--goal`: Analysis goal (optional, default: "capabilities")
- `-v, --verbose`: Enable verbose output (optional)
- `--debug`: Enable debug mode (optional)

### Examples

#### Basic Capabilities Analysis

```bash
python orca_cli.py -b /path/to/binary -f "Text editor application" -o results.json
```

#### Comprehensive Analysis (Capabilities + Malware)

```bash
python orca_cli.py -b suspicious.exe -f "Unknown application" -o analysis.json --goal "capabilities and malware analysis"
```

#### Verbose Output

```bash
python orca_cli.py -b app.bin -f "Network utility" -o output.json --verbose
```

#### Debug Mode

```bash
python orca_cli.py -b binary.elf -f "System tool" -o debug_results.json --debug
```

## Analysis Goals

The `--goal` parameter accepts various analysis objectives:

- `"capabilities"` (default): Focus on identifying binary capabilities
- `"malware analysis"`: Focus on malware detection and classification
- `"capabilities and malware analysis"`: Comprehensive analysis including both

## Output Format

The tool generates a JSON file containing comprehensive analysis results:

```json
{
  "binary_path": "/path/to/binary",
  "binary_functionality": "Description provided",
  "goal": "capabilities",
  "analysis_complete": true,
  "completed_steps": [
    "static_analysis",
    "api_analysis",
    "capabilities_analysis"
  ],
  "static_analysis": {
    "file_info": {
      "name": "binary",
      "size": 12345,
      "type": "ELF 64-bit",
      "sha256": "abc123..."
    },
    "imports": ["printf", "malloc", "free"],
    "functions_count": 42,
    "strings": {
      "apis": ["CreateFile", "WriteFile"],
      "urls": ["http://example.com"],
      "paths": ["/tmp/file"]
    }
  },
  "capabilities": {
    "core_functionality": "Text processing application",
    "network_capabilities": ["HTTP client"],
    "file_system_operations": ["File read/write"],
    "process_manipulation": [],
    "persistence_mechanisms": [],
    "anti_analysis_techniques": []
  },
  "api_analysis": {
    "referenced_apis": ["CreateFile", "WriteFile", "ReadFile"],
    "filtered_functions_count": 15
  },
  "metadata": {
    "orca_version": "enhanced",
    "total_steps_completed": 6,
    "analysis_successful": true
  }
}
```

## Key Features

### Static Analysis

- File metadata extraction
- Import/export analysis
- String extraction and categorization
- Function identification
- Section analysis

### API Analysis

- API cross-reference analysis
- Function clustering by behavior
- API relevance assessment
- Suspicious API detection

### Capabilities Identification

- Core functionality assessment
- Network capabilities detection
- File system operations analysis
- Process manipulation detection
- Persistence mechanism identification
- Anti-analysis technique detection

### Malware Analysis (when enabled)

- Malicious behavior detection
- Threat level assessment
- Confidence scoring
- IOC (Indicators of Compromise) extraction

## Testing

Run the test suite to verify the tool works correctly:

```bash
python test_orca_cli.py
```

This will test:

- Help functionality
- Basic analysis workflow
- Output file generation
- Result validation

*Note: Test file may need to be implemented*

## Troubleshooting

### Common Issues

1. **Import Errors**

   ```
   Error importing ORCA modules
   ```

   - Ensure you're running from the correct directory
   - Check that all dependencies are installed
   - Verify the orca/src/cmd directory exists

2. **Binary Ninja Not Found**

   ```
   Warning: Binary Ninja python API not found
   ```

   - This is a warning, not an error
   - Some advanced features may be limited
   - The tool will continue with available analyzers

3. **OpenAI API Key Missing**

   ```
   Error: OpenAI API key not found
   ```

   - Set your API key: `export OPENAI_API_KEY="your-key"`
   - Ensure the key has sufficient credits

4. **Analysis Timeout**
   - Large binaries may take longer to analyze
   - Use `--debug` to see detailed progress
   - Consider analyzing smaller binaries first

### Debug Mode

Enable debug mode for detailed logging:

```bash
python orca_cli.py -b binary -f "description" -o results.json --debug
```

This will show:

- Detailed workflow progress
- Agent execution status
- Error stack traces
- Analysis step completion

## Dependencies

The tool requires the following Python packages:

- langchain-openai
- langgraph
- pathlib
- json
- argparse

Additional ORCA dependencies:

- See orca/requirements.txt for complete list

## Architecture

The CLI tool is built on top of the ORCA multi-agentic framework:

1. **Supervisor Agent**: Validates inputs and manages workflow
2. **Planning Agent**: Creates analysis plan based on goals
3. **Static Analysis Agent**: Performs file analysis
4. **API Analysis Agent**: Analyzes API usage patterns
5. **Capabilities Agent**: Identifies binary capabilities
6. **Malware Analysis Agent**: Detects malicious behavior
7. **Summary Agent**: Generates final analysis report

## Performance

Typical analysis times:

- Small binaries (<1MB): 30-60 seconds
- Medium binaries (1-10MB): 1-3 minutes
- Large binaries (>10MB): 3-10 minutes

Performance depends on:

- Binary size and complexity
- Number of imports/functions
- Analysis goal complexity
- OpenAI API response times

## Security Considerations

- The tool analyzes binaries statically by default
- Dynamic analysis (if enabled) runs in a sandboxed environment
- No binary execution occurs during static analysis
- API keys should be kept secure
- Analysis results may contain sensitive information

## Contributing

To extend the CLI tool:

1. Modify the workflow in orca/src/cmd/workflow.py
2. Add new agents for specialized analysis
3. Update the serialization logic for new result types
4. Add tests for new functionality

## License

This tool is part of the ORCA framework. See the main project license for details.
