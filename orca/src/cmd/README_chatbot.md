# ORCA Enhanced Chatbot Implementation

## Overview

The ORCA Enhanced Chatbot (`chatbot.py`) provides a comprehensive interactive chat interface for binary analysis with deep context from all analysis results. It integrates with the workflow system to use complete analysis data as a knowledge base.

## Features

### Core Functionality

- **Interactive Chat Interface**: Natural language queries about binary analysis results
- **Comprehensive Context Integration**: Uses all analysis modules' results as knowledge base
- **Specific Command Processing**: Handles specialized commands for targeted analysis
- **LLM Integration**: Uses advanced language models for intelligent responses
- **Conversation Management**: Tracks, saves, and loads conversation history

### Analysis Context Integration

The chatbot integrates with multiple analysis modules:

- Static analysis results (functions, imports, exports, strings)
- API cross-references and clustering
- Malware analysis and threat assessment
- Capabilities analysis
- Binary summary and security assessment
- Dynamic analysis results (when available)
- Enhanced string analysis with suspicious pattern detection

## Class Structure

### ORCA Chatbot

Main chatbot class that provides interactive analysis capabilities.

#### Initialization

```python
chatbot = ORCAChatbot(analysis_context=None)
```

**Parameters:**

- `analysis_context`: Dictionary containing complete analysis results from workflow

#### Key Methods

##### Core Chat Methods

- `chat(user_message: str) -> str`: Process user message and return response
- `update_context(new_context: Dict[str, Any])`: Update analysis context
- `interactive_chat()`: Start interactive chat session

##### Conversation Management

- `get_conversation_summary() -> Dict[str, Any]`: Get conversation statistics
- `clear_conversation()`: Clear conversation history
- `save_conversation(filepath: str)`: Save conversation to file
- `load_conversation(filepath: str) -> bool`: Load conversation from file

##### Context Processing

- `_prepare_comprehensive_context() -> str`: Prepare analysis summary for LLM
- `_process_specific_commands(message: str) -> Optional[str]`: Handle specific commands
- `_process_general_query(message: str) -> str`: Process general queries with LLM

## Supported Commands

### Specific Commands

- `find string "text"` - Search for specific strings in the binary
- `find api "name"` - Search for specific API usage
- `analyze function "name"` - Get detailed analysis of a function
- `list functions` - Show all functions found in the binary
- `list apis` - Show all APIs/imports used by the binary
- `suspicious strings` - Find strings that might indicate malicious behavior
- `cross reference "item"` - Find cross-references for APIs or strings
- `help` - Show available commands

### General Queries

The chatbot can answer natural language questions such as:

- "What does this binary do?"
- "Is this binary malicious?"
- "What network capabilities does this have?"
- "What files does this access?"
- "Explain the main functionality"
- "What are the security implications?"

## Integration with Analysis Modules

### Enhanced String Analysis

- Integrates with `EnhancedStringAnalyzer` for suspicious string detection
- Analyzes strings for malware indicators, backdoor patterns, and evasion techniques
- Provides risk scoring and categorized threat assessment

### Code Reference Analysis

- Uses `CodeReferenceAnalyzer` for finding string references in code
- Provides assembly context and function information
- Supports Binary Ninja integration when available

### API Reference Analysis

- Integrates with `ApiReferenceAnalyzer` for detailed API usage analysis
- Provides cross-reference information and usage context
- Includes LLM-based analysis of API behavior

## Usage Examples

### Basic Usage

```python
from chatbot import ORCAChatbot, create_chatbot_with_context

# Create chatbot with analysis context
analysis_context = {
    "binary_functionality": "Network monitoring tool",
    "static_analysis_results": {...},
    "api_crossrefs_results": {...},
    # ... other analysis results
}

chatbot = create_chatbot_with_context(analysis_context)

# Interactive queries
response = chatbot.chat("What does this binary do?")
response = chatbot.chat("list functions")
response = chatbot.chat("find api CreateFile")
```

### Interactive Session

```python
# Start interactive chat session
chatbot.interactive_chat()
```

### Conversation Management

```python
# Save conversation
chatbot.save_conversation("analysis_session.json")

# Load previous conversation
chatbot.load_conversation("analysis_session.json")

# Get conversation summary
summary = chatbot.get_conversation_summary()
```

## Context Structure

The chatbot expects analysis context in the following structure:

```python
analysis_context = {
    "binary_functionality": str,  # Declared purpose of binary
    "goal": str,  # Analysis goal
    "static_analysis_results": {
        "file_info": {...},
        "imports": [...],
        "exports": [...],
        "functions": [...],
        "strings": {...}
    },
    "api_crossrefs_results": {...},
    "api_clustering_results": {...},
    "api_analysis_results": {...},
    "capabilities": {...},
    "malware_analysis_results": {...},
    "binary_summary_results": {...},
    "dynamic_analysis_results": {...},
    "final_summary": {...}
}
```

## Dependencies

### Required Modules

- `llm_module`: For LLM integration and intelligent responses
- `enhanced_string_analysis`: For suspicious string detection
- `code_reference_analyzer`: For code reference analysis
- `api_reference_analyzer`: For API reference analysis

### Optional Dependencies

- Binary Ninja API (for enhanced code analysis)
- Various analysis modules from the ORCA framework

## Error Handling

The chatbot includes comprehensive error handling:

- Graceful degradation when analysis modules are unavailable
- Fallback responses when LLM queries fail
- Safe handling of malformed analysis context
- User-friendly error messages

## Testing

### Test Files

- `test_chatbot.py`: Comprehensive test suite with full dependencies
- `test_chatbot_simple.py`: Basic test suite with mocked dependencies

### Running Tests

```bash
# Basic syntax check
python3 -m py_compile chatbot.py

# Simple test (with mocked dependencies)
python3 test_chatbot_simple.py

# Full test (requires all dependencies)
python3 test_chatbot.py
```

## Configuration

### LLM Configuration

The chatbot uses the `llm_module` for language model integration. Ensure proper configuration of:

- API keys for LLM services
- Model selection and parameters
- Rate limiting and error handling

### Analysis Module Configuration

Configure the integrated analysis modules:

- Binary Ninja path (if using Binary Ninja integration)
- Analysis parameters and thresholds
- Output formats and verbosity levels

## Performance Considerations

### Context Management

- Large analysis contexts are summarized for LLM processing
- Conversation history is limited to recent exchanges
- Caching is used for repeated queries

### Memory Usage

- Analysis context is stored in memory for fast access
- Conversation history grows with usage
- Consider periodic cleanup for long sessions

## Security Considerations

### Input Validation

- User inputs are sanitized before processing
- Quoted text extraction prevents injection attacks
- File operations include path validation

### Analysis Context

- Analysis context may contain sensitive information
- Consider encryption for saved conversations
- Implement access controls for production use

## Future Enhancements

### Planned Features

- Multi-language support for international users
- Voice interface integration
- Advanced visualization of analysis results
- Integration with additional analysis tools
- Custom command plugins

### Extensibility

- Plugin architecture for custom commands
- Configurable response templates
- Custom analysis module integration
- API endpoints for external integration

## Troubleshooting

### Common Issues

1. **Import Errors**: Ensure all required modules are installed
2. **LLM Failures**: Check API configuration and network connectivity
3. **Context Errors**: Validate analysis context structure
4. **Performance Issues**: Consider reducing context size or conversation history

### Debug Mode

Enable debug logging by setting environment variables or modifying the logging configuration in the chatbot module.

## Contributing

When extending the chatbot:

1. Follow the existing code structure and patterns
2. Add comprehensive error handling
3. Include unit tests for new functionality
4. Update documentation for new features
5. Consider backward compatibility

## License

This module is part of the ORCA framework and follows the same licensing terms.
