# ORCA Architecture Documentation

## Overview

ORCA is a sophisticated multi-agentic binary analysis framework that leverages Large Language Models (LLMs) and advanced static analysis techniques to provide comprehensive binary analysis capabilities. The system is built around a workflow-driven architecture using LangGraph for orchestrating multiple specialized analysis agents.

## Core Architecture

### Workflow Orchestration

The heart of ORCA is implemented in `workflow.py`, which defines a LangGraph-based state machine that orchestrates multiple specialized agents:

```
┌─────────────────┐    ┌─────────────────┐    ┌─────────────────┐
│   Supervisor    │───▶│   Planning      │───▶│ Static Analysis │
│     Agent       │    │     Agent       │    │     Agent       │
└─────────────────┘    └─────────────────┘    └─────────────────┘
                                                        │
┌─────────────────┐    ┌─────────────────┐    ┌─────────────────┐
│   Chatbot       │◀───│  Generate       │◀───│ API CrossRefs   │
│     Agent       │    │   Summary       │    │     Agent       │
└─────────────────┘    └─────────────────┘    └─────────────────┘
                                                        │
┌─────────────────┐    ┌─────────────────┐    ┌─────────────────┐
│   Malware       │◀───│ Capabilities    │◀───│ API Clustering  │
│   Analysis      │    │   Analysis      │    │     Agent       │
└─────────────────┘    └─────────────────┘    └─────────────────┘
                                                        │
┌─────────────────┐                        ┌─────────────────┐
│   Binary        │◀───────────────────────│ API Analysis    │
│   Summary       │                        │     Agent       │
└─────────────────┘                        └─────────────────┘
```

### 2. Workflow State Management

The system uses a comprehensive `WorkflowState` TypedDict that maintains:

- **Input Parameters**: Binary path, functionality description, analysis goals
- **Analysis Results**: Static analysis, API cross-references, clustering results
- **Workflow Control**: Current step, completed steps, execution plan
- **Output Data**: Capabilities, malware analysis, summaries
- **Chat Integration**: Message history for interactive sessions

### 3. Agent Specialization

Each agent in the workflow has a specific responsibility:

#### Supervisor Agent
- Validates required inputs (binary path, functionality, goal)
- Routes to appropriate workflow paths
- Handles chatbot interaction routing

#### Planning Agent
- Derives execution plan based on analysis goals
- Supports multiple analysis types: capabilities, malware analysis, comprehensive
- Creates dynamic workflow sequences

#### Static Analysis Agent (`smart_static_analysis.py`)
- Uses Binary Ninja API for comprehensive binary analysis
- Extracts imports, exports, functions, sections, strings
- Performs entropy analysis and ELF header parsing
- Integrates LLM for enhanced behavior pattern detection

#### API Analysis Agents
- **API CrossRefs Agent**: Analyzes API cross-references using Binary Ninja
- **API Clustering Agent**: Groups APIs by functionality using LLM
- **API Analysis Agent**: Filters and analyzes API usage patterns

#### Specialized Analysis Agents
- **Capabilities Analysis Agent**: Identifies binary capabilities using LLM
- **Malware Analysis Agent**: Performs security assessment and threat analysis
- **Binary Summary Agent**: Generates comprehensive analysis summaries

## Key Components

### 1. Enhanced CLI Interface (`main_enhanced.py`)

The main interface provides a comprehensive command-line experience:

```python
class OrcaCLI(cmd.Cmd):
    # Interactive commands for binary analysis
    # Enhanced chatbot integration
    # Workflow execution and result management
```

**Key Features:**
- Interactive command-line interface with help system
- Quick analysis modes (quick_analyze, comprehensive_analyze)
- Enhanced chatbot integration with context preservation
- Result saving and conversation history management
- Suspicious string analysis with pattern recognition

### 2. Smart Static Analysis Engine

The static analysis engine (`smart_static_analysis.py`) provides:

**Binary Analysis Capabilities:**
- File information extraction (hashes, permissions, ELF headers)
- String categorization (APIs, URLs, IPs, registry keys, suspicious patterns)
- Import/export analysis with symbol resolution
- Function analysis with behavior pattern detection
- Section analysis with entropy calculation
- Linux-specific malware checks

**LLM Integration:**
- Enhanced behavior pattern detection
- Intelligent string categorization
- Function behavior analysis
- Security assessment generation

### 3. Enhanced Chatbot System

The chatbot system provides multiple interaction modes:

#### Basic Chatbot (`chatbot.py`)
- Simple Q&A interface with analysis context
- Basic string and API search capabilities

#### Enhanced Chatbot (`enhanced_chatbot_complete.py`)
- **Workflow 1**: Comprehensive API listing with clustering
- **Workflow 2**: Detailed API usage analysis with assembly context
- **Workflow 3**: Function analysis with LLM insights
- **Workflow 4**: Malware analysis and vulnerability research

**Advanced Features:**
- Assembly instruction analysis with before/after context
- Cross-reference analysis with code context
- LLM-powered security assessment
- Suspicious string pattern recognition
- Interactive help system

### 4. LLM Integration Layer (`llm_module.py`)

The LLM handler provides robust AI integration:

**Core Features:**
- Multiple LLM provider support via LiteLLM
- Intelligent retry logic with exponential backoff
- Rate limit handling with adaptive token reduction
- Batch processing for large datasets
- JSON response parsing with error recovery

**Analysis Capabilities:**
- Binary behavior analysis
- API function clustering
- Behavior pattern generation
- Security assessment
- Summary report generation

### 5. Configuration Management (`config.py`)

Centralized configuration system supporting:
- LLM provider settings (model, API keys, rate limits)
- Analysis parameters (file size limits, function limits)
- Feature toggles (LLM analysis)
- Behavior pattern definitions
- Environment variable overrides

## Data Flow Architecture

### 1. Analysis Pipeline

```
Binary File Input
       │
       ▼
┌─────────────────┐
│ Static Analysis │ ──┐
│   (Binary Ninja)│   │
└─────────────────┘   │
       │              │
       ▼              │
┌─────────────────┐   │
│ String Analysis │   │
│ & Categorization│   │
└─────────────────┘   │
       │              │
       ▼              │
┌─────────────────┐   │
│ API Cross-Refs  │   │
│   & Clustering  │   │
└─────────────────┘   │
       │              │
       ▼              │
┌─────────────────┐   │
│ LLM Enhancement │◀──┘
│  & Analysis     │
└─────────────────┘
       │
       ▼
┌─────────────────┐
│ Results         │
│ Aggregation     │
└─────────────────┘
       │
       ▼
┌─────────────────┐
│ Interactive     │
│ Chatbot         │
└─────────────────┘
```

### 2. State Management

The workflow maintains comprehensive state through:

```python
class WorkflowState(TypedDict):
    # Input parameters
    binary_path: Optional[str]
    binary_functionality: Optional[str]
    goal: Optional[str]
    
    # Analysis results
    static_analysis_results: Optional[Dict[str, Any]]
    api_crossrefs_results: Optional[Dict[str, Any]]
    api_clustering_results: Optional[Dict[str, Any]]
    
    # Output products
    capabilities: Optional[Dict[str, Any]]
    malware_analysis_results: Optional[Dict[str, Any]]
    final_summary: Optional[Dict[str, Any]]
    
    # Interactive features
    messages: Annotated[List[AnyMessage], add_messages]
```

## Advanced Features

### 1. Cross-Platform Support

**Binary Ninja Integration:**
- Automatic detection of Binary Ninja installation
- Fallback mechanisms for limited functionality
- Cross-platform binary analysis support


### 2. Enhanced String Analysis

The string analysis system (`enhanced_string_analysis.py`) provides:
- Pattern-based suspicious string detection
- Encoding detection (Base64, hex, XOR)
- Risk scoring algorithms
- Contextual analysis with security implications

### 3. API Reference Analysis

Comprehensive API analysis through multiple specialized tools:
- **API Cross-Reference Tool**: Maps API usage to functions
- **Code Reference Analyzer**: Provides assembly context
- **API Reference Analyzer**: Detailed function analysis with LLM insights

### 4. Security Assessment Framework

Multi-layered security analysis:
- **Static Indicators**: Suspicious imports, strings, functions
- **Behavioral Analysis**: Function behavior pattern detection
- **LLM Assessment**: AI-powered threat classification

## Integration Points

### 1. Binary Ninja API
- Primary disassembly and analysis engine
- Function analysis and cross-reference generation
- Symbol resolution and import/export extraction

### 2. LLM Providers
- OpenAI GPT models (primary)
- Extensible to other providers via LiteLLM
- Adaptive token management and rate limiting

### 4. File System Integration
- Result persistence and caching
- Configuration file management
- Conversation history storage

## Error Handling and Resilience

### 1. Graceful Degradation
- Fallback mechanisms for missing components
- Partial analysis completion on errors
- Comprehensive error logging and reporting

### 2. Rate Limit Management
- Adaptive token reduction on rate limits
- Exponential backoff with jitter
- Batch processing optimization

### 3. Resource Management
- Memory-efficient processing of large binaries
- Configurable analysis limits
- Automatic cleanup of temporary resources

## Usage Patterns

### 1. Command-Line Analysis
```bash
# Quick capabilities analysis
python main_enhanced.py --binary sample.exe --functionality "Text editor" --analyze

# Interactive mode
python main_enhanced.py
orca> set_binary sample.exe
orca> set_functionality "Text editor application"
orca> analyze
orca> chat
```

### 2. Programmatic Integration
```python
from workflow import run_workflow

results = run_workflow(
    binary_path="sample.exe",
    binary_functionality="Text editor",
    goal="capabilities and malware analysis"
)
```

### 3. Enhanced Chatbot Workflows
```
chat> list apis                    # Comprehensive API listing
chat> how is CreateFile used?      # Detailed API usage analysis
chat> analyze function main        # Function-level analysis
chat> malware analysis            # Security assessment
```

## Performance Considerations

### 1. Analysis Optimization
- Configurable limits on functions and strings analyzed
- Batch processing for LLM operations
- Intelligent caching of analysis results

### 2. Memory Management
- Streaming analysis for large binaries
- Cleanup of Binary Ninja resources
- Efficient state serialization

### 3. Network Efficiency
- Rate limit compliance
- Adaptive token usage
- Retry logic with backoff

## Security Considerations

### 1. Input Validation
- File type verification
- Size limit enforcement
- Path traversal protection

### 2. Output Sanitization
- Safe handling of binary content
- Secure temporary file management
- Controlled LLM output processing

### 3. Static Analysis Security
- No binary execution during analysis
- Safe disassembly and parsing
- Controlled string extraction and processing

## Extensibility

The architecture supports extension through:

### 1. New Analysis Agents
- Plugin-style agent development
- Standardized state interface
- LangGraph integration patterns

### 2. Additional LLM Providers
- LiteLLM abstraction layer
- Provider-specific optimizations
- Fallback provider support

### 3. Custom Workflows
- Configurable analysis pipelines
- Goal-based workflow selection
- Dynamic agent routing

## Conclusion

ORCA represents a sophisticated approach to binary analysis that combines traditional reverse engineering techniques with modern AI capabilities. The multi-agentic architecture provides flexibility, scalability, and comprehensive analysis capabilities while maintaining usability through enhanced interactive interfaces.

The system's modular design allows for easy extension and customization while providing robust error handling and graceful degradation. The integration of LLM capabilities enhances traditional static analysis with intelligent pattern recognition and contextual understanding, making it a powerful tool for both security researchers and malware analysts.
