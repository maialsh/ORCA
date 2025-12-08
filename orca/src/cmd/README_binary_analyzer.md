# Binary Analyzer Module

A comprehensive Binary Ninja-based analysis module for ELF and PE binaries that provides advanced functionality for call graph generation, API analysis, and function relationship mapping.

## Overview

The `BinaryAnalyzer` module is a refactored and enhanced version of the original `testre.py` script. It provides a clean, object-oriented interface for binary analysis using Binary Ninja's powerful analysis capabilities.

## Features

### Core Functionality

- **Binary Loading**: Supports ELF and PE binary formats
- **Call Graph Generation**: Creates comprehensive call graphs with caller/callee relationships
- **API Function Analysis**: Finds and analyzes specific API functions (e.g., strcpy, malloc)
- **Function Relationship Mapping**: Identifies directly connected functions and their assembly
- **Assembly Instruction Extraction**: Retrieves detailed assembly code for any function
- **Export Capabilities**: Exports call graphs in JSON, DOT, and text formats

### Key Classes

#### `BinaryAnalyzer`

The main analysis class that provides all functionality.

```python
from binary_analyzer import BinaryAnalyzer

# Initialize with a binary file
analyzer = BinaryAnalyzer("path/to/binary")

# Generate call graph
call_graph = analyzer.generate_call_graph()

# Find specific API function
strcpy_info = analyzer.find_api_function("strcpy")

# Get connected functions
connected = analyzer.get_connected_functions("main")

# Clean up
analyzer.close()
```

#### `FunctionInfo`

Data class containing comprehensive function information:

- Function name and address
- Assembly instructions
- Functions it calls (callees)
- Functions that call it (callers)

#### `CallGraphNode`

Data class representing nodes in the call graph:

- Function name and address
- List of caller functions
- List of callee functions

## API Reference

### BinaryAnalyzer Methods

#### `__init__(binary_path: str)`

Initialize the analyzer with a binary file.

#### `generate_call_graph() -> Dict[str, CallGraphNode]`

Generate a complete call graph for the binary.

#### `find_api_function(api_name: str) -> Optional[FunctionInfo]`

Find a specific API function and return its detailed information.

```python
# Example: Find strcpy function
strcpy_info = analyzer.find_api_function("strcpy")
if strcpy_info:
    print(f"Found at: 0x{strcpy_info.address:x}")
    print(f"Assembly lines: {len(strcpy_info.assembly_instructions)}")
```

#### `get_connected_functions(function_name: str) -> Dict[str, FunctionInfo]`

Get all functions directly connected to the specified function.

```python
# Example: Get functions connected to main
connected = analyzer.get_connected_functions("main")
for name, func_info in connected.items():
    print(f"{name}: {func_info.name} at 0x{func_info.address:x}")
```

#### `get_function_assembly(function_name: str) -> List[str]`

Get assembly instructions for a specific function.

#### `search_api_usage(api_name: str) -> List[Tuple[str, List[str]]]`

Search for usage of a specific API across all functions.

#### `export_call_graph(output_file: str, format_type: str = "json") -> bool`

Export the call graph to a file in various formats:

- `"json"`: JSON format for programmatic use
- `"dot"`: Graphviz DOT format for visualization
- `"txt"`: Plain text format for human reading

#### `get_binary_info() -> Dict[str, Any]`

Get general information about the loaded binary.

#### `close()`

Clean up resources and close the binary.

## Usage Examples

### Basic Analysis

```python
from binary_analyzer import BinaryAnalyzer

# Load binary
analyzer = BinaryAnalyzer("sample_binary")

# Get binary information
info = analyzer.get_binary_info()
print(f"Architecture: {info['architecture']}")
print(f"Functions: {info['function_count']}")

# Generate call graph
call_graph = analyzer.generate_call_graph()
print(f"Call graph has {len(call_graph)} nodes")

analyzer.close()
```

### API Function Analysis

```python
# Find strcpy function
strcpy_info = analyzer.find_api_function("strcpy")
if strcpy_info:
    print(f"strcpy found at 0x{strcpy_info.address:x}")

    # Show assembly instructions
    for instruction in strcpy_info.assembly_instructions[:5]:
        print(instruction)

    # Show what calls strcpy
    print(f"Called by: {strcpy_info.called_by}")
```

### Function Relationship Analysis

```python
# Analyze main function relationships
connected = analyzer.get_connected_functions("main")

# Separate callers and callees
callers = {k: v for k, v in connected.items() if k.startswith('caller_')}
callees = {k: v for k, v in connected.items() if k.startswith('callee_')}

print(f"Functions calling main: {len(callers)}")
print(f"Functions called by main: {len(callees)}")

# Show assembly for each callee
for name, func_info in callees.items():
    print(f"\n{name}:")
    for instruction in func_info.assembly_instructions[:3]:
        print(f"  {instruction}")
```

### Call Graph Export

```python
# Export in different formats
analyzer.export_call_graph("call_graph.json", "json")
analyzer.export_call_graph("call_graph.dot", "dot")
analyzer.export_call_graph("call_graph.txt", "txt")

# Visualize DOT file with Graphviz
# dot -Tpng call_graph.dot -o call_graph.png
```

## Command Line Usage

### Using the refactored testre.py

```bash
# Run comprehensive analysis
python testre.py /path/to/binary

# This will:
# - Display binary information
# - Generate call graph
# - Search for common APIs
# - Analyze function relationships
# - Export call graphs in multiple formats
```

### Using the test script

```bash
# Test the module functionality
python test_binary_analyzer.py

# This will run a comprehensive test suite
```

## File Structure

```
binsleuth/src/cmd/
├── binary_analyzer.py          # Main BinaryAnalyzer module
├── testre.py                   # Refactored demonstration script
├── test_binary_analyzer.py     # Test suite
└── README_binary_analyzer.md   # This documentation
```

## Dependencies

- **Binary Ninja**: Commercial binary analysis platform
  - Python API must be available
  - Default path: `/Applications/Binary Ninja.app/Contents/Resources/python`
- **Python 3.7+**: Required for type hints and dataclasses
- **Standard libraries**: os, sys, json, typing

## Installation and Setup

1. **Install Binary Ninja**: Ensure Binary Ninja is installed and licensed
2. **Verify Python API**: Check that the Binary Ninja Python API is accessible
3. **Update path if needed**: Modify `BINARY_NINJA_PATH` in the module if your installation differs

## Error Handling

The module includes comprehensive error handling:

- **Binary loading failures**: Graceful handling of unsupported formats
- **Analysis errors**: Continues operation when individual functions fail
- **Export errors**: Reports issues with file writing
- **Missing APIs**: Handles cases where requested functions don't exist

## Performance Considerations

- **Large binaries**: Analysis time scales with binary size and complexity
- **Memory usage**: Call graphs for large binaries can consume significant memory
- **Caching**: Function information is cached for repeated access

## Integration with Existing Code

The module is designed to integrate seamlessly with the existing binsleuth framework:

```python
# Import in other modules
from binary_analyzer import BinaryAnalyzer, FunctionInfo

# Use in analysis workflows
def analyze_binary_for_vulnerabilities(binary_path):
    analyzer = BinaryAnalyzer(binary_path)

    # Look for dangerous functions
    dangerous_apis = ['strcpy', 'gets', 'sprintf']
    vulnerabilities = []

    for api in dangerous_apis:
        usage = analyzer.search_api_usage(api)
        if usage:
            vulnerabilities.extend(usage)

    analyzer.close()
    return vulnerabilities
```

## Future Enhancements

Potential areas for expansion:

1. **Control Flow Analysis**: Add CFG generation capabilities
2. **Data Flow Analysis**: Track data flow between functions
3. **Vulnerability Detection**: Automated detection of common vulnerability patterns
4. **Interactive Visualization**: Web-based call graph visualization
5. **Batch Processing**: Support for analyzing multiple binaries
6. **Plugin System**: Extensible analysis plugins

## Troubleshooting

### Common Issues

1. **Binary Ninja not found**

   ```
   Warning: Binary Ninja python API not found in expected folder
   ```

   - Solution: Update `BINARY_NINJA_PATH` or install Binary Ninja

2. **Binary loading fails**

   ```
   Error: Failed to load binary
   ```

   - Solution: Ensure binary is valid ELF/PE format and readable

3. **No functions found**
   ```
   No functions found in binary
   ```
   - Solution: Binary may be stripped or packed; try different analysis settings

### Debug Mode

Enable verbose output by modifying the analyzer initialization:

```python
# Add debug prints in _load_binary method
analyzer = BinaryAnalyzer(binary_path)
```

## Contributing

When contributing to this module:

1. **Maintain compatibility**: Ensure changes work with existing Binary Ninja versions
2. **Add tests**: Include test cases for new functionality
3. **Update documentation**: Keep this README current with changes
4. **Follow style**: Use consistent coding style and type hints

## License

This module is part of the binsleuth project and follows the same licensing terms.
