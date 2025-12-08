# API Cross-References Tool

This directory contains tools for analyzing binary files to find cross-references to API functions.

## Files

- `api_crossrefs.py`: The main module containing the `ApiCrossReferenceTool` class
- `test_api_crossrefs.py`: A test script for using the `ApiCrossReferenceTool` class
- `example_api_crossrefs.sh`: Example shell script demonstrating usage of the test script

## Requirements

- Binary Ninja (with Python API)
- Python 3.6+

## Usage

### Basic Usage

```bash
python test_api_crossrefs.py <binary_path> [api_names...]
```

### Arguments

- `binary_path`: Path to the binary file to analyze
- `api_names`: (Optional) API function names to search for. If not provided, defaults to `_memcpy`, `_strcpy`, `_malloc`, and `_bind`

### Options

- `-o, --output`: Output file path for JSON results (default: stdout)
- `-v, --verbose`: Enable verbose output

### Examples

1. Basic usage with default API functions:

   ```bash
   python test_api_crossrefs.py /path/to/binary
   ```

2. Specify specific API functions:

   ```bash
   python test_api_crossrefs.py /path/to/binary _memcpy _malloc
   ```

3. Save results to a file:

   ```bash
   python test_api_crossrefs.py /path/to/binary _strcpy _bind -o api_crossrefs_results.json
   ```

4. Verbose output:
   ```bash
   python test_api_crossrefs.py /path/to/binary -v
   ```

### Using the Example Script

The `example_api_crossrefs.sh` script demonstrates various ways to use the test script:

```bash
./example_api_crossrefs.sh /path/to/binary
```

## Output Format

The output is a JSON object with API names as keys and lists of cross-reference information as values:

```json
{
  "_memcpy": [
    {
      "api_name": "_memcpy",
      "references": [
        {
          "function": "main",
          "start_addr": "0x1000",
          "end_addr": "0x1100",
          "callsites": ["0x1050", "0x1080"]
        },
        {
          "function": "process_data",
          "start_addr": "0x2000",
          "end_addr": "0x2100",
          "callsites": ["0x2030"]
        }
      ]
    }
  ],
  "_malloc": [
    {
      "api_name": "_malloc",
      "references": [
        {
          "function": "init",
          "start_addr": "0x3000",
          "end_addr": "0x3100",
          "callsites": ["0x3020", "0x3080"]
        }
      ]
    }
  ]
}
```

## Implementation Details

The `ApiCrossReferenceTool` class uses Binary Ninja's API to analyze the binary file. It looks for call instructions in the binary's low-level IL and checks if the destination of the call matches any of the specified API functions.

The tool is optimized to efficiently find and deduplicate API references within functions, making it suitable for analyzing large binaries.
