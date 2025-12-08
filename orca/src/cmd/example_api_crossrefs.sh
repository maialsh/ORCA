#!/bin/bash
# Example usage of test_api_crossrefs.py

# Check if a binary path was provided
if [ $# -eq 0 ]; then
    echo "Usage: $0 <path_to_binary>"
    echo "Example: $0 /path/to/binary"
    exit 1
fi

BINARY_PATH=$1

# Example 1: Basic usage with default API functions
echo "Example 1: Basic usage with default API functions"
python test_api_crossrefs.py "$BINARY_PATH"

# Example 2: Specify specific API functions
echo -e "\nExample 2: Specify specific API functions"
python test_api_crossrefs.py "$BINARY_PATH" _memcpy _malloc

# Example 3: Save results to a file
echo -e "\nExample 3: Save results to a file"
python test_api_crossrefs.py "$BINARY_PATH" _strcpy _bind -o api_crossrefs_results.json
echo "Results saved to api_crossrefs_results.json"

# Example 4: Verbose output
echo -e "\nExample 4: Verbose output"
python test_api_crossrefs.py "$BINARY_PATH" -v
