#!/bin/bash
# BinSleuth Analysis Script
# This script demonstrates how to run the BinSleuth multi-agentic workflow

# Check if required arguments are provided
if [ $# -lt 3 ]; then
    echo "Usage: $0 <binary_path> <functionality> <goal>"
    echo "Example: $0 /path/to/binary 'A network utility' 'capabilities'"
    exit 1
fi

BINARY_PATH="$1"
FUNCTIONALITY="$2"
GOAL="$3"

# Check if binary exists
if [ ! -f "$BINARY_PATH" ]; then
    echo "Error: Binary file not found: $BINARY_PATH"
    exit 1
fi

# Set up environment (if needed)
if [ -z "$OPENAI_API_KEY" ]; then
    echo "Warning: OPENAI_API_KEY environment variable not set."
    echo "You may need to set this for the analysis to work properly."
    echo "Example: export OPENAI_API_KEY=your_api_key_here"
fi

# Run the analysis
echo "Starting BinSleuth analysis..."
echo "Binary: $BINARY_PATH"
echo "Functionality: $FUNCTIONALITY"
echo "Goal: $GOAL"
echo ""
echo "This may take some time. Please wait..."
echo ""

# Run the workflow using the test_workflow.py script
python3 src/cmd/test_workflow.py --binary "$BINARY_PATH" --functionality "$FUNCTIONALITY" --goal "$GOAL"

# Exit with the same status as the Python script
exit $?
