#!/bin/bash
# Example script for using the API Analysis Agent in a workflow
# This script demonstrates how to analyze a binary file using the API Analysis Agent

# Check if a binary file is provided
if [ $# -lt 1 ]; then
    echo "Usage: $0 <binary_file>"
    exit 1
fi

BINARY_FILE=$1
GOAL="Analyze API capabilities and identify suspicious behavior"
FUNCTIONALITY="A utility program that processes files"

echo "=== API Analysis Example ==="
echo "Binary: $BINARY_FILE"
echo "Goal: $GOAL"
echo "Functionality: $FUNCTIONALITY"
echo "=========================="

# Run the API analysis test script
echo "Running API analysis..."
python test_api_analysis.py "$BINARY_FILE" "$GOAL" "$FUNCTIONALITY"

# Check if the analysis was successful
if [ $? -ne 0 ]; then
    echo "Error: API analysis failed"
    exit 1
fi

# Get the output file name
OUTPUT_FILE="$(basename $BINARY_FILE)_api_analysis.json"

# Check if the output file exists
if [ ! -f "$OUTPUT_FILE" ]; then
    echo "Error: Output file not found"
    exit 1
fi

echo "=========================="
echo "API analysis completed successfully"
echo "Results saved to $OUTPUT_FILE"
echo "=========================="

# Optional: Run the full workflow with the API analysis step
echo "Would you like to run the full workflow? (y/n)"
read -r RESPONSE
if [[ "$RESPONSE" =~ ^([yY][eE][sS]|[yY])$ ]]; then
    echo "Running full workflow..."
    python workflow.py "$BINARY_FILE" "$FUNCTIONALITY" "$GOAL"
    
    echo "=========================="
    echo "Workflow completed"
    echo "=========================="
fi

echo "Example completed"
