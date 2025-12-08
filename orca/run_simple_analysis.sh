#!/bin/bash
# Simple wrapper script to run the simplified workflow

# Check if binary path is provided
if [ -z "$1" ]; then
  echo "Usage: $0 <binary_path> [output_file]"
  exit 1
fi

BINARY_PATH="$1"
OUTPUT_FILE="${2:-tres.json}"
FUNCTIONALITY="Network utility binary, nslookup"
GOAL="capabilities"
QUESTION="summarize this binary's features"

# Check if binary exists
if [ ! -f "$BINARY_PATH" ]; then
  echo "Error: Binary file not found: $BINARY_PATH"
  exit 1
fi

echo "Running simplified analysis on $BINARY_PATH..."
echo "Output will be saved to $OUTPUT_FILE"

# Run the simplified workflow
cd "$(dirname "$0")"
poetry run python src/cmd/test_simple_workflow.py -b "$BINARY_PATH" -f "$FUNCTIONALITY" -g "$GOAL" -o "$OUTPUT_FILE" -q "$QUESTION"

# Check if the output file was created
if [ -f "$OUTPUT_FILE" ]; then
  echo "Analysis completed successfully. Results saved to $OUTPUT_FILE"
else
  echo "Error: Output file was not created"
  exit 1
fi
