#!/usr/bin/env python3
"""
Simple script to check if the sample file exists
"""
import os
import sys
from pathlib import Path
os.environ['OPENAI_API_KEY'] = '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'

def main():
    """Main function"""
    # Check if OpenAI API key is set
    if not os.environ.get('OPENAI_API_KEY'):
        print("Error: OPENAI_API_KEY environment variable is not set")
        print("Please set it before running this script")
        sys.exit(1)
    else:
        print(f"OPENAI_API_KEY is set: {os.environ.get('OPENAI_API_KEY')[:5]}...")
    
    # Define sample path
    binary_path = "samples/nslookupbin"
    
    # Check if binary exists
    if Path(binary_path).exists():
        print(f"Sample file exists: {binary_path}")
        print(f"Absolute path: {Path(binary_path).absolute()}")
    else:
        print(f"Error: Sample file not found: {binary_path}")
        print(f"Current working directory: {os.getcwd()}")
        print("Listing contents of 'samples' directory (if it exists):")
        samples_dir = Path("samples")
        if samples_dir.exists():
            for item in samples_dir.iterdir():
                print(f"  {item.name}")
        else:
            print("  'samples' directory does not exist")
    
    # Print Python path
    print("\nPython path:")
    for path in sys.path:
        print(f"  {path}")

if __name__ == "__main__":
    main()
