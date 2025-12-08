#!/usr/bin/env python3
"""
Simple script to check if the test_result.json file contains the malware_analysis_results key
"""
import sys
import json
import os

def main():
    """Check if the test_result.json file contains the malware_analysis_results key"""
    try:
        # Check if the test_result.json file exists
        if not os.path.exists("test_result.json"):
            print("Error: test_result.json file not found")
            return 1
        
        # Read the test_result.json file
        with open("test_result.json", "r") as f:
            data = json.load(f)
        
        # Check if the file contains the malware_analysis_results key
        if "malware_analysis_results" in data:
            print("SUCCESS: test_result.json contains malware_analysis_results key")
            print(f"Value: {data['malware_analysis_results']}")
            return 0
        else:
            print("ERROR: test_result.json does not contain malware_analysis_results key")
            print(f"Keys found: {list(data.keys())}")
            return 1
    except Exception as e:
        print(f"Error checking test_result.json: {str(e)}")
        return 1

if __name__ == "__main__":
    sys.exit(main())
