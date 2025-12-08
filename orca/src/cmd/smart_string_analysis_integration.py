"""
Smart String Analysis Integration Example
Shows how to integrate the smart string analysis module into the BinSleuth workflow
"""
import json
import os
from typing import List, Dict, Any, Optional

from string_analysis import analyze_binary_strings
from smart_string_analysis import (
    SmartStringAnalyzer,
    filter_valid_strings,
    filter_valid_urls,
    filter_valid_domains,
    filter_valid_ips
)

def analyze_strings_with_smart_validation(
    strings: List[str], 
    use_llm: bool = True, 
    llm_threshold: int = 50,
    analyze_files: bool = True
) -> Dict[str, Any]:
    """
    Enhanced string analysis that combines traditional binary string analysis
    with smart string validation.
    
    Args:
        strings: List of extracted strings from binary
        use_llm: Whether to use LLM for advanced analysis
        llm_threshold: Minimum number of strings before using sampling for LLM
        analyze_files: Whether to analyze found file paths
    
    Returns:
        Dictionary containing categorized artifacts with validation information
    """
    # First, run the traditional string analysis
    traditional_results = analyze_binary_strings(
        strings, 
        use_llm=use_llm, 
        llm_threshold=llm_threshold, 
        analyze_files=analyze_files
    )
    
    # Then, run smart string analysis on the extracted categories
    smart_results = {
        "valid": {},
        "invalid": {},
        "metadata": {}
    }
    
    # Create analyzer
    analyzer = SmartStringAnalyzer(use_llm=use_llm)
    
    # Process URLs
    if traditional_results.get("urls"):
        valid_urls, invalid_urls = filter_valid_urls(traditional_results["urls"], use_llm=use_llm)
        smart_results["valid"]["urls"] = valid_urls
        smart_results["invalid"]["urls"] = invalid_urls
    
    # Process domains
    if traditional_results.get("domains"):
        valid_domains, invalid_domains = filter_valid_domains(traditional_results["domains"], use_llm=use_llm)
        smart_results["valid"]["domains"] = valid_domains
        smart_results["invalid"]["domains"] = invalid_domains
    
    # Process IP addresses
    if traditional_results.get("ip_addresses"):
        valid_ips, invalid_ips = filter_valid_ips(traditional_results["ip_addresses"], use_llm=use_llm)
        smart_results["valid"]["ip_addresses"] = valid_ips
        smart_results["invalid"]["ip_addresses"] = invalid_ips
    
    # Process other strings that might be interesting
    other_strings = []
    for category in ["apis", "hashes", "keys", "paths", "registry", "suspicious"]:
        if traditional_results.get(category):
            other_strings.extend(traditional_results[category])
    
    if other_strings:
        other_results = filter_valid_strings(other_strings, use_llm=use_llm)
        
        # Merge results
        for category in other_results["valid"]:
            if category not in smart_results["valid"]:
                smart_results["valid"][category] = []
            smart_results["valid"][category].extend(other_results["valid"][category])
        
        for category in other_results["invalid"]:
            if category not in smart_results["invalid"]:
                smart_results["invalid"][category] = []
            smart_results["invalid"][category].extend(other_results["invalid"][category])
        
        # Add metadata
        smart_results["metadata"].update(other_results["metadata"])
    
    # Combine results
    combined_results = {
        # Keep original categories for backward compatibility
        **traditional_results,
        
        # Add smart validation results
        "smart_validation": {
            "valid": smart_results["valid"],
            "invalid": smart_results["invalid"]
        },
        
        # Add summary statistics
        "summary": {
            "total_strings": len(strings),
            "valid_count": sum(len(items) for items in smart_results["valid"].values()),
            "invalid_count": sum(len(items) for items in smart_results["invalid"].values()),
            "categories": {
                category: len(traditional_results.get(category, [])) 
                for category in ["apis", "hashes", "keys", "paths", "urls", "registry", "ip_addresses", "domains", "suspicious"]
            }
        }
    }
    
    return combined_results


def analyze_binary_file(
    binary_path: str, 
    output_path: Optional[str] = None,
    use_llm: bool = True
) -> Dict[str, Any]:
    """
    Analyze strings in a binary file using smart string analysis
    
    Args:
        binary_path: Path to the binary file
        output_path: Optional path to save results
        use_llm: Whether to use LLM for analysis
        
    Returns:
        Analysis results
    """
    # Import here to avoid circular imports
    from static_analysis import extract_strings_from_binary
    
    # Extract strings from binary
    print(f"Extracting strings from {binary_path}...")
    strings = extract_strings_from_binary(binary_path)
    print(f"Extracted {len(strings)} strings")
    
    # Analyze strings
    print("Analyzing strings with smart validation...")
    results = analyze_strings_with_smart_validation(strings, use_llm=use_llm)
    
    # Save results if output path is provided
    if output_path:
        os.makedirs(os.path.dirname(os.path.abspath(output_path)), exist_ok=True)
        with open(output_path, 'w') as f:
            json.dump(results, f, indent=2)
        print(f"Results saved to {output_path}")
    
    return results


def print_analysis_summary(results: Dict[str, Any]) -> None:
    """
    Print a summary of the analysis results
    
    Args:
        results: Analysis results
    """
    print("\n=== String Analysis Summary ===")
    
    # Print summary statistics
    summary = results.get("summary", {})
    print(f"Total strings analyzed: {summary.get('total_strings', 'N/A')}")
    print(f"Valid strings: {summary.get('valid_count', 'N/A')}")
    print(f"Invalid strings: {summary.get('invalid_count', 'N/A')}")
    
    # Print category counts
    print("\nCategory counts:")
    for category, count in summary.get("categories", {}).items():
        print(f"  {category}: {count}")
    
    # Print valid URLs, domains, and IPs
    smart_validation = results.get("smart_validation", {})
    valid = smart_validation.get("valid", {})
    
    print("\nValid URLs:")
    for url in valid.get("urls", [])[:10]:  # Limit to 10 for brevity
        print(f"  - {url}")
    if len(valid.get("urls", [])) > 10:
        print(f"  ... and {len(valid.get('urls', [])) - 10} more")
    
    print("\nValid domains:")
    for domain in valid.get("domains", [])[:10]:
        print(f"  - {domain}")
    if len(valid.get("domains", [])) > 10:
        print(f"  ... and {len(valid.get('domains', [])) - 10} more")
    
    print("\nValid IP addresses:")
    for ip in valid.get("ip_addresses", [])[:10]:
        print(f"  - {ip}")
    if len(valid.get("ip_addresses", [])) > 10:
        print(f"  ... and {len(valid.get('ip_addresses', [])) - 10} more")
    
    # Print suspicious strings
    print("\nSuspicious strings:")
    for s in results.get("suspicious", [])[:10]:
        print(f"  - {s}")
    if len(results.get("suspicious", [])) > 10:
        print(f"  ... and {len(results.get('suspicious', [])) - 10} more")


if __name__ == "__main__":
    import sys
    
    if len(sys.argv) < 2:
        print("Usage: python smart_string_analysis_integration.py <binary_path> [output_path]")
        sys.exit(1)
    
    binary_path = sys.argv[1]
    output_path = sys.argv[2] if len(sys.argv) > 2 else None
    
    # Analyze binary
    results = analyze_binary_file(binary_path, output_path)
    
    # Print summary
    print_analysis_summary(results)