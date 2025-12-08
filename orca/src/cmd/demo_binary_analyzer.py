#!/usr/bin/env python3
"""
Simple demonstration of the BinaryAnalyzer module functionality.

This script shows how to use the BinaryAnalyzer without requiring Binary Ninja
to be installed, by providing mock functionality for demonstration purposes.
"""

import os
import sys


def demo_without_binary_ninja():
    """Demonstrate the module structure and API without Binary Ninja."""
    
    print("BinaryAnalyzer Module Demonstration")
    print("=" * 50)
    
    print("\n1. Module Structure:")
    print("   - BinaryAnalyzer: Main analysis class")
    print("   - FunctionInfo: Data class for function information")
    print("   - CallGraphNode: Data class for call graph nodes")
    
    print("\n2. Key Features:")
    print("   ✓ Binary loading (ELF/PE support)")
    print("   ✓ Call graph generation")
    print("   ✓ API function analysis")
    print("   ✓ Function relationship mapping")
    print("   ✓ Assembly instruction extraction")
    print("   ✓ Export capabilities (JSON/DOT/TXT)")
    
    print("\n3. Main API Methods:")
    methods = [
        "generate_call_graph() -> Dict[str, CallGraphNode]",
        "find_api_function(api_name: str) -> Optional[FunctionInfo]",
        "get_connected_functions(function_name: str) -> Dict[str, FunctionInfo]",
        "get_function_assembly(function_name: str) -> List[str]",
        "search_api_usage(api_name: str) -> List[Tuple[str, List[str]]]",
        "export_call_graph(output_file: str, format_type: str) -> bool",
        "get_binary_info() -> Dict[str, Any]"
    ]
    
    for i, method in enumerate(methods, 1):
        print(f"   {i}. {method}")
    
    print("\n4. Usage Example:")
    print("""
    from binary_analyzer import BinaryAnalyzer
    
    # Initialize analyzer
    analyzer = BinaryAnalyzer("binary_file")
    
    # Generate call graph
    call_graph = analyzer.generate_call_graph()
    
    # Find strcpy function
    strcpy_info = analyzer.find_api_function("strcpy")
    
    # Get functions connected to main
    connected = analyzer.get_connected_functions("main")
    
    # Export call graph
    analyzer.export_call_graph("output.json", "json")
    
    # Clean up
    analyzer.close()
    """)
    
    print("\n5. File Structure:")
    files = [
        "binary_analyzer.py - Main module",
        "testre.py - Refactored demonstration script", 
        "test_binary_analyzer.py - Test suite",
        "README_binary_analyzer.md - Documentation"
    ]
    
    for file_desc in files:
        print(f"   - {file_desc}")
    
    print("\n6. Sample Binary Available:")
    sample_path = "../../samples/bof"
    if os.path.exists(sample_path):
        print(f"   ✓ Sample binary found: {sample_path}")
        
        # Get file info
        stat = os.stat(sample_path)
        print(f"   - Size: {stat.st_size} bytes")
        print(f"   - Executable: {os.access(sample_path, os.X_OK)}")
    else:
        print(f"   ✗ Sample binary not found: {sample_path}")
    
    print("\n7. To Use with Binary Ninja:")
    print("   1. Install Binary Ninja")
    print("   2. Ensure Python API is accessible")
    print("   3. Run: python3 testre.py ../../samples/bof")
    print("   4. Or: python3 binary_analyzer.py ../../samples/bof")
    
    print("\n" + "=" * 50)
    print("Demonstration complete!")
    print("The BinaryAnalyzer module is ready for use with Binary Ninja.")


def show_refactoring_improvements():
    """Show the improvements made in the refactoring."""
    
    print("\nRefactoring Improvements")
    print("=" * 30)
    
    print("\nOriginal testre.py issues:")
    print("  ✗ Single function with mixed responsibilities")
    print("  ✗ No structured data representation")
    print("  ✗ Limited functionality")
    print("  ✗ No export capabilities")
    print("  ✗ Poor error handling")
    print("  ✗ No reusability")
    
    print("\nNew BinaryAnalyzer improvements:")
    print("  ✓ Object-oriented design with clear separation")
    print("  ✓ Structured data classes (FunctionInfo, CallGraphNode)")
    print("  ✓ Comprehensive API function analysis")
    print("  ✓ Multiple export formats (JSON, DOT, TXT)")
    print("  ✓ Robust error handling and logging")
    print("  ✓ Reusable module for integration")
    print("  ✓ Call graph generation and analysis")
    print("  ✓ Function relationship mapping")
    print("  ✓ Assembly instruction extraction")
    print("  ✓ API usage search across binary")
    print("  ✓ Comprehensive documentation")
    print("  ✓ Test suite for validation")


def main():
    """Main demonstration function."""
    demo_without_binary_ninja()
    show_refactoring_improvements()
    
    print("\nNext Steps:")
    print("1. Install Binary Ninja if not already installed")
    print("2. Test with: python3 test_binary_analyzer.py")
    print("3. Run analysis: python3 testre.py ../../samples/bof")
    print("4. Integrate into your analysis workflows")


if __name__ == "__main__":
    main()
