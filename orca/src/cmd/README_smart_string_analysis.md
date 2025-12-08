# Smart String Analysis Module

The Smart String Analysis module is an advanced component of BinSleuth that uses LLM (Large Language Model) capabilities to filter and validate strings, domains, URLs, and IP addresses found in binary files. This module enhances the existing string analysis functionality by providing more accurate validation and categorization of strings.

## Features

- **Advanced String Validation**: Validates strings using multiple methods, including regex patterns, standard libraries, and LLM-based analysis.
- **Confidence Scoring**: Provides confidence scores for validation results to help prioritize findings.
- **Detailed Metadata**: Extracts and provides detailed metadata about validated strings.
- **Multiple String Types**: Supports validation of various string types:
  - URLs
  - Domains
  - IP addresses
  - File paths
  - Cryptographic hashes
  - API keys and other sensitive strings
  - Email addresses
  - General strings
- **Batch Processing**: Efficiently processes large numbers of strings in batches.
- **Caching**: Caches validation results to improve performance for repeated validations.
- **Fallback Mechanisms**: Falls back to simpler validation methods when LLM is unavailable or fails.

## Installation

The module is included in the BinSleuth package. Make sure you have the required dependencies installed:

```bash
pip install -r requirements.txt
```

## Usage

### Basic Usage

```python
from smart_string_analysis import filter_valid_strings

# Sample strings to filter
test_strings = [
    "https://www.example.com/path?query=value",
    "invalid-url",
    "example.com",
    "192.168.1.1",
    "999.999.999.999",  # Invalid IP
    "/usr/local/bin/python",
    "5f4dcc3b5aa765d61d8327deb882cf99",  # MD5 hash
    "user@example.com"
]

# Filter strings into valid and invalid categories
results = filter_valid_strings(test_strings)

# Access valid strings by category
valid_urls = results["valid"]["urls"]
valid_domains = results["valid"]["domains"]
valid_ips = results["valid"]["ip_addresses"]

# Access invalid strings by category
invalid_urls = results["invalid"]["urls"]
```

### Filtering Specific Types

```python
from smart_string_analysis import filter_valid_urls, filter_valid_domains, filter_valid_ips

# Filter URLs
urls = ["https://example.com", "invalid-url", "http://localhost:8080"]
valid_urls, invalid_urls = filter_valid_urls(urls)

# Filter domains
domains = ["example.com", "invalid..domain", "subdomain.example.co.uk"]
valid_domains, invalid_domains = filter_valid_domains(domains)

# Filter IP addresses
ips = ["192.168.1.1", "999.999.999.999", "127.0.0.1:8080"]
valid_ips, invalid_ips = filter_valid_ips(ips)
```

### Detailed Validation

```python
from smart_string_analysis import get_string_validation_details

# Get detailed validation information for a string
url = "https://www.example.com/path?query=value"
details = get_string_validation_details(url, "url")

print(f"Valid: {details['valid']}")
print(f"Confidence: {details['confidence']}")
print(f"Reason: {details['reason']}")
print(f"Metadata: {details['metadata']}")
```

### Integration with Binary Analysis

```python
from smart_string_analysis_integration import analyze_binary_file

# Analyze strings in a binary file
results = analyze_binary_file("path/to/binary", "output.json")

# Print a summary of the results
from smart_string_analysis_integration import print_analysis_summary
print_analysis_summary(results)
```

## Advanced Usage

### Using the SmartStringValidator Class

```python
from smart_string_analysis import SmartStringValidator

# Create a validator with custom settings
validator = SmartStringValidator(use_llm=True, confidence_threshold=0.8)

# Validate a URL
url_result = validator.validate_url("https://example.com")

# Validate a domain
domain_result = validator.validate_domain("example.com")

# Validate an IP address
ip_result = validator.validate_ip("192.168.1.1")

# Validate a path
path_result = validator.validate_path("/usr/local/bin/python")

# Auto-detect and validate a string
auto_result = validator.validate_string("user@example.com")
```

### Using the SmartStringAnalyzer Class

```python
from smart_string_analysis import SmartStringAnalyzer

# Create an analyzer with custom settings
analyzer = SmartStringAnalyzer(use_llm=True, batch_size=100)

# Analyze a list of strings
strings = [
    "https://example.com",
    "user@example.com",
    "192.168.1.1",
    "malicious.exe",
    "5f4dcc3b5aa765d61d8327deb882cf99"
]

results = analyzer.analyze_strings(strings)

# Access results
valid_strings = results["valid"]
invalid_strings = results["invalid"]
metadata = results["metadata"]
```

### Disabling LLM for Faster Processing

```python
from smart_string_analysis import filter_valid_strings

# Process strings without using LLM
results = filter_valid_strings(strings, use_llm=False)
```

## Command Line Usage

You can use the test script to validate strings from the command line:

```bash
python test_smart_string_analysis.py
```

Or run specific tests:

```bash
python test_smart_string_analysis.py validation urls domains
```

For binary analysis:

```bash
python smart_string_analysis_integration.py path/to/binary output.json
```

## Module Structure

- `SmartStringValidator`: Core class for validating individual strings
- `SmartStringAnalyzer`: Class for analyzing and categorizing multiple strings
- Helper functions:
  - `filter_valid_strings`: Filter a list of strings into valid and invalid categories
  - `filter_valid_urls`: Filter a list of URLs
  - `filter_valid_domains`: Filter a list of domains
  - `filter_valid_ips`: Filter a list of IP addresses
  - `get_string_validation_details`: Get detailed validation information for a string

## Integration with Existing Code

The module is designed to work seamlessly with the existing BinSleuth codebase. It enhances the string analysis functionality without replacing it, allowing for backward compatibility.

See `smart_string_analysis_integration.py` for an example of how to integrate the module into your existing workflow.

## Performance Considerations

- LLM-based validation is more accurate but slower than regex-based validation
- Use `use_llm=False` for faster processing when accuracy is less critical
- The module uses caching to improve performance for repeated validations
- Batch processing is used to reduce the number of LLM API calls

## Contributing

Contributions to the Smart String Analysis module are welcome! Please follow the BinSleuth contribution guidelines.

## License

This module is part of BinSleuth and is subject to the same license terms.
