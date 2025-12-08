# LLM-Based Backdoor Detection Evaluation

This evaluation system uses Large Language Models (LLM) to analyze ORCA and CAPA outputs for sophisticated backdoor detection evaluation on the Rosa benchmark dataset.

## 🎯 Overview

Instead of using simple heuristic scoring, this system leverages LLM intelligence to:
- **Analyze complex patterns** in tool outputs
- **Make informed backdoor classifications** based on contextual understanding
- **Provide explainable results** with detailed reasoning for each decision
- **Generate publication-ready metrics** for research papers

## 📊 Ground Truth (Rosa Benchmark)

The evaluation uses the Rosa benchmark labeling scheme:
- **Alpha** = Real/Authentic binaries, **Beta** = Synthetic binaries
- **Odd numbers** = Safe (benign), **Even numbers** = Unsafe (backdoor)

Examples:
- `Alpha-01` = Real + Safe = **Benign**
- `Alpha-02` = Real + Unsafe = **Backdoor** 
- `Beta-01` = Synthetic + Safe = **Benign**
- `Beta-02` = Synthetic + Unsafe = **Backdoor**

## 🚀 Quick Start

### Simple Auto-Discovery Run
```bash
python run_llm_backdoor_evaluation.py
```

This script automatically:
1. 🔍 Searches for ORCA and CAPA result files
2. 🎯 Identifies the best directories to use
3. 🤖 Runs LLM analysis on all results
4. 📊 Generates comprehensive evaluation metrics
5. 📁 Saves results to `llm_backdoor_evaluation_results/`

### Manual Directory Specification
```bash
python llm_backdoor_evaluator.py \
  --orca-dir /path/to/orca/results \
  --capa-dir /path/to/capa/results \
  --output-dir custom_output_directory
```

## 🧠 LLM Analysis Process

### For ORCA Results
The LLM analyzes:
- **Suspicious Strings**: Network-related strings, shell commands, suspicious file paths
- **API Clustering**: "potentially_dangerous" clusters, networking/persistence APIs
- **Malware Analysis**: Threat levels, suspicious behaviors identified
- **Capabilities**: Network capabilities, process manipulation, anti-analysis techniques

### For CAPA Results  
The LLM examines:
- **Communication Capabilities**: Network sockets, HTTP, TCP/UDP communications
- **Persistence Mechanisms**: Registry modifications, service installation, startup entries
- **Command Execution**: Shell execution, process creation, code injection
- **Anti-Analysis**: Obfuscation, packing, debugging detection
- **Data Handling**: File operations, encryption, compression

## 📈 Output Files

### Core Results
- `rq2_llm_backdoor_detection_results.tex` - **LaTeX tables ready for paper**
- `detailed_llm_backdoor_evaluation.json` - Raw metrics and data
- `orca-llm_confusion_matrix.png` - Visual confusion matrix
- `capa-llm_confusion_matrix.png` - Visual confusion matrix

### Detailed Analysis
- `orca_llm_results.csv` - **Individual classifications with LLM reasoning**
- `capa_llm_results.csv` - **Individual classifications with LLM reasoning**

### Key Metrics Generated
- **Accuracy**: Overall correct predictions
- **Precision**: True positive rate (how many flagged backdoors are actual backdoors)
- **Recall**: Sensitivity (how many actual backdoors were detected)
- **F1-Score**: Harmonic mean of precision and recall
- **Confidence Scores**: Average LLM confidence in predictions
- **Confusion Matrices**: Detailed breakdown of classifications
- **Timing Analysis**: Speed comparison between tools

## 📋 Example Output

```
======================================================================
LLM-BASED BACKDOOR DETECTION EVALUATION RESULTS
======================================================================

ORCA + LLM Performance:
  Accuracy:     0.875
  Precision:    0.833
  Recall:       0.909
  F1-Score:     0.870
  Avg Confidence: 0.782

CAPA + LLM Performance:
  Accuracy:     0.750
  Precision:    0.778
  Recall:       0.636
  F1-Score:     0.700
  Avg Confidence: 0.691

Timing Comparison:
  ORCA avg: 45.23s
  CAPA avg:      2.18s
  Speed ratio:   20.75x

==================================================
EXAMPLE LLM REASONING
==================================================

ORCA Examples:
  Alpha-02: Analysis reveals network socket APIs, suspicious shell command strings...
  Beta-04: Detected process injection capabilities and registry persistence...
  Alpha-06: Found covert communication patterns and data exfiltration APIs...

CAPA Examples:
  Alpha-02: Detected rules for socket communication, process injection, and registry...
  Beta-04: Found persistence mechanisms and command execution capabilities...
  Alpha-06: Identified network backdoor functionality and anti-analysis techniques...
```

## 💡 Key Advantages

### Over Heuristic Scoring:
- ✅ **Contextual Understanding**: LLM considers relationships between different indicators
- ✅ **Adaptable Analysis**: Can understand new patterns without hardcoded rules  
- ✅ **Explainable Results**: Provides reasoning for each decision
- ✅ **Reduced False Positives**: More nuanced than keyword matching

### For Research Papers:
- 📊 **Publication-Ready Tables**: LaTeX formatted results
- 🔍 **Detailed Reasoning**: Transparent decision-making process
- 📈 **Comprehensive Metrics**: All standard ML evaluation metrics
- 🎯 **Reproducible Results**: Consistent evaluation methodology

## 🔧 Technical Details

### File Requirements

**ORCA Results** should contain:
- `static_analysis` section with strings analysis
- `api_clustering` with security assessments
- `malware_analysis_results` with threat levels
- `capabilities` analysis results

**CAPA Results** should contain:
- `rules` section with detected capabilities
- `meta` section with analysis metadata

### LLM Integration

The system automatically tries to use ORCA's LLM module:
```python
from llm_module import LLMModule
from config import Config
```

If unavailable, falls back to intelligent keyword-based analysis.

### Customization

You can customize the evaluation by:
- Modifying prompt templates in `create_orca_analysis_prompt()` or `create_capa_analysis_prompt()`
- Adjusting backdoor indicator keywords in `_simulate_llm_analysis()`
- Changing confidence thresholds and scoring weights

## 🐛 Troubleshooting

### No Results Found
- Ensure JSON files contain `Alpha-XX` or `Beta-XX` in filenames
- Check that ORCA files have expected keys (`static_analysis`, `api_clustering`, etc.)
- Verify CAPA files have `rules` and `meta` sections

### LLM Module Errors
- The system will fall back to keyword analysis if LLM unavailable
- Check ORCA configuration if you want full LLM analysis

### Performance Issues
- LLM analysis can be slow - each result requires individual analysis
- Consider running on a subset first to test
- Use `--output-dir` to organize multiple runs

## 📚 Research Usage

This evaluation system is designed for academic research comparing binary analysis tools. The LaTeX output can be directly included in research papers, and the detailed CSV files provide full transparency for reproducibility.

**Citation**: When using this evaluation methodology, please cite the appropriate ORCA and evaluation framework papers.

---

**Need help?** Check the console output for detailed progress information and error messages during evaluation.
