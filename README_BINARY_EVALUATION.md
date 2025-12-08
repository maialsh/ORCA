# ORCA Binary Evaluation System

This system evaluates ORCA's ability to detect real binary capabilities when given misleading functionality descriptions.

## 🎯 Evaluation Objective

Test whether ORCA can correctly identify what binaries actually do (e.g., "packet capture") even when told they do something completely different (e.g., "image editor").

## 📋 System Overview

The evaluation uses 76 anonymized binaries across 6 categories:
- **Network Tools** (12): tcpdump, nmap, nc, socat, dig, iptables, etc.
- **Monitoring Tools** (14): strace, ltrace, gdb, top, htop, ps, etc.  
- **Build Tools** (10): gcc, g++, clang, make, cmake, ninja, etc.
- **Binary Utils** (10): ar, as, ld, nm, objcopy, objdump, etc.
- **Core Utils** (19): grep, sed, awk, cat, cp, mv, rm, tar, etc.
- **Applications** (11): vim, git, tmux, openssl, sqlite3, python3, etc.

## 🔒 Blind Evaluation Strategy

- **Binary Files**: Anonymous IDs only (BIN_001, BIN_002, etc.)
- **Descriptions**: Only misleading descriptions (never real names)
- **Pure Analysis**: BinSleuth must discover capabilities through binary analysis alone

## 📁 File Structure

```
/Users/maitha/Desktop/Binsleuth_Evaluations_October/Capabilities/
├── ground_truth_mapping.json      # Maps BIN_001 -> tcpdump, etc.
├── binaries/                      # Anonymous binary files
│   ├── BIN_001                    # Actually tcpdump
│   ├── BIN_002                    # Actually nmap
│   └── ...
└── individual_results/            # Generated results
    ├── BIN_001_result.json
    ├── BIN_002_result.json
    ├── evaluation_summary.json
    └── ...
```

## 🚀 Usage

### 1. Test the System (Recommended First Step)

```bash
# Test with first 3 binaries
python test_evaluation_runner.py
```

This will:
- Verify all imports work
- Test BinSleuth on BIN_001, BIN_002, BIN_003
- Show you expected output format
- Ensure everything is working before full run

### 2. Run Small Batch

```bash
# Test with first 10 binaries
python binary_evaluation_runner.py --max-binaries 10
```

### 3. Run Full Evaluation

```bash
# Run all 76 binaries
python binary_evaluation_runner.py
```

### 4. Resume from Interruption 

```bash
# Resume from a specific binary (if you had to stop)
python binary_evaluation_runner.py --start-from BIN_025
```

### 5. Force Re-run Everything

```bash
# Don't skip completed binaries
python binary_evaluation_runner.py --no-resume
```

## 📊 Expected Output

### Progress Display
```
🚀 Starting BinSleuth Binary Evaluation
📅 Start time: 2025-11-01 19:25:30 UTC
================================================================================

[1/76] 🔍 Processing BIN_001
       📋 Real capability: Packet capture (network)
       🎭 Misleading description: "Image editor"
   🔍 Analyzing binary: /path/to/BIN_001
   📝 Using description: "Image editor"
   🎯 Goal: capabilities and malware analysis
   ⏱️  Starting analysis...
       ✅ BIN_001 completed (0.45 min, $0.0001)

[2/76] 🔍 Processing BIN_002
       📋 Real capability: Port scanner (network)
       🎭 Misleading description: "Calculator"
   🔍 Analyzing binary: /path/to/BIN_002
   📝 Using description: "Calculator"
   🎯 Goal: capabilities and malware analysis
   ⏱️  Starting analysis...
       ✅ BIN_002 completed (0.52 min, $0.0001)

... (continuing through all 76) ...
```

### Final Summary
```
================================================================================
📊 EVALUATION COMPLETED
================================================================================
✅ Completed: 74/76 binaries
❌ Failed: 2/76 binaries  
📈 Success Rate: 97.4%
💰 Total Cost: $0.0856
⏱️  Total Time: 34.2 minutes
⚡ Avg Time/Binary: 0.46 minutes
📁 Results saved to: /path/to/individual_results
📋 Ready for metrics analysis!
```

## 📄 Result File Format

Each binary generates a detailed JSON result file:

```json
{
  "evaluation_metadata": {
    "binary_id": "BIN_001",
    "evaluation_timestamp": "2025-11-01T19:25:30Z",
    "binsleuth_version": "enhanced_workflow_with_string_analysis",
    "evaluation_goal": "detect_real_capabilities_despite_misleading_description"
  },
  "ground_truth": {
    "original_name": "tcpdump",
    "real_capability": "Packet capture", 
    "category": "network",
    "file_size_bytes": 1331320
  },
  "test_parameters": {
    "binary_path": "/path/to/BIN_001",
    "misleading_description": "Image editor",
    "goal": "capabilities and malware analysis",
    "analysis_type": "blind_evaluation"
  },
  "binsleuth_results": {
    // Complete BinSleuth output including:
    // - static_analysis_results
    // - comprehensive_string_results  
    // - capabilities
    // - final_summary
    // - timing_metrics
  },
  "execution_metadata": {
    "status": "completed",
    "execution_time_minutes": 0.45,
    "llm_cost_usd": 0.0001,
    "analysis_duration_seconds": 27.3,
    "workflow_completed_steps": ["static_analysis", "api_crossrefs", ...]
  }
}
```

## 🔧 Advanced Options

### Command Line Arguments

```bash
python binary_evaluation_runner.py [options]

Options:
  --ground-truth PATH     Path to ground truth mapping JSON
  --binaries-dir PATH     Directory containing binary files  
  --results-dir PATH      Directory to save results
  --start-from BIN_XXX    Resume from specific binary
  --max-binaries N        Process only N binaries (for testing)
  --no-resume            Don't skip completed binaries
  -h, --help             Show help message
```

### Environment Setup

Make sure you're in the ogbinsleuth directory with:
```bash
cd /Users/maitha/Desktop/ogbinsleuth
python binary_evaluation_runner.py
```

## 📈 Next Steps: Metrics Analysis

After the evaluation completes, you'll have individual JSON results for each binary. The next step is running metrics analysis to calculate:

- **True Positives (TP)**: Correctly identified real capabilities
- **False Negatives (FN)**: Missed real capabilities  
- **False Positives (FP)**: Incorrectly accepted misleading descriptions
- **True Negatives (TN)**: Correctly rejected misleading descriptions
- **Accuracy, Precision, Recall, F1-Score**
- **Category-wise performance analysis**

This will be
