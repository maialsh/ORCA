#!/usr/bin/env python3
"""
Fast Binary Evaluation Runner - Disables heavy string analysis for original BinSleuth testing
"""

import sys
import os
sys.path.append('.')

# Temporarily disable comprehensive string analysis
os.environ['DISABLE_COMPREHENSIVE_STRINGS'] = '1'

from binary_evaluation_runner import main

if __name__ == "__main__":
    print("🚀 Running evaluation with comprehensive string analysis DISABLED")
    print("📊 This tests original BinSleuth capabilities without new heavy analysis")
    main()
