#!/usr/bin/env python3
"""
ORCA Streamlit Frontend Launcher
Simple script to launch the Streamlit frontend with proper configuration
"""

import os
import sys
import subprocess
import json
from pathlib import Path

# Try to load credentials from AGENTCONFIG if available
try:
    if 'AGENTCONFIG' in os.environ:
        creds = json.load(open(os.environ['AGENTCONFIG']))
        os.environ['OPENAI_API_KEY'] = creds['OPENAI_API_KEY']
    else:
        print("Warning: AGENTCONFIG environment variable not set. Using default configuration.")
except Exception as e:
    print(f"Warning: Failed to load credentials from AGENTCONFIG: {str(e)}")
def check_requirements():
    """Check if required dependencies are installed"""
    try:
        import streamlit
        import pandas
        import plotly
        print("✅ All required dependencies are installed")
        return True
    except ImportError as e:
        print(f"❌ Missing dependency: {e}")
        print("Please install requirements: pip install -r requirements_frontend.txt")
        return False

def check_environment():
    """Check if environment is properly configured"""
    issues = []
    
    # Check OpenAI API key
    if not os.environ.get('OPENAI_API_KEY'):
        issues.append("OPENAI_API_KEY environment variable not set")
    
    # Check ORCA modules
    orca_path = Path(__file__).parent / "orca" / "src" / "cmd"
    if not orca_path.exists():
        issues.append(f"ORCA modules not found at {orca_path}")
    
    if issues:
        print("⚠️  Environment issues detected:")
        for issue in issues:
            print(f"   - {issue}")
        print("\nThe frontend may not work properly without these.")
        return False
    
    print("✅ Environment is properly configured")
    return True

def main():
    """Main launcher function"""
    print("🔍 ORCA Streamlit Frontend Launcher")
    print("=" * 50)
    
    # Check requirements
    if not check_requirements():
        sys.exit(1)
    
    # Check environment
    env_ok = check_environment()
    
    # Ask user if they want to continue despite environment issues
    if not env_ok:
        response = input("\nDo you want to continue anyway? (y/n): ")
        if response.lower() != 'y':
            print("Exiting...")
            sys.exit(1)
    
    print("\n🚀 Starting Streamlit frontend...")
    print("The application will open in your default browser")
    print("Press Ctrl+C to stop the server")
    print("-" * 50)
    
    # Launch Streamlit
    try:
        subprocess.run([
            sys.executable, "-m", "streamlit", "run", 
            "streamlit_frontend.py",
            "--server.address", "localhost",
            "--server.port", "8501",
            "--browser.gatherUsageStats", "false"
        ])
    except KeyboardInterrupt:
        print("\n\n👋 Shutting down ORCA frontend...")
    except Exception as e:
        print(f"\n❌ Error starting frontend: {e}")
        sys.exit(1)

if __name__ == "__main__":
    main()
