#!/usr/bin/env python3
"""
GitGuard - GitHub Security Scanner
Main Entry Point

This script launches the GitGuard GUI application for scanning GitHub
repositories and detecting sensitive information.

Usage:
    python main.py

Requirements:
    - Python 3.10+
    - All dependencies from requirements.txt installed
    - GitHub credentials (Personal Access Token or username/password)

Security Note:
    GitGuard processes all data locally and does not transmit any
    information to external services. Your GitHub credentials and
    scan results remain private and secure.
"""

import sys
import os

# Add src directory to Python path
sys.path.insert(0, os.path.join(os.path.dirname(__file__), 'src'))

def check_dependencies():
    """Check if required dependencies are installed."""
    missing_deps = []
    
    try:
        import tkinter
    except ImportError:
        missing_deps.append("tkinter (usually comes with Python)")
    
    try:
        from github import Github
    except ImportError:
        missing_deps.append("PyGithub")
    
    try:
        import requests
    except ImportError:
        missing_deps.append("requests")
    
    if missing_deps:
        print("ERROR: Missing required dependencies:")
        for dep in missing_deps:
            print(f"  - {dep}")
        print("\nPlease install dependencies with:")
        print("  pip install -r requirements.txt")
        print("  # Or: pip3 install -r requirements.txt")
        return False
    
    return True


def main():
    """Main entry point for GitGuard application."""
    print("GitGuard - GitHub Security Scanner v1.0.0")
    print("=" * 45)
    print()
    
    # Check dependencies
    if not check_dependencies():
        sys.exit(1)
    
    print("✅ All dependencies found")
    print("🚀 Starting GitGuard GUI...")
    print()
    
    try:
        # Import and start GUI
        from gui import GitGuardGUI
        
        app = GitGuardGUI()
        app.run()
        
    except ImportError as e:
        print(f"❌ Failed to import GitGuard modules: {e}")
        print("Make sure all source files are present in the src/ directory")
        sys.exit(1)
        
    except KeyboardInterrupt:
        print("\n🛑 Application interrupted by user")
        sys.exit(0)
        
    except Exception as e:
        print(f"❌ Unexpected error: {e}")
        print("Please check your Python environment and dependencies")
        sys.exit(1)


if __name__ == "__main__":
    main()