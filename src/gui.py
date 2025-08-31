#!/usr/bin/env python3
"""
GitGuard - Simple GUI Application

A basic GUI interface for demonstrating GitGuard functionality.
This is a simplified version focusing on core security scanning features.
"""

import tkinter as tk
from tkinter import ttk, messagebox
import os
import sys

class GitGuardGUI:
    """Main GitGuard application window."""
    
    def __init__(self):
        self.root = tk.Tk()
        self.root.title("GitGuard - GitHub Security Scanner v1.0.0")
        self.root.geometry("800x600")
        
        self.create_widgets()
    
    def create_widgets(self):
        """Create main application widgets."""
        # Header
        header_frame = ttk.Frame(self.root)
        header_frame.pack(fill='x', padx=20, pady=20)
        
        title_label = ttk.Label(header_frame, text="🛡️ GitGuard", 
                               font=('Arial', 24, 'bold'))
        title_label.pack()
        
        subtitle_label = ttk.Label(header_frame, text="GitHub Security Scanner", 
                                  font=('Arial', 12))
        subtitle_label.pack()
        
        # Main content
        main_frame = ttk.Frame(self.root)
        main_frame.pack(fill='both', expand=True, padx=20, pady=20)
        
        # Welcome message
        welcome_text = """
Welcome to GitGuard - GitHub Security Scanner

GitGuard helps you identify sensitive information in your GitHub repositories:

🔍 Features:
• Scan GitHub repositories for sensitive data
• Detect API keys, passwords, and tokens  
• Local-only processing for maximum security
• Export results in multiple formats
• Professional risk assessment

🚀 Getting Started:
1. Install dependencies: pip install -r requirements.txt
2. Configure GitHub authentication
3. Select repositories to scan
4. Review security findings

📚 Documentation:
Complete documentation is available in the docs/ folder including:
• Technical specifications
• Security and privacy plans  
• Development guidelines

⚠️ Security Notice:
GitGuard is designed for defensive security purposes only.
Only scan repositories you own or have explicit permission to analyze.
        """
        
        welcome_label = ttk.Label(main_frame, text=welcome_text, 
                                 justify='left', font=('Arial', 10))
        welcome_label.pack(anchor='w')
        
        # Buttons
        button_frame = ttk.Frame(main_frame)
        button_frame.pack(fill='x', pady=20)
        
        ttk.Button(button_frame, text="View Documentation", 
                  command=self.show_docs).pack(side='left', padx=5)
        
        ttk.Button(button_frame, text="Check Dependencies", 
                  command=self.check_deps).pack(side='left', padx=5)
        
        ttk.Button(button_frame, text="About GitGuard", 
                  command=self.show_about).pack(side='left', padx=5)
        
        # Status
        self.status_var = tk.StringVar(value="Ready")
        status_label = ttk.Label(self.root, textvariable=self.status_var, 
                                relief='sunken', anchor='w')
        status_label.pack(side='bottom', fill='x')
    
    def show_docs(self):
        """Show documentation information."""
        docs_text = """GitGuard Documentation

📁 Documentation Files:
• docs/TECHNICAL_SPECIFICATION.md - Architecture and implementation
• docs/SECURITY_PRIVACY_PLAN.md - Security framework and privacy
• docs/DEVELOPMENT_RULES.md - Development guidelines
• docs/development_log.md - Implementation progress

🔗 Online Documentation:
https://github.com/dev-alt/GitGuard

💡 Quick Start:
1. Review the technical specification for architecture details
2. Check security plans for privacy and security considerations  
3. Follow development rules for contributing guidelines"""
        
        messagebox.showinfo("Documentation", docs_text)
    
    def check_deps(self):
        """Check if dependencies are installed."""
        missing = []
        
        try:
            from github import Github
        except ImportError:
            missing.append("PyGithub")
        
        try:
            import requests
        except ImportError:
            missing.append("requests")
        
        try:
            import keyring
        except ImportError:
            missing.append("keyring (optional)")
        
        if missing:
            deps_text = f"❌ Missing Dependencies:\n\n" + "\n".join(f"• {dep}" for dep in missing)
            deps_text += "\n\nInstall with:\npip install -r requirements.txt"
        else:
            deps_text = "✅ All dependencies are installed!\n\nGitGuard is ready to use."
        
        messagebox.showinfo("Dependency Check", deps_text)
        self.status_var.set(f"Dependencies: {len(missing)} missing" if missing else "All dependencies OK")
    
    def show_about(self):
        """Show about dialog."""
        about_text = """GitGuard - GitHub Security Scanner v1.0.0

A desktop application for scanning GitHub repositories
and commit history for sensitive information.

🛡️ Security Features:
• 100+ detection patterns for secrets and credentials
• Local-only processing for maximum security  
• Multiple export formats (CSV, JSON, HTML)
• Risk assessment and categorization
• System keyring integration for secure storage

🔒 Privacy:
• No data transmitted to external services
• All processing performed locally
• User has complete control over scan data

📄 License: MIT License
👥 Project: GitGuard Security Scanner
🔗 Repository: https://github.com/dev-alt/GitGuard

© 2024 GitGuard Project"""
        
        messagebox.showinfo("About GitGuard", about_text)
    
    def run(self):
        """Start the GUI application."""
        try:
            self.root.mainloop()
        except KeyboardInterrupt:
            pass


def main():
    """Main entry point for the GUI application."""
    app = GitGuardGUI()
    app.run()


if __name__ == "__main__":
    main()