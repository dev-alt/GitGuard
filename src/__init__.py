"""
GitGuard - GitHub Security Scanner

A desktop application for scanning GitHub repositories and commit history
to detect sensitive information such as API keys, passwords, tokens, and
other security vulnerabilities.

Main Components:
- auth: GitHub authentication management
- detection: Pattern detection engine with 100+ patterns
- scanner: Repository and commit history scanning
- reporting: Export functionality (CSV, JSON, HTML)
- gui: Tkinter-based user interface

Security Features:
- Local-only processing (no external data transmission)
- System keyring integration for secure credential storage
- Comprehensive pattern detection with entropy analysis
- Risk assessment and categorization
- Multi-format reporting capabilities
"""

__version__ = "1.0.0"
__author__ = "GitGuard Project"
__license__ = "MIT"