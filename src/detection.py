#!/usr/bin/env python3
"""
GitGuard - Security Pattern Detection Engine

Implements comprehensive detection patterns for identifying sensitive information
in GitHub repositories and commit history.
"""

import re
import hashlib
import math
from typing import Dict, List, Tuple, Optional
from dataclasses import dataclass
from enum import Enum

class RiskLevel(Enum):
    """Risk levels for detected findings."""
    CRITICAL = "CRITICAL"
    HIGH = "HIGH"
    MEDIUM = "MEDIUM"
    LOW = "LOW"

@dataclass
class Finding:
    """Represents a security finding."""
    pattern_name: str
    file_path: str
    line_number: int
    line_content: str
    matched_text: str
    risk_level: RiskLevel
    description: str
    commit_hash: Optional[str] = None
    commit_date: Optional[str] = None

class SecurityPatternDetector:
    """Main security pattern detection engine."""
    
    def __init__(self):
        self.patterns = self._initialize_patterns()
        self.high_risk_files = self._initialize_file_patterns()
    
    def _initialize_patterns(self) -> Dict[str, Dict]:
        """Initialize detection patterns."""
        return {
            # API Keys and Tokens
            "aws_access_key": {
                "pattern": r"AKIA[0-9A-Z]{16}",
                "risk": RiskLevel.CRITICAL,
                "description": "AWS Access Key detected"
            },
            "github_token": {
                "pattern": r"gh[pousr]_[A-Za-z0-9_]{36,251}",
                "risk": RiskLevel.CRITICAL,
                "description": "GitHub Personal Access Token detected"
            },
            "generic_api_key": {
                "pattern": r"(?i)(api[_\-]?key|apikey)['\"\s]*[:=]['\"\s]*[a-zA-Z0-9_\-]{20,}",
                "risk": RiskLevel.HIGH,
                "description": "Generic API key pattern detected"
            },
            "bearer_token": {
                "pattern": r"Bearer\s+[A-Za-z0-9\-_=]{20,}",
                "risk": RiskLevel.HIGH,
                "description": "Bearer token detected"
            },
            
            # Database Credentials
            "mongodb_uri": {
                "pattern": r"mongodb(\+srv)?://[^:\s]+:[^@\s]+@[^/\s]+",
                "risk": RiskLevel.CRITICAL,
                "description": "MongoDB connection string with credentials"
            },
            "mysql_connection": {
                "pattern": r"mysql://[^:\s]+:[^@\s]+@[^/\s]+",
                "risk": RiskLevel.CRITICAL,
                "description": "MySQL connection string with credentials"
            },
            "postgres_connection": {
                "pattern": r"postgres(ql)?://[^:\s]+:[^@\s]+@[^/\s]+",
                "risk": RiskLevel.CRITICAL,
                "description": "PostgreSQL connection string with credentials"
            },
            
            # Private Keys
            "rsa_private_key": {
                "pattern": r"-----BEGIN RSA PRIVATE KEY-----",
                "risk": RiskLevel.CRITICAL,
                "description": "RSA Private Key detected"
            },
            "openssh_private_key": {
                "pattern": r"-----BEGIN OPENSSH PRIVATE KEY-----",
                "risk": RiskLevel.CRITICAL,
                "description": "OpenSSH Private Key detected"
            },
            "ec_private_key": {
                "pattern": r"-----BEGIN EC PRIVATE KEY-----",
                "risk": RiskLevel.CRITICAL,
                "description": "EC Private Key detected"
            },
            
            # Environment Variables
            "secret_env_var": {
                "pattern": r"(?i)(secret|password|token|key)[_\-]?[a-z0-9]*\s*[:=]\s*['\"][^'\"]{8,}['\"]",
                "risk": RiskLevel.MEDIUM,
                "description": "Secret environment variable detected"
            },
            "docker_env_secrets": {
                "pattern": r"(?i)(JWT_SECRET|DB_PASSWORD|API_KEY|SECRET_KEY|PRIVATE_KEY|ACCESS_TOKEN)\s*[:=]\s*\$\{[^}]+\}",
                "risk": RiskLevel.HIGH,
                "description": "Docker environment secret variable detected"
            },
            "exposed_env_vars": {
                "pattern": r"(?i)- (JWT_SECRET|MONGO_INITDB_ROOT_PASSWORD|DATABASE_PASSWORD|API_SECRET|PRIVATE_KEY)=",
                "risk": RiskLevel.HIGH,
                "description": "Exposed environment variable in Docker/Config file"
            },
            "aws_env_vars": {
                "pattern": r"(?i)AWS_(ACCESS_KEY_ID|SECRET_ACCESS_KEY)\s*[:=]\s*['\"][A-Za-z0-9/+=]{16,}['\"]",
                "risk": RiskLevel.HIGH,
                "description": "AWS environment variable detected"
            },
            
            # Passwords and Authentication
            "hardcoded_password": {
                "pattern": r"(?i)(password|pwd|pass)['\"\s]*[:=]['\"\s]*[a-zA-Z0-9!@#$%^&*()_+\-=\[\]{};':\"\\|,.<>?~`]{8,}",
                "risk": RiskLevel.MEDIUM,
                "description": "Hardcoded password pattern detected"
            },
            "basic_auth": {
                "pattern": r"Basic\s+[A-Za-z0-9+/]+=*",
                "risk": RiskLevel.MEDIUM,
                "description": "Basic authentication header detected"
            },
            
            # Cloud Services
            "google_api_key": {
                "pattern": r"AIza[0-9A-Za-z\\-_]{35}",
                "risk": RiskLevel.HIGH,
                "description": "Google API key detected"
            },
            "gcp_service_account": {
                "pattern": r"(?i)\.json.*service.?account|service.?account.*\.json|gcp.?creds.*\.json",
                "risk": RiskLevel.CRITICAL,
                "description": "Google Cloud service account key file reference detected"
            },
            "slack_token": {
                "pattern": r"xox[baprs]-[0-9]{12}-[0-9]{12}-[0-9a-zA-Z]{24}",
                "risk": RiskLevel.HIGH,
                "description": "Slack token detected"
            },
            "discord_token": {
                "pattern": r"[MN][A-Za-z\d]{23}\.[\w-]{6}\.[\w-]{27}",
                "risk": RiskLevel.HIGH,
                "description": "Discord token detected"
            },
            
            # Cryptocurrency
            "bitcoin_private_key": {
                "pattern": r"[5KL][1-9A-HJ-NP-Za-km-z]{50,51}",
                "risk": RiskLevel.CRITICAL,
                "description": "Bitcoin private key detected"
            },
            
            # Email and URLs with credentials
            "email_password_combo": {
                "pattern": r"[a-zA-Z0-9._%+-]+@[a-zA-Z0-9.-]+\.[a-zA-Z]{2,}:[a-zA-Z0-9!@#$%^&*()_+\-=\[\]{};':\"\\|,.<>?~`]{4,}",
                "risk": RiskLevel.MEDIUM,
                "description": "Email and password combination detected"
            },
            
            # Docker and Container specific
            "docker_env_file": {
                "pattern": r"(?i)env_file\s*:\s*-.*\.env",
                "risk": RiskLevel.MEDIUM,
                "description": "Docker environment file reference detected"
            },
            "docker_secrets_mount": {
                "pattern": r"(?i)volumes.*secrets|secrets.*volumes|/secrets/|/config/.*\.json.*:ro",
                "risk": RiskLevel.HIGH,
                "description": "Docker secrets or credential file mount detected"
            },
            "hardcoded_db_creds": {
                "pattern": r"(?i)(mongodb|mysql|postgres)://[^:\s]+:[^@\s]+@[^/\s]+",
                "risk": RiskLevel.CRITICAL,
                "description": "Database connection string with hardcoded credentials"
            },
            
            # JWT Tokens
            "jwt_token": {
                "pattern": r"eyJ[A-Za-z0-9-_=]+\.[A-Za-z0-9-_=]+\.?[A-Za-z0-9-_.+/=]*",
                "risk": RiskLevel.HIGH,
                "description": "JWT (JSON Web Token) detected"
            },
            
            # Stripe API Keys
            "stripe_api_key": {
                "pattern": r"sk_(live|test)_[0-9a-zA-Z]{24}",
                "risk": RiskLevel.CRITICAL,
                "description": "Stripe API key detected"
            },
            
            # Firebase Keys
            "firebase_api_key": {
                "pattern": r"AIza[0-9A-Za-z\\-_]{35}",
                "risk": RiskLevel.HIGH,
                "description": "Firebase API key detected"
            },
            
            # SendGrid API Keys
            "sendgrid_api_key": {
                "pattern": r"SG\.[0-9A-Za-z\\-_]{22}\.[0-9A-Za-z\\-_]{43}",
                "risk": RiskLevel.HIGH,
                "description": "SendGrid API key detected"
            },
            
            # Twilio API Keys
            "twilio_api_key": {
                "pattern": r"AC[a-f0-9]{32}",
                "risk": RiskLevel.HIGH,
                "description": "Twilio API key detected"
            },
            
            # Azure Storage Keys
            "azure_storage_key": {
                "pattern": r"DefaultEndpointsProtocol=https;AccountName=[^;]+;AccountKey=[A-Za-z0-9+/]{88}==",
                "risk": RiskLevel.CRITICAL,
                "description": "Azure storage connection string detected"
            },
            
            # Shopify API Keys
            "shopify_api_key": {
                "pattern": r"shpat_[a-fA-F0-9]{32}",
                "risk": RiskLevel.HIGH,
                "description": "Shopify API token detected"
            },
            
            # Square API Keys
            "square_api_key": {
                "pattern": r"sq0[a-z]{3}-[0-9A-Za-z\\-_]{22,43}",
                "risk": RiskLevel.HIGH,
                "description": "Square API key detected"
            },
            
            # PayPal Client Secrets
            "paypal_client_secret": {
                "pattern": r"EO[0-9A-Za-z\\-_]{21,32}",
                "risk": RiskLevel.CRITICAL,
                "description": "PayPal client secret detected"
            },
            
            # Docker Secrets
            "docker_secret": {
                "pattern": r"--secret\\s+id=[a-zA-Z0-9_-]+",
                "risk": RiskLevel.MEDIUM,
                "description": "Docker secret reference detected"
            },
            
            # Kubernetes Secrets
            "kubernetes_secret": {
                "pattern": r"kind:\\s*Secret",
                "risk": RiskLevel.MEDIUM,
                "description": "Kubernetes secret manifest detected"
            },
            
            # Generic high entropy strings (potential secrets)
            "high_entropy_string": {
                "pattern": r"['\"][a-zA-Z0-9+/]{40,}={0,2}['\"]",
                "risk": RiskLevel.LOW,
                "description": "High entropy string (potential secret)",
                "entropy_check": True
            }
        }
    
    def _initialize_file_patterns(self) -> List[str]:
        """Initialize high-risk file patterns."""
        return [
            r"\.env(\.|$)",
            r"\.env\.",
            r"config\.json$",
            r"settings\.json$",
            r"secrets\.json$",
            r"\.secret$",
            r"\.private$",
            r"id_rsa$",
            r"id_dsa$",
            r"id_ecdsa$",
            r"id_ed25519$",
            r"\.pem$",
            r"\.key$",
            r"\.p12$",
            r"\.pfx$",
            r"docker-compose\.ya?ml$",
            r"\.npmrc$",
            r"\.pypirc$",
            r"\.dockerenv$",
            r"Dockerfile\.secrets$",
            r"\.kube/config$",
            r"\.aws/credentials$",
            r"\.ssh/config$",
            r"service.?account.*\.json$",
            r"gcp.?creds.*\.json$",
            r"firebase.?service.?account.*\.json$",
            r"\.terraform/.*\.tfstate$"
        ]
    
    def calculate_entropy(self, text: str) -> float:
        """Calculate Shannon entropy of a string."""
        if not text:
            return 0.0
        
        # Count character frequencies
        char_counts = {}
        for char in text:
            char_counts[char] = char_counts.get(char, 0) + 1
        
        # Calculate entropy
        entropy = 0.0
        text_len = len(text)
        for count in char_counts.values():
            probability = count / text_len
            if probability > 0:
                entropy -= probability * math.log2(probability)
        
        return entropy
    
    def is_high_risk_file(self, file_path: str) -> bool:
        """Check if file path matches high-risk patterns."""
        # First check for safe development files that should be excluded
        safe_dev_files = [
            r"launchSettings\.json$",      # Visual Studio launch settings
            r"appsettings\.json$",         # ASP.NET Core app settings
            r"appsettings\.[^.]+\.json$",  # Environment-specific app settings
            r"Properties/.*\.json$",       # .NET project properties
            r"project\.json$",             # .NET Core project files
            r"package\.json$",             # Node.js package files
            r"tsconfig\.json$",            # TypeScript config
            r"jsconfig\.json$",            # JavaScript config
            r"eslint\.json$",              # ESLint config
            r"\.vscode/.*\.json$",         # VS Code settings
            r"AndroidManifest\.xml$",      # Android manifest
            r"Info\.plist$",               # iOS info plist
        ]
        
        # Check if it's a safe development file
        for safe_pattern in safe_dev_files:
            if re.search(safe_pattern, file_path, re.IGNORECASE):
                return False
        
        # Check against high-risk patterns
        for pattern in self.high_risk_files:
            if re.search(pattern, file_path, re.IGNORECASE):
                return True
        return False
    
    def detect_patterns(self, content: str, file_path: str, commit_hash: str = None, commit_date: str = None) -> List[Finding]:
        """Detect security patterns in content."""
        findings = []
        lines = content.split('\n')
        
        # Get file extension for context-aware filtering
        file_ext = file_path.lower().split('.')[-1] if '.' in file_path else ''
        
        for line_num, line in enumerate(lines, 1):
            # Skip empty lines and comments
            stripped_line = line.strip()
            if not stripped_line or stripped_line.startswith('#') or stripped_line.startswith('//'):
                continue
            
            # Skip XML/XAML comments
            if stripped_line.startswith('<!--') or stripped_line.endswith('-->'):
                continue
            
            for pattern_name, pattern_info in self.patterns.items():
                matches = re.finditer(pattern_info["pattern"], line, re.IGNORECASE)
                
                for match in matches:
                    matched_text = match.group(0)
                    
                    # Special handling for entropy-based patterns
                    if pattern_info.get("entropy_check"):
                        entropy = self.calculate_entropy(matched_text)
                        if entropy < 4.0:  # Skip low entropy matches
                            continue
                    
                    # Context-aware filtering for specific file types
                    if self._is_context_false_positive(matched_text, pattern_name, file_ext, line):
                        continue
                    
                    # Skip obvious false positives
                    if self._is_false_positive(matched_text, pattern_name):
                        continue
                    
                    finding = Finding(
                        pattern_name=pattern_name,
                        file_path=file_path,
                        line_number=line_num,
                        line_content=line.strip(),
                        matched_text=matched_text,
                        risk_level=pattern_info["risk"],
                        description=pattern_info["description"],
                        commit_hash=commit_hash,
                        commit_date=commit_date
                    )
                    findings.append(finding)
        
        return findings
    
    def _is_false_positive(self, matched_text: str, pattern_name: str) -> bool:
        """Filter out common false positives."""
        false_positive_patterns = {
            "generic_api_key": [
                r"example", r"test", r"demo", r"placeholder", r"your_api_key",
                r"insert_key_here", r"xxxxxxxxxx", r"0123456789"
            ],
            "hardcoded_password": [
                r"password", r"123456", r"admin", r"test", r"example",
                r"placeholder", r"your_password", r"change_me"
            ],
            "high_entropy_string": [
                r"^[0-9]+$",  # Pure numbers
                r"^[a-f0-9]{32}$",  # MD5 hash
                r"^[a-f0-9]{40}$",  # SHA1 hash
                r"^[a-f0-9]{64}$",  # SHA256 hash
            ],
            "secret_env_var": [
                r"Key=.*Brush",  # CSS/XAML brushes
                r"Key=.*Color",  # Color keys
                r"Key=.*Style",  # Style keys
                r"Key=.*Theme",  # Theme keys
                r"^[A-Za-z]+Brush$",  # Brush names
                r"^[A-Za-z]+Color$",  # Color names
                r"primarybrush", r"secondarybrush", r"accentbrush",  # Common UI brushes
                r"primary", r"secondary", r"accent", r"background", r"foreground"  # UI colors
            ],
            "bitcoin_private_key": [
                r"SDWARF",  # Go/Assembly constants
                r"DWARF",   # Debug format constants
                r"CUINFO",  # Compilation unit info
                r"FCNSDW",  # Function symbols
                r"ABSFCN",  # Abstract functions
                r"SYMKIND", # Symbol kinds
                r"[A-Z]{20,}",  # Long uppercase constants (likely not Bitcoin keys)
                r"^[A-Z_]+$"    # Pure uppercase with underscores
            ]
        }
        
        if pattern_name in false_positive_patterns:
            for fp_pattern in false_positive_patterns[pattern_name]:
                if re.search(fp_pattern, matched_text, re.IGNORECASE):
                    return True
        
        return False
    
    def _is_context_false_positive(self, matched_text: str, pattern_name: str, file_ext: str, line_content: str) -> bool:
        """Context-aware false positive filtering based on file type and line content."""
        
        # XAML/XML specific filtering
        if file_ext in ['xaml', 'xml', 'axaml']:
            # Skip XAML resource keys and property definitions
            if pattern_name == "secret_env_var":
                if any(keyword in line_content for keyword in [
                    'Key=', 'x:Key=', 'Name=', 'TargetName=', 
                    '<ResourceDictionary', '<Style', '<SolidColorBrush',
                    'Brush"', 'Color"', 'Style"', 'Theme"'
                ]):
                    return True
        
        # Go source file filtering
        if file_ext == 'go':
            # Skip Go constants and string literals
            if pattern_name == "bitcoin_private_key":
                if any(keyword in line_content for keyword in [
                    'const', 'var', 'string', '=', 'DWARF', 'objabi', 
                    'symkind', '_string.go', 'golang'
                ]):
                    return True
        
        # Assembly and object files
        if file_ext in ['s', 'asm', 'S']:
            if pattern_name in ["bitcoin_private_key", "high_entropy_string"]:
                return True  # Skip assembly files entirely for these patterns
        
        # Configuration files - be more careful
        if file_ext in ['json', 'yaml', 'yml', 'toml', 'ini']:
            # But allow scanning, just be more specific about what we flag
            pass
        
        # Minified files - high entropy is expected
        if any(keyword in file_ext for keyword in ['min.js', 'min.css', '.min.']):
            if pattern_name == "high_entropy_string":
                return True
        
        return False
    
    def scan_file(self, file_path: str, content: str, commit_hash: str = None, commit_date: str = None) -> List[Finding]:
        """Scan a single file for security patterns."""
        findings = []
        
        # Check if it's a high-risk file type
        if self.is_high_risk_file(file_path):
            finding = Finding(
                pattern_name="high_risk_file",
                file_path=file_path,
                line_number=0,
                line_content="",
                matched_text=file_path,
                risk_level=RiskLevel.HIGH,
                description=f"High-risk file type detected: {file_path}",
                commit_hash=commit_hash,
                commit_date=commit_date
            )
            findings.append(finding)
        
        # Scan file content for patterns
        content_findings = self.detect_patterns(content, file_path, commit_hash, commit_date)
        findings.extend(content_findings)
        
        return findings
    
    def get_pattern_statistics(self) -> Dict[str, int]:
        """Get statistics about available patterns."""
        stats = {
            "total_patterns": len(self.patterns),
            "critical": sum(1 for p in self.patterns.values() if p["risk"] == RiskLevel.CRITICAL),
            "high": sum(1 for p in self.patterns.values() if p["risk"] == RiskLevel.HIGH),
            "medium": sum(1 for p in self.patterns.values() if p["risk"] == RiskLevel.MEDIUM),
            "low": sum(1 for p in self.patterns.values() if p["risk"] == RiskLevel.LOW),
            "file_patterns": len(self.high_risk_files)
        }
        return stats

if __name__ == "__main__":
    # Example usage and testing
    detector = SecurityPatternDetector()
    
    # Test content
    test_content = """
    # Configuration file
    API_KEY = "sk-1234567890abcdefghijklmnopqrstuvwxyz"
    DATABASE_URL = "postgresql://user:password123@localhost:5432/mydb"
    SECRET_TOKEN = "very_secret_token_here"
    
    # This should be detected
    github_token = "ghp_1234567890abcdefghijklmnopqrstuvwxyz123"
    """
    
    findings = detector.scan_file("config/settings.py", test_content)
    
    print(f"Detected {len(findings)} findings:")
    for finding in findings:
        print(f"  {finding.risk_level.value}: {finding.description} in {finding.file_path}:{finding.line_number}")
    
    print(f"\nPattern statistics: {detector.get_pattern_statistics()}")