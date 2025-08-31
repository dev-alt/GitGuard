# GitHub Security Scanner - Technical Specification

## Overview
A desktop GUI application for scanning GitHub repositories and commit history to detect sensitive information such as API keys, passwords, tokens, environment files, and other security vulnerabilities.

## Application Architecture

### Technology Stack
- **Language**: Python 3.10+
- **GUI Framework**: Tkinter (for simplicity and no external dependencies)
- **GitHub API**: PyGithub library
- **Additional Libraries**:
  - `requests` - HTTP requests
  - `gitpython` - Git operations
  - `python-dotenv` - Environment file handling
  - `threading` - Background processing
  - `tkinter.ttk` - Enhanced GUI widgets

### Core Components

#### 1. Authentication Module (`auth.py`)
- GitHub username/password or Personal Access Token authentication
- Secure credential storage (optional local keyring integration)
- Session management and token validation

#### 2. Repository Scanner (`scanner.py`)
- Repository enumeration (public/private repos)
- Commit history traversal
- File content analysis
- Progress tracking and reporting

#### 3. Pattern Detection Engine (`detection.py`)
- Regex-based pattern matching for sensitive data
- Entropy analysis for high-entropy strings
- File type-specific scanning rules
- Custom pattern support

#### 4. GUI Application (`gui.py`)
- Main application window
- Authentication form
- Repository selection interface
- Scan progress display
- Results viewer with filtering/sorting

#### 5. Report Generator (`reporting.py`)
- Scan results export (CSV, JSON)
- Detailed finding reports
- Risk assessment scoring

## Sensitive Data Detection Patterns

### Primary Detection Categories

#### 1. API Keys & Tokens
```regex
# AWS Access Key
AKIA[0-9A-Z]{16}

# GitHub Personal Access Token
ghp_[a-zA-Z0-9]{36}

# Generic API Key
[aA][pP][iI][_]?[kK][eE][yY].*['"][0-9a-zA-Z]{32,45}['"]

# Generic Token
[tT][oO][kK][eE][nN].*['"][0-9a-zA-Z]{32,45}['"]
```

#### 2. Database Credentials
```regex
# Database URLs
(mongodb|mysql|postgres|redis)://[^\s'"]+

# Connection Strings
[cC]onnection[sS]tring.*['"][^'"]+['"]

# Database Password
[dD][bB]_?[pP]ass(word)?.*['"][^'"]+['"]
```

#### 3. Private Keys
```regex
# RSA Private Key
-----BEGIN RSA PRIVATE KEY-----

# SSH Private Key
-----BEGIN OPENSSH PRIVATE KEY-----

# PGP Private Key
-----BEGIN PGP PRIVATE KEY BLOCK-----
```

#### 4. Environment Variables
```regex
# Common Secret Environment Variables
(SECRET|PASSWORD|TOKEN|KEY|PASS|PWD).*=.+

# AWS Environment Variables
AWS_(ACCESS|SECRET)_KEY.*=.+

# API Keys in .env format
[A-Z_]+_API_KEY.*=.+
```

#### 5. Hardcoded Passwords
```regex
# Password assignments
[pP]ass(word)?['"\s]*[:=]['"\s]*[^'"\s]+

# Common password patterns
(admin|root|password|123456|qwerty)['"\s]*[:=]
```

### File-Specific Scanning

#### High-Risk Files
- `.env`, `.env.*` - Environment files
- `config.json`, `settings.json` - Configuration files
- `*.pem`, `*.key` - Private key files
- `docker-compose.yml` - Docker configurations
- `*.sql` - Database scripts

#### Exclusions
- Binary files (images, executables)
- Large files (>10MB)
- Test fixtures (when explicitly marked)

## User Interface Design

### Main Window Layout
```
┌─────────────────────────────────────────────────┐
│ GitHub Security Scanner                         │
├─────────────────────────────────────────────────┤
│ Authentication Tab                              │
│ ┌─────────────────────────────────────────────┐ │
│ │ Username: [________________]                │ │
│ │ Password: [________________]                │ │
│ │          [Login] [Use Token Instead]        │ │
│ └─────────────────────────────────────────────┘ │
├─────────────────────────────────────────────────┤
│ Repository Selection Tab                        │
│ ┌─────────────────────────────────────────────┐ │
│ │ □ All Repositories  □ Selected Only         │ │
│ │ Repository List:                            │ │
│ │ ☑ repo1    ☑ repo2    □ repo3              │ │
│ │ [Refresh] [Select All] [Scan Selected]     │ │
│ └─────────────────────────────────────────────┘ │
├─────────────────────────────────────────────────┤
│ Scan Progress                                   │
│ Repository: repo1 (2/10)                       │
│ ████████░░░░ 75% Complete                      │
│ Current: Scanning commit abc123...             │
├─────────────────────────────────────────────────┤
│ Results Tab                                     │
│ ┌─────────────────────────────────────────────┐ │
│ │ Filter: [All] [High Risk] [Medium] [Low]    │ │
│ │ ┌─────────────────────────────────────────┐ │ │
│ │ │ Repo    File         Issue       Risk   │ │ │
│ │ │ repo1   .env         API_KEY     HIGH   │ │ │
│ │ │ repo2   config.js    Password    MED    │ │ │
│ │ └─────────────────────────────────────────┘ │ │
│ │ [Export CSV] [Export JSON] [Generate PDF]  │ │
│ └─────────────────────────────────────────────┘ │
└─────────────────────────────────────────────────┘
```

### Workflow
1. User enters GitHub credentials
2. Application fetches user's repositories
3. User selects repositories to scan
4. Scanning process begins with progress indication
5. Results displayed in sortable/filterable table
6. Export options for reporting

## Security Considerations

### Credential Protection
- No plaintext password storage
- Optional integration with system keyring
- Session timeout after inactivity
- Clear sensitive data on application exit

### API Usage
- Rate limit compliance with GitHub API
- Graceful handling of API errors
- Retry logic with exponential backoff
- Support for both GitHub.com and GitHub Enterprise

### Data Privacy
- No data transmission to external services
- Local-only processing and storage
- User control over data retention
- Clear privacy notice in application

## Performance Requirements

### Scalability Targets
- Handle repositories with 10,000+ commits
- Process files up to 10MB efficiently
- Support scanning 100+ repositories per session
- Memory usage under 500MB during normal operation

### Optimization Strategies
- Multi-threaded scanning with thread pool
- Lazy loading of commit history
- Efficient regex compilation and caching
- Progress checkpointing for large scans

## Error Handling

### Network Issues
- Graceful degradation on API failures
- Retry mechanism with backoff
- Offline mode for previously scanned data

### Authentication Errors
- Clear error messages for invalid credentials
- Two-factor authentication support guidance
- Token permission validation

### Resource Constraints
- Memory usage monitoring
- Large file skipping with user notification
- Scan interruption and resumption capability

## Testing Strategy

### Unit Tests
- Pattern detection accuracy
- API integration mocking
- GUI component behavior
- Error condition handling

### Integration Tests
- End-to-end scanning workflows
- GitHub API integration
- Cross-platform compatibility

### Security Tests
- Credential handling validation
- Data sanitization verification
- False positive/negative analysis

## Deployment and Distribution

### Installation Methods
- Standalone executable (PyInstaller)
- Python package (pip installable)
- Source code distribution

### Platform Support
- Windows 10/11
- macOS 10.15+
- Linux (Ubuntu, CentOS, Debian)

### Dependencies
- Minimal external dependencies
- Self-contained execution option
- Clear installation documentation

## Future Enhancements

### Planned Features
- GitLab and Bitbucket support
- Custom regex pattern editor
- Scheduled scanning
- Integration with security tools
- Machine learning-based detection

### Extensibility
- Plugin architecture for custom detectors
- API for external tool integration
- Configuration file customization
- Rule set versioning and updates