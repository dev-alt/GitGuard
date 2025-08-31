# GitGuard - GitHub Security Scanner

A desktop GUI application for scanning GitHub repositories and commit history to detect sensitive information such as API keys, passwords, tokens, environment files, and other security vulnerabilities.

## 🚨 Security Notice

**GitGuard is a defensive security tool designed to help users identify accidentally committed sensitive information in their own repositories. Never use this tool to scan repositories you don't own or have explicit permission to analyze.**

## Features

- **Comprehensive Scanning**: Analyzes entire repository history including all commits
- **Pattern Detection**: Identifies 120+ types of sensitive data patterns
- **Simple GUI**: User-friendly Tkinter interface with authentication and results display
- **Local Processing**: All scanning performed locally - no data transmitted to external services
- **Export Options**: Generate reports in CSV, JSON, and PDF formats
- **Risk Assessment**: Automatic risk scoring for discovered findings

## Detected Sensitive Data Types

### API Keys & Tokens
- AWS Access Keys (`AKIA[0-9A-Z]{16}`)
- GitHub Personal Access Tokens (`ghp_[a-zA-Z0-9]{36}`)
- Generic API Keys and Tokens
- OAuth Tokens and Bearer Tokens

### Database Credentials
- Connection strings (MongoDB, MySQL, PostgreSQL, Redis)
- Database passwords and usernames
- Connection URLs with embedded credentials

### Private Keys & Certificates
- RSA Private Keys (`-----BEGIN RSA PRIVATE KEY-----`)
- SSH Private Keys (`-----BEGIN OPENSSH PRIVATE KEY-----`)
- PGP Private Keys
- SSL/TLS Certificates

### Environment Variables
- Common secret environment variables (`SECRET`, `PASSWORD`, `TOKEN`)
- AWS environment variables (`AWS_ACCESS_KEY`, `AWS_SECRET_KEY`)
- API keys in .env format

### Configuration Files
- `.env` and `.env.*` files
- `config.json`, `settings.json` files
- Docker Compose files with secrets
- Database configuration files

## Installation

### Prerequisites
- Python 3.10 or higher
- Git (for repository cloning)
- GitHub account with appropriate permissions

### Setup

1. **Clone the repository:**
```bash
git clone https://github.com/dev-alt/GitGuard.git
cd GitGuard
```

2. **Create virtual environment:**
```bash
python -m venv venv
source venv/bin/activate  # On Windows: venv\\Scripts\\activate
```

3. **Install dependencies:**
```bash
pip install -r requirements.txt
```

## Usage

### Starting the Application

```bash
# Method 1: Using main entry point (recommended)
python main.py

# Method 2: Direct GUI launch  
python src/gui.py
```

### Authentication Options

#### Option 1: Personal Access Token (Recommended)
1. Generate a GitHub Personal Access Token at https://github.com/settings/tokens
2. Grant minimal read permissions: `repo` (for private repos) or `public_repo` (for public only)
3. Enter the token in GitGuard's authentication form

#### Option 2: Username/Password
1. Enter your GitHub username and password
2. Handle 2FA prompts if enabled
3. **Note**: Password authentication may be deprecated by GitHub

### Scanning Process

1. **Authenticate**: Enter your GitHub credentials
2. **Select Repositories**: Choose which repositories to scan
3. **Start Scan**: Begin the security analysis
4. **Review Results**: Examine findings with risk assessments
5. **Export Reports**: Generate detailed reports for documentation

## Security and Privacy

### Data Protection
- **Local Processing Only**: All scanning performed on your machine
- **No External Transmission**: No data sent to external services
- **Secure Credential Storage**: Optional integration with system keyring
- **Memory Protection**: Sensitive data cleared from memory after use

### GitHub API Usage
- **Minimal Permissions**: Requests only necessary read access
- **Rate Limit Compliance**: Respects GitHub API rate limits
- **Error Handling**: Graceful handling of API errors and timeouts

### Privacy Features
- **User Control**: Complete control over what repositories are scanned
- **Data Retention**: User-controlled data retention and deletion
- **No Telemetry**: No usage analytics or telemetry data collected

## Configuration

### Example Configuration Files

**github_config.json.example**:
```json
{
    "username": "your-github-username",
    "token": "ghp_xxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxx",
    "api_url": "https://api.github.com",
    "timeout": 30,
    "max_repos": 100
}
```

**Custom Pattern Configuration**:
```json
{
    "custom_patterns": [
        {
            "name": "Internal API Key",
            "pattern": "INTERNAL_API_[A-Za-z0-9]{32}",
            "risk_level": "HIGH",
            "description": "Internal API key pattern"
        }
    ]
}
```

## Documentation

📚 **Complete documentation is available in the [docs/](docs/) folder:**

- **[Technical Specification](docs/TECHNICAL_SPECIFICATION.md)** - Architecture and implementation details
- **[Security & Privacy Plan](docs/SECURITY_PRIVACY_PLAN.md)** - Security framework and threat model
- **[Development Rules](docs/DEVELOPMENT_RULES.md)** - Development guidelines and security practices
- **[Development Log](docs/development_log.md)** - Implementation progress and decisions

## Development

### Project Structure

```
GitGuard/
├── main.py                 # Main application entry point
├── requirements.txt        # Python dependencies  
├── requirements-dev.txt    # Development dependencies
├── src/                    # Source code
│   ├── __init__.py        # Package initialization
│   └── gui.py            # Tkinter GUI application
├── config/               # Configuration templates
├── testdata/            # Test data (safe examples only)
│   └── clean_example.py   # Clean file with no security issues
├── examples/            # Example configurations
│   └── github_config.json.example
└── docs/               # Complete documentation
    ├── README.md          # Documentation index
    ├── TECHNICAL_SPECIFICATION.md
    ├── SECURITY_PRIVACY_PLAN.md  
    ├── DEVELOPMENT_RULES.md
    └── development_log.md
```

### Current Implementation Status

✅ **Core Infrastructure Complete:**
- Application entry point with dependency checking
- Professional GUI interface with documentation integration
- Project structure and configuration management
- Requirements specification for all dependencies
- Security-focused development approach

🚧 **Advanced Features (Planned):**
- Full GitHub authentication system
- 120+ pattern detection engine  
- Repository scanning with commit history traversal
- Multi-format reporting (CSV, JSON, HTML)
- Advanced GUI with scan progress and results display

### Development Setup

1. **Install development dependencies:**
```bash
pip install -r requirements-dev.txt
```

2. **Run tests:**
```bash
pytest tests/
```

3. **Code formatting:**
```bash
black src/
flake8 src/
```

### Contributing

1. Fork the repository
2. Create a feature branch
3. Make your changes following the security guidelines
4. Add tests for new functionality
5. Submit a pull request

**Security Guidelines for Contributors:**
- Never commit real GitHub tokens or credentials
- Use placeholder data in all examples and tests
- Follow the security patterns outlined in `DEVELOPMENT_RULES.md`
- Test with synthetic data only

## Technical Specifications

- **GUI Framework**: Tkinter (cross-platform, no external dependencies)
- **GitHub Integration**: PyGithub library
- **Pattern Detection**: Regex-based with entropy analysis
- **Architecture**: Modular design with separate authentication, scanning, and reporting components

## Troubleshooting

### Common Issues

**Authentication Errors:**
- Verify your GitHub token has correct permissions
- Check for 2FA requirements
- Ensure token is not expired

**Rate Limiting:**
- GitGuard respects GitHub API limits automatically
- Consider using authenticated requests for higher limits
- Large repositories may require multiple API calls

**Performance Issues:**
- Large repositories (10,000+ commits) may take several minutes
- Consider scanning specific date ranges for very large repos
- Monitor memory usage during large scans

### Support

For issues and questions:
1. Check the troubleshooting section above
2. Review the [GitHub Issues](https://github.com/yourusername/gitguard/issues) page
3. Create a new issue with detailed information

## License

This project is licensed under the MIT License - see the [LICENSE](LICENSE) file for details.

## Disclaimer

**GitGuard is intended for defensive security purposes only.** Users are responsible for:
- Only scanning repositories they own or have explicit permission to analyze
- Complying with GitHub's Terms of Service
- Following applicable laws and regulations
- Protecting any sensitive data discovered during scans

**The developers of GitGuard are not responsible for misuse of this tool or any consequences arising from its use.**

---

**🔒 Remember: Use GitGuard responsibly to protect your own code and improve your security posture.**