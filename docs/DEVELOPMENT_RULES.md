# GitGuard Development Rules

**Established**: Session 1  
**Purpose**: Ensure consistent, secure, and well-documented development practices for GitGuard - GitHub Security Scanner

---

## Mandatory Workflow for ALL Future Development

### 1. Documentation First 📚
- **Always update README.md** for any new features
- **Update relevant documentation** files (this file, examples, etc.)
- **Maintain .development_log.md** with session details including:
  - User instructions/requests
  - Implementation steps taken by Claude
  - Files created/modified and reasoning
  - Security considerations and decisions

### 2. Security Review 🔐
**Before every commit, verify:**
- ✅ Check all files for sensitive data (passwords, keys, IPs)
- ✅ Verify .gitignore excludes new sensitive patterns  
- ✅ Review for SSH keys, passwords, API keys, server details
- ✅ Use example/template files for sensitive configurations
- ✅ Never commit real credentials or production data
- ✅ **NEVER commit real GitHub tokens or user credentials**
- ✅ **NEVER commit actual scan results with real repository data**

**Security Exclusions Checklist:**
```
# SSH Keys and Certificates
*.pem, *.key, *.crt, *.p12, *.pfx
id_*, *_rsa*, *_ed25519*, *_ecdsa*
gitguard_ed25519, gitguard_ed25519.pub

# GitHub Authentication
.env*, config.json, github_token.txt
auth_config.json, credentials.json

# Scan Results and Cache
scan_results/, cache/, reports/
*.csv, *.json (scan reports)
.gitguard_cache/, temp_scan_data/

# Application Data
logs/, *.log (application logs)
user_data/, saved_scans/, exports/
```

### 3. Development Session Tracking 📝
**For every development session, document:**
- User's exact instructions/requests
- Claude's interpretation and approach
- Step-by-step implementation details
- Files created/modified with explanations
- Testing performed (including GUI testing)
- Security considerations
- Any issues encountered and resolutions

### 4. Git Workflow 🚀
**Standard sequence for every development session:**
```bash
# 1. Stage all changes
git add .

# 2. Commit with descriptive message
git commit -m "Descriptive commit message with feature summary

- Key changes made
- Files affected
- Security considerations

🤖 Generated with [Claude Code](https://claude.ai/code)
Co-Authored-By: Claude <noreply@anthropic.com>"

# 3. Push to GitHub  
git push

# 4. Verify no sensitive data in commit history
git log --oneline -3
```

### 5. Testing & Validation ✅
**Before every commit:**
- ✅ Test new features work correctly
- ✅ Test GUI components and user interactions
- ✅ Verify pattern detection accuracy
- ✅ Ensure existing functionality still works
- ✅ Test that .gitignore exclusions work
- ✅ Verify no sensitive data is staged for commit
- ✅ Test with example/dummy repositories only

---

## Security Standards

### Never Commit:
- ❌ SSH private keys (id_rsa, id_ed25519, *.pem, *.key)
- ❌ GitHub Personal Access Tokens or passwords
- ❌ Real repository scan results or cached data
- ❌ **REAL GITHUB USERNAMES** in examples or test data
- ❌ **ACTUAL REPOSITORY NAMES** from scans
- ❌ SSL certificates or credential files
- ❌ Real log files with production data
- ❌ Environment files with real values (.env)
- ❌ Database connection strings
- ❌ Any file containing "password", "secret", "key", "token"
- ❌ **CLIENT/CUSTOMER REPOSITORY DATA** - Never expose scanned content
- ❌ **ACTUAL API KEYS FOUND IN SCANS** - Never commit discovered secrets

### Always Use:
- ✅ Example files with placeholder values
- ✅ Template configurations (github_config.json.example)
- ✅ Environment variable references
- ✅ **GENERIC GITHUB USERNAMES**: testuser, example-user, demo-account
- ✅ **EXAMPLE REPOSITORY NAMES**: my-repo, test-project, sample-code
- ✅ **PLACEHOLDER TOKENS**: ghp_xxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxx
- ✅ Dummy/test credentials in documentation
- ✅ Clear security warnings in README
- ✅ **MOCK SCAN RESULTS** with fake/sanitized data

### Always Exclude in .gitignore:
- ✅ Real configuration files (github_config.json, .env*)
- ✅ SSH key files (id_*, *.pem, *.key, *.crt, gitguard_ed25519*)
- ✅ Scan result directories and cache (scan_results/, cache/, .gitguard_cache/)
- ✅ Export files and reports (exports/, *.csv, *.json, scan_report.*)
- ✅ User data and saved scans (user_data/, saved_scans/)
- ✅ Application logs (logs/, *.log, debug.log)
- ✅ Backup and temporary files
- ✅ IDE-specific files with potential secrets

---

## Project Structure Standards

### Folder Organization:
```
gitguard/
├── src/             # Source code (included in git)
│   ├── auth.py      # Authentication module
│   ├── scanner.py   # Repository scanning logic
│   ├── detection.py # Pattern detection engine
│   ├── gui.py       # Tkinter GUI application
│   └── reporting.py # Report generation
├── config/          # Configuration templates (check for sensitive data)
├── scan_results/    # Scan outputs (ALWAYS excluded from git)
├── cache/           # Application cache (ALWAYS excluded from git)
├── exports/         # User exports (ALWAYS excluded from git)
├── testdata/        # Sample/test data (safe for git - no real data)
├── docs/            # Additional documentation (included in git)
└── examples/        # Example configurations and usage (included in git)
```

### Folder Security Rules:
- **config/**: May contain sensitive data when implemented - verify before commits
- **scan_results/**: NEVER commit - contains real scan data with potentially sensitive information
- **cache/**: NEVER commit - contains cached GitHub data and temporary files
- **exports/**: NEVER commit - contains user-generated reports that may expose sensitive data
- **testdata/**: Safe to commit - contains only sanitized sample data
- **examples/**: Review carefully - must contain only placeholder/example data

### New Folder Guidelines:
- Any new folder that might contain real scan data must be added to .gitignore
- Document the purpose and security considerations in folder README.md files
- Use placeholder/example files for any configuration templates

---

## Documentation Standards

### README.md Requirements:
- **Feature documentation** for every new capability
- **Usage examples** with safe placeholder values
- **Security warnings** for authentication and scanning features
- **Installation and setup** instructions
- **Command line options** documentation (if CLI added later)
- **Security notes** section
- **GUI user guide** with screenshots (sanitized)
- **Pattern detection documentation** with example (fake) findings

### Code Documentation:
- **Clear function comments** for all modules
- **Security warnings** in code near sensitive operations
- **Example usage** in function documentation
- **Error handling** explanations
- **Pattern regex documentation** with explanations

### .development_log.md Format:
```markdown
### Session X: [Title]
**User Request**: "[Exact user instruction - sanitized]"

**Tasks Completed**:
1. ✅ **Task description**
   - Implementation details
   - Files affected
   - Security considerations

**Files Added/Modified**:
- filename.py - Description of changes
- README.md - Updated sections

**Security Review**:
- Verified no credentials committed
- Updated .gitignore for new patterns
- Added security warnings to docs
```

### Documentation Security Guidelines

**Critical Rule: ALL examples in documentation MUST use generic placeholders**

#### ✅ Safe Documentation Examples:
```python
# Safe configuration examples
github_username = "example-user"
github_token = "ghp_xxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxx"
repository_name = "my-test-repo"

# Safe scan result examples
scan_results = {
    "repository": "user/example-repo",
    "findings": [
        {"file": "config.py", "pattern": "API_KEY", "risk": "HIGH"}
    ]
}
```

#### ❌ Dangerous Documentation Examples:
```python
# NEVER include real usernames or tokens in documentation
github_username = "johnsmith123"  # ❌ Real username
github_token = "ghp_real_token_here"  # ❌ Real token
```

#### Development Log Security:
- **User Requests**: Sanitize user quotes to remove any real GitHub usernames/repos
- **Command Examples**: Always use placeholder usernames and repository names
- **Error Messages**: Redact any real repository information from logged errors
- **Scan Results**: Use generic examples, never log actual findings

---

## Emergency Security Procedures

### If Sensitive Data is Accidentally Committed:

1. **Immediate Actions:**
   ```bash
   # If not yet pushed
   git reset --soft HEAD~1  # Undo last commit
   git reset HEAD filename  # Unstage sensitive file
   
   # If already pushed (DANGEROUS - rewrites history)
   git revert <commit-hash>  # Safer option
   # OR contact GitHub support for sensitive data removal
   ```

2. **Rotate Compromised Credentials:**
   - Revoke any GitHub tokens that were exposed
   - Generate new SSH keys if compromised
   - Update authentication configurations
   - Notify relevant stakeholders

3. **Review and Improve:**
   - Update .gitignore patterns
   - Review development workflow
   - Add additional security checks

---

## GitGuard-Specific Security Considerations

### Pattern Detection Safety:
- **Test patterns** only with synthetic/example data
- **Never log** actual discovered secrets during development
- **Sanitize** any real findings before documentation
- **Use mock data** for all testing and examples

### GUI Security:
- **Never screenshot** real scan results for documentation
- **Use example data** in GUI mockups and demos
- **Clear sensitive data** from memory after processing
- **Secure credential storage** implementation testing

### GitHub API Usage:
- **Rate limiting** implementation and testing
- **Token validation** without exposing token values
- **Error handling** without leaking authentication details
- **API response** sanitization in logs and debug output

---

## Compliance Checklist

**Before every commit, confirm:**
- [ ] No real GitHub tokens or credentials
- [ ] No SSH private keys or certificates  
- [ ] No real GitHub usernames or repository names in examples
- [ ] No actual scan results or cached data
- [ ] No real discovered secrets from testing
- [ ] .gitignore updated for new sensitive patterns
- [ ] Documentation updated for new features
- [ ] Security warnings added where appropriate
- [ ] Example files use placeholder values only
- [ ] .development_log.md updated with session details
- [ ] New folders properly documented and secured

**Before every push, confirm:**
- [ ] All tests pass (with mock data only)
- [ ] GUI components work correctly with example data
- [ ] Pattern detection accurate on test cases
- [ ] No sensitive data in git history
- [ ] README.md reflects current features
- [ ] Security notes are up to date

---

## Continuous Improvement

These rules should be:
- **Reviewed** after every major feature addition
- **Updated** when new security concerns arise
- **Enhanced** based on lessons learned from GitGuard development
- **Followed consistently** by all contributors

Remember: **Security and Documentation are not optional - they are requirements, especially for a security tool like GitGuard.**

---

*These rules ensure the GitGuard project maintains the highest security standards and comprehensive documentation while enabling rapid development of a sensitive security scanning tool.*