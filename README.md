<div align="center">

# 🛡️ GitGuard - GitHub Security Scanner

<p align="center">
  <img src="https://img.shields.io/badge/Python-3.10%2B-blue?style=for-the-badge&logo=python&logoColor=white" alt="Python 3.10+">
  <img src="https://img.shields.io/badge/GUI-Tkinter-brightgreen?style=for-the-badge&logo=python&logoColor=white" alt="Tkinter GUI">
  <img src="https://img.shields.io/badge/License-MIT-yellow?style=for-the-badge" alt="MIT License">
  <img src="https://img.shields.io/badge/Platform-Windows%20%7C%20macOS%20%7C%20Linux-lightgrey?style=for-the-badge" alt="Cross Platform">
</p>

<p align="center">
  <img src="https://img.shields.io/badge/Security-Scanning-critical?style=for-the-badge&logo=security&logoColor=white" alt="Security Scanning">
  <img src="https://img.shields.io/badge/Detection-37%2B%20Patterns-success?style=for-the-badge&logo=search&logoColor=white" alt="37+ Patterns">
  <img src="https://img.shields.io/badge/Export-HTML%20%7C%20CSV%20%7C%20JSON-blue?style=for-the-badge&logo=export&logoColor=white" alt="Multi-Format Export">
</p>

**🔍 A powerful desktop GUI application for scanning GitHub repositories and commit history to detect accidentally committed sensitive information like API keys, passwords, tokens, and other security vulnerabilities.**

<p align="center">
  <strong>🚀 Fast • 🎯 Accurate • 🔒 Secure • 🎨 User-Friendly</strong>
</p>

</div>

---

## 🚨 Security Notice

> **⚠️ IMPORTANT:** GitGuard is a **defensive security tool** designed to help users identify accidentally committed sensitive information in their **own repositories**. Never use this tool to scan repositories you don't own or have explicit permission to analyze.

---

## ✨ Features Overview

<table>
<tr>
<td width="50%">

### 🔍 **Core Scanning & Detection**
- 🌟 **Comprehensive Scanning**: Analyzes entire repository history including all commits
- 🧠 **Advanced Pattern Detection**: Identifies 37+ types of sensitive data with intelligent context-aware filtering
- 🎯 **False Positive Elimination**: Smart filtering for test files, documentation, checksums, and development configs
- 📊 **Risk Assessment**: Automatic risk scoring with color-coded visualization and severity categorization

### 🖥️ **User Interface & Workflow**  
- ✨ **Professional GUI**: User-friendly Tkinter interface with 4-tab workflow and comprehensive menu system
- 🔐 **Authentication Management**: Secure token storage with optional obfuscation and user consent warnings
- 🎨 **Custom Pattern Editor**: GUI-based creation, testing, and management of custom detection rules
- 🛠️ **Advanced Error Handling**: Context-aware error dialogs with technical details and suggested solutions

</td>
<td width="50%">

### ⚡ **Performance & Export**
- 🚀 **High-Performance Scanning**: 10x faster with batch processing and smart file prioritization
- 🌐 **Professional HTML Reports**: Auto-opening responsive reports with statistics and risk visualization
- 📄 **Multi-Format Export**: Generate reports in CSV, JSON, and HTML with comprehensive metadata
- 🧠 **Intelligent Caching**: Repository-specific result caching with commit-hash validation

### 🔒 **Security & Privacy**
- 🏠 **Local Processing**: All scanning performed locally - no data transmitted to external services
- 🛡️ **Secure Authentication**: Optional GitHub token storage with encryption warnings and user control
- ⚙️ **Configuration Management**: Persistent settings with import/export and security controls
- 📝 **Comprehensive Logging**: Full application logging with session tracking and performance metrics

</td>
</tr>
</table>

---

## 🕵️ Detected Sensitive Data Types

<details>
<summary><strong>🔑 API Keys & Tokens</strong> (Click to expand)</summary>

| Service | Pattern Example | Risk Level |
|---------|----------------|------------|
| 🔶 **AWS Access Keys** | `AKIA[0-9A-Z]{16}` | 🔴 Critical |
| 🐙 **GitHub PAT** | `ghp_[a-zA-Z0-9]{36}` | 🔴 Critical |
| 🔥 **Firebase Keys** | `AIza[0-9A-Za-z-_]{35}` | 🟠 High |
| 💳 **Stripe API** | `sk_live_`, `sk_test_` | 🔴 Critical |
| 📧 **SendGrid** | `SG.[0-9A-Za-z-_]{22}` | 🟠 High |
| 📱 **Twilio** | `AC[a-f0-9]{32}` | 🟠 High |
| 💰 **PayPal** | `EO[0-9A-Za-z-_]{50}` | 🔴 Critical |
| 🛍️ **Shopify** | `shpat_[a-zA-Z0-9]{32}` | 🟠 High |

</details>

<details>
<summary><strong>🗃️ Database Credentials</strong> (Click to expand)</summary>

- 🍃 **MongoDB**: `mongodb://[user:pass@]host:port/db`
- 🐬 **MySQL**: `mysql://[user:pass@]host:port/db`
- 🐘 **PostgreSQL**: `postgresql://[user:pass@]host:port/db`
- 🗄️ **Redis**: Connection strings with embedded credentials
- 🔗 **Generic DB URLs**: Any connection URL with embedded credentials

</details>

<details>
<summary><strong>🔐 Private Keys & Certificates</strong> (Click to expand)</summary>

- 🔑 **RSA Private Keys**: `-----BEGIN RSA PRIVATE KEY-----`
- 🔒 **SSH Private Keys**: `-----BEGIN OPENSSH PRIVATE KEY-----`
- 🛡️ **PGP Private Keys**: `-----BEGIN PGP PRIVATE KEY-----`
- 📜 **SSL/TLS Certificates**: Various certificate formats
- 🎫 **JWT Tokens**: JSON Web Tokens with high entropy

</details>

<details>
<summary><strong>🌍 Environment Variables</strong> (Click to expand)</summary>

- ⚡ **Common Secrets**: `SECRET`, `PASSWORD`, `TOKEN`, `KEY`
- ☁️ **AWS Variables**: `AWS_ACCESS_KEY`, `AWS_SECRET_KEY`
- 🔧 **API Keys**: `.env` format API keys and tokens
- 🐳 **Docker Secrets**: Docker Compose environment secrets
- ☸️ **Kubernetes**: Secret manifests and config maps

</details>

---

## 🆕 Latest Improvements (Session 7)

<div align="center">

### 🎉 **Major Feature Updates** 🎉

</div>

<table>
<tr>
<td width="33%">

#### 🔐 **Authentication & Token Management**
- 💾 **Save Authentication Button**: New manual save option for GitHub credentials
- 🔐 **Secure Token Storage**: Optional GitHub token persistence with Base64 obfuscation  
- ⚠️ **Security Warnings**: Clear consent dialogs for token storage with risk explanations
- 🔄 **Auto-Load Credentials**: Automatic restoration of saved authentication on startup

</td>
<td width="33%">

#### 📊 **Export & Report Enhancements**  
- 🌐 **Auto-Open HTML Reports**: HTML exports now automatically open in browser
- 📈 **Enhanced Report Quality**: Improved error handling and fallback mechanisms
- 📁 **Output Organization**: Default output folder creation with proper gitignore protection

</td>
<td width="33%">

#### 🎯 **False Positive Detection Improvements**
- 🧪 **Smart Test File Filtering**: Automatic detection and filtering of test files (_test.go, /tests/, etc.)
- 📚 **Documentation Exclusions**: Skip obvious examples in .md files and documentation  
- 🔧 **Development Config Filtering**: Intelligent handling of docker-compose.dev.yml and localhost configs

</td>
</tr>
</table>

<div align="center">

#### 🔬 **Detection Accuracy Improvements**

</div>

- ⚔️ **Basic Auth False Positives**: Enhanced filtering for game content ("Basic Sword" vs authentication)
- 🧮 **Checksum File Handling**: Proper exclusion of Go package checksums (go.sum) from secret detection
- 🔍 **Template Pattern Recognition**: Filter environment variable templates like `${JWT_SECRET}`
- 🗃️ **Database Credential Filtering**: Smart detection of test/development database connections

---

## 🚀 Quick Start

### 📋 Prerequisites

<p align="center">
<img src="https://img.shields.io/badge/Python-3.10%2B-blue?style=flat-square&logo=python" alt="Python 3.10+">
<img src="https://img.shields.io/badge/Git-Required-orange?style=flat-square&logo=git" alt="Git Required">
<img src="https://img.shields.io/badge/GitHub-Token-black?style=flat-square&logo=github" alt="GitHub Token">
</p>

### 📥 Installation

```bash
# Clone the repository
git clone https://github.com/dev-alt/GitGuard.git
cd GitGuard

# Install dependencies
pip install -r requirements.txt

# Launch GitGuard
python src/gui.py
```

### 🎯 Quick Usage

1. **🔐 Authenticate**: Enter your GitHub token in the Authentication tab
2. **📂 Load Repositories**: Browse and select repositories from your GitHub account  
3. **🔍 Configure Scan**: Choose scan depth and configure detection patterns
4. **▶️ Start Scanning**: Click scan and watch real-time progress
5. **📊 Review Results**: Export results to HTML, CSV, or JSON formats

---

## 🎨 Custom Pattern Editor

<div align="center">

**🛠️ Create Your Own Detection Rules!**

</div>

GitGuard includes a powerful GUI-based pattern editor for creating custom detection rules:

```regex
# Example Custom Pattern
Name: Internal API Key
Description: Company-specific API key format  
Pattern: MYCO_API_[A-Za-z0-9]{32}
Risk Level: HIGH
```

**Features:**
- 🎯 **Real-time Regex Testing**: Test patterns before saving
- 📚 **Pattern Library**: Import/Export pattern collections  
- 🔧 **JSON Export/Import**: Share patterns across installations
- ✅ **Validation**: Automatic pattern validation and suggestions

---

## 🛠️ Advanced Configuration

<details>
<summary><strong>⚙️ Scanning Configuration</strong> (Click to expand)</summary>

### Scan Depth Options
- **🏄 Surface (Latest Commit)**: Fast scanning of current repository state
- **🏊 Deep (Full History)**: Complete commit history analysis  
- **🏗️ Custom**: User-defined commit range and file filtering

### Performance Tuning
- **📊 Batch Processing**: Configure concurrent file operations
- **🎯 File Prioritization**: Scan high-risk files first
- **💾 Intelligent Caching**: Skip unchanged repositories
- **⏱️ Timeout Controls**: Prevent hung operations

</details>

<details>
<summary><strong>📊 Export Formats</strong> (Click to expand)</summary>

### Available Formats
- **🌐 HTML**: Interactive reports with charts and statistics
- **📄 CSV**: Spreadsheet-compatible tabular data
- **📝 JSON**: Structured data for programmatic analysis

### Report Features  
- **📈 Risk Visualization**: Color-coded severity indicators
- **📊 Statistical Analysis**: Finding counts by type and severity
- **🔗 Interactive Navigation**: Click-to-view source code
- **📅 Metadata**: Scan configuration and timestamp information

</details>

---

## 🤝 Contributing

We welcome contributions! Here's how you can help:

<div align="center">

<a href="https://github.com/dev-alt/GitGuard/issues"><img src="https://img.shields.io/badge/Report%20Issues-red?style=for-the-badge&logo=github" alt="Report Issues"></a>
<a href="https://github.com/dev-alt/GitGuard/pulls"><img src="https://img.shields.io/badge/Submit%20PR-green?style=for-the-badge&logo=github" alt="Submit PR"></a>
<a href="https://github.com/dev-alt/GitGuard/discussions"><img src="https://img.shields.io/badge/Join%20Discussion-blue?style=for-the-badge&logo=github" alt="Join Discussion"></a>

</div>

1. 🍴 Fork the repository
2. 🌿 Create a feature branch (`git checkout -b feature/amazing-feature`)
3. 💾 Commit your changes (`git commit -m 'Add amazing feature'`)
4. 🚀 Push to branch (`git push origin feature/amazing-feature`)
5. 📮 Open a Pull Request

---

## 📄 License

<div align="center">

This project is licensed under the **MIT License** - see the [LICENSE](LICENSE) file for details.

<img src="https://img.shields.io/badge/License-MIT-yellow?style=for-the-badge" alt="MIT License">

</div>

---

## 🙏 Acknowledgments

- 🐙 **GitHub API**: For providing excellent repository access
- 🐍 **Python Community**: For the amazing ecosystem and libraries
- 🔐 **Security Researchers**: For inspiration and pattern identification
- 👥 **Open Source Community**: For feedback and contributions

---

<div align="center">

### 🌟 **Star this repository if you find it helpful!** ⭐

<p align="center">
  <img src="https://img.shields.io/github/stars/dev-alt/GitGuard?style=social" alt="GitHub Stars">
  <img src="https://img.shields.io/github/forks/dev-alt/GitGuard?style=social" alt="GitHub Forks">
  <img src="https://img.shields.io/github/watchers/dev-alt/GitGuard?style=social" alt="GitHub Watchers">
</p>

**Made with ❤️ for the security community**

---

*GitGuard - Protecting your repositories, one commit at a time* 🛡️

</div>