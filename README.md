# Advanced Security Scanner & Risk Assessment Tool

A comprehensive, production-ready security scanning and risk assessment framework built with Python. This tool performs network scans using Nmap, analyzes results, identifies vulnerabilities, and generates detailed reports in multiple formats.

## 🚀 Features

### Core Capabilities

- **Advanced Nmap Integration**
  - Async/sync scanning support
  - Comprehensive error handling
  - Multiple output formats (XML, JSON)
  - Configurable timeouts and privilege escalation
  - Concurrent multi-target scanning

- **Flexible Scan Profiles**
  - 10+ pre-configured scan profiles (quick, comprehensive, stealth, vulnerability, etc.)
  - Custom profile creation
  - Profile combination capabilities
  - Optimized for different use cases

- **Intelligent Parsing**
  - Comprehensive XML parsing
  - Service and version detection
  - OS detection extraction
  - Script output parsing
  - CPE (Common Platform Enumeration) extraction

- **Advanced Risk Assessment**
  - CVE mapping and vulnerability detection
  - CVSS score integration
  - Service-based risk scoring
  - Port-based risk assessment
  - Automatic recommendation generation

- **Professional Reporting**
  - **JSON Reports**: Machine-readable structured data
  - **HTML Reports**: Beautiful, styled web reports with visualizations
  - **CSV Reports**: Spreadsheet-friendly vulnerability lists
  - Comprehensive summaries and statistics
  - Risk level categorization

## 📋 Prerequisites

- Python 3.8 or higher
- Nmap installed on the system
  - **Linux**: `sudo apt-get install nmap` (Debian/Ubuntu) or `sudo yum install nmap` (RHEL/CentOS)
  - **macOS**: `brew install nmap`
  - **Windows**: Download from [nmap.org](https://nmap.org/download.html)

## 🛠️ Installation

1. Clone or navigate to the project directory:
```bash
cd /home/tls123/Projects/prototype_2
```

2. (Optional) Create a virtual environment:
```bash
python3 -m venv venv
source venv/bin/activate  # On Windows: venv\Scripts\activate
```

3. The project uses only Python standard library modules, so no pip install is required!

4. Ensure Nmap is accessible:
```bash
nmap --version
```

## 📖 Usage

### Basic Usage

```bash
# Quick scan with default profile
python main.py 192.168.1.0/24

# Scan specific host
python main.py 192.168.1.1

# Scan multiple targets
python main.py 192.168.1.1 10.0.0.1 172.16.0.1
```

### Scan Profiles

List available profiles:
```bash
python main.py --list-profiles
```

Use a specific profile:
```bash
# Comprehensive scan (all ports, OS detection, scripts)
python main.py 192.168.1.1 --profile comprehensive

# Vulnerability-focused scan
python main.py 192.168.1.1 --profile vulnerability

# Stealth scan (SYN scan with decoys)
python main.py 192.168.1.1 --profile stealth

# Quick scan (fast, top 100 ports)
python main.py 192.168.1.1 --profile quick
```

### Custom Scan Arguments

```bash
# Custom port range and arguments
python main.py 192.168.1.1 --args "-p 80,443,8080 -sV -A"

# UDP scan
python main.py 192.168.1.1 --profile udp
```

### Output Options

```bash
# Specify output directory
python main.py 192.168.1.1 --output-dir /path/to/reports

# Save raw XML output
python main.py 192.168.1.1 --output-xml scan_results.xml

# Use custom CVE database
python main.py 192.168.1.1 --cve-db /path/to/cve_mapping.csv
```

### Advanced Options

```bash
# Increase timeout for slow networks
python main.py 192.168.1.0/24 --timeout 600

# Use sudo for privileged scans (SYN scan, OS detection)
python main.py 192.168.1.1 --sudo --profile comprehensive

# Verbose logging
python main.py 192.168.1.1 --verbose
```

### Complete Example

```bash
python main.py 192.168.1.0/24 \
  --profile comprehensive \
  --output-dir reports \
  --cve-db reports/cve_mapping.csv \
  --timeout 600 \
  --verbose
```

## 📊 Report Formats

All reports are saved in the `reports/` directory (or specified output directory) with timestamps.

### JSON Report
- Machine-readable format
- Complete scan data and risk assessments
- Suitable for automation and integration

### HTML Report
- Professional web-based visualization
- Color-coded risk levels
- Interactive tables and summaries
- Beautiful styling and layout
- Can be opened in any web browser

### CSV Report
- Spreadsheet-friendly format
- Vulnerability details
- Easy to import into Excel/Google Sheets
- Suitable for tracking and analysis

## 🏗️ Architecture

```
prototype_2/
├── scanner/
│   ├── __init__.py
│   ├── nmap_runner.py      # Nmap execution and result handling
│   └── scan_profile.py     # Scan profile configurations
├── analyzer/
│   ├── __init__.py
│   ├── parser.py           # XML parsing and data extraction
│   └── risk_engine.py      # Risk assessment and CVE mapping
├── reports/
│   ├── __init__.py
│   ├── cve_mapping.csv     # CVE database
│   └── report_generator.py # Multi-format report generation
├── main.py                 # CLI entry point
├── requirements.txt        # Dependencies (none required!)
└── README.md              # This file
```

## 🔍 Available Scan Profiles

| Profile | Description | Use Case |
|---------|-------------|----------|
| `quick` | Fast scan of top 100 ports with version detection | Quick reconnaissance |
| `comprehensive` | All ports, OS detection, scripts, aggressive scan | Full assessment |
| `stealth` | SYN scan with packet fragmentation and decoys | Evasion scenarios |
| `vulnerability` | Focused on vulnerability detection scripts | Security audits |
| `udp` | UDP port scanning | UDP service discovery |
| `os_detection` | OS fingerprinting focused | System identification |
| `service_scan` | Maximum version detection intensity | Service enumeration |
| `safe` | Standard ports (1-1024) only | Conservative scanning |
| `intense` | All ports with aggressive timing | Fast comprehensive scan |

## 🛡️ Risk Assessment

The risk engine evaluates:

- **Known Vulnerabilities**: CVE mapping with CVSS scores
- **Service Risks**: Inherent risks of exposed services (FTP, Telnet, etc.)
- **Port Risks**: High-risk ports (RDP, SMB, databases, etc.)
- **Version Exposure**: Information disclosure risks
- **Configuration Issues**: Common misconfigurations

**Risk Levels:**
- 🔴 **Critical** (80-100): Immediate action required
- 🟠 **High** (60-79): Priority remediation needed
- 🟡 **Medium** (40-59): Should be addressed
- 🔵 **Low** (20-39): Consider addressing
- ⚪ **Info** (0-19): Informational only

## 🔧 Configuration

### CVE Database

The CVE mapping CSV file (`reports/cve_mapping.csv`) maps services to known vulnerabilities. Format:

```csv
service,cve_id,description,cvss_score
apache,CVE-2021-41773,Path Traversal in Apache 2.4.49,9.8
nginx,CVE-2021-23017,Use-after-free in DNS resolver,7.5
```

You can expand this database with additional CVEs relevant to your environment.

### Custom Scan Profiles

You can create custom profiles programmatically:

```python
from scanner.scan_profile import ScanProfile

ScanProfile.create_custom_profile(
    name="my_profile",
    ports="80,443,8080",
    scripts=["vuln", "auth"],
    scan_type="-sV",
    timing="-T4"
)
```

## ⚠️ Legal and Ethical Considerations

**IMPORTANT**: This tool is for authorized security testing only.

- Only scan networks you own or have explicit written permission to test
- Unauthorized scanning is illegal in many jurisdictions
- Always obtain proper authorization before conducting security scans
- Respect network policies and rate limits
- Be aware of your local laws regarding security scanning

## 🐛 Troubleshooting

### Nmap not found
```bash
# Verify installation
which nmap
nmap --version

# Install if missing (example for Debian/Ubuntu)
sudo apt-get update && sudo apt-get install nmap
```

### Permission denied errors
- Use `--sudo` flag for privileged scans (SYN scan, OS detection)
- Ensure user has sudo privileges if using --sudo flag

### Timeout errors
- Increase timeout with `--timeout` option
- Use faster scan profiles (e.g., `quick` instead of `comprehensive`)
- Check network connectivity

### No results or empty reports
- Verify target is reachable
- Check firewall rules
- Try with different scan profiles
- Use verbose mode (`--verbose`) for debugging

## 📝 Development

### Code Structure

The project follows a modular architecture:

- **scanner/**: Network scanning functionality
- **analyzer/**: Data parsing and risk assessment
- **reports/**: Report generation
- **main.py**: CLI orchestration

### Adding Features

- **New scan profiles**: Edit `scanner/scan_profile.py`
- **CVE mappings**: Update `reports/cve_mapping.csv`
- **Risk rules**: Modify `analyzer/risk_engine.py`
- **Report formats**: Extend `reports/report_generator.py`

## 📄 License

This project is provided as-is for security assessment purposes.

## 🤝 Contributing

Contributions welcome! Areas for improvement:

- Additional CVE mappings
- More scan profiles
- Enhanced risk assessment algorithms
- Additional report formats
- Performance optimizations
- Additional vulnerability databases

## 🔗 References

- [Nmap Documentation](https://nmap.org/book/)
- [CVE Database](https://cve.mitre.org/)
- [CVSS Scoring](https://www.first.org/cvss/)

## 📞 Support

For issues, questions, or contributions, please refer to the project documentation or create an issue in the project repository.

---

**Remember**: Always scan responsibly and with proper authorization! 🛡️

