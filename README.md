# 🛡️ CyberPath 2.0

## Context-Aware Security Assessment Platform

CyberPath 2.0 is a Python-based **context-aware security assessment platform** designed to automate reconnaissance, service identification, security checks, risk analysis, and reporting.

CyberPath provides its own **CLI interface** for performing assessments. Internally, it uses **Nmap as the reconnaissance engine**, processes the discovered information, identifies the target's services, selects applicable security rules, performs security checks, and generates assessment results.

---

## 🚀 Features

- 🔍 Automated reconnaissance
- 🖥️ Host and port discovery
- 🌐 Service and version detection
- 📄 Nmap XML processing
- 🧠 Context-aware target analysis
- ⚙️ Dynamic rule selection
- 🔐 Service-specific security checks
- 📊 Finding analysis
- ⚠️ Risk assessment
- 📝 JSON report generation
- 🌐 HTML report generation
- 🧪 Automated testing
- 🐧 Kali Linux support
- 🧩 Modular architecture
- 💻 Command-line interface

---

# 🧠 How CyberPath 2.0 Works

The user interacts with **CyberPath CLI**, while Nmap works internally as the reconnaissance component.

```text
                 USER
                  │
                  ▼
          ┌────────────────┐
          │ CYBERPATH CLI  │
          └───────┬────────┘
                  │
                  ▼
          ┌────────────────┐
          │   NMAP ENGINE  │
          │ Reconnaissance │
          └───────┬────────┘
                  │
                  ▼
             NMAP XML
                  │
                  ▼
          ┌────────────────┐
          │   XML PARSER   │
          └───────┬────────┘
                  │
                  ▼
          ┌────────────────┐
          │ TARGET CONTEXT │
          └───────┬────────┘
                  │
                  ▼
          ┌────────────────┐
          │   RULE ENGINE  │
          └───────┬────────┘
                  │
                  ▼
          ┌────────────────┐
          │ SECURITY CHECKS│
          └───────┬────────┘
                  │
                  ▼
          ┌────────────────┐
          │    FINDINGS    │
          └───────┬────────┘
                  │
                  ▼
          ┌────────────────┐
          │   RISK ENGINE  │
          └───────┬────────┘
                  │
             ┌────┴────┐
             ▼         ▼
          JSON       HTML
         REPORT     REPORT
```

---

# 🔥 Why CyberPath Uses Nmap

CyberPath does **not require the user to manually run Nmap**.

Nmap is used internally because it provides reliable network and service reconnaissance.

The user interacts with:

```text
CyberPath CLI
```

while CyberPath handles:

```text
CyberPath CLI
      ↓
Nmap
      ↓
Reconnaissance
      ↓
CyberPath Analysis
```

This makes the workflow easier for the user and allows CyberPath to control the complete assessment pipeline.

---

# 📁 Project Structure

```text
CyberPath/
│
├── cyberpath/
│   ├── analyzer/
│   ├── checks/
│   ├── core/
│   ├── input/
│   ├── reporting/
│   ├── reports/
│   ├── scanner/
│   ├── cli.py
│   ├── main.py
│   └── __init__.py
│
├── data/
├── rules/
├── samples/
├── tests/
├── requirements.txt
└── README.md
```

---

# ⚙️ Requirements

- Kali Linux or compatible Linux distribution
- Python 3.x
- Nmap
- pip
- Python virtual environment

CyberPath requires Python packages listed in:

```text
requirements.txt
```

---

# 🔧 Installation

## 1. Clone the repository

```bash
git clone https://github.com/nkharsha2006/CyberPath.git
```

Enter the project:

```bash
cd CyberPath
```

---

## 2. Create a virtual environment

```bash
python3 -m venv .venv
```

---

## 3. Activate the environment

```bash
source .venv/bin/activate
```

You should see:

```text
(.venv)
```

in your terminal.

---

## 4. Install dependencies

```bash
pip install -r requirements.txt
```

---

## 5. Verify Nmap

```bash
nmap --version
```

If Nmap is not installed:

```bash
sudo apt update
sudo apt install nmap
```

---

# ▶️ Start CyberPath 2.0

Always run CyberPath from the **project root**.

```bash
cd ~/Projects/CyberPath
```

Activate the environment:

```bash
source .venv/bin/activate
```

Start CyberPath:

```bash
python3 -m cyberpath.main
```

A successful startup should display:

```text
============================================================
              CYBERPATH 2.0
   Context-Aware Security Assessment Platform
============================================================

[+] Detecting environment...
```

and eventually:

```text
============================================================
ENVIRONMENT STATUS: READY
============================================================
```

---

# 💻 CyberPath CLI

CyberPath provides its own command-line interface for performing security assessments.

View the available commands and options:

```bash
python3 -m cyberpath.cli --help
```

The CLI is the **recommended interface for running assessments**.

Instead of manually running Nmap commands, the user provides the target to CyberPath through its CLI.

```text
User
  ↓
CyberPath CLI
  ↓
Nmap
  ↓
Assessment Pipeline
  ↓
Reports
```

---

# 🎯 Performing an Assessment

Only assess systems that you own or have explicit authorization to test.

First display the available assessment options:

```bash
python3 -m cyberpath.cli --help
```

Use the target/scan option provided by the CLI to specify an authorized IP address or hostname.

For example, the intended workflow is:

```text
CyberPath CLI
      ↓
Target IP
      ↓
Nmap reconnaissance
      ↓
Service discovery
      ↓
Rule selection
      ↓
Security assessment
      ↓
Risk analysis
      ↓
Report
```

> **Note:** The exact CLI arguments may change as CyberPath evolves. Always use `--help` to see the currently supported syntax.

---

# 🏠 Testing CyberPath on 127.0.0.1

`127.0.0.1` refers to the local machine.

It is a good target for testing CyberPath in a controlled environment.

Start by checking the CLI:

```bash
python3 -m cyberpath.cli --help
```

Then provide:

```text
127.0.0.1
```

as the target using the supported CyberPath CLI option.

CyberPath should then perform the workflow internally:

```text
127.0.0.1
    ↓
CyberPath CLI
    ↓
Nmap
    ↓
Nmap Results
    ↓
Parser
    ↓
Service Detection
    ↓
Rule Engine
    ↓
Security Checks
    ↓
Findings
    ↓
Risk Analysis
    ↓
Reports
```

---

# 🌐 Scanning an IP Address

CyberPath can be used to assess an IP address when you have permission to test it.

Example authorized lab target:

```text
192.168.1.100
```

Use the CyberPath CLI:

```bash
python3 -m cyberpath.cli --help
```

Then use the appropriate target option supported by the current version.

Conceptually:

```text
CyberPath CLI
      ↓
192.168.1.100
      ↓
Nmap
      ↓
Open Ports
      ↓
Services
      ↓
Applicable Rules
      ↓
Security Checks
      ↓
Findings
      ↓
Reports
```

---

# 🧠 Context-Aware Assessment

CyberPath does not simply run every security check against every target.

It first identifies the services discovered during reconnaissance.

For example:

```text
22/tcp    SSH
80/tcp    HTTP
3306/tcp  MySQL
```

CyberPath can build a context:

```text
Target
│
├── SSH
│
├── HTTP
│
└── MySQL
```

The rule engine then selects relevant rules:

```text
SSH
 ↓
SSH Rules

HTTP
 ↓
HTTP Rules

MySQL
 ↓
MySQL Rules
```

This makes the assessment more targeted and modular.

---

# 🔐 Example Security Rules

CyberPath can contain service-specific rules.

### SSH

```text
SSH service detection
SSH version identification
SSH configuration checks
SSH authentication checks
SSH cryptographic configuration checks
SSH information disclosure checks
```

### HTTP

```text
HTTP security headers
HTTP methods
Server information disclosure
Web service configuration checks
```

The exact checks depend on the rules implemented in the current version.

---

# 📊 Assessment Results

After the assessment, CyberPath processes the results through its analysis pipeline.

```text
Reconnaissance
      ↓
Parsing
      ↓
Context
      ↓
Rules
      ↓
Security Checks
      ↓
Evidence
      ↓
Findings
      ↓
Risk
      ↓
Reports
```

CyberPath can produce:

### JSON

Designed for:

- Machine processing
- Automation
- Future integrations
- Dashboards
- Security pipelines

### HTML

Designed for:

- Human-readable analysis
- Security assessment review
- Demonstrations
- Reporting

---

# 🧪 Run Tests

Run the tests from the project root:

```bash
cd ~/Projects/CyberPath
source .venv/bin/activate
pytest -v
```

The test suite covers components including:

```text
Nmap Parser
Normalizer
Context
Rule Engine
Check Executor
HTTP Checks
Finding Analyzer
Risk Engine
JSON Reports
HTML Reports
Assessment Pipeline
```

---

# 🛠️ Troubleshooting

## `ModuleNotFoundError: No module named 'cyberpath'`

Make sure you are in the project root:

```bash
cd ~/Projects/CyberPath
```

Activate the virtual environment:

```bash
source .venv/bin/activate
```

Then use:

```bash
python3 -m cyberpath.main
```

Do not run:

```bash
cd cyberpath
python3 main.py
```

because the project is structured as a Python package.

---

## Nmap not found

Check:

```bash
nmap --version
```

Install if necessary:

```bash
sudo apt update
sudo apt install nmap
```

---

## Python dependencies missing

Run:

```bash
source .venv/bin/activate
pip install -r requirements.txt
```

---

# 🧹 Keeping the Repository Clean

Do not commit:

```text
.venv/
__pycache__/
*.pyc
*.log
*.pcap
*.pcapng
.env
private keys
API keys
passwords
tokens
personal scan results
```

A suitable `.gitignore` should include:

```gitignore
.venv/
venv/
env/

__pycache__/
*.py[cod]
.pytest_cache/

*.log
*.pcap
*.pcapng

.env
*.pem
*.key

.vscode/
.idea/
```

---

# 🔒 Responsible Use

CyberPath 2.0 is intended for:

- Authorized penetration testing
- Cybersecurity education
- CTF and lab environments
- Security research
- Testing systems you own
- Authorized organizational assessments

**Do not scan or assess systems without permission.**

The user is responsible for complying with all applicable laws, regulations, organizational policies, and authorization requirements.

---

# 🔮 Future Development

Potential future improvements include:

- Additional service-specific rules
- CVE integration
- Expanded OWASP/CWE mapping
- Improved risk scoring
- More security checks
- Dashboard integration
- Database-backed results
- Plugin-based rule system
- Parallel assessment
- CI/CD integration
- Additional report formats

---

# 👨‍💻 Author

**Harsha Vardhan Reddy**

Cybersecurity | Penetration Testing | Ethical Hacking

---

# ⭐ Project

**CyberPath 2.0**

> Context-Aware Security Assessment Platform

If you find the project useful, consider giving the repository a ⭐.

---

## ⚠️ Disclaimer

CyberPath 2.0 is provided for educational, research, and authorized security assessment purposes. The developers are not responsible for misuse of the software or unauthorized security testing.
