# 🏥 HealthGuard AI

### AI-Powered Medical Device Cybersecurity Risk Assessment Platform

HealthGuard AI is an AI-assisted cybersecurity decision-support platform designed to help healthcare technology professionals assess the security posture of network-connected medical devices and healthcare technology assets.

The application combines a **deterministic Python risk-scoring engine** with vulnerability intelligence, known-exploitation data, MITRE ATT&CK technique mapping, and Generative AI to produce structured cybersecurity assessments and prioritized security recommendations.

HealthGuard AI currently integrates:

- NIST National Vulnerability Database (NVD)
- CISA Known Exploited Vulnerabilities (KEV)
- MITRE ATT&CK
- OpenAI API
- SQLite
- Flask

> **Disclaimer**
>
> HealthGuard AI is an educational prototype developed for research, academic, and portfolio purposes. It is **not** intended to replace professional cybersecurity assessments, vulnerability scanning, penetration testing, regulatory audits, clinical engineering evaluations, or HIPAA compliance reviews.

---

# Features

## Medical Device Risk Assessment

HealthGuard AI evaluates the cybersecurity posture of medical devices and healthcare technology assets by documenting security conditions including:

- Device information
- Manufacturer and model
- Operating system
- Software support status
- Network connectivity
- Internet exposure
- Wireless connectivity
- Vendor remote access
- Multifactor authentication
- Authentication controls
- Encryption in transit
- Encryption at rest
- Network segmentation
- Patch management
- Audit logging
- Endpoint protection
- Lifecycle status
- Backup and recovery

The assessment produces a structured cybersecurity risk profile for the device.

---

## Deterministic Risk Engine

HealthGuard AI does **not** allow the AI model to determine or modify the numerical cybersecurity risk score.

Risk scores are calculated using a reproducible Python rule engine based on the security conditions entered during the assessment.

The scoring methodology evaluates conditions such as:

- Unsupported operating systems
- End-of-life devices
- Internet exposure
- Vendor remote access
- Missing multifactor authentication
- Weak account controls
- Default credentials
- Missing encryption
- Insufficient network segmentation
- Missing audit logging
- Inadequate patch management
- Missing endpoint protection
- Missing backup and recovery controls

Risk scores are normalized between:

```text
0 - 100
```

Risk levels:

| Risk Level | Score |
|---|---:|
| Low | 0–24 |
| Medium | 25–49 |
| High | 50–74 |
| Critical | 75–100 |

The deterministic design ensures that the same security conditions produce consistent risk calculations.

---

## NVD CVE Intelligence

HealthGuard AI integrates with the **NIST National Vulnerability Database (NVD)** to retrieve CVE candidates related to a user-supplied product or software search term.

Example search terms:

```text
Apache Log4j
Microsoft Windows 7
OpenSSL
VMware ESXi
Apache HTTP Server
```

For each CVE candidate, HealthGuard AI can display:

- CVE identifier
- CVSS score
- Severity
- Vulnerability description
- Published date
- Last modified date
- CVSS vector
- Direct NVD reference

Example:

```text
CVE-2021-44228
CVSS: 10.0
Severity: CRITICAL
```

> **Important:** The current implementation uses keyword-based CVE discovery. A keyword match does **not** confirm that a specific medical device, software product, configuration, or version is vulnerable.

The application therefore treats these results as **CVE candidates requiring validation**, rather than confirmed vulnerabilities.

Future versions can improve precision through CPE-based product and version matching.

---

## CISA Known Exploited Vulnerabilities Integration

After CVE candidates are retrieved from NVD, HealthGuard AI automatically compares their CVE identifiers against the **CISA Known Exploited Vulnerabilities (KEV) Catalog**.

This adds real-world exploitation context to vulnerability information.

For matching vulnerabilities, HealthGuard AI displays:

- Known Exploited: Yes / No
- Vendor
- Product
- Vulnerability name
- Date added to the KEV catalog
- Required remediation action
- CISA due date
- Known ransomware campaign use
- CWE identifiers

Example:

```text
CVE-2021-44228

CVSS: 10.0
Severity: CRITICAL

Known Exploited: Yes
Known Ransomware Use: Known
```

This allows HealthGuard AI to distinguish between vulnerabilities that are severe based on CVSS and vulnerabilities that also have evidence of exploitation in the wild.

---

## MITRE ATT&CK Mapping

HealthGuard AI maps selected cybersecurity conditions to potentially relevant **MITRE ATT&CK techniques**.

Example mappings include:

| Security Condition | MITRE ATT&CK Technique |
|---|---|
| Default credentials | T1078.001 – Default Accounts |
| Weak account controls | T1078 – Valid Accounts |
| Vendor remote access | T1133 – External Remote Services |
| Remote administration | T1021 – Remote Services |
| Internet exposure | T1190 – Exploit Public-Facing Application |

For each mapping, HealthGuard AI can display:

- ATT&CK technique ID
- Technique name
- Associated tactic
- Explanation of relevance
- Direct MITRE ATT&CK reference

> **Important:** ATT&CK mappings identify adversary techniques that may be relevant to the security conditions discovered during the assessment. They do **not** indicate that malicious activity or an actual attack was observed.

---

## AI-Assisted Security Analysis

After deterministic scoring and security-intelligence processing are completed, HealthGuard AI uses the OpenAI API to generate a structured cybersecurity analysis.

The AI analysis can include:

- Executive Summary
- Primary Cybersecurity Risks
- Patient Safety and Operational Considerations
- HIPAA Security Considerations
- Immediate Priority Actions
- Long-Term Recommendations
- Limitations and Assumptions

The AI component explains and organizes the assessment rather than replacing the deterministic scoring methodology.

The model is specifically instructed not to:

- Modify the application-generated risk score
- Invent CVEs
- Invent product vulnerabilities
- Invent affected software versions
- Invent manufacturer claims
- Make unsupported regulatory findings
- Declare HIPAA compliance
- Make legal conclusions
- Invent clinical facts

This separation keeps the numerical risk assessment deterministic while using AI for explanation and decision support.

---

## Assessment History

HealthGuard AI stores completed assessments locally using SQLite.

Users can:

- Review previous assessments
- Reopen assessment results
- Compare device risk levels
- Review saved security findings
- Review CVE intelligence
- Review CISA KEV information
- Review MITRE ATT&CK mappings
- Generate printable reports

---

## Printable Security Reports

Each assessment can generate a printable cybersecurity report containing:

- Device Information
- Risk Score
- Risk Level
- Security Findings
- Recommended Controls
- Positive Security Controls
- CVE Candidates
- CVSS Information
- CISA KEV Exploitation Intelligence
- MITRE ATT&CK Technique Mappings
- AI-Assisted Security Analysis
- Limitations and Assumptions

Reports can be printed or saved as PDF directly through the browser.

---

## Automated Testing

HealthGuard AI includes automated tests using **Pytest**.

Testing covers areas including:

- Risk engine validation
- Score boundaries
- Security findings
- Flask application routes
- Input validation
- Database behavior
- NVD data parsing
- CISA KEV matching
- MITRE ATT&CK mapping
- Risk scoring consistency

External live APIs are intentionally separated from normal unit tests where possible to improve reliability.

---

# System Architecture

```text
                         User
                           |
                           v
             Medical Device Assessment Form
                           |
                           v
                   Flask Application
                           |
          +----------------+----------------+
          |                |                |
          v                v                v
  Rule-Based Engine    SQLite Database   MITRE ATT&CK
          |                               Mapping
          v
 Structured Findings
          |
          v
       NVD API
          |
          v
    Candidate CVEs
          |
          v
      CISA KEV
          |
          v
 Exploitation Context
          |
          v
      OpenAI API
          |
          v
 AI-Assisted Analysis
          |
          v
 Dashboard / History / Printable Reports
```

---

# Technology Stack

| Technology | Purpose |
|---|---|
| Python | Backend development |
| Flask | Web application framework |
| SQLite | Local assessment database |
| OpenAI API | AI-assisted cybersecurity analysis |
| NVD API | CVE vulnerability intelligence |
| CISA KEV | Known exploitation intelligence |
| MITRE ATT&CK | Adversary technique mapping |
| Requests | External API communication |
| HTML5 | User interface |
| Bootstrap 5 | Responsive interface design |
| CSS | Custom styling |
| Jinja2 | Dynamic server-side templates |
| Pytest | Automated testing |
| Git | Version control |
| GitHub | Source-code hosting |

---

# Risk Assessment Methodology

HealthGuard AI evaluates cybersecurity conditions across several security domains.

These include:

- Software lifecycle
- Operating system support
- Internet exposure
- Network connectivity
- Wireless connectivity
- Vendor remote access
- Multifactor authentication
- Encryption at rest
- Encryption in transit
- Network segmentation
- Unique user accounts
- Default credentials
- Audit logging
- Patch management
- Endpoint protection
- Backup and recovery
- End-of-life status

The rule engine assigns a deterministic score between **0 and 100**.

The AI component does not calculate or modify this score.

Threat-intelligence information from NVD, CISA KEV, and MITRE ATT&CK provides additional security context but is kept separate from the core deterministic scoring methodology.

---

# Security Intelligence Workflow

HealthGuard AI processes security intelligence using the following workflow:

```text
Device Assessment
       |
       v
Deterministic Risk Engine
       |
       v
Security Findings
       |
       +-----------------> MITRE ATT&CK Mapping
       |
       v
NVD CVE Search
       |
       v
Candidate CVEs
       |
       v
CISA KEV Matching
       |
       v
Known Exploitation Context
       |
       v
AI-Assisted Analysis
       |
       v
Security Report
```

This approach separates:

1. Risk calculation
2. Vulnerability intelligence
3. Known exploitation intelligence
4. Adversary technique mapping
5. Generative AI explanation

---

# AI Safety

HealthGuard AI uses Generative AI only after deterministic risk scoring has completed.

The AI model receives structured assessment information and generates explanatory cybersecurity analysis.

The model is instructed to:

- Explain the calculated score
- Summarize security findings
- Prioritize mitigations
- Identify operational considerations
- Distinguish confirmed information from unknown information
- Avoid hallucinating vulnerabilities
- Avoid inventing CVEs
- Avoid modifying the risk score
- Avoid unsupported legal conclusions
- Avoid declaring HIPAA compliance

If the OpenAI API becomes unavailable, the deterministic assessment can still complete.

---

# Installation

## Requirements

Recommended:

- Python 3.11+
- Git
- Internet connection
- OpenAI API key for AI-assisted analysis

An NVD API key is optional but can improve API request limits.

---

## Clone the Repository

```bash
git clone https://github.com/MoncadaR/healthguard-ai.git
cd healthguard-ai
```

---

## Create a Virtual Environment

### macOS / Linux

```bash
python3 -m venv venv
source venv/bin/activate
```

### Windows

```powershell
python -m venv venv
venv\Scripts\activate
```

---

## Install Dependencies

```bash
python -m pip install -r requirements.txt
```

---

# Environment Variables

Create a file named:

```text
.env
```

Add:

```text
OPENAI_API_KEY=your_openai_api_key_here
OPENAI_MODEL=gpt-5-mini
FLASK_SECRET_KEY=replace_with_your_secret_key

NVD_API_KEY=
NVD_RESULTS_LIMIT=10
```

The NVD API key is optional.

Your real `.env` file should **never** be committed to GitHub.

---

# Initialize Database

Run:

```bash
flask --app app init-db
```

Expected:

```text
Database initialized successfully.
```

> Running this command resets the development database.

---

# Run HealthGuard AI

### macOS / Linux

```bash
flask --app app run --debug --port 5001
```

Then open:

```text
http://127.0.0.1:5001
```

Port `5001` is used for local development because some macOS systems may already use port `5000` for system services.

---

# Running Tests

Make sure the virtual environment is active.

Then run:

```bash
python -m pytest -v
```

A successful test run should show all tests passing.

---

# Project Structure

```text
healthguard-ai/
|
├── app.py
├── ai_service.py
├── database.py
├── risk_engine.py
├── nvd_service.py
├── kev_service.py
├── mitre_service.py
├── schema.sql
├── requirements.txt
├── README.md
├── .gitignore
|
├── instance/
│   └── healthguard.db
|
├── static/
│   └── css/
│       └── style.css
|
├── templates/
│   ├── assessment.html
│   ├── base.html
│   ├── error.html
│   ├── history.html
│   ├── index.html
│   ├── report.html
│   └── result.html
|
└── tests/
    ├── test_app.py
    ├── test_risk_engine.py
    ├── test_nvd_service.py
    ├── test_kev_service.py
    └── test_mitre_service.py
```

The local SQLite database and `.env` file are excluded from version control.

---

# Example Assessment

A fictional assessment might use:

```text
Device Name:
Legacy Medical Server

Device Type:
Medical Server

Operating System:
Linux

Support Status:
Unsupported

Internet Access:
Yes

Vendor Remote Access:
Yes

Remote Access MFA:
No

Unique User Accounts:
No

Default Passwords Changed:
No

CVE Search Term:
Apache Log4j
```

The deterministic engine may identify significant security exposure.

The NVD integration may return:

```text
CVE-2021-44228
CVSS: 10.0
Severity: CRITICAL
```

CISA KEV enrichment may identify:

```text
Known Exploited: Yes
Known Ransomware Use: Known
```

MITRE ATT&CK mappings may include:

```text
T1078.001 - Default Accounts
T1078     - Valid Accounts
T1133     - External Remote Services
T1021     - Remote Services
T1190     - Exploit Public-Facing Application
```

The AI component can then produce an executive-level explanation and prioritized remediation recommendations.

---

# Current Capabilities

- Medical device cybersecurity assessments
- Deterministic cybersecurity risk scoring
- Risk classification from Low to Critical
- NVD CVE candidate lookup
- CVSS severity analysis
- CISA Known Exploited Vulnerabilities matching
- Known ransomware-use intelligence
- CWE information
- MITRE ATT&CK technique mapping
- AI-generated executive security analysis
- Patient-safety and operational considerations
- SQLite assessment storage
- Assessment history
- Printable security reports
- Automated testing
- Secure API key management
- External API failure handling

---

# Current Limitations

HealthGuard AI is an educational prototype and has several known limitations.

## CVE Matching

The current NVD implementation uses keyword-based CVE searching.

A keyword match does not establish that a specific product or version is vulnerable.

Future versions should use CPE-based matching to improve product and version applicability.

## CISA KEV

A CVE not appearing in the CISA KEV catalog does not mean that exploitation is impossible.

KEV status provides additional prioritization context only.

## MITRE ATT&CK

ATT&CK mappings are generated from assessment conditions.

They represent potentially relevant adversary techniques and do not indicate actual malicious activity.

## AI Analysis

Generative AI may produce incomplete or inaccurate explanations despite prompt safeguards.

AI-generated recommendations should be reviewed by qualified personnel.

## Risk Scoring

The HealthGuard AI risk-scoring methodology is educational.

It is not an official scoring methodology published by NIST, FDA, HHS, CISA, MITRE, or any healthcare regulatory organization.

---

# Future Improvements

Planned improvements include:

- CPE-based CVE matching
- Product and version validation
- Automated CPE discovery
- Medical device inventory management
- Threat intelligence caching
- Additional MITRE ATT&CK mappings
- NIST Cybersecurity Framework mapping
- Dashboard analytics
- Risk distribution charts
- Department-level security analytics
- Risk trend visualization
- Vulnerability remediation tracking
- User authentication
- Role-Based Access Control
- SIEM integration
- REST API
- Docker deployment
- Cloud deployment
- Automatic PDF generation
- Multi-user support
- Real-time threat-intelligence updates

---

# Security Design

HealthGuard AI follows several defensive-development principles.

## API Keys

API keys and application secrets are stored using environment variables rather than hardcoded into source code.

Files such as:

```text
.env
```

are excluded from Git.

## Local Database

The development SQLite database is excluded from the public Git repository.

## External API Failure Handling

If NVD, CISA KEV, or OpenAI becomes unavailable, HealthGuard AI is designed so that the core deterministic assessment does not depend entirely on those external services.

## AI Separation

AI is used for explanation and recommendation generation.

The deterministic Python engine remains responsible for the numerical risk score.

---

# Security & Privacy Notice

HealthGuard AI is an educational decision-support platform.

Do **not** enter or upload:

- Protected Health Information (PHI)
- Patient names
- Medical record numbers
- Credentials
- Passwords
- API keys
- Confidential hospital documentation
- Internal production network information
- Confidential organizational data

Use fictional, sanitized, or authorized information only.

---

# Educational Purpose

HealthGuard AI demonstrates the integration of:

```text
Healthcare Cybersecurity
        +
Python / Flask
        +
Deterministic Risk Analysis
        +
NVD Vulnerability Intelligence
        +
CISA Exploitation Intelligence
        +
MITRE ATT&CK
        +
Generative AI
        +
Secure Software Development
```

The project demonstrates how deterministic cybersecurity logic and Generative AI can be combined while maintaining separation between risk scoring and AI-generated explanation.

---

# Disclaimer

HealthGuard AI is provided for educational, research, and portfolio purposes only.

It does **not** provide:

- Vulnerability scanning
- Penetration testing
- HIPAA certification
- FDA compliance determination
- Legal advice
- Regulatory certification
- Clinical safety certification
- Medical advice

Security findings should be independently validated before being used for operational, clinical, compliance, or security decisions.

---

# Author

**Ramón Moncada**

Biomedical Engineer | Cybersecurity Graduate Student

California State University, Dominguez Hills

GitHub:  
https://github.com/MoncadaR

LinkedIn:  
https://linkedin.com/in/ramón-moncada-0646a21b0

---
