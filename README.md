# 🏥 HealthGuard AI
### AI-Powered Medical Device Cybersecurity Risk Assessment Platform

HealthGuard AI is an AI-assisted cybersecurity decision-support platform designed to help healthcare technology professionals assess the security posture of network-connected medical devices.

The application combines a deterministic Python risk-scoring engine with Generative AI to produce structured cybersecurity assessments, identify security weaknesses, and generate executive-ready recommendations.

> **Disclaimer**
>
> This project is an educational prototype developed for research and academic purposes. It is **not** intended to replace professional cybersecurity assessments, regulatory audits, clinical engineering evaluations, or HIPAA compliance reviews.

---

# Features

### Medical Device Risk Assessment

Evaluate the cybersecurity posture of medical devices by documenting:

- Device information
- Operating system
- Network connectivity
- Remote access
- Authentication controls
- Encryption
- Patch management
- Logging
- Lifecycle status
- Backup and recovery

---

### Deterministic Risk Engine

Unlike traditional AI-only systems, HealthGuard AI does **not** allow the language model to determine risk scores.

Risk levels are calculated using a reproducible Python rule engine based on cybersecurity best practices.

Risk Levels

- 🟢 Low
- 🟡 Medium
- 🟠 High
- 🔴 Critical

---

### AI-Assisted Analysis

After the risk score is calculated, OpenAI generates:

- Executive Summary
- Primary Cybersecurity Risks
- Patient Safety Considerations
- HIPAA Security Considerations
- Immediate Priority Actions
- Long-Term Recommendations
- Limitations and Assumptions

The AI explains the assessment rather than replacing the scoring methodology.

---

### Assessment History

HealthGuard AI stores assessments locally using SQLite.

Users can review previous evaluations and generate printable reports.

---

### Printable Reports

Each assessment includes:

- Device Information
- Risk Score
- Findings
- Recommendations
- Positive Security Controls
- AI Security Analysis

Reports can be exported as PDF directly from the browser.

---

### Automated Testing

The project includes automated tests using Pytest covering:

- Risk engine validation
- Flask application routes
- Input validation
- Security logic
- Risk scoring consistency

---

# System Architecture

```
                    User
                      │
                      ▼
        Medical Device Assessment Form
                      │
                      ▼
                Flask Application
                      │
        ┌─────────────┴─────────────┐
        │                           │
        ▼                           ▼
 Risk Scoring Engine          SQLite Database
        │
        ▼
 Structured Security Findings
        │
        ▼
      OpenAI API
        │
        ▼
 AI Security Assessment
        │
        ▼
 Dashboard • Reports • History
```

---

# Technology Stack

| Technology | Purpose |
|------------|---------|
| Python | Backend Development |
| Flask | Web Framework |
| SQLite | Local Database |
| OpenAI API | AI Security Analysis |
| HTML5 | User Interface |
| Bootstrap 5 | Responsive Design |
| CSS | Styling |
| Jinja2 | Dynamic Templates |
| Pytest | Automated Testing |
| Git | Version Control |
| GitHub | Repository Hosting |

---

# Risk Assessment Methodology

The application evaluates security across several domains including:

- Software lifecycle
- Operating system support
- Internet exposure
- Vendor remote access
- Multifactor authentication
- Encryption at rest
- Encryption in transit
- Network segmentation
- Unique user accounts
- Default credentials
- Audit logging
- Patch management
- Backup and recovery
- End-of-life status

The rule engine assigns a deterministic score between **0 and 100**, ensuring reproducibility across assessments.

---

# AI Safety

HealthGuard AI uses AI only after deterministic scoring has completed.

The model is instructed to:

- Explain the calculated score
- Summarize findings
- Recommend mitigations
- Avoid hallucinating vulnerabilities
- Avoid inventing CVEs
- Avoid making legal or regulatory claims
- Avoid declaring HIPAA compliance

---

# Installation

Clone the repository

```bash
git clone https://github.com/MoncadaR/HealthGuard-AI.git
cd HealthGuard-AI
```

Create a virtual environment

```bash
python3 -m venv venv
```

Activate it

macOS / Linux

```bash
source venv/bin/activate
```

Windows

```powershell
venv\Scripts\activate
```

Install dependencies

```bash
pip install -r requirements.txt
```

---

# Environment Variables

Create a `.env` file:

```text
OPENAI_API_KEY=your_openai_api_key
OPENAI_MODEL=gpt-5-mini
FLASK_SECRET_KEY=your_secret_key
```

---

# Initialize Database

```bash
flask --app app init-db
```

---

# Run

```bash
flask --app app run
```

Open:

```
http://127.0.0.1:5000
```

---

# Running Tests

```bash
python -m pytest -v
```

---

# Project Structure

```
HealthGuard-AI/
│
├── app.py
├── ai_service.py
├── database.py
├── risk_engine.py
├── schema.sql
├── requirements.txt
├── README.md
│
├── static/
│   └── css/
│
├── templates/
│
├── tests/
│
└── instance/
```

---

# Current Capabilities

- Medical device cybersecurity assessments
- Deterministic risk scoring
- AI-generated executive reports
- SQLite assessment storage
- Assessment history
- Printable reports
- Automated testing
- Secure API key management

---

# Future Improvements

- CVE integration (NVD)
- CISA Known Exploited Vulnerabilities feed
- MITRE ATT&CK mapping
- Medical Device Inventory
- User authentication
- Role-Based Access Control
- SIEM Integration
- Docker deployment
- Cloud deployment (AWS)
- REST API
- Dashboard analytics
- Risk trend visualization
- PDF report generation
- Multi-user support

---

# Security Notice

HealthGuard AI is an educational decision-support platform.

Do **not** upload:

- Protected Health Information (PHI)
- Credentials
- API Keys
- Internal hospital documentation
- Confidential patient information

---

# Author

**Ramón Moncada**

Biomedical Engineer | Cybersecurity Graduate Student

California State University, Dominguez Hills

GitHub: https://github.com/MoncadaR

LinkedIn: https://linkedin.com/in/ramón-moncada-0646a21b0

---

# License

This project is released for educational and research purposes.
