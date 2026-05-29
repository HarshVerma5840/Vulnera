# 🛡️ Vulnera: AI-Assisted Vulnerability Intelligence Platform

![Status](https://img.shields.io/badge/Status-MVP%20Development-blue)
![Python](https://img.shields.io/badge/Python-3.11+-blue)
![React](https://img.shields.io/badge/React-18+-blue)


## 🚀 Overview

**Vulnera** is an AI-powered cybersecurity platform that combines **Nmap**, **OWASP ZAP**, and intelligent risk-scoring algorithms to identify, prioritize, and explain security vulnerabilities in web applications.

Unlike traditional scanners that generate large volumes of technical findings, Vulnera correlates network-level and application-level vulnerabilities, applies AI-driven contextual scoring, and presents results in plain English for developers, security teams, and non-technical stakeholders.

---

# 📌 The Problem

Modern vulnerability scanners operate independently.

* Nmap discovers open ports and exposed services.
* OWASP ZAP identifies web application vulnerabilities.
* Security teams manually correlate findings.
* Business owners struggle to understand technical alerts.

A medium-sized application can generate dozens of findings, making it difficult to determine what should be fixed first.

---

# 💡 The Solution

Vulnera acts as an intelligent orchestration layer that:

* Discovers vulnerabilities using industry-standard tools.
* Correlates findings across multiple security layers.
* Scores risks using contextual AI heuristics.
* Prioritizes findings based on endpoint criticality.
* Generates plain-English explanations.
* Continuously improves through analyst feedback.

---

# ⚡ Key Features

## 🔍 Network Reconnaissance

Powered by Nmap:

* Open port discovery
* Service version detection
* SSL/TLS analysis
* Vulnerability script execution

## 🌐 Web Vulnerability Scanning

Powered by OWASP ZAP:

* SQL Injection
* Cross-Site Scripting (XSS)
* CSRF
* SSRF
* Path Traversal
* Command Injection
* Open Redirect
* Security Header Analysis

## 🤖 AI-Powered Risk Prioritization

* Semantic endpoint analysis
* K-Means endpoint clustering
* EPSS exploitation probability integration
* CVSS enrichment
* Cross-tool correlation scoring

## 🧠 Adaptive Learning

* Analyst TP/FP feedback collection
* Automated retraining
* Logistic Regression learning pipeline
* Continuous improvement over time

## 📊 Plain-English Reporting

Transforms technical findings into understandable business risks.

Example:

**Technical Alert**

```
CWE-89 SQL Injection detected at /checkout?id=1
```

**Vulnera Explanation**

```
An attacker may be able to read or modify customer payment information through this endpoint.
Immediate remediation is recommended.
```

---

# 🏗️ System Architecture

```text
User
 │
 ▼
Browser Extension / Selenium
 │
 ▼
Flask Orchestrator
 │
 ├──────────────► Nmap
 │
 ├──────────────► OWASP ZAP
 │
 ▼
Alert Normalizer
 │
 ▼
AI Heuristic Engine
 │
 ├─ Semantic Similarity
 ├─ K-Means Clustering
 ├─ CVSS Enrichment
 ├─ EPSS Enrichment
 └─ Risk Scoring
 │
 ▼
PostgreSQL Database
 │
 ▼
React Dashboard
```

---

# 🎯 Vulnerability Coverage

| Category                | Detection Source |
| ----------------------- | ---------------- |
| SQL Injection           | OWASP ZAP        |
| Reflected XSS           | OWASP ZAP        |
| Stored XSS              | OWASP ZAP        |
| DOM XSS                 | OWASP ZAP        |
| CSRF                    | OWASP ZAP        |
| SSRF                    | OWASP ZAP        |
| Path Traversal          | OWASP ZAP        |
| Command Injection       | OWASP ZAP        |
| Open Redirect           | OWASP ZAP        |
| Clickjacking            | OWASP ZAP        |
| Weak Security Headers   | OWASP ZAP        |
| Weak TLS Configurations | Nmap             |
| Exposed Services        | Nmap             |
| Vulnerable Versions     | Nmap             |

---

# 📊 Risk Scoring Model

Vulnera calculates a composite score using:

```text
Risk Score =
ZAP Confidence
× CVSS
× Endpoint Criticality
× EPSS
× Amplification Factor
```

Factors considered:

* Vulnerability severity
* Endpoint importance
* Real-world exploit probability
* Cross-tool confirmation

---

# 🛠 Tech Stack

## Backend

* Python 3.11
* Flask
* PostgreSQL
* scikit-learn
* sentence-transformers

## Frontend

* React
* Tailwind CSS

## Security Tools

* Nmap
* OWASP ZAP
* Selenium

## Intelligence Layer

* K-Means Clustering
* Logistic Regression
* Semantic Embeddings
* EPSS API
* NVD API

---

# 🔒 Security & Privacy

Vulnera follows a privacy-first approach.

Captured:

✅ Endpoint paths

✅ HTTP methods

✅ Response status codes

Captured:

❌ Passwords

❌ Cookies

❌ Request bodies

❌ Personal information

❌ Page content

All scan data remains local except CVE lookups to public vulnerability databases.

---

# 🤝 Contributing

1. Fork the repository
2. Create a feature branch

```bash
git checkout -b feature/my-feature
```

3. Commit changes

```bash
git commit -m "Add feature"
```

4. Push branch

```bash
git push origin feature/my-feature
```

5. Open Pull Request

---


# ⭐ Support

If you find this project useful:

* Star the repository
* Report bugs through Issues
* Suggest new features
* Contribute improvements

---

## 🛡️ Vulnera

**Intelligent Vulnerability Discovery, Prioritization, and Security Insights**

Making cybersecurity accessible through AI-powered security orchestration.
