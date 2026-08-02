# 🛡️ AI Secure Code Intelligence Platform

> **Final-Year Computer Science Minor Project**  
> An integrated, enterprise-grade AI-powered Static Application Security Testing (SAST) platform combining Machine Learning, Python AST Parsing, Security Rule Engines, Knowledge Base Search, AI Security Assistant, and Multi-Format Audit Exporters.

---

## 🌟 Features Overview

- **🔍 AI Code Scanner**: Scans Python files, folders, and GitHub repositories for critical vulnerabilities (SQL Injection, OS Command Injection, Unsafe `eval`/`exec`, Hardcoded Passwords/API Keys, Insecure Randomness, Path Traversal, Unsafe Pickle Deserialization, and Weak Cryptography).
- **💻 Interactive Playground**: Monaco-style code playground with real-time AST node tree parsing, line-by-line vulnerability highlights, and automated secure code generation.
- **🐙 GitHub Scanner**: Clones public repositories and performs end-to-end multi-file vulnerability analysis with risk scoring.
- **📊 Executive Dashboard**: Plots real-time telemetry, OWASP Top 10 distributions, confusion matrices, ROC curves, and training loss progression charts.
- **🤖 AI Security Assistant**: Contextual chatbot capable of generating security unit tests, explaining vulnerability risks, comparing cryptographic algorithms (e.g. SHA-1 vs SHA-256), and refactoring insecure snippets.
- **⚡ Security Search Engine & Knowledge Base**: Searchable database of OWASP Top 10, CWE definitions, vulnerable vs secure code examples, attack vectors, and mitigation strategies.
- **📄 Audit Report Exporter**: Export comprehensive audit reports in PDF, HTML, JSON, and CSV formats.
- **⚡ REST API**: FastAPI backend powering modular security intelligence microservices.

---

## 🛠️ Technology Stack

- **Backend Framework**: Python 3.10+, FastAPI, Uvicorn
- **Frontend Framework**: Streamlit, Plotly
- **Database**: SQLite, SQLAlchemy ORM
- **Machine Learning & Analysis Engine**: scikit-learn, TF-IDF / CodeBERT embeddings, Python `ast` module, GitPython
- **Report Exporters**: ReportLab, CSV, JSON, HTML
- **Containerization**: Docker, Docker Compose

---

## 🏗️ Project Architecture

```
ai_code_audit/
├── backend/
│   ├── api.py               # FastAPI REST API endpoints
│   ├── ast_parser.py        # Python AST Visitor & Tree Summarizer
│   ├── scanner.py           # SAST Engine & Security Rules
│   ├── ml_engine.py         # CodeBERT / ML Vulnerability Classifier
│   ├── github_scanner.py    # Git Repository Cloner & SAST Pipeline
│   └── report_generator.py  # PDF, HTML, JSON, CSV Exporters
├── frontend/
│   └── app.py               # Streamlit Multi-Page Cybersecurity UI
├── database/
│   ├── db.py                # SQLite Database Connector
│   └── models.py            # SQLAlchemy Relational Schemas
├── knowledge_base/
│   └── kb_data.py           # OWASP Top 10 & CWE Articles
├── chat/
│   └── assistant.py         # AI Security Assistant Engine
├── tests/
│   └── test_scanner.py      # Pytest Unit Test Suite
├── Dockerfile               # Container Deployment Script
├── docker-compose.yml       # Multi-service Orchestration
├── requirements.txt         # Dependency Manifest
└── README.md                # Documentation
```

---

## 🚀 Quickstart & Execution Guide

### 1. Local Environment Setup

```bash
# Clone or navigate to the project root directory
cd ai_code_audit

# Install required dependencies
pip install -r requirements.txt
```

### 2. Launch Streamlit Frontend App

```bash
streamlit run frontend/app.py
```
> Access the interactive web interface at `http://localhost:8501`.

### 3. Launch FastAPI REST Backend Server

```bash
uvicorn backend.api:app --reload
```
> Access interactive API documentation at `http://localhost:8000/docs`.

### 4. Run Unit Tests

```bash
pytest tests/test_scanner.py
```

---

## 🐳 Docker Deployment

To build and run using Docker Compose:

```bash
docker-compose up --build
```

---

## 📄 License
This project is released for educational, academic minor project, and research purposes.
