import os
import time
import tempfile
from typing import List, Optional
from fastapi import FastAPI, Depends, HTTPException, UploadFile, File, Form
from fastapi.middleware.cors import CORSMiddleware
from pydantic import BaseModel
from sqlalchemy.orm import Session

try:
    import dotenv
    dotenv.load_dotenv()
except ImportError:
    pass

from database.db import init_db, get_db

from database.models import User, Scan, Vulnerability, KnowledgeBaseArticle, SearchHistory, ChatHistory, AuditLog
from backend.scanner import StaticCodeScanner
from backend.ast_parser import PythonASTParser
from backend.ml_engine import MLVulnerabilityClassifier
from backend.github_scanner import GitHubScanner
from backend.report_generator import ReportGenerator
from knowledge_base.kb_data import KB_ARTICLES
from chat.assistant import AISecurityAssistant

app = FastAPI(title="AI Secure Code Intelligence Platform API", version="1.0.0")

# Enable CORS
app.add_middleware(
    CORSMiddleware,
    allow_origins=["*"],
    allow_credentials=True,
    allow_methods=["*"],
    allow_headers=["*"],
)

# Initialize engines
scanner = StaticCodeScanner()
ml_classifier = MLVulnerabilityClassifier()
github_scanner = GitHubScanner()
ai_assistant = AISecurityAssistant()

@app.on_event("startup")
def startup_event():
    init_db()

# Pydantic Schemas
class ScanCodeRequest(BaseModel):
    code: str
    file_path: Optional[str] = "main.py"

class GitHubScanRequest(BaseModel):
    repo_url: str

class ChatRequest(BaseModel):
    message: str
    code_context: Optional[str] = ""

class SearchRequest(BaseModel):
    query: str

@app.get("/")
def read_root():
    return {"status": "online", "platform": "AI Secure Code Intelligence Platform API v1.0"}

@app.post("/api/scan")
def scan_code(req: ScanCodeRequest, db: Session = Depends(get_db)):
    start_time = time.time()
    sast_res = scanner.scan_code(req.code, file_path=req.file_path)
    ml_res = ml_classifier.predict_snippet(req.code)
    ast_parser = PythonASTParser(req.code)

    duration = round(time.time() - start_time, 3)

    vulns = sast_res["vulnerabilities"]
    crit = sum(1 for v in vulns if v["severity"] == "Critical")
    high = sum(1 for v in vulns if v["severity"] == "High")
    med = sum(1 for v in vulns if v["severity"] == "Medium")
    low = sum(1 for v in vulns if v["severity"] == "Low")

    risk_score = min(100.0, round((crit * 25) + (high * 15) + (med * 5) + (low * 2) + ml_res["risk_score"] * 0.2, 1))

    # Save to SQLite DB
    scan_rec = Scan(
        scan_type="file",
        total_files=1,
        total_vulnerabilities=len(vulns),
        critical_count=crit,
        high_count=high,
        medium_count=med,
        low_count=low,
        risk_score=risk_score,
        scan_duration_sec=duration
    )
    db.add(scan_rec)
    db.commit()
    db.refresh(scan_rec)

    for v in vulns:
        vuln_rec = Vulnerability(
            scan_id=scan_rec.id,
            file_path=v["file_path"],
            vuln_type=v["vuln_type"],
            severity=v["severity"],
            confidence=v["confidence"],
            line_number=v["line_number"],
            vulnerable_code=v["vulnerable_code"],
            description=v["description"],
            cwe_id=v["cwe_id"],
            owasp_category=v["owasp_category"],
            recommendation=v["recommendation"]
        )
        db.add(vuln_rec)
    db.commit()

    return {
        "scan_id": scan_rec.id,
        "total_lines": sast_res["total_lines"],
        "total_vulnerabilities": len(vulns),
        "critical_count": crit,
        "high_count": high,
        "medium_count": med,
        "low_count": low,
        "risk_score": risk_score,
        "scan_duration_sec": duration,
        "ml_classification": ml_res,
        "ast_summary": ast_parser.get_summary(),
        "vulnerabilities": vulns
    }

@app.post("/api/scan-github")
def scan_github(req: GitHubScanRequest, db: Session = Depends(get_db)):
    start_time = time.time()
    res = github_scanner.scan_repository(req.repo_url)
    duration = round(time.time() - start_time, 3)

    scan_rec = Scan(
        scan_type="github",
        total_files=res["total_files"],
        total_vulnerabilities=res["total_vulnerabilities"],
        critical_count=res["critical_count"],
        high_count=res["high_count"],
        medium_count=res["medium_count"],
        low_count=res["low_count"],
        risk_score=res["risk_score"],
        scan_duration_sec=duration
    )
    db.add(scan_rec)
    db.commit()

    return res

@app.post("/api/chat")
def chat_assistant(req: ChatRequest, db: Session = Depends(get_db)):
    reply = ai_assistant.process_query(req.message, req.code_context)
    chat_rec = ChatHistory(user_message=req.message, assistant_response=reply)
    db.add(chat_rec)
    db.commit()
    return {"user_message": req.message, "response": reply}

@app.get("/api/knowledge")
def get_knowledge_base():
    return {"articles": KB_ARTICLES}

@app.post("/api/search")
def search_vulnerabilities(req: SearchRequest, db: Session = Depends(get_db)):
    q = req.query.lower()
    results = [a for a in KB_ARTICLES if q in a["title"].lower() or q in a["description"].lower() or q in a["category"].lower() or q in a["cwe_id"].lower()]
    sh = SearchHistory(query=req.query)
    db.add(sh)
    db.commit()
    return {"query": req.query, "total_results": len(results), "results": results}

@app.get("/api/dashboard")
def get_dashboard_metrics(db: Session = Depends(get_db)):
    total_scans = db.query(Scan).count()
    scans = db.query(Scan).all()

    total_files = sum(s.total_files for s in scans)
    total_vulns = sum(s.total_vulnerabilities for s in scans)
    crit = sum(s.critical_count for s in scans)
    high = sum(s.high_count for s in scans)
    med = sum(s.medium_count for s in scans)
    low = sum(s.low_count for s in scans)

    ml_metrics = ml_classifier.get_model_evaluation_metrics()

    return {
        "total_scans": total_scans,
        "total_files": total_files,
        "total_vulnerabilities": total_vulns,
        "critical_count": crit,
        "high_count": high,
        "medium_count": med,
        "low_count": low,
        "ml_metrics": ml_metrics
    }
