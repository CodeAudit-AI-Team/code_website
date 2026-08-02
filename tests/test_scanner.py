import pytest
from backend.scanner import StaticCodeScanner
from backend.ast_parser import PythonASTParser
from backend.ml_engine import MLVulnerabilityClassifier
from backend.report_generator import ReportGenerator

def test_ast_parser():
    code = """
import os
def greet(name):
    return "Hello " + name
"""
    parser = PythonASTParser(code)
    summary = parser.get_summary()
    assert summary["valid"] is True
    assert summary["total_functions"] == 1
    assert summary["total_imports"] == 1

def test_scanner_detects_eval_and_sqli():
    vulnerable_code = """
import sqlite3
def unsafe_func(user_input):
    eval(user_input)
    cursor.execute("SELECT * FROM users WHERE name='" + user_input + "'")
"""
    scanner = StaticCodeScanner()
    res = scanner.scan_code(vulnerable_code)
    vulns = res["vulnerabilities"]
    
    assert len(vulns) >= 2
    vuln_types = [v["vuln_type"] for v in vulns]
    assert any("eval" in vt for vt in vuln_types)
    assert any("SQL" in vt for vt in vuln_types)

def test_ml_classifier():
    classifier = MLVulnerabilityClassifier()
    res = classifier.predict_snippet("eval(user_input)")
    assert res["is_vulnerable"] is True
    assert res["risk_score"] > 50.0

def test_report_generator():
    scan_data = {
        "total_files": 1,
        "total_vulnerabilities": 1,
        "risk_score": 75.0,
        "vulnerabilities": [
            {
                "file_path": "main.py",
                "line_number": 5,
                "vuln_type": "Unsafe eval()",
                "severity": "Critical",
                "cwe_id": "CWE-95",
                "vulnerable_code": "eval(input)",
                "recommendation": "Use ast.literal_eval"
            }
        ]
    }
    html = ReportGenerator.generate_html(scan_data)
    assert "AI Secure Code Intelligence Platform" in html
    assert "Unsafe eval()" in html

    csv_data = ReportGenerator.generate_csv(scan_data)
    assert "File Path,Line,Vulnerability Type" in csv_data
