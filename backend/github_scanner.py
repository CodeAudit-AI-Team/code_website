import os
import shutil
import tempfile
from typing import Dict, Any, List
from git import Repo
from backend.scanner import StaticCodeScanner
from backend.ast_parser import PythonASTParser

class GitHubScanner:
    """
    Clones GitHub repositories securely to a temporary directory
    and runs multi-file Python SAST analysis across the entire project.
    """

    def __init__(self):
        self.scanner = StaticCodeScanner()

    def scan_repository(self, repo_url: str) -> Dict[str, Any]:
        temp_dir = tempfile.mkdtemp(prefix="repo_scan_")
        try:
            # Clone repository
            Repo.clone_from(repo_url, temp_dir, depth=1)

            python_files = []
            for root, _, files in os.walk(temp_dir):
                for file in files:
                    if file.endswith(".py"):
                        python_files.append(os.path.join(root, file))

            all_vulnerabilities = []
            scanned_files_count = 0
            critical_count = 0
            high_count = 0
            medium_count = 0
            low_count = 0

            for file_path in python_files:
                rel_path = os.path.relpath(file_path, temp_dir)
                try:
                    with open(file_path, "r", encoding="utf-8", errors="ignore") as f:
                        code = f.read()

                    res = self.scanner.scan_code(code, file_path=rel_path)
                    vulns = res["vulnerabilities"]
                    scanned_files_count += 1
                    all_vulnerabilities.extend(vulns)

                    for v in vulns:
                        sev = v.get("severity", "Low")
                        if sev == "Critical":
                            critical_count += 1
                        elif sev == "High":
                            high_count += 1
                        elif sev == "Medium":
                            medium_count += 1
                        else:
                            low_count += 1

                except Exception:
                    continue

            # Calculate risk score (weighted formula out of 100)
            total_vulns = len(all_vulnerabilities)
            weighted_score = (critical_count * 25) + (high_count * 15) + (medium_count * 5) + (low_count * 2)
            risk_score = min(100.0, round(float(weighted_score), 1))

            return {
                "repo_url": repo_url,
                "total_files": scanned_files_count,
                "total_vulnerabilities": total_vulns,
                "critical_count": critical_count,
                "high_count": high_count,
                "medium_count": medium_count,
                "low_count": low_count,
                "risk_score": risk_score,
                "vulnerabilities": all_vulnerabilities
            }

        finally:
            shutil.rmtree(temp_dir, ignore_errors=True)
