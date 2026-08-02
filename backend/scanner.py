import re
import ast
import math
from typing import List, Dict, Any

class StaticCodeScanner:
    """
    Advanced SAST Engine combining regex heuristics and Python AST node pattern matching
    to detect vulnerabilities, code smells, and security misconfigurations.
    """

    def __init__(self):
        # Patterns for dangerous constructs
        self.secret_patterns = [
            (r'(?i)(api[_-]?key|secret|password|passwd|auth[_-]?token)\s*=\s*["\']([A-Za-z0-9_\-\.\=\+]{8,})["\']', "Hardcoded Credentials", "CWE-798", "OWASP A07:2021-Identification and Authentication Failures"),
            (r'-----BEGIN PRIVATE KEY-----', "Hardcoded Private Key", "CWE-321", "OWASP A02:2021-Cryptographic Failures"),
            (r'(?i)bearer\s+[A-Za-z0-9\-\._~\+\/]+=*', "Hardcoded JWT / Bearer Token", "CWE-798", "OWASP A07:2021")
        ]

        self.weak_crypto_patterns = [
            (r'hashlib\.md5\(', "Weak Hash Algorithm (MD5)", "CWE-328", "OWASP A02:2021-Cryptographic Failures"),
            (r'hashlib\.sha1\(', "Weak Hash Algorithm (SHA1)", "CWE-328", "OWASP A02:2021-Cryptographic Failures"),
            (r'Crypto\.Cipher\.DES', "Weak Encryption Algorithm (DES)", "CWE-326", "OWASP A02:2021"),
            (r'MODE_ECB', "Insecure Cipher Mode (ECB)", "CWE-327", "OWASP A02:2021")
        ]

        self.sqli_patterns = [
            (r'(?i)SELECT\s+.*\s+FROM\s+.*%s', "SQL Injection via string formatting", "CWE-89", "OWASP A03:2021-Injection"),
            (r'(?i)SELECT\s+.*\s+FROM\s+.*\.format\(', "SQL Injection via .format()", "CWE-89", "OWASP A03:2021-Injection"),
            (r'(?i)execute\s*\(\s*f["\']SELECT', "SQL Injection via f-string", "CWE-89", "OWASP A03:2021-Injection"),
            (r'(?i)execute\s*\(\s*["\']SELECT.*\+\s*', "SQL Injection via concatenation", "CWE-89", "OWASP A03:2021-Injection")
        ]

        self.cmd_injection_patterns = [
            (r'os\.system\(', "OS Command Injection via os.system", "CWE-78", "OWASP A03:2021-Injection"),
            (r'subprocess\.(Popen|call|run)\(.*shell\s*=\s*True', "Shell Injection via subprocess", "CWE-78", "OWASP A03:2021-Injection"),
            (r'popen\(', "OS Command Injection via popen", "CWE-78", "OWASP A03:2021-Injection")
        ]

        self.path_traversal_patterns = [
            (r'open\s*\(\s*.*(?:request|input|sys\.argv)', "Potential Path Traversal in open()", "CWE-22", "OWASP A01:2021-Broken Access Control"),
            (r'send_file\s*\(\s*.*(?:request|filename)', "Potential Directory Traversal in file download", "CWE-22", "OWASP A01:2021")
        ]

    def _shannon_entropy(self, string: str) -> float:
        """Calculate Shannon entropy to identify random/secret keys"""
        if not string:
            return 0.0
        prob = [float(string.count(c)) / len(string) for c in set(string)]
        return -sum(p * math.log2(p) for p in prob)

    def scan_code(self, code: str, file_path: str = "main.py") -> Dict[str, Any]:
        vulnerabilities = []
        lines = code.split("\n")

        # 1. Regex & Pattern Matching Scan
        for idx, line in enumerate(lines, 1):
            stripped = line.strip()
            if not stripped or stripped.startswith("#"):
                continue

            # Hardcoded Secrets & High Entropy
            for pattern, name, cwe, owasp in self.secret_patterns:
                if re.search(pattern, stripped):
                    vulnerabilities.append({
                        "file_path": file_path,
                        "vuln_type": name,
                        "severity": "Critical",
                        "confidence": 0.95,
                        "line_number": idx,
                        "vulnerable_code": stripped,
                        "description": f"Found hardcoded credential or secret key on line {idx}.",
                        "cwe_id": cwe,
                        "owasp_category": owasp,
                        "recommendation": "Use environment variables or a secrets manager (e.g., HashiCorp Vault, AWS Secrets Manager) instead of hardcoding secrets."
                    })

            # SQL Injection
            for pattern, name, cwe, owasp in self.sqli_patterns:
                if re.search(pattern, stripped):
                    vulnerabilities.append({
                        "file_path": file_path,
                        "vuln_type": name,
                        "severity": "High",
                        "confidence": 0.90,
                        "line_number": idx,
                        "vulnerable_code": stripped,
                        "description": "Constructing SQL queries using dynamic string formatting allows attackers to execute arbitrary SQL commands.",
                        "cwe_id": cwe,
                        "owasp_category": owasp,
                        "recommendation": "Use parameterized queries (prepared statements) or an ORM like SQLAlchemy."
                    })

            # Command Injection
            for pattern, name, cwe, owasp in self.cmd_injection_patterns:
                if re.search(pattern, stripped):
                    vulnerabilities.append({
                        "file_path": file_path,
                        "vuln_type": name,
                        "severity": "Critical",
                        "confidence": 0.92,
                        "line_number": idx,
                        "vulnerable_code": stripped,
                        "description": "Executing system commands directly with shell=True or os.system can allow OS command injection.",
                        "cwe_id": cwe,
                        "owasp_category": owasp,
                        "recommendation": "Avoid using shell=True in subprocess. Pass arguments as a list: subprocess.run(['cmd', arg1, arg2])."
                    })

            # Weak Cryptography
            for pattern, name, cwe, owasp in self.weak_crypto_patterns:
                if re.search(pattern, stripped):
                    vulnerabilities.append({
                        "file_path": file_path,
                        "vuln_type": name,
                        "severity": "Medium",
                        "confidence": 0.88,
                        "line_number": idx,
                        "vulnerable_code": stripped,
                        "description": "Using weak crypto hashing or outdated cipher algorithms risks data compromise.",
                        "cwe_id": cwe,
                        "owasp_category": owasp,
                        "recommendation": "Upgrade to secure hashing algorithms such as SHA-256/SHA-512 or Argon2/bcrypt for passwords."
                    })

            # Insecure Randomness
            if re.search(r'import\s+random|random\.randint|random\.random', stripped) and not re.search(r'secrets', stripped):
                if "random" in stripped and ("token" in stripped or "password" in stripped or "key" in stripped):
                    vulnerabilities.append({
                        "file_path": file_path,
                        "vuln_type": "Insecure Randomness for Security Tokens",
                        "severity": "Medium",
                        "confidence": 0.85,
                        "line_number": idx,
                        "vulnerable_code": stripped,
                        "description": "Standard 'random' module is PRNG and predictable. Not cryptographically secure.",
                        "cwe_id": "CWE-330",
                        "owasp_category": "OWASP A02:2021-Cryptographic Failures",
                        "recommendation": "Use Python's built-in 'secrets' module for cryptographically secure random number generation."
                    })

            # Path Traversal
            for pattern, name, cwe, owasp in self.path_traversal_patterns:
                if re.search(pattern, stripped):
                    vulnerabilities.append({
                        "file_path": file_path,
                        "vuln_type": name,
                        "severity": "High",
                        "confidence": 0.82,
                        "line_number": idx,
                        "vulnerable_code": stripped,
                        "description": "Unchecked file path parameter opening allows reading arbitrary files outside target directory.",
                        "cwe_id": cwe,
                        "owasp_category": owasp,
                        "recommendation": "Sanitize and validate input using os.path.basename() or pathlib.Path.resolve() checks."
                    })

        # 2. AST Visitor Scan for AST-level AST vulnerabilities & Code Smells
        try:
            tree = ast.parse(code)
            ast_visitor = SecurityASTVisitor(file_path, lines)
            ast_visitor.visit(tree)
            vulnerabilities.extend(ast_visitor.vulnerabilities)
        except Exception:
            pass # Syntax errors caught separately

        # Deduplicate vulnerabilities on line_number & vuln_type
        unique_vulns = []
        seen = set()
        for v in vulnerabilities:
            key = (v["line_number"], v["vuln_type"])
            if key not in seen:
                seen.add(key)
                unique_vulns.append(v)

        return {
            "file_path": file_path,
            "total_lines": len(lines),
            "vulnerabilities": unique_vulns
        }

class SecurityASTVisitor(ast.NodeVisitor):
    def __init__(self, file_path: str, lines: List[str]):
        self.file_path = file_path
        self.lines = lines
        self.vulnerabilities = []
        self.imported_modules = set()

    def visit_Import(self, node: ast.Import):
        for name in node.names:
            self.imported_modules.add(name.name)
            if name.name in ["pickle", "cPickle", "telnetlib", "ftplib"]:
                self.vulnerabilities.append({
                    "file_path": self.file_path,
                    "vuln_type": f"Dangerous Import: {name.name}",
                    "severity": "Medium",
                    "confidence": 0.90,
                    "line_number": node.lineno,
                    "vulnerable_code": self.lines[node.lineno - 1].strip(),
                    "description": f"Importing dangerous library '{name.name}' which may introduce insecure deserialization or unencrypted protocols.",
                    "cwe_id": "CWE-502",
                    "owasp_category": "OWASP A08:2021-Software and Data Integrity Failures",
                    "recommendation": "Replace pickle with safer serialization formats like JSON, YAML (SafeLoader), or Protocol Buffers."
                })
        self.generic_visit(node)

    def visit_Call(self, node: ast.Call):
        func_name = ""
        if isinstance(node.func, ast.Name):
            func_name = node.func.id
        elif isinstance(node.func, ast.Attribute):
            func_name = node.func.attr

        # Detect eval() / exec()
        if func_name in ["eval", "exec"]:
            self.vulnerabilities.append({
                "file_path": self.file_path,
                "vuln_type": f"Unsafe Dynamic Code Execution ({func_name})",
                "severity": "Critical",
                "confidence": 0.98,
                "line_number": node.lineno,
                "vulnerable_code": self.lines[node.lineno - 1].strip() if node.lineno <= len(self.lines) else "",
                "description": f"Using {func_name}() evaluates arbitrary string inputs as Python code, creating arbitrary code execution vulnerabilities.",
                "cwe_id": "CWE-95",
                "owasp_category": "OWASP A03:2021-Injection",
                "recommendation": "Avoid eval() and exec(). Use ast.literal_eval() if parsing static literal expressions."
            })

        # Detect pickle.loads / pickle.load
        if func_name in ["loads", "load"] and isinstance(node.func, ast.Attribute):
            if isinstance(node.func.value, ast.Name) and node.func.value.id in ["pickle", "cPickle"]:
                self.vulnerabilities.append({
                    "file_path": self.file_path,
                    "vuln_type": "Unsafe Pickle Deserialization",
                    "severity": "Critical",
                    "confidence": 0.95,
                    "line_number": node.lineno,
                    "vulnerable_code": self.lines[node.lineno - 1].strip() if node.lineno <= len(self.lines) else "",
                    "description": "Deserializing untrusted pickle data allows attacker execution of arbitrary Python bytecodes via __reduce__.",
                    "cwe_id": "CWE-502",
                    "owasp_category": "OWASP A08:2021-Software and Data Integrity Failures",
                    "recommendation": "Never unpickle untrusted data. Use json, msgpack, or cryptographic signatures (hmac) to verify integrity."
                })

        self.generic_visit(node)

    def visit_ExceptHandler(self, node: ast.ExceptHandler):
        if node.type is None:
            self.vulnerabilities.append({
                "file_path": self.file_path,
                "vuln_type": "Security Misconfiguration: Bare Except Clause",
                "severity": "Low",
                "confidence": 0.85,
                "line_number": node.lineno,
                "vulnerable_code": self.lines[node.lineno - 1].strip() if node.lineno <= len(self.lines) else "",
                "description": "Catching all exceptions with a bare 'except:' catches SystemExit, KeyboardInterrupt, and masks critical errors.",
                "cwe_id": "CWE-396",
                "owasp_category": "OWASP A05:2021-Security Misconfiguration",
                "recommendation": "Catch specific exception types (e.g. except ValueError, KeyError:) instead of a bare catch."
            })
        self.generic_visit(node)
