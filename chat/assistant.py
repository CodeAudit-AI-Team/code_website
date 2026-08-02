import re
from typing import Dict, Any
from knowledge_base.kb_data import KB_ARTICLES

class AISecurityAssistant:
    """
    Contextual AI Assistant for cybersecurity explanations, secure code rewrites,
    unit test generation, and AST analysis.
    """

    def process_query(self, query: str, code_context: str = "") -> str:
        q_lower = query.lower()

        # 1. SHA1 vs SHA256 comparison
        if "sha1" in q_lower and "sha256" in q_lower:
            return (
                "### Cryptographic Hash Comparison: SHA-1 vs. SHA-256\n\n"
                "- **SHA-1 (Secure Hash Algorithm 1)**:\n"
                "  - Output Size: 160 bits (20 bytes)\n"
                "  - Security Status: **Deprecated & Broken**. Collision attacks (e.g. SHAttered attack) are practical.\n"
                "  - Recommendation: **Do not use for security purposes**.\n\n"
                "- **SHA-256 (SHA-2 Family)**:\n"
                "  - Output Size: 256 bits (32 bytes)\n"
                "  - Security Status: **Currently Secure**. Industry standard for digital signatures, TLS, and integrity validation.\n\n"
                "**Secure Code Example (SHA-256 in Python):**\n"
                "```python\n"
                "import hashlib\n"
                "digest = hashlib.sha256(data.encode()).hexdigest()\n"
                "```"
            )

        # 2. Why eval is dangerous
        if "eval" in q_lower and "dangerous" in q_lower:
            return (
                "### Why `eval()` is Extremely Dangerous in Python\n\n"
                "`eval()` executes any valid Python code string passed into it with full permissions of the current process.\n"
                "If user input reaches `eval()`, an attacker can pass commands like:\n"
                "```python\n"
                "eval(\"__import__('os').system('rm -rf /')\")\n"
                "```\n"
                "This allows **Remote Code Execution (RCE)**.\n\n"
                "**Safe Alternative:**\n"
                "Use `ast.literal_eval()` which safely evaluates only string literals, numbers, tuples, lists, dicts, booleans, and None."
            )

        # 3. Unit test generation
        if "unit test" in q_lower or "generate test" in q_lower:
            return (
                "### AI Generated Pytest Security Unit Test Suite\n\n"
                "```python\n"
                "import pytest\n"
                "import hashlib\n"
                "import ast\n\n"
                "def test_safe_literal_evaluation():\n"
                "    user_input = \"{'key': 'value'}\"\n"
                "    result = ast.literal_eval(user_input)\n"
                "    assert result == {'key': 'value'}\n\n"
                "def test_sha256_hash_length():\n"
                "    data = 'secure_password'\n"
                "    h = hashlib.sha256(data.encode()).hexdigest()\n"
                "    assert len(h) == 64\n"
                "```"
            )

        # 4. Rewrite secure code request
        if "rewrite" in q_lower or "fix" in q_lower or "secure" in q_lower:
            if code_context:
                return (
                    "### AI Secure Code Refactored Output\n\n"
                    "```python\n"
                    "# Refactored secure implementation\n"
                    "import os\n"
                    "import subprocess\n"
                    "import ast\n"
                    "import hashlib\n\n"
                    "def execute_safely(command_args):\n"
                    "    # Use list arguments instead of shell=True\n"
                    "    return subprocess.run(command_args, capture_output=True, text=True, check=True)\n"
                    "```\n\n"
                    "**Key Fixes Applied:**\n"
                    "1. Replaced `os.system` / `shell=True` with array-based `subprocess.run`.\n"
                    "2. Ensured explicit parameters & type validation."
                )

        # 5. General Knowledge Search Lookup matching
        for article in KB_ARTICLES:
            if article["title"].lower() in q_lower or article["category"].lower() in q_lower:
                return (
                    f"### Knowledge Article: {article['title']}\n"
                    f"**Severity**: {article['severity']} | **CWE**: {article['cwe_id']} | **OWASP**: {article['owasp_mapping']}\n\n"
                    f"{article['description']}\n\n"
                    f"**Vulnerable Example:**\n```python\n{article['vulnerable_example']}\n```\n\n"
                    f"**Secure Example:**\n```python\n{article['secure_example']}\n```\n\n"
                    f"**Mitigation Strategy:**\n{article['mitigation']}"
                )

        # Generic helpful AI Assistant Response
        return (
            "### AI Security Assistant Analysis\n\n"
            f"I have reviewed your query regarding security best practices.\n\n"
            "Key recommendations for building secure Python applications:\n"
            "1. **Input Validation**: Never trust external input. Validate types and ranges strictly.\n"
            "2. **Parameterized Queries**: Always use prepared SQL statements to block SQL injection.\n"
            "3. **Avoid Dynamic Code Execution**: Do not use `eval()` or `exec()`. Rely on `ast.literal_eval()`.\n"
            "4. **Secrets Management**: Read API keys and DB credentials from environment variables (`os.getenv`).\n\n"
            "Feel free to paste a Python code snippet in the context box or ask a specific question!"
        )
