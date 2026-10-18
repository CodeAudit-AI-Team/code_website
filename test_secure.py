import os
import sqlite3
import hashlib
import json
import secrets
import pathlib
import ast

# 1. Environment Variable for Secrets (No hardcoded credentials)
API_KEY = os.getenv("API_KEY", "")

def safe_login(username, password):
    # 2. Strong SHA-256 Hashing with Salt
    salt = secrets.token_hex(16)
    pwd_hash = hashlib.sha256((password + salt).encode("utf-8")).hexdigest()
    
    # 3. Parameterized SQL Query (Prevents SQL Injection)
    conn = sqlite3.connect("database.db")
    cursor = conn.cursor()
    query = "SELECT * FROM users WHERE username = ? AND password_hash = ?"
    cursor.execute(query, (username, pwd_hash))
    return cursor.fetchone()

def safe_file_read(filename):
    # 4. Path Sanitization (Prevents Path Traversal)
    safe_name = pathlib.Path(filename).name
    base_dir = pathlib.Path("./uploads").resolve()
    target_path = (base_dir / safe_name).resolve()
    
    if base_dir in target_path.parents:
        with open(target_path, "r", encoding="utf-8") as f:
            return f.read()
    return None

def safe_evaluate_math(expression):
    # 5. Safe AST Evaluation (Prevents Code Injection)
    try:
        return ast.literal_eval(expression)
    except (ValueError, SyntaxError):
        return None

def safe_data_load(json_str):
    # 6. Secure JSON Deserialization (Prevents Pickle RCE)
    return json.loads(json_str)
