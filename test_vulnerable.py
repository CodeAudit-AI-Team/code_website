import os
import sqlite3
import hashlib
import pickle

# 1. Hardcoded API Secret Vulnerability
SECRET_API_KEY = "sk_live_99887766554433221100"

def login(username, password):
    # 2. Weak MD5 Hash Vulnerability
    hashed_pwd = hashlib.md5(password.encode()).hexdigest()
    
    # 3. SQL Injection Vulnerability
    conn = sqlite3.connect("users.db")
    cursor = conn.cursor()
    query = f"SELECT * FROM users WHERE username = '{username}' AND password = '{hashed_pwd}'"
    cursor.execute(query)
    return cursor.fetchone()

def ping_host(user_ip):
    # 4. OS Command Injection Vulnerability
    os.system("ping -c 1 " + user_ip)

def evaluate_math(expression):
    # 5. Unsafe Eval Vulnerability
    return eval(expression)

def load_data(raw_bytes):
    # 6. Insecure Deserialization Vulnerability
    return pickle.loads(raw_bytes)
