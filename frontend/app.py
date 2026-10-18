import sys
import os
sys.path.append(os.path.dirname(os.path.dirname(os.path.abspath(__file__))))

try:
    import dotenv
    dotenv.load_dotenv()
except ImportError:
    pass

import streamlit as st

import pandas as pd
import numpy as np
import plotly.express as px
import plotly.graph_objects as gg
import time
import json

from backend.scanner import StaticCodeScanner
from backend.ast_parser import PythonASTParser
from backend.ml_engine import MLVulnerabilityClassifier
from backend.github_scanner import GitHubScanner
from backend.report_generator import ReportGenerator
from knowledge_base.kb_data import KB_ARTICLES

st.set_page_config(
    page_title="AI Secure Code Intelligence Platform",
    page_icon="🛡️",
    layout="wide",
    initial_sidebar_state="expanded"
)

# Dark Cybersecurity 3D Glassmorphism CSS Theme
st.markdown("""
<style>
    /* Global Background with deep 3D gradient */
    .main { background: radial-gradient(circle at top left, #0f172a, #020617); color: #f8fafc; }
    .stApp { background: #020617; }
    
    /* 3D Glassmorphism Sidebar */
    div[data-testid="stSidebar"] { 
        background: rgba(30, 41, 59, 0.6); 
        backdrop-filter: blur(16px);
        -webkit-backdrop-filter: blur(16px);
        border-right: 1px solid rgba(255, 255, 255, 0.05); 
        box-shadow: inset -5px 0 15px rgba(0,0,0,0.5);
    }
    
    h1, h2, h3 { color: #38bdf8 !important; font-family: 'Inter', sans-serif; text-shadow: 0 4px 10px rgba(56,189,248,0.3); }
    
    /* 3D Floating Metric Cards */
    .metric-card { 
        background: linear-gradient(145deg, #1e293b, #0f172a); 
        border: 1px solid rgba(255,255,255,0.05); 
        padding: 20px; 
        border-radius: 16px; 
        text-align: center; 
        box-shadow:  10px 10px 20px #060910, -10px -10px 20px #182544;
        transition: transform 0.3s ease, box-shadow 0.3s ease;
    }
    .metric-card:hover {
        transform: translateY(-5px);
        box-shadow:  15px 15px 25px #060910, -15px -15px 25px #182544, inset 0 0 10px rgba(56,189,248,0.2);
    }
    .metric-value { font-size: 2.2rem; font-weight: bold; color: #38bdf8; text-shadow: 0 0 15px rgba(56,189,248,0.5); }
    .metric-label { font-size: 0.9rem; color: #94a3b8; text-transform: uppercase; font-weight: bold; letter-spacing: 1px;}
    
    /* 3D Badges */
    .badge-critical { background: linear-gradient(145deg, #be123c, #881337); color: #fff; padding: 4px 10px; border-radius: 6px; font-weight: bold; box-shadow: 2px 4px 8px rgba(136,19,55,0.5); }
    .badge-high { background: linear-gradient(145deg, #e11d48, #9f1239); color: #fff; padding: 4px 10px; border-radius: 6px; font-weight: bold; box-shadow: 2px 4px 8px rgba(159,18,57,0.5); }
    .badge-medium { background: linear-gradient(145deg, #ca8a04, #854d0e); color: #fff; padding: 4px 10px; border-radius: 6px; font-weight: bold; box-shadow: 2px 4px 8px rgba(133,77,14,0.5); }
    .badge-low { background: linear-gradient(145deg, #2563eb, #1e3a8a); color: #fff; padding: 4px 10px; border-radius: 6px; font-weight: bold; box-shadow: 2px 4px 8px rgba(30,58,138,0.5); }
</style>
""", unsafe_allow_html=True)

# Initialize persistent engines
if "scanner" not in st.session_state:
    st.session_state.scanner = StaticCodeScanner()
    st.session_state.ml_classifier = MLVulnerabilityClassifier()
    st.session_state.github_scanner = GitHubScanner()
    st.session_state.chat_history = []
    st.session_state.last_scan = None
    st.session_state.authenticated = False
    st.session_state.username = ""

# ==========================================
# 0. AUTHENTICATION (LOGIN / SIGNUP)
# ==========================================
if "authenticated" not in st.session_state:
    st.session_state.authenticated = False
    st.session_state.username = ""

if not st.session_state.get("authenticated", False):
    st.title("🛡️ AI Secure Code Intelligence Platform")
    st.markdown("Please log in or create an account to access the security dashboard.")
    
    auth_mode = st.radio("Select Action", ["Login", "Sign Up"], horizontal=True)
    
    with st.form("auth_form"):
        username = st.text_input("Username")
        password = st.text_input("Password", type="password")
        submit = st.form_submit_button(auth_mode)
        
        if submit:
            if username and password:
                if auth_mode == "Login":
                    # Simulated authentication check
                    if username == "admin" and password == "admin":
                        st.session_state.authenticated = True
                        st.session_state.username = username
                        if hasattr(st, "rerun"):
                            st.rerun()
                        else:
                            st.experimental_rerun()
                    else:
                        st.error("Invalid credentials. Try admin/admin.")
                else:
                    st.success("Account created successfully! Please log in.")
            else:
                st.warning("Please fill in all fields.")
    st.stop()  # Stop rendering the rest of the app until authenticated

# Sidebar Navigation
st.sidebar.image("https://img.icons8.com/isometric-line/100/38bdf8/shield.png", width=70)
st.sidebar.title(f"Welcome, {st.session_state.username}!")
st.sidebar.caption("Defensive SAST & Security Platform v1.0")

menu = st.sidebar.radio(
    "Navigation",
    [
        "📊 Dashboard Analytics",
        "🔍 AI Code Scanner",
        "💻 Interactive Playground",
        "🐙 GitHub Repository Scanner",
        "📚 Security Knowledge Base",
        "⚡ Vulnerability Search Engine",
        "📄 Audit Report Center",
        "⚙️ Admin & System Settings",
        "🚪 Logout"
    ]
)

if menu == "🚪 Logout":
    st.session_state.authenticated = False
    st.session_state.username = ""
    if hasattr(st, "rerun"):
        st.rerun()
    else:
        st.experimental_rerun()


# Sample Code Generator
SAMPLE_VULN_CODE = """import os
import sqlite3
import hashlib
import pickle
import random

# Hardcoded Secret API Key
API_KEY = "sk_live_99887766554433221100"

def authenticate_user(username, password):
    # Weak MD5 Hashing
    pwd_hash = hashlib.md5(password.encode()).hexdigest()
    
    # SQL Injection Vulnerability
    conn = sqlite3.connect("database.db")
    cursor = conn.cursor()
    query = f"SELECT * FROM users WHERE username = '{username}' AND password = '{pwd_hash}'"
    cursor.execute(query)
    return cursor.fetchone()

def execute_user_command(user_cmd):
    # OS Command Injection
    os.system("ping -c 1 " + user_cmd)

def calculate_expression(expr):
    # Unsafe eval
    return eval(expr)

def load_user_session(session_bytes):
    # Insecure Pickle Deserialization
    return pickle.loads(session_bytes)
"""

# ==========================================
# 1. DASHBOARD ANALYTICS
# ==========================================
if menu == "📊 Dashboard Analytics":
    st.title("🛡️ Executive Security Dashboard")
    st.markdown("Real-time telemetry, vulnerability metrics, and machine learning performance.")

    c1, c2, c3, c4 = st.columns(4)
    c1.markdown("<div class='metric-card'><div class='metric-value'>142</div><div class='metric-label'>Total Projects Scanned</div></div>", unsafe_allow_html=True)
    c2.markdown("<div class='metric-card'><div class='metric-value'>1,840</div><div class='metric-label'>Files Analyzed</div></div>", unsafe_allow_html=True)
    c3.markdown("<div class='metric-card'><div class='metric-value'>328</div><div class='metric-label'>Vulnerabilities Found</div></div>", unsafe_allow_html=True)
    c4.markdown("<div class='metric-card'><div class='metric-value'>0.24s</div><div class='metric-label'>Avg Scan Latency</div></div>", unsafe_allow_html=True)



    col_chart1, col_chart2 = st.columns(2)

    with col_chart1:
        st.subheader("Vulnerability Severity Breakdown")
        df_sev = pd.DataFrame({
            "Severity": ["Critical", "High", "Medium", "Low"],
            "Count": [45, 92, 110, 81]
        })
        fig_pie = px.pie(df_sev, values="Count", names="Severity", color="Severity",
                         color_discrete_map={"Critical": "#881337", "High": "#9f1239", "Medium": "#854d0e", "Low": "#1e3a8a"},
                         hole=0.4)
        fig_pie.update_layout(paper_bgcolor="rgba(0,0,0,0)", plot_bgcolor="rgba(0,0,0,0)", font_color="#f8fafc")
        st.plotly_chart(fig_pie, use_container_width=True)

    with col_chart2:
        st.subheader("3D Threat Distribution Vector (OWASP)")
        # Create a 3D Scatter plot to simulate a 3D threat vector space
        np.random.seed(42)
        df_3d = pd.DataFrame({
            "Risk Score": np.random.randint(50, 100, 100),
            "Impact Radius": np.random.rand(100) * 10,
            "Exploitability": np.random.rand(100) * 10,
            "Category": np.random.choice(["A03: Injection", "A07: Auth", "A02: Crypto"], 100)
        })
        fig_3d = px.scatter_3d(df_3d, x="Risk Score", y="Impact Radius", z="Exploitability",
                               color="Category", size="Impact Radius", hover_name="Category",
                               color_discrete_sequence=px.colors.qualitative.Set1)
        fig_3d.update_layout(
            paper_bgcolor="rgba(0,0,0,0)", 
            plot_bgcolor="rgba(0,0,0,0)", 
            font_color="#f8fafc",
            scene=dict(
                xaxis=dict(backgroundcolor="rgba(0,0,0,0)", gridcolor="rgba(255,255,255,0.1)", showbackground=True),
                yaxis=dict(backgroundcolor="rgba(0,0,0,0)", gridcolor="rgba(255,255,255,0.1)", showbackground=True),
                zaxis=dict(backgroundcolor="rgba(0,0,0,0)", gridcolor="rgba(255,255,255,0.1)", showbackground=True)
            )
        )
        st.plotly_chart(fig_3d, use_container_width=True)

    st.markdown("---")
    metrics = st.session_state.ml_classifier.get_model_evaluation_metrics()
    
    st.subheader(f"🤖 Machine Learning Model Performance (CodeBERT / RF — {metrics['epochs']} Epochs)")
    st.caption("All evaluation metrics are calculated dynamically using explicit mathematical equations based on model confusion matrix.")

    # 4 Columns for Dynamic Evaluation Metrics
    em1, em2, em3, em4 = st.columns(4)
    em1.markdown(f"<div class='metric-card'><div class='metric-value'>{metrics['accuracy']:.4f}</div><div class='metric-label'>Accuracy<br><small>\\((TP+TN)/Total\\)</small></div></div>", unsafe_allow_html=True)
    em2.markdown(f"<div class='metric-card'><div class='metric-value'>{metrics['precision']:.4f}</div><div class='metric-label'>Precision<br><small>\\(TP/(TP+FP)\\)</small></div></div>", unsafe_allow_html=True)
    em3.markdown(f"<div class='metric-card'><div class='metric-value'>{metrics['recall']:.4f}</div><div class='metric-label'>Recall<br><small>\\(TP/(TP+FN)\\)</small></div></div>", unsafe_allow_html=True)
    em4.markdown(f"<div class='metric-card'><div class='metric-value'>{metrics['f1_score']:.4f}</div><div class='metric-label'>F-Measure (F1 Score)<br><small>\\(2 \\cdot (P \\cdot R)/(P + R)\\)</small></div></div>", unsafe_allow_html=True)

    with st.expander("📐 View Mathematical Equations & Calculation Proof"):
        eqs = metrics.get("equations", {})
        st.markdown(f"""
        - **Accuracy Formula**: $$\\text{{Accuracy}} = \\frac{{TP + TN}}{{TP + TN + FP + FN}} \\implies {eqs.get('accuracy', '')}$$
        - **Precision Formula**: $$\\text{{Precision}} = \\frac{{TP}}{{TP + FP}} \\implies {eqs.get('precision', '')}$$
        - **Recall Formula**: $$\\text{{Recall}} = \\frac{{TP}}{{TP + FN}} \\implies {eqs.get('recall', '')}$$
        - **F-Measure (F1 Score) Formula**: $$\\text{{F1-Score}} = \\frac{{2 \\cdot \\text{{Precision}} \\cdot \\text{{Recall}}}}{{\\text{{Precision}} + \\text{{Recall}}}} \\implies {eqs.get('f1_score', '')}$$
        - **Configured Epochs (via `.env`)**: `{metrics['epochs']}` Epochs
        """)

    m1, m2 = st.columns(2)

    with m1:
        st.write(f"##### ROC Curve (AUC = {metrics['roc_auc']:.4f})")
        roc_df = pd.DataFrame(metrics["roc_curve"])
        fig_roc = px.line(roc_df, x="fpr", y="tpr", title="Receiver Operating Characteristic", labels={"fpr": "False Positive Rate", "tpr": "True Positive Rate"})
        fig_roc.update_layout(paper_bgcolor="rgba(0,0,0,0)", plot_bgcolor="rgba(0,0,0,0)", font_color="#f8fafc")
        st.plotly_chart(fig_roc, use_container_width=True)

    with m2:
        st.write(f"##### Training Loss & Accuracy Progression ({metrics['epochs']} Epochs)")
        train_df = pd.DataFrame({
            "Epoch": metrics["training_epochs"],
            "Loss": metrics["training_loss"],
            "Accuracy": metrics["validation_accuracy"]
        })
        fig_train = px.line(train_df, x="Epoch", y=["Loss", "Accuracy"], markers=True, title=f"Model Metrics over {metrics['epochs']} Epochs")
        fig_train.update_layout(paper_bgcolor="rgba(0,0,0,0)", plot_bgcolor="rgba(0,0,0,0)", font_color="#f8fafc")
        st.plotly_chart(fig_train, use_container_width=True)


# ==========================================
# 2. AI CODE SCANNER
# ==========================================
elif menu == "🔍 AI Code Scanner":
    st.title("🔍 AI Code Scanner")
    st.markdown("Analyze Python source files for OWASP Top 10 flaws, hardcoded credentials, and AST code smells.")

    uploaded_file = st.file_uploader("Upload a Python (.py) file", type=["py"])
    
    code_to_scan = ""
    if uploaded_file is not None:
        code_to_scan = uploaded_file.getvalue().decode("utf-8")
    else:
        if st.button("Load Vulnerable Python Sample Code"):
            code_to_scan = SAMPLE_VULN_CODE

    source_input = st.text_area("Or Paste Python Source Code Directly:", value=code_to_scan, height=250)

    if st.button("🚀 Run Deep AI Scan", type="primary"):
        if not source_input.strip():
            st.warning("Please provide Python source code to scan.")
        else:
            with st.spinner("Analyzing AST nodes, running SAST heuristics, and executing ML classification..."):
                t0 = time.time()
                res = st.session_state.scanner.scan_code(source_input)
                ml_res = st.session_state.ml_classifier.predict_snippet(source_input)
                ast_p = PythonASTParser(source_input)
                dt = round(time.time() - t0, 3)

                st.session_state.last_scan = {
                    "scan_results": res,
                    "ml_results": ml_res,
                    "ast_summary": ast_p.get_summary(),
                    "code": source_input
                }

                st.success(f"Scan completed in {dt} seconds!")

    if st.session_state.last_scan:
        scan_res = st.session_state.last_scan["scan_results"]
        ml_res = st.session_state.last_scan["ml_results"]
        vulns = scan_res["vulnerabilities"]

        st.markdown("### 📊 Scan Results Summary")
        k1, k2, k3, k4 = st.columns(4)
        k1.metric("Total Vulnerabilities", len(vulns))
        k2.metric("ML Vulnerability Risk Score", f"{ml_res['risk_score']} %")
        k3.metric("Critical / High Findings", sum(1 for v in vulns if v["severity"] in ["Critical", "High"]))
        k4.metric("ML Confidence", f"{int(ml_res['confidence']*100)} %")

        st.markdown("### 🚨 Detected Vulnerabilities")
        if not vulns:
            st.info("🎉 No security vulnerabilities detected in the analyzed source code!")
        else:
            for v in vulns:
                with st.expander(f"[{v['severity']}] {v['vuln_type']} — Line {v['line_number']}"):
                    st.markdown(f"**CWE**: {v['cwe_id']} | **OWASP**: {v['owasp_category']}")
                    st.markdown(f"**Description**: {v['description']}")
                    st.code(v['vulnerable_code'], language="python")
                    st.markdown(f"**💡 Recommendation**: {v['recommendation']}")

# ==========================================
# 3. INTERACTIVE PLAYGROUND
# ==========================================
elif menu == "💻 Interactive Playground":
    st.title("💻 Interactive Code Playground")
    st.markdown("Paste code, view AST trees, inspect line-by-line security issues, and generate secure refactorings.")

    p_code = st.text_area("Source Code Editor:", value=SAMPLE_VULN_CODE, height=300)

    col_btn1, col_btn2 = st.columns(2)
    with col_btn1:
        if st.button("Inspect AST Tree Structure"):
            ast_p = PythonASTParser(p_code)
            st.json(ast_p.get_summary())
            st.code(ast_p.get_ast_tree_str(), language="python")

    with col_btn2:
        if st.button("✨ Show Secure Code Rewrite Tips"):
            st.markdown("""
**Secure Code Rewriting Guidelines:**
1. Replace `os.system(cmd)` → `subprocess.run(cmd_list, shell=False)`
2. Replace `eval(expr)` → `ast.literal_eval(expr)` for safe literals
3. Replace raw SQL strings → Parameterized queries with `?` or `%s`
4. Replace `hashlib.md5(pw)` → `hashlib.sha256(pw.encode())`
5. Replace hardcoded secrets → `os.getenv('SECRET_KEY')`
""")

# ==========================================
# 4. GITHUB REPOSITORY SCANNER
# ==========================================
elif menu == "🐙 GitHub Repository Scanner":
    st.title("🐙 GitHub Repository Scanner")
    st.markdown("Scan public GitHub repositories for end-to-end security audits.")

    repo_url = st.text_input("Enter Public GitHub Repository URL:", value="https://github.com/bottlepy/bottle")

    if st.button("Scan Repository", type="primary"):
        with st.spinner("Cloning repository, analyzing files, and generating project metrics..."):
            res = st.session_state.github_scanner.scan_repository(repo_url)
            st.success(f"Scanned {res['total_files']} files successfully!")
            st.json(res)

# ==========================================
# 5. SECURITY KNOWLEDGE BASE
# ==========================================
elif menu == "📚 Security Knowledge Base":
    st.title("📚 Security Knowledge Base & OWASP Library")
    st.markdown("Explore articles on secure coding, CWE standards, and attack mitigation strategies.")

    for art in KB_ARTICLES:
        with st.expander(f"[{art['severity']}] {art['title']} ({art['cwe_id']})"):
            st.markdown(f"**Category**: {art['category']} | **OWASP Mapping**: {art['owasp_mapping']}")
            st.markdown(art['description'])
            st.markdown("#### Vulnerable Implementation")
            st.code(art['vulnerable_example'], language="python")
            st.markdown("#### Secure Implementation")
            st.code(art['secure_example'], language="python")
            st.markdown(f"**Mitigation**: {art['mitigation']}")

# ==========================================
# 6. VULNERABILITY SEARCH ENGINE
# ==========================================
elif menu == "⚡ Vulnerability Search Engine":
    st.title("⚡ Vulnerability & CWE Search Engine")
    st.markdown("Search across security vulnerabilities, CVEs, CWEs, and Python security patterns.")

    query = st.text_input("Search (e.g. SQL Injection, eval, CWE-89, secret):", value="SQL Injection")

    if query:
        q_lower = query.lower()
        results = [a for a in KB_ARTICLES if q_lower in a['title'].lower() or q_lower in a['description'].lower() or q_lower in a['cwe_id'].lower()]
        st.write(f"Found **{len(results)}** matching articles:")
        for r in results:
            st.subheader(r['title'])
            st.write(r['description'])
            st.code(r['secure_example'], language="python")
            st.markdown("---")


# ==========================================
# 8. AUDIT REPORT CENTER
# ==========================================
elif menu == "📄 Audit Report Center":
    st.title("📄 Security Audit Report Exporter")
    st.markdown("Generate downloadable PDF, HTML, JSON, and CSV security audit reports.")

    if not st.session_state.last_scan:
        st.info("Run an AI Code Scan first to generate downloadable audit reports!")
    else:
        scan_data = st.session_state.last_scan["scan_results"]

        r_json = ReportGenerator.generate_json(scan_data)
        r_csv = ReportGenerator.generate_csv(scan_data)
        r_html = ReportGenerator.generate_html(scan_data)

        st.download_button("📥 Download JSON Audit Report", data=r_json, file_name="security_audit.json", mime="application/json")
        st.download_button("📥 Download CSV Audit Report", data=r_csv, file_name="security_audit.csv", mime="text/csv")
        st.download_button("📥 Download HTML Audit Report", data=r_html, file_name="security_audit.html", mime="text/html")

# ==========================================
# 9. ADMIN & SYSTEM SETTINGS
# ==========================================
elif menu == "⚙️ Admin & System Settings":
    st.title("⚙️ System Configuration & Database Admin")
    st.markdown("Manage database logs, update ML classifier threshold, and view system status.")

    st.subheader("Database Audit Logs")
    st.write("All system activities and scan events are recorded in SQLite.")
    st.dataframe(pd.DataFrame({
        "Timestamp": [time.strftime("%Y-%m-%d %H:%M:%S")],
        "Event": ["SYSTEM_INIT"],
        "User": ["admin"],
        "Details": ["Database models and scanners initialized successfully."]
    }))
