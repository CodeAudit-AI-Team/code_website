import os
from reportlab.lib.pagesizes import letter
from reportlab.lib import colors
from reportlab.platypus import (
    SimpleDocTemplate, Paragraph, Spacer, Table, TableStyle, PageBreak, HRFlowable
)
from reportlab.lib.styles import getSampleStyleSheet, ParagraphStyle
from reportlab.lib.units import inch

def build_deep_pdf():
    pdf_filename = "Project_Documentation_and_Execution_Guide.pdf"
    doc = SimpleDocTemplate(
        pdf_filename,
        pagesize=letter,
        rightMargin=0.5*inch,
        leftMargin=0.5*inch,
        topMargin=0.5*inch,
        bottomMargin=0.5*inch
    )

    styles = getSampleStyleSheet()

    # Color Palette
    primary_color = colors.HexColor("#0f172a") # Deep Slate
    secondary_color = colors.HexColor("#0284c7") # Ocean Blue
    accent_color = colors.HexColor("#38bdf8") # Light Cyan
    dark_text = colors.HexColor("#1e293b")
    bg_light = colors.HexColor("#f8fafc")

    title_style = ParagraphStyle(
        'DocTitle',
        parent=styles['Title'],
        fontName='Helvetica-Bold',
        fontSize=22,
        leading=26,
        textColor=primary_color,
        alignment=0,
        spaceAfter=6
    )

    subtitle_style = ParagraphStyle(
        'DocSubtitle',
        parent=styles['Normal'],
        fontName='Helvetica-Bold',
        fontSize=12,
        leading=15,
        textColor=secondary_color,
        spaceAfter=12
    )

    h1_style = ParagraphStyle(
        'Heading1_Custom',
        parent=styles['Heading1'],
        fontName='Helvetica-Bold',
        fontSize=14,
        leading=17,
        textColor=primary_color,
        spaceBefore=14,
        spaceAfter=6
    )

    h2_style = ParagraphStyle(
        'Heading2_Custom',
        parent=styles['Heading2'],
        fontName='Helvetica-Bold',
        fontSize=11,
        leading=14,
        textColor=secondary_color,
        spaceBefore=10,
        spaceAfter=4
    )

    body_style = ParagraphStyle(
        'Body_Custom',
        parent=styles['BodyText'],
        fontName='Helvetica',
        fontSize=9.5,
        leading=13.5,
        textColor=dark_text,
        spaceAfter=6
    )

    code_style = ParagraphStyle(
        'Code_Custom',
        parent=styles['Code'],
        fontName='Courier',
        fontSize=8.5,
        leading=11,
        textColor=colors.HexColor("#0f172a"),
        backColor=colors.HexColor("#f1f5f9"),
        borderColor=colors.HexColor("#cbd5e1"),
        borderWidth=1,
        borderPadding=6,
        spaceBefore=4,
        spaceAfter=6
    )

    story = []

    # Title Banner
    story.append(Paragraph("AI Secure Code Intelligence Platform", title_style))
    story.append(Paragraph("Deep Architectural Analysis, Motivation, Utility & Execution Guide", subtitle_style))
    story.append(HRFlowable(width="100%", thickness=2, color=secondary_color, spaceAfter=12))

    # SECTION 1: MOTIVATION & PROBLEM STATEMENT
    story.append(Paragraph("1. Motivation: Why Was This Platform Developed?", h1_style))
    story.append(Paragraph(
        "Modern software engineering relies heavily on rapid iteration, third-party libraries, and AI-assisted code generation tools. "
        "However, this speed often comes at the expense of software security. Developers frequently push code containing high-severity security flaws "
        "such as <b>SQL Injection (SQLi)</b>, <b>Command Injection</b>, <b>Insecure Deserialization</b>, and <b>Hardcoded Secret Keys</b> into production environments.<br/><br/>"
        "Traditional static analysis tools (like standard linter rules) suffer from two major flaws:<br/>"
        "<b>1. High False Positive Rates:</b> Pure regex-based scanners flag benign code, overwhelming developers with noise.<br/>"
        "<b>2. Lack of Contextual & ML Intelligence:</b> Conventional scanners cannot evaluate code intent or semantic context.<br/><br/>"
        "<b>Project Objective:</b> This platform was created to bridge this critical gap by unifying <b>AST Structural Parsing</b>, "
        "<b>Rule-based SAST Heuristics</b>, <b>HuggingFace CodeBERT Deep Learning Embeddings</b>, and an <b>AI Security Assistant</b> into a unified, high-performance web platform.",
        body_style
    ))

    # SECTION 2: REAL-WORLD UTILITY & IMPACT
    story.append(Paragraph("2. Practical Utility & Real-World Applications", h1_style))
    story.append(Paragraph(
        "The AI Secure Code Intelligence Platform provides direct utility across multiple domains in the software ecosystem:",
        body_style
    ))

    utility_data = [
        [Paragraph("<b>Target Audience / Domain</b>", body_style), Paragraph("<b>Practical Real-World Utility</b>", body_style)],
        [
            Paragraph("<b>Software Developers</b>", body_style),
            Paragraph("Serves as an automated, instant secure code reviewer. Provides auto-generated secure code refactorings so developers learn secure coding practices in real time.", body_style)
        ],
        [
            Paragraph("<b>Security Analysts & Auditors</b>", body_style),
            Paragraph("Automates end-to-end repository audits. Generates compliance-ready PDF, HTML, CSV, and JSON audit reports for vulnerability management.", body_style)
        ],
        [
            Paragraph("<b>DevSecOps Pipelines</b>", body_style),
            Paragraph("Embeds static security scanning into Continuous Integration / Continuous Deployment (CI/CD) pipelines to block insecure code commits before production deployment.", body_style)
        ],
        [
            Paragraph("<b>Computer Science Education</b>", body_style),
            Paragraph("Functions as an interactive learning playground where students inspect Abstract Syntax Tree (AST) structures and learn OWASP Top 10 & CWE mitigation strategies.", body_style)
        ]
    ]

    t_ut = Table(utility_data, colWidths=[2.2*inch, 5.3*inch])
    t_ut.setStyle(TableStyle([
        ('BACKGROUND', (0,0), (-1,0), colors.HexColor("#e2e8f0")),
        ('GRID', (0,0), (-1,-1), 0.5, colors.HexColor("#cbd5e1")),
        ('VALIGN', (0,0), (-1,-1), 'TOP'),
        ('BOTTOMPADDING', (0,0), (-1,-1), 5),
        ('TOPPADDING', (0,0), (-1,-1), 5),
    ]))
    story.append(t_ut)
    story.append(Spacer(1, 10))

    # SECTION 3: TECHNICAL ARCHITECTURE & DEEP DIVE
    story.append(Paragraph("3. Technical Deep Dive & System Architecture", h1_style))
    story.append(Paragraph(
        "The platform implements a multi-layered defensive strategy combining deterministic rules with deep neural networks:",
        body_style
    ))

    story.append(Paragraph("<b>A. Abstract Syntax Tree (AST) Analysis Engine (<code>backend/ast_parser.py</code>)</b>", h2_style))
    story.append(Paragraph(
        "Unlike basic text-search scanners, the platform parses Python source code into an Abstract Syntax Tree using Python's native <code>ast</code> library. "
        "It traverses call nodes to detect dangerous built-in expressions like <code>eval()</code>, <code>exec()</code>, and unsafe <code>pickle.loads()</code> deserializations.",
        body_style
    ))

    story.append(Paragraph("<b>B. Deep Learning Model (CodeBERT Integration) (<code>backend/ml_engine.py</code>)</b>", h2_style))
    story.append(Paragraph(
        "To evaluate code context, the platform utilizes HuggingFace's <b><code>microsoft/codebert-base</code></b> model built on PyTorch. "
        "CodeBERT processes code tokens and outputs 768-dimensional vector representations ([CLS] embeddings). A classifier trained on top of these embeddings "
        "predicts a continuous <b>ML Vulnerability Risk Score (0-100%)</b> and confidence interval.",
        body_style
    ))

    story.append(Paragraph("<b>C. Interactive 3D Glassmorphism Frontend (<code>frontend/app.py</code>)</b>", h2_style))
    story.append(Paragraph(
        "The user interface is crafted using Streamlit enhanced with custom CSS Glassmorphism effects (frosted-glass overlays, deep shadows) "
        "and interactive <b>3D Plotly threat vector scatter plots</b>, enabling users to analyze vulnerability distribution in 3D space.",
        body_style
    ))

    story.append(Spacer(1, 10))

    # SECTION 4: STEP-BY-STEP EXECUTION GUIDE
    story.append(Paragraph("4. Step-by-Step Execution Guide (How to Run)", h1_style))
    story.append(Paragraph("Follow these exact instructions to launch and run the application on your computer:", body_style))

    story.append(Paragraph("<b>Step 1: Open Terminal & Navigate to Project Directory</b>", h2_style))
    story.append(Paragraph("cd \"C:\\Users\\Soooraj Mohan\\Desktop\\ai_code_audit\"", code_style))

    story.append(Paragraph("<b>Step 2: Start the FastAPI Backend Server</b>", h2_style))
    story.append(Paragraph("uvicorn backend.api:app --reload", code_style))

    story.append(Paragraph("<b>Step 3: Start the Streamlit Frontend Dashboard (in a second terminal)</b>", h2_style))
    story.append(Paragraph("streamlit run frontend/app.py", code_style))

    story.append(Paragraph("<b>Step 4: Access the Dashboard & Log In</b>", h2_style))
    story.append(Paragraph(
        "Open your browser to <b>http://localhost:8501</b><br/>"
        "• <b>Username:</b> admin<br/>"
        "• <b>Password:</b> admin",
        body_style
    ))

    story.append(Spacer(1, 10))

    # SECTION 5: DAILY DEVELOPMENT DIARY
    story.append(Paragraph("5. Academic Project Diary / Logbook Timeline", h1_style))
    story.append(Paragraph("Use these entries for writing your daily project logbook entries:", body_style))

    diary_data = [
        [Paragraph("<b>Timeline / Phase</b>", body_style), Paragraph("<b>Development Activity Log</b>", body_style)],
        [Paragraph("<b>Day 1 – Day 2</b><br/>Scope & SAST Setup", body_style), Paragraph("Defined project objectives. Built deterministic SAST scanner (<code>backend/scanner.py</code>) targeting SQLi, Command Injection, and hardcoded secrets.", body_style)],
        [Paragraph("<b>Day 3 – Day 4</b><br/>AST & Database", body_style), Paragraph("Developed AST structural parser (<code>backend/ast_parser.py</code>). Formulated SQLite schema with SQLAlchemy ORM (<code>database/models.py</code>).", body_style)],
        [Paragraph("<b>Day 5 – Day 6</b><br/>CodeBERT ML Engine", body_style), Paragraph("Integrated HuggingFace <code>microsoft/codebert-base</code> via PyTorch (<code>backend/ml_engine.py</code>) to extract 768-dim embeddings.", body_style)],
        [Paragraph("<b>Day 7 – Day 8</b><br/>GitHub & OWASP KB", body_style), Paragraph("Created Git repository auditing engine (<code>backend/github_scanner.py</code>) and OWASP Top 10 Knowledge Base (<code>knowledge_base/kb_data.py</code>).", body_style)],
        [Paragraph("<b>Day 9 – Day 10</b><br/>3D UI & Authentication", body_style), Paragraph("Constructed Streamlit dashboard (<code>frontend/app.py</code>) featuring user authentication, 3D Glassmorphism CSS, and 3D Plotly scatter charts.", body_style)],
        [Paragraph("<b>Day 11 – Day 12</b><br/>Reports & Version Control", body_style), Paragraph("Implemented ReportLab PDF, CSV, and HTML exporters (<code>backend/report_generator.py</code>). Performed integration testing and Git commits.", body_style)]
    ]

    t_diary = Table(diary_data, colWidths=[2.0*inch, 5.5*inch])
    t_diary.setStyle(TableStyle([
        ('BACKGROUND', (0,0), (-1,0), colors.HexColor("#e2e8f0")),
        ('GRID', (0,0), (-1,-1), 0.5, colors.HexColor("#cbd5e1")),
        ('VALIGN', (0,0), (-1,-1), 'TOP'),
        ('BOTTOMPADDING', (0,0), (-1,-1), 5),
        ('TOPPADDING', (0,0), (-1,-1), 5),
    ]))
    story.append(t_diary)

    doc.build(story)
    print("Successfully built deep PDF documentation.")

if __name__ == "__main__":
    build_deep_pdf()
