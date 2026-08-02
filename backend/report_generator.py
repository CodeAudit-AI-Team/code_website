import os
import json
import csv
import io
from typing import Dict, Any, List
from reportlab.lib.pagesizes import letter
from reportlab.lib import colors
from reportlab.platypus import SimpleDocTemplate, Paragraph, Spacer, Table, TableStyle
from reportlab.lib.styles import getSampleStyleSheet, ParagraphStyle

class ReportGenerator:
    """
    Generates security audit reports in PDF, HTML, JSON, and CSV formats.
    """

    @staticmethod
    def generate_json(scan_results: Dict[str, Any]) -> str:
        return json.dumps(scan_results, indent=2)

    @staticmethod
    def generate_csv(scan_results: Dict[str, Any]) -> str:
        output = io.StringIO()
        writer = csv.writer(output)
        writer.writerow(["File Path", "Line", "Vulnerability Type", "Severity", "CWE ID", "OWASP Category", "Vulnerable Code", "Recommendation"])

        for v in scan_results.get("vulnerabilities", []):
            writer.writerow([
                v.get("file_path", ""),
                v.get("line_number", ""),
                v.get("vuln_type", ""),
                v.get("severity", ""),
                v.get("cwe_id", ""),
                v.get("owasp_category", ""),
                v.get("vulnerable_code", ""),
                v.get("recommendation", "")
            ])

        return output.getvalue()

    @staticmethod
    def generate_html(scan_results: Dict[str, Any]) -> str:
        total_vulns = scan_results.get("total_vulnerabilities", len(scan_results.get("vulnerabilities", [])))
        risk_score = scan_results.get("risk_score", 0.0)

        rows_html = ""
        for v in scan_results.get("vulnerabilities", []):
            sev = v.get("severity", "Low")
            color_class = "sev-critical" if sev == "Critical" else ("sev-high" if sev == "High" else ("sev-medium" if sev == "Medium" else "sev-low"))
            rows_html += f"""
            <tr>
                <td>{v.get('file_path', 'main.py')}</td>
                <td>{v.get('line_number', 0)}</td>
                <td><strong>{v.get('vuln_type', '')}</strong></td>
                <td><span class="badge {color_class}">{sev}</span></td>
                <td>{v.get('cwe_id', '')}</td>
                <td><code>{v.get('vulnerable_code', '')}</code></td>
                <td>{v.get('recommendation', '')}</td>
            </tr>
            """

        html_content = f"""
        <!DOCTYPE html>
        <html>
        <head>
            <title>AI Security Audit Report</title>
            <style>
                body {{ font-family: 'Segoe UI', Tahoma, Geneva, Verdana, sans-serif; background: #0f172a; color: #f8fafc; padding: 30px; }}
                h1 {{ color: #38bdf8; border-bottom: 2px solid #334155; padding-bottom: 10px; }}
                .summary {{ display: flex; gap: 20px; margin-bottom: 30px; }}
                .card {{ background: #1e293b; padding: 20px; border-radius: 8px; flex: 1; border: 1px solid #334155; }}
                .card h3 {{ margin: 0; color: #94a3b8; font-size: 14px; text-transform: uppercase; }}
                .card p {{ margin: 10px 0 0 0; font-size: 28px; font-weight: bold; color: #f8fafc; }}
                table {{ width: 100%; border-collapse: collapse; background: #1e293b; border-radius: 8px; overflow: hidden; }}
                th, td {{ padding: 12px 15px; text-align: left; border-bottom: 1px solid #334155; }}
                th {{ background: #0f172a; color: #94a3b8; font-size: 13px; }}
                code {{ background: #0f172a; color: #f43f5e; padding: 2px 6px; border-radius: 4px; font-family: monospace; }}
                .badge {{ padding: 4px 8px; border-radius: 4px; font-weight: bold; font-size: 12px; }}
                .sev-critical {{ background: #881337; color: #fda4af; }}
                .sev-high {{ background: #9f1239; color: #fecdd3; }}
                .sev-medium {{ background: #854d0e; color: #fef08a; }}
                .sev-low {{ background: #1e3a8a; color: #bfdbfe; }}
            </style>
        </head>
        <body>
            <h1>AI Secure Code Intelligence Platform — Audit Report</h1>
            <div class="summary">
                <div class="card">
                    <h3>Total Vulnerabilities</h3>
                    <p>{total_vulns}</p>
                </div>
                <div class="card">
                    <h3>Overall Risk Score</h3>
                    <p>{risk_score} / 100</p>
                </div>
            </div>

            <h2>Detected Security Findings</h2>
            <table>
                <thead>
                    <tr>
                        <th>File</th>
                        <th>Line</th>
                        <th>Vulnerability</th>
                        <th>Severity</th>
                        <th>CWE</th>
                        <th>Vulnerable Snippet</th>
                        <th>Remediation</th>
                    </tr>
                </thead>
                <tbody>
                    {rows_html}
                </tbody>
            </table>
        </body>
        </html>
        """
        return html_content

    @staticmethod
    def generate_pdf(scan_results: Dict[str, Any], output_path: str):
        doc = SimpleDocTemplate(output_path, pagesize=letter)
        styles = getSampleStyleSheet()

        title_style = ParagraphStyle(
            'TitleStyle',
            parent=styles['Heading1'],
            fontSize=20,
            textColor=colors.HexColor("#0f172a"),
            spaceAfter=15
        )

        sub_style = ParagraphStyle(
            'SubStyle',
            parent=styles['Normal'],
            fontSize=10,
            textColor=colors.HexColor("#475569"),
            spaceAfter=20
        )

        elements = [
            Paragraph("AI Security Audit Report", title_style),
            Paragraph("Generated by AI Secure Code Intelligence Platform", sub_style),
            Spacer(1, 10)
        ]

        # Summary Table
        summary_data = [
            ["Metric", "Value"],
            ["Total Files Scanned", str(scan_results.get("total_files", 1))],
            ["Total Vulnerabilities", str(scan_results.get("total_vulnerabilities", len(scan_results.get("vulnerabilities", []))))],
            ["Overall Risk Score", f"{scan_results.get('risk_score', 0.0)} / 100"]
        ]
        sum_table = Table(summary_data, colWidths=[200, 200])
        sum_table.setStyle(TableStyle([
            ('BACKGROUND', (0,0), (-1,0), colors.HexColor("#1e293b")),
            ('TEXTCOLOR', (0,0), (-1,0), colors.white),
            ('FONTNAME', (0,0), (-1,0), 'Helvetica-Bold'),
            ('GRID', (0,0), (-1,-1), 1, colors.HexColor("#cbd5e1")),
            ('PADDING', (0,0), (-1,-1), 8)
        ]))
        elements.append(sum_table)
        elements.append(Spacer(1, 20))

        # Vulnerabilities Table
        vuln_data = [["Line", "Vulnerability", "Severity", "CWE"]]
        for v in scan_results.get("vulnerabilities", []):
            vuln_data.append([
                str(v.get("line_number", "")),
                v.get("vuln_type", ""),
                v.get("severity", ""),
                v.get("cwe_id", "")
            ])

        if len(vuln_data) > 1:
            vuln_table = Table(vuln_data, colWidths=[50, 220, 90, 90])
            vuln_table.setStyle(TableStyle([
                ('BACKGROUND', (0,0), (-1,0), colors.HexColor("#0f172a")),
                ('TEXTCOLOR', (0,0), (-1,0), colors.white),
                ('GRID', (0,0), (-1,-1), 0.5, colors.HexColor("#cbd5e1")),
                ('PADDING', (0,0), (-1,-1), 6)
            ]))
            elements.append(vuln_table)

        doc.build(elements)
