from datetime import datetime, timezone
from io import BytesIO
import json
from flask import Flask, render_template, request, send_file
from assessment import run_assessment
from database import initialize_database, save_assessment, get_connection
from reportlab.lib import colors
from reportlab.lib.pagesizes import A4
from reportlab.lib.styles import getSampleStyleSheet
from reportlab.lib.units import cm
from reportlab.platypus import (
    SimpleDocTemplate,
    Paragraph,
    Spacer,
    Table,
    TableStyle,
)

from assessment import run_assessment

app = Flask(__name__)
initialize_database()

HTML_PAGE = """
<!DOCTYPE html>
<html lang="en">
<head>
    <meta charset="UTF-8">
    <meta name="viewport" content="width=device-width, initial-scale=1">
    <title>AegisAPI Security Assessment</title>
    <style>
        body {
            font-family: Arial, sans-serif;
            background: #f4f7fb;
            color: #243247;
            margin: 0;
        }

        header {
            background: white;
            padding: 22px 7%;
            border-bottom: 1px solid #dfe6ef;
        }

        header h1 {
            color: #2457c5;
            margin: 0;
        }

        header p {
            margin-bottom: 0;
            color: #65748b;
        }

        main {
            max-width: 1100px;
            margin: 30px auto;
            padding: 0 20px;
        }

        section {
            background: white;
            border: 1px solid #e0e7f0;
            border-radius: 10px;
            padding: 24px;
            margin-bottom: 22px;
        }

        h2 {
            margin-top: 0;
            font-size: 20px;
        }

        label {
            display: block;
            margin-bottom: 8px;
            font-weight: bold;
        }

        input {
            box-sizing: border-box;
            width: 100%;
            padding: 12px;
            border: 1px solid #cbd5e1;
            border-radius: 6px;
            font-size: 16px;
            margin-bottom: 14px;
        }

        button, .download {
            display: inline-block;
            background: #2457c5;
            color: white;
            padding: 12px 18px;
            border: none;
            border-radius: 6px;
            font-size: 15px;
            text-decoration: none;
            cursor: pointer;
        }

        button:hover, .download:hover {
            background: #19439e;
        }

        .cards {
            display: grid;
            grid-template-columns: repeat(auto-fit, minmax(150px, 1fr));
            gap: 14px;
        }

        .card {
            background: #f7f9fd;
            border: 1px solid #e3eaf5;
            border-radius: 8px;
            padding: 16px;
        }

        .number {
            display: block;
            font-size: 28px;
            font-weight: bold;
            margin-top: 8px;
            color: #2457c5;
        }

        .table-wrap {
            overflow-x: auto;
        }

        table {
            border-collapse: collapse;
            width: 100%;
            min-width: 650px;
        }

        th, td {
            border-bottom: 1px solid #e4e9f1;
            padding: 12px;
            text-align: left;
            vertical-align: top;
        }

        th {
            background: #f5f7fb;
        }

        .severity {
            font-weight: bold;
        }

        .HIGH { color: #b42318; }
        .MEDIUM { color: #b54708; }
        .LOW { color: #2457c5; }
        .INFO { color: #596579; }

        .message {
            background: #fff4e5;
            padding: 12px;
            border-radius: 6px;
            margin-bottom: 18px;
        }

        .muted {
            color: #65748b;
        }

        @media (max-width: 600px) {
            header { padding: 20px; }
            section { padding: 16px; }
        }
    </style>
</head>
<body>
<header>
    <h1>AegisAPI</h1>
    <p>REST API Security Assessment Platform</p>
</header>

<main>
    <section>
        <h2>Target Configuration</h2>
        <form method="POST" action="/">
            <label for="target_url">API Base URL</label>
            <input
                id="target_url"
                name="target_url"
                type="url"
                placeholder="http://127.0.0.1:5000"
                value="{{ target_url }}"
                required
            >
            <button type="submit">Run Assessment</button>
        </form>
        <p class="muted">
            Only scan APIs you own or have permission to assess.
        </p>
    </section>

    {% if error %}
    <section>
        <div class="message">{{ error }}</div>
    </section>
    {% endif %}

    {% if results %}
    <section>
        <h2>Assessment Summary</h2>
        <div class="cards">
    <div class="card">
        Endpoints Found
        <span class="number">{{ results.summary.endpoints_found }}</span>
    </div>


    <div class="card">
        Total Findings
        <span class="number">{{ results.summary.findings_count }}</span>
    </div>

    <div class="card">
        High Severity
        <span class="number">{{ results.summary.high }}</span>
    </div>

    <div class="card">
        Medium Severity
        <span class="number">{{ results.summary.medium }}</span>
    </div>

    <div class="card">
        Low Severity
        <span class="number">{{ results.summary.low }}</span>
    </div>

    <div class="card">
        Informational
        <span class="number">{{ results.summary.info }}</span>
    </div>
</div>

<p class="muted">
    Target: {{ results.target }} |
    HTTP status: {{ results.target_status }}
</p>
    </section>

    <section>
        <h2>Discovered Endpoints</h2>
        {% if results.endpoints %}
        <div class="table-wrap">
            <table>
                <thead>
                    <tr>
                        <th>Path</th>
                        <th>Method</th>
                        <th>HTTP Status</th>
                        <th>Content Type</th>
                    </tr>
                </thead>
                <tbody>
                {% for endpoint in results.endpoints %}
                    <tr>
                        <td>{{ endpoint.path }}</td>
                        <td>{{ endpoint.method }}</td>
                        <td>{{ endpoint.status_code }}</td>
                        <td>{{ endpoint.content_type }}</td>
                    </tr>
                {% endfor %}
                </tbody>
            </table>
        </div>
        {% else %}
        <p>No endpoints were identified by the current path list.</p>
        {% endif %}
    </section>

    <section>
        <h2>Security Findings</h2>
        {% if results.findings %}
        <div class="table-wrap">
            <table>
                <thead>
                    <tr>
                        <th>Category</th>
                        <th>Endpoint</th>
                        <th>Method</th>
                        <th>Issue</th>
                        <th>Severity</th>
                        <th>Evidence / Details</th>
                    </tr>
                </thead>
                <tbody>
                {% for finding in results.findings %}
                    <tr>
                        <td>{{ finding.category }}</td>
                        <td>{{ finding.endpoint }}</td>
                        <td>{{ finding.method }}</td>
                        <td>{{ finding.issue }}</td>
                        <td class="severity {{ finding.severity }}">
                            {{ finding.severity }}
                        </td>
                        <td>{{ finding.evidence }}</td>
                    </tr>
                {% endfor %}
                </tbody>
            </table>
        </div>
        {% else %}
        <p>No findings were recorded by the current checks.</p>
        {% endif %}
        <p class="muted">
            Findings are preliminary. Missing headers alone do not prove
            that an exploitable vulnerability exists.
        </p>
    </section>

    <section>
        <h2>Report Preview</h2>
        <p><strong>Tool:</strong> AegisAPI</p>
        <p><strong>Target:</strong> {{ results.target }}</p>
        <p><strong>Endpoints:</strong> {{ results.summary.endpoints_found }}</p>
        <p><strong>Findings:</strong> {{ results.summary.findings_count }}</p>
        <p class="muted">
            The PDF contains the assessment summary, discovered endpoints,
            and security findings.
        </p>
        <form method="POST" action="/download">
            <input type="hidden" name="target_url" value="{{ results.target }}">
            <button type="submit">Download PDF Report</button>
        </form>
    </section>
    {% endif %}
</main>
</body>
</html>
"""


def generate_pdf(results):
    buffer = BytesIO()

    document = SimpleDocTemplate(
        buffer,
        pagesize=A4,
        rightMargin=1.5 * cm,
        leftMargin=1.5 * cm,
        topMargin=1.5 * cm,
        bottomMargin=1.5 * cm,
    )

    styles = getSampleStyleSheet()
    story = []

    story.append(
        Paragraph("AegisAPI Security Assessment Report", styles["Title"])
    )
    story.append(Spacer(1, 12))
    story.append(
        Paragraph(
            "<b>A Modular API Security Assessment Platform</b>",
            styles["Normal"],
        )
    )
    story.append(Spacer(1, 12))
    story.append(
        Paragraph(f"Target: {results['target']}", styles["Normal"])
    )
    story.append(
        Paragraph(
            f"Generated (UTC): {datetime.now(timezone.utc).isoformat()}",
            styles["Normal"],
        )
    )
    story.append(Spacer(1, 16))

    summary = results["summary"]

    # Assessment Summary
    story.append(
        Paragraph("Assessment Summary", styles["Heading2"])
    )

    story.append(
        Paragraph(
            f"HTTP Status: {results['target_status']}<br/>"
            f"Endpoints Found: {summary['endpoints_found']}<br/>"
            f"Total Findings: {summary['findings_count']}<br/>"
            f"High Severity: {summary['high']}<br/>"
            f"Medium Severity: {summary['medium']}<br/>"
            f"Low Severity: {summary['low']}<br/>"
            f"Informational: {summary['info']}",
            styles["Normal"],
        )
    )

    story.append(Spacer(1, 16))

    # Discovered Endpoints
    story.append(
        Paragraph("Discovered Endpoints", styles["Heading2"])
    )

    endpoint_rows = [["Path", "Method", "Status", "Content Type"]]

    for endpoint in results["endpoints"]:
        endpoint_rows.append([
            endpoint["path"],
            endpoint["method"],
            str(endpoint["status_code"]),
            endpoint["content_type"],
        ])

    endpoint_table = Table(
        endpoint_rows,
        repeatRows=1,
        colWidths=[4 * cm, 2 * cm, 2 * cm, 8 * cm],
    )

    endpoint_table.setStyle(TableStyle([
        ("BACKGROUND", (0, 0), (-1, 0), colors.HexColor("#2457c5")),
        ("TEXTCOLOR", (0, 0), (-1, 0), colors.white),
        ("GRID", (0, 0), (-1, -1), 0.5, colors.lightgrey),
        ("VALIGN", (0, 0), (-1, -1), "TOP"),
        ("FONTSIZE", (0, 0), (-1, -1), 8),
        ("BOTTOMPADDING", (0, 0), (-1, -1), 7),
        ("TOPPADDING", (0, 0), (-1, -1), 7),
    ]))

    story.append(endpoint_table)
    story.append(Spacer(1, 16))

    # Security Findings
    story.append(
        Paragraph("Security Findings", styles["Heading2"])
    )

    finding_rows = [["Category", "Endpoint", "Issue", "Severity"]]

    for finding in results["findings"]:
        finding_rows.append([
            finding["category"],
            finding["endpoint"],
            Paragraph(finding["issue"], styles["BodyText"]),
            finding["severity"],
        ])

    finding_table = Table(
        finding_rows,
        repeatRows=1,
        colWidths=[3 * cm, 2.5 * cm, 7.5 * cm, 2.5 * cm],
    )

    finding_table.setStyle(TableStyle([
        ("BACKGROUND", (0, 0), (-1, 0), colors.HexColor("#2457c5")),
        ("TEXTCOLOR", (0, 0), (-1, 0), colors.white),
        ("GRID", (0, 0), (-1, -1), 0.5, colors.lightgrey),
        ("VALIGN", (0, 0), (-1, -1), "TOP"),
        ("FONTSIZE", (0, 0), (-1, -1), 8),
        ("BOTTOMPADDING", (0, 0), (-1, -1), 7),
        ("TOPPADDING", (0, 0), (-1, -1), 7),
    ]))

    story.append(finding_table)
    story.append(Spacer(1, 16))

    # Additional Security Checks
    story.append(
        Paragraph("Additional Security Checks", styles["Heading2"])
    )

    check_rows = [["Security Check", "Status", "Details"]]

    for check in results.get("checks", []):
        check_rows.append([
            check["name"],
            check["status"],
            Paragraph(check["details"], styles["BodyText"]),
        ])

    if len(check_rows) > 1:
        check_table = Table(
            check_rows,
            repeatRows=1,
            colWidths=[4 * cm, 2.5 * cm, 9 * cm],
        )

        check_table.setStyle(TableStyle([
            ("BACKGROUND", (0, 0), (-1, 0), colors.HexColor("#2457c5")),
            ("TEXTCOLOR", (0, 0), (-1, 0), colors.white),
            ("GRID", (0, 0), (-1, -1), 0.5, colors.lightgrey),
            ("VALIGN", (0, 0), (-1, -1), "TOP"),
            ("FONTSIZE", (0, 0), (-1, -1), 8),
            ("BOTTOMPADDING", (0, 0), (-1, -1), 7),
            ("TOPPADDING", (0, 0), (-1, -1), 7),
        ]))

        story.append(check_table)
        story.append(Spacer(1, 16))

    # Assessment Limitations
    story.append(
        Paragraph("Assessment Limitations", styles["Heading2"])
    )

    story.append(
        Paragraph(
            "This report documents the checks performed by the current "
            "AegisAPI prototype, including security-header inspection, "
            "endpoint discovery, basic authentication checks, and input-length "
            "validation. Findings are preliminary observations and require "
            "manual verification. Comprehensive authorization, business-logic, "
            "rate-limit, and advanced vulnerability testing are not yet implemented.",
            styles["Normal"],
        )
    )

    document.build(story)
    buffer.seek(0)

    return buffer


@app.route("/")
def index():
    return render_template("home.html")

@app.route("/dashboard")
def dashboard():

    connection = get_connection()
    cursor = connection.cursor()

    # Total assessments
    total_assessments = cursor.execute("""
        SELECT COUNT(*) FROM assessments
    """).fetchone()[0]

    # Total endpoints discovered
    endpoints_found = cursor.execute("""
        SELECT COALESCE(SUM(endpoints_found), 0)
        FROM assessments
    """).fetchone()[0]

    # Total findings
    findings_count = cursor.execute("""
        SELECT COUNT(*) FROM findings
    """).fetchone()[0]

    # Findings by severity
    severity_counts = cursor.execute("""
        SELECT
            SUM(CASE WHEN severity = 'HIGH' THEN 1 ELSE 0 END),
            SUM(CASE WHEN severity = 'MEDIUM' THEN 1 ELSE 0 END),
            SUM(CASE WHEN severity = 'LOW' THEN 1 ELSE 0 END),
            SUM(CASE WHEN severity = 'INFO' THEN 1 ELSE 0 END)
        FROM findings
    """).fetchone()

    high_count = severity_counts[0] or 0
    medium_count = severity_counts[1] or 0
    low_count = severity_counts[2] or 0
    info_count = severity_counts[3] or 0

    # Latest assessment
    latest_assessment = cursor.execute("""
        SELECT *
        FROM assessments
        ORDER BY assessment_id DESC
        LIMIT 1
    """).fetchone()

    connection.close()

    return render_template(
        "dashboard.html",
        total_assessments=total_assessments,
        endpoints_found=endpoints_found,
        findings_count=findings_count,
        high_count=high_count,
        medium_count=medium_count,
        low_count=low_count,
        info_count=info_count,
        latest_assessment=latest_assessment
    )

@app.route("/findings")
def findings_page():

    connection = get_connection()
    cursor = connection.cursor()

    severity = request.args.get("severity", "").upper()
    search_query = request.args.get("search", "").strip()
    sort_by = request.args.get("sort", "newest")

    allowed_severities = ["HIGH", "MEDIUM", "LOW", "INFO"]

    query = """
        SELECT
            findings.finding_id,
            findings.assessment_id,
            findings.category,
            findings.endpoint,
            findings.method,
            findings.issue,
            findings.severity,
            findings.evidence,
            assessments.target_url,
            assessments.scan_date
        FROM findings
        JOIN assessments
        ON findings.assessment_id = assessments.assessment_id
    """

    conditions = []
    parameters = []

    if severity in allowed_severities:
        conditions.append("findings.severity = ?")
        parameters.append(severity)
    else:
        severity = ""

    if search_query:
        conditions.append("""
            (
                assessments.target_url LIKE ?
                OR findings.endpoint LIKE ?
                OR findings.issue LIKE ?
                OR findings.evidence LIKE ?
            )
        """)

        search_value = f"%{search_query}%"

        parameters.extend([
            search_value,
            search_value,
            search_value,
            search_value
        ])

    if conditions:
        query += " WHERE " + " AND ".join(conditions)

    # Sorting options
    if sort_by == "severity":
        query += """
            ORDER BY
            CASE findings.severity
                WHEN 'HIGH' THEN 1
                WHEN 'MEDIUM' THEN 2
                WHEN 'LOW' THEN 3
                WHEN 'INFO' THEN 4
                ELSE 5
            END,
            findings.finding_id DESC
        """

    elif sort_by == "oldest":
        query += " ORDER BY findings.finding_id ASC"

    else:
        sort_by = "newest"
        query += " ORDER BY findings.finding_id DESC"

    cursor.execute(query, parameters)

    findings = cursor.fetchall()

    connection.close()

    return render_template(
        "findings.html",
        findings=findings,
        selected_severity=severity,
        search_query=search_query,
        sort_by=sort_by
    )

@app.route("/reports")
def reports_page():
    connection = get_connection()
    cursor = connection.cursor()

    search_query = request.args.get("search", "").strip()
    selected_severity = request.args.get("severity", "").upper()
    sort_by = request.args.get("sort", "newest")

    query = "SELECT * FROM assessments WHERE 1=1"
    parameters = []

    # Search reports by target URL
    if search_query:
        query += " AND target_url LIKE ?"
        parameters.append(f"%{search_query}%")

    # Filter reports by severity
    severity_columns = {
        "HIGH": "high_count",
        "MEDIUM": "medium_count",
        "LOW": "low_count",
        "INFO": "info_count"
    }

    if selected_severity in severity_columns:
        column = severity_columns[selected_severity]
        query += f" AND {column} > 0"

    # Sort reports by scan date
    if sort_by == "oldest":
        query += " ORDER BY scan_date ASC, assessment_id ASC"
    else:
        query += " ORDER BY scan_date DESC, assessment_id DESC"

    cursor.execute(query, parameters)
    reports = cursor.fetchall()

    connection.close()

    return render_template(
        "reports.html",
        reports=reports,
        search_query=search_query,
        selected_severity=selected_severity,
        sort_by=sort_by
    )

@app.route("/reports/<int:assessment_id>")
def view_report(assessment_id):

    connection = get_connection()
    cursor = connection.cursor()

    # Retrieve selected assessment
    assessment = cursor.execute("""
        SELECT *
        FROM assessments
        WHERE assessment_id = ?
    """, (assessment_id,)).fetchone()

    if assessment is None:
        connection.close()
        return "Assessment report not found.", 404

    # Retrieve findings belonging to this assessment
    findings = cursor.execute("""
        SELECT *
        FROM findings
        WHERE assessment_id = ?
        ORDER BY finding_id
    """, (assessment_id,)).fetchall()

    connection.close()

    return render_template(
        "report_detail.html",
        assessment=assessment,
        findings=findings
    )

@app.route("/assessment", methods=["GET", "POST"])
def assessment_page():
    target_url = ""
    results = None
    error = None

    if request.method == "POST":
        target_url = request.form.get("target_url", "").strip()

        try:
            results = run_assessment(target_url)

            # Save completed assessment in SQLite
            save_assessment(target_url, results)

        except ValueError as exc:
            error = str(exc)

        except ConnectionError:
            error = (
                "Unable to connect to the target API. "
                "Please verify that the URL is correct, "
                "the API server is running, and the target "
                "is reachable. Assessment could not be completed."
            )

    return render_template(
        "assessment.html",
        target_url=target_url,
        results=results,
        error=error
    )

@app.route("/download", methods=["POST"])
def download():
    target_url = request.form.get("target_url", "").strip()

    try:
        results = run_assessment(target_url)
        pdf_buffer = generate_pdf(results)

        return send_file(
            pdf_buffer,
            mimetype="application/pdf",
            as_attachment=True,
            download_name="AegisAPI_Assessment_Report.pdf",
        )

    except (ValueError, ConnectionError) as exc:
        return f"Could not generate report: {exc}", 400

@app.route("/reports/<int:assessment_id>/download", methods=["POST"])
def download_saved_report(assessment_id):
    connection = get_connection()
    cursor = connection.cursor()

    cursor.execute(
        "SELECT * FROM assessments WHERE assessment_id = ?",
        (assessment_id,)
    )
    assessment = cursor.fetchone()

    if assessment is None:
        connection.close()
        return "Assessment report not found.", 404

    cursor.execute(
        "SELECT * FROM findings WHERE assessment_id = ?",
        (assessment_id,)
    )
    saved_findings = cursor.fetchall()

    connection.close()

    results = {
    "target": assessment["target_url"],
    "target_status": "Previously assessed",
    "summary": {
        "endpoints_found": assessment["endpoints_found"],
        "findings_count": assessment["findings_count"],
        "high": assessment["high_count"],
        "medium": assessment["medium_count"],
        "low": assessment["low_count"],
        "info": assessment["info_count"],
    },
    "endpoints": json.loads(assessment["endpoints_json"] or "[]"),
    "findings": [dict(finding) for finding in saved_findings],
    "checks": json.loads(assessment["checks_json"] or "[]"),
}

    pdf_buffer = generate_pdf(results)

    return send_file(
        pdf_buffer,
        as_attachment=True,
        download_name=f"AegisAPI_Report_{assessment_id}.pdf",
        mimetype="application/pdf",
    )

if __name__ == "__main__":
    app.run(host="127.0.0.1", port=5001, debug=False)