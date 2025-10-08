# app.py
"""
Static Analysis Framework (No Login Version)
Features:
 - Upload APK and scan with MobSF
 - Store full JSON reports in SQLite
 - Dashboard with chart and vulnerability modals
 - Export PDF (with chart embedded)
"""
import requests
import os
import json
import uuid
import sqlite3
import base64
from io import BytesIO
from datetime import datetime
from flask import (
    Flask, render_template, request, redirect, url_for, flash,
    send_file, g, abort
)
from werkzeug.utils import secure_filename
from mob_sf_client import MobSFClient
from reportlab.lib.pagesizes import letter
from reportlab.pdfgen import canvas
from reportlab.lib.utils import ImageReader
from PIL import Image
from dotenv import load_dotenv

# ===== Load .env (optional) =====
load_dotenv()

# ===== Config =====
UPLOAD_FOLDER = "uploads"
REPORT_FOLDER = "reports"
DB_PATH = "scans.db"
ALLOWED_EXTENSIONS = {"apk"}

os.makedirs(UPLOAD_FOLDER, exist_ok=True)
os.makedirs(REPORT_FOLDER, exist_ok=True)

app = Flask(__name__)
app.secret_key = os.environ.get("FLASK_SECRET", "dev-secret-key")
app.config["UPLOAD_FOLDER"] = UPLOAD_FOLDER
app.config["REPORT_FOLDER"] = REPORT_FOLDER
app.config["DATABASE"] = DB_PATH

MOBSF_URL = os.environ.get("MOBSF_URL", "http://localhost:8000")
MOBSF_API_KEY = os.environ.get("MOBSF_API_KEY")

mob = MobSFClient(MOBSF_URL, MOBSF_API_KEY)

# ===== Database =====
def get_db():
    db = getattr(g, "_database", None)
    if db is None:
        db = g._database = sqlite3.connect(app.config["DATABASE"], check_same_thread=False)
        db.row_factory = sqlite3.Row
    return db


def init_db():
    db = get_db()
    db.execute("""
        CREATE TABLE IF NOT EXISTS scans (
            id INTEGER PRIMARY KEY AUTOINCREMENT,
            scan_id TEXT UNIQUE,
            filename TEXT,
            package_name TEXT,
            total INTEGER,
            high INTEGER,
            medium INTEGER,
            low INTEGER,
            report_json TEXT,
            created_at TEXT
        )
    """)
    db.commit()


@app.teardown_appcontext
def close_connection(exception):
    db = getattr(g, "_database", None)
    if db is not None:
        db.close()


with app.app_context():
    init_db()

# ===== Helpers =====
def allowed_file(filename):
    return "." in filename and filename.rsplit(".", 1)[1].lower() in ALLOWED_EXTENSIONS


MITIGATION_TIPS = {
    "Hardcoded API Key": "Avoid hardcoding keys. Use Android Keystore, environment variables, or remote secrets.",
    "Insecure SSL Validation": "Use proper certificate pinning and never disable SSL verification in production.",
    "Logging Sensitive Info": "Avoid logging PII or tokens. Redact or remove sensitive logs before release.",
    "exported_activities": "Add explicit permissions or set exported=false for components that shouldn't be public.",
    "default": "Follow secure coding practices: validate inputs, use secure storage, and avoid hardcoded secrets."
}

# ===== Routes =====
@app.route("/")
def index():
    return render_template("index.html")


@app.route("/about")
def about():
    return render_template("about.html")


@app.route("/upload", methods=["POST"])
def upload():
    if "apk" not in request.files:
        flash("No file part")
        return redirect(url_for("index"))

    file = request.files["apk"]
    if file.filename == "":
        flash("No selected file")
        return redirect(url_for("index"))

    if file and allowed_file(file.filename):
        filename = secure_filename(file.filename)
        local_path = os.path.join(app.config["UPLOAD_FOLDER"], filename)
        file.save(local_path)

        scan_id = str(uuid.uuid4())
        try:
            mob_hash = mob.upload_apk(local_path)
            mob.scan_apk(mob_hash)
            report_json = mob.get_report_json(mob_hash)
        except Exception as e:
            app.logger.error("MobSF error: %s", e)
            flash("Could not reach MobSF. Showing demo sample report instead.")
            report_json = mob.sample_report()

        package_name = report_json.get("package_name") or report_json.get("app_name") or ""

        summary = report_json.get("summary", {})
        high = int(summary.get("high", 0))
        medium = int(summary.get("medium", 0))
        low = int(summary.get("low", 0))
        total = high + medium + low

        report_path = os.path.join(app.config["REPORT_FOLDER"], f"{scan_id}.json")
        with open(report_path, "w", encoding="utf-8") as f:
            json.dump(report_json, f, indent=2)

        db = get_db()
        db.execute(
            "INSERT INTO scans (scan_id, filename, package_name, total, high, medium, low, report_json, created_at) VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?)",
            (scan_id, filename, package_name, total, high, medium, low, json.dumps(report_json), datetime.utcnow().isoformat())
        )
        db.commit()

        flash("Scan completed and saved.")
        return redirect(url_for("results", scan_id=scan_id))
    else:
        flash("Invalid file format. Only .apk allowed.")
        return redirect(url_for("index"))


@app.route("/results/<scan_id>")
def results(scan_id):
    db = get_db()
    row = db.execute("SELECT report_json FROM scans WHERE scan_id = ?", (scan_id,)).fetchone()
    if not row:
        flash("Report not found.")
        return redirect(url_for("index"))

    report_json = json.loads(row["report_json"])
    permissions = report_json.get("permissions", [])
    issues = report_json.get("code_analysis", {}).get("issues", []) or report_json.get("static_analysis", {}).get("vulnerabilities", [])
    manifest_issues = report_json.get("manifest_issues", [])
    libraries = report_json.get("third_party", {}).get("libraries", []) or report_json.get("dependencies", [])

    vuln_list = []
    if isinstance(issues, dict):
        for k, v in issues.items():
            if isinstance(v, list):
                vuln_list.extend(v)
    elif isinstance(issues, list):
        vuln_list = issues

    severity_counts = {"High": 0, "Medium": 0, "Low": 0, "Info": 0}
    for v in vuln_list:
        sev = (v.get("severity") or v.get("level") or "Info").title()
        severity_counts[sev] = severity_counts.get(sev, 0) + 1

    total_issues = sum(severity_counts.values())

    for v in vuln_list:
        title = v.get("title") or v.get("name") or ""
        v["mitigation"] = MITIGATION_TIPS.get(title, MITIGATION_TIPS.get(v.get("category", ""), MITIGATION_TIPS["default"]))
        v.setdefault("file", v.get("file", "-"))
        v.setdefault("line", v.get("line", "-"))
        v.setdefault("code_snippet", v.get("code_snippet", ""))

    return render_template(
        "results.html",
        scan_id=scan_id,
        permissions=permissions,
        manifest_issues=manifest_issues,
        libraries=libraries,
        vulnerability_list=vuln_list,
        severity_counts=severity_counts,
        total_issues=total_issues,
        report_json=json.dumps(report_json)
    )


@app.route("/export_chart/<scan_id>", methods=["POST"])
def export_chart(scan_id):
    db = get_db()
    row = db.execute("SELECT report_json FROM scans WHERE scan_id = ?", (scan_id,)).fetchone()
    if not row:
        abort(404)

    payload = request.get_json(silent=True)
    if not payload or "chart" not in payload:
        abort(400, "Missing chart in payload")

    chart_data_uri = payload["chart"]
    _, b64 = chart_data_uri.split(",", 1)
    chart_bytes = base64.b64decode(b64)
    img = Image.open(BytesIO(chart_bytes)).convert("RGB")
    img_buf = BytesIO()
    img.save(img_buf, format="PNG")
    img_buf.seek(0)

    report = json.loads(row["report_json"])
    summary = report.get("summary", {})
    high = int(summary.get("high", 0))
    medium = int(summary.get("medium", 0))
    low = int(summary.get("low", 0))
    total = high + medium + low

    pdf_path = os.path.join(app.config["REPORT_FOLDER"], f"{scan_id}_chart.pdf")
    c = canvas.Canvas(pdf_path, pagesize=letter)
    width, height = letter

    c.setFont("Helvetica-Bold", 18)
    c.drawString(40, height - 60, "Static Analysis Report (with Chart)")
    c.setFont("Helvetica", 11)
    c.drawString(40, height - 90, f"Scan ID: {scan_id}")
    c.drawString(40, height - 110, f"Issues: {total} (High: {high}, Medium: {medium}, Low: {low})")
    c.drawString(40, height - 130, f"Generated: {datetime.utcnow().isoformat()} UTC")

    c.drawImage(ImageReader(img_buf), 40, height - 400, width - 80, 250, preserveAspectRatio=True, mask="auto")
    c.setFont("Helvetica-Oblique", 9)
    c.drawString(40, 40, "Generated by Static Analysis Framework")
    c.save()

    return send_file(pdf_path, as_attachment=True, download_name=f"scan_{scan_id}_chart.pdf")


@app.route("/history")
def history():
    db = get_db()
    rows = db.execute("SELECT scan_id, filename, package_name, total, high, medium, low, created_at FROM scans ORDER BY created_at DESC").fetchall()
    return render_template("history.html", scans=rows)


@app.route("/search", methods=["GET", "POST"])
def search():
    results = []
    query = ""
    if request.method == "POST":
        query = request.form.get("query", "").strip()
        db = get_db()
        q = f"%{query}%"
        rows = db.execute("SELECT scan_id, filename, package_name, total, created_at FROM scans WHERE filename LIKE ? OR package_name LIKE ? ORDER BY created_at DESC", (q, q)).fetchall()
        results = rows
    return render_template("search.html", results=results, query=query)

@app.route("/export/<scan_id>")
def export_pdf(scan_id):
    """
    Simple textual PDF export (no chart). Reads report JSON from DB and
    writes a plain PDF summary. Matches the template link that calls export_pdf.
    """
    db = get_db()
    row = db.execute("SELECT report_json FROM scans WHERE scan_id = ?", (scan_id,)).fetchone()
    if not row:
        abort(404, "Report not found")

    report = json.loads(row["report_json"])
    summary = report.get("summary", {})
    high = int(summary.get("high", 0))
    medium = int(summary.get("medium", 0))
    low = int(summary.get("low", 0))
    total = high + medium + low

    pdf_path = os.path.join(app.config["REPORT_FOLDER"], f"{scan_id}.pdf")
    c = canvas.Canvas(pdf_path, pagesize=letter)
    width, height = letter

    c.setFont("Helvetica-Bold", 18)
    c.drawString(40, height - 60, "Static Analysis Framework - Scan Report")

    c.setFont("Helvetica", 11)
    c.drawString(40, height - 90, f"Scan ID: {scan_id}")
    # show app name or package if available
    appname = report.get("app_name") or report.get("package_name") or ""
    if appname:
        c.drawString(40, height - 110, f"App: {appname}")
        y_start = height - 130
    else:
        y_start = height - 110

    c.drawString(40, y_start, f"Total Issues: {total} (High: {high} / Medium: {medium} / Low: {low})")
    c.drawString(40, y_start - 20, f"Generated: {datetime.utcnow().isoformat()} UTC")

    c.setFont("Helvetica-Bold", 12)
    c.drawString(40, y_start - 50, "Top Vulnerabilities:")
    c.setFont("Helvetica", 10)

    y = y_start - 70
    issues = report.get("code_analysis", {}).get("issues", []) or report.get("static_analysis", {}).get("vulnerabilities", [])
    count = 0
    if isinstance(issues, list):
        for it in issues:
            title = it.get("title") or it.get("name") or "Unnamed"
            sev = it.get("severity") or it.get("level") or "Info"
            c.drawString(45, y, f"- {title} [{sev}]")
            y -= 14
            count += 1
            if y < 60 or count >= 12:
                break

    c.setFont("Helvetica-Oblique", 9)
    c.drawString(40, 40, "Generated by Static Analysis Framework (MobSF)")
    c.save()

    return send_file(pdf_path, as_attachment=True, download_name=f"scan_{scan_id}.pdf")



if __name__ == "__main__":
    app.run(host="0.0.0.0", port=5000, debug=True)
