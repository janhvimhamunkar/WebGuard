import logging
from flask import Flask, render_template, request, jsonify, abort, url_for, send_file
import config
from scanner import run_scan, ScanError
from models import database as db
import io
import datetime
from urllib.parse import urlparse

app = Flask(__name__)
app.config.from_object(config)
logging.basicConfig(level=logging.INFO, format='%(asctime)s - %(name)s - %(levelname)s - %(message)s')
db.init_db()

@app.route("/")
def index():
    return render_template("index.html")

@app.route("/scanner")
def scanner_page():
    return render_template("scan.html")

@app.post("/api/scan")
def api_scan():
    data = request.get_json(silent=True) or {}
    if data.get("authorized") is not True:
        return jsonify(ok=False, error="You must confirm you are authorized to test this website."), 400
    target = data.get("url", "")
    app.logger.info(f"Scan started for target: {target}")
    start_time = datetime.datetime.now()
    try:
        result = run_scan(target)
        scan_id = db.save_scan(result)
        duration = (datetime.datetime.now() - start_time).total_seconds()
        findings_count = result["summary"]["total_findings"]
        app.logger.info(f"Scan completed for {target}. Duration: {duration:.2f}s. Findings: {findings_count}")
    except ScanError as e:
        app.logger.warning(f"ScanError for {target}: {str(e)}")
        return jsonify(ok=False, error=str(e)), 400
    except Exception:
        app.logger.exception(f"Scan failed for target: {target}")
        return jsonify(ok=False, error="An internal error occurred."), 500
    return jsonify(ok=True, redirect=url_for("dashboard", scan_id=scan_id))

def _scan_or_404(scan_id):
    scan = db.get_scan(scan_id)
    if not scan:
        abort(404)
    return scan

@app.route("/dashboard/<int:scan_id>")
def dashboard(scan_id):
    return render_template("dashboard.html", scan=_scan_or_404(scan_id))

@app.route("/report/<int:scan_id>")
def report(scan_id):
    return render_template("report.html", scan=_scan_or_404(scan_id))

@app.route("/report/<int:scan_id>/pdf")
def report_pdf(scan_id):
    scan = _scan_or_404(scan_id)
    from scanner.pdf_generator import generate_pdf
    pdf_bytes = generate_pdf(scan)
    domain = urlparse(scan['target_url']).hostname or "target"
    date_str = scan['scan_date'].split(' ')[0]
    filename = f"WebGuard_Report_{domain}_{date_str}.pdf"
    return send_file(io.BytesIO(pdf_bytes), mimetype='application/pdf', as_attachment=True, download_name=filename)

@app.route("/delete/<int:scan_id>", methods=["POST"])
def delete_scan(scan_id):
    db.delete_scan(scan_id)
    return jsonify(ok=True)

@app.route("/history")
def history():
    return render_template("history.html", scans=db.list_scans())

@app.route("/about")
def about():
    return render_template("about.html")

@app.errorhandler(404)
def not_found(e):
    return render_template("about.html", not_found=True), 404

@app.errorhandler(500)
def server_error(e):
    return "Internal server error.", 500

if __name__ == "__main__":
    app.run(host="127.0.0.1", port=5000, debug=False)
