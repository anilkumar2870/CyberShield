
from flask import Flask, render_template, request, send_file

from modules.network_discovery import discover_network
from modules.security_monitoring import monitor_network
from modules.scan_history import get_scan_history, get_scan_by_id
from modules.security_reports import get_available_reports
from modules.pdf_reports import generate_security_report

from modules.monitoring_database import (
    initialize_database,
    get_previous_devices,
    save_devices,
    save_security_events,
    get_security_events,
    save_monitoring_scan,
    get_latest_monitoring_scan
)


app = Flask(__name__)

# Initialize SQLite database
initialize_database()


# ==========================================
# MODULE 01 - NETWORK DISCOVERY
# ==========================================

@app.route("/", methods=["GET", "POST"])
def dashboard():

    result = None
    target = ""

    if request.method == "POST":

        target = request.form.get("network", "").strip()

        result = discover_network(target)

    return render_template(
        "index.html",
        result=result,
        target=target
    )


# ==========================================
# MODULE 02 - SECURITY MONITORING
# ==========================================

@app.route("/monitoring", methods=["GET", "POST"])
def security_monitoring():

    result = get_latest_monitoring_scan()

    target = "192.168.56.0/24"

    if request.method == "POST":

        target = request.form.get("network", "").strip()

        previous_devices = get_previous_devices()

        result = monitor_network(
            target,
            previous_devices
        )

        if result.get("success"):

            save_devices(
                result["devices"],
                result["monitoring_time"]
            )

            save_security_events(
                result.get("events", [])
            )

            save_monitoring_scan(result)

    events = get_security_events()

    return render_template(
        "monitoring.html",
        result=result,
        target=target,
        events=events
    )


# ==========================================
# MODULE 03 - SCAN HISTORY
# ==========================================

@app.route("/history")
def scan_history():

    result = get_scan_history()

    return render_template(
        "history.html",
        result=result
    )


@app.route("/history/<int:scan_id>")
def scan_history_detail(scan_id):

    scan = get_scan_by_id(scan_id)

    if scan is None:
        return "Scan record not found.", 404

    return render_template(
        "history_detail.html",
        scan=scan
    )


# ==========================================
# MODULE 04 - SECURITY REPORTS
# ==========================================

@app.route("/reports")
def security_reports():

    result = get_available_reports()

    return render_template(
        "reports.html",
        result=result
    )


# Display HTML security assessment report
@app.route("/reports/<int:scan_id>")
def report_detail(scan_id):

    report = get_scan_by_id(scan_id)

    if report is None:
        return "Security report not found.", 404

    return render_template(
        "report_detail.html",
        scan=report
    )


# ==========================================
# MODULE 04 - AUTOMATED PDF GENERATION
# ==========================================

@app.route("/reports/<int:scan_id>/download")
def download_report(scan_id):

    scan = get_scan_by_id(scan_id)

    if scan is None:
        return "Security report not found.", 404

    try:

        pdf_buffer = generate_security_report(scan)

        return send_file(
            pdf_buffer,
            mimetype="application/pdf",
            as_attachment=True,
            download_name=f"CyberShield_Report_{scan_id}.pdf"
        )

    except Exception:

        app.logger.exception(
            "Security report PDF generation failed"
        )

        return "Unable to generate security report PDF.", 500


# ==========================================
# APPLICATION ENTRY POINT
# ==========================================

if __name__ == "__main__":

    app.run(
        debug=True,
        host="127.0.0.1",
        port=5000
    )
