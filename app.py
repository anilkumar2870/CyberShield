import os

from flask import (
    Flask,
    render_template,
    request,
    send_file,
    redirect,
    url_for,
    jsonify
)

from modules.network_discovery import discover_network
from modules.security_monitoring import monitor_network
from modules.scan_history import get_scan_history, get_scan_by_id
from modules.security_reports import get_available_reports
from modules.pdf_reports import generate_security_report

from modules.kali_connector import get_kali_ssh_authentication_logs
from modules.ssh_security_analysis import analyze_ssh_logs
from modules.ssh_threat_tracking import analyze_persistent_ssh_threats

from modules.monitoring_database import (
    initialize_database,
    get_previous_devices,
    save_devices,
    save_security_events,
    get_security_events,
    get_connection,
    save_monitoring_scan,
    get_latest_monitoring_scan,
    get_alert_by_id,
    update_alert_status,
    update_investigation_notes,
    get_alert_summary,
    save_ssh_security_events
)


app = Flask(__name__)

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

        result = monitor_network(target, previous_devices)

        if result.get("success"):

            save_devices(
                result["devices"],
                result["monitoring_time"]
            )

            save_security_events(result.get("events", []))
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


@app.route("/reports/<int:scan_id>")
def report_detail(scan_id):

    report = get_scan_by_id(scan_id)

    if report is None:
        return "Security report not found.", 404

    return render_template(
        "report_detail.html",
        scan=report
    )


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
# MODULE 05 - ALERT MANAGEMENT
# ==========================================

@app.route("/alerts")
def alert_dashboard():

    status_filter = request.args.get(
        "status", "All"
    ).strip()

    severity_filter = request.args.get(
        "severity", "All"
    ).strip()

    allowed_statuses = {
        "All", "New", "Acknowledged", "Resolved"
    }

    allowed_severities = {
        "All", "Critical", "High", "Medium", "Low"
    }

    if status_filter not in allowed_statuses:
        status_filter = "All"

    if severity_filter not in allowed_severities:
        severity_filter = "All"

    # Retrieve alerts newest first.
    all_alerts = get_security_events(limit=1000)

    # Apply filters in Python to remain compatible
    # with the existing database function.
    alerts = []

    for alert in all_alerts:

        alert_status = alert.get("status") or "New"
        alert_severity = alert.get("severity") or "Low"

        if (
            status_filter != "All"
            and alert_status != status_filter
        ):
            continue

        if (
            severity_filter != "All"
            and alert_severity != severity_filter
        ):
            continue

        alerts.append(alert)

    summary = get_alert_summary()

    return render_template(
        "alerts.html",
        alerts=alerts,
        summary=summary,
        status_filter=status_filter,
        severity_filter=severity_filter
    )


# ==========================================
# DELETE SELECTED ALERTS
# ==========================================

@app.route("/alerts/delete", methods=["POST"])
def delete_selected_alerts():

    selected_ids = request.form.getlist("alert_ids")

    if not selected_ids:
        return redirect(url_for("alert_dashboard"))

    try:

        # Accept only positive integer alert IDs.
        alert_ids = []

        for value in selected_ids:

            alert_id = int(value)

            if alert_id <= 0:
                raise ValueError

            alert_ids.append(alert_id)

        # Delete only the selected alert records.
        placeholders = ",".join(
            "?" for _ in alert_ids
        )

        with get_connection() as connection:

            connection.execute(
                f"DELETE FROM security_events "
                f"WHERE id IN ({placeholders})",
                alert_ids
            )

    except (ValueError, TypeError):

        return "Invalid alert selection.", 400

    return redirect(url_for("alert_dashboard"))


# ==========================================
# ALERT STATUS MANAGEMENT
# ==========================================

@app.route(
    "/alerts/<int:alert_id>/status",
    methods=["POST"]
)
def manage_alert_status(alert_id):

    alert = get_alert_by_id(alert_id)

    if alert is None:
        return "Alert not found.", 404

    status = request.form.get("status", "").strip()

    try:
        update_alert_status(alert_id, status)

    except ValueError:
        return "Invalid alert status.", 400

    return redirect(url_for("alert_dashboard"))


# ==========================================
# INVESTIGATION NOTES
# ==========================================

@app.route(
    "/alerts/<int:alert_id>/notes",
    methods=["POST"]
)
def save_alert_notes(alert_id):

    alert = get_alert_by_id(alert_id)

    if alert is None:
        return "Alert not found.", 404

    notes = request.form.get(
        "investigation_notes", ""
    ).strip()

    update_investigation_notes(
        alert_id,
        notes
    )

    return redirect(url_for("alert_dashboard"))


# ==========================================
# MODULE 05 - SSH SECURITY INTELLIGENCE
# ==========================================

@app.route(
    "/ssh-security/analyze",
    methods=["POST"]
)
def analyze_ssh_security():

    try:

        # Retrieve SSH authentication logs.
        log_result = get_kali_ssh_authentication_logs()

        if not log_result.get("success"):

            return jsonify({
                "success": False,
                "error": log_result.get(
                    "error",
                    "Unable to retrieve SSH logs."
                )
            }), 502

        logs = log_result.get("logs", [])

        # Read approved SSH source IPs.
        approved_ips = [
            ip.strip()
            for ip in os.getenv(
                "CYBERSHIELD_APPROVED_SSH_IPS",
                ""
            ).split(",")
            if ip.strip()
        ]

        if not approved_ips:
            approved_ips = None

        # Standard SSH analysis.
        analysis = analyze_ssh_logs(
            logs,
            approved_ips=approved_ips
        )

        if not analysis.get("success"):

            return jsonify({
                "success": False,
                "error": analysis.get(
                    "error",
                    "SSH log analysis failed."
                )
            }), 400

        # Persistent brute-force analysis.
        threat_analysis = analyze_persistent_ssh_threats(
            logs,
            threshold=5,
            window_minutes=15
        )

        if not threat_analysis.get("success"):

            return jsonify({
                "success": False,
                "error": threat_analysis.get(
                    "error",
                    "Persistent SSH threat analysis failed."
                )
            }), 400

        # Combine events.
        events = [
            event
            for event in analysis.get("events", [])
            if event.get("type") != "REPEATED_SSH_LOGIN_FAILURES"
        ]

        events.extend(
            threat_analysis.get("events", [])
        )

        # Save alerts.
        storage_result = save_ssh_security_events(events)

        return jsonify({

            "success": True,

            "message": "SSH security analysis completed.",

            "log_count": log_result.get("total", 0),

            "successful_logins": analysis.get(
                "successful_logins", 0
            ),

            "failed_logins": analysis.get(
                "failed_logins", 0
            ),

            "invalid_user_attempts": analysis.get(
                "invalid_user_attempts", 0
            ),

            "events_detected": len(events),

            "alerts_inserted": storage_result.get(
                "inserted", 0
            ),

            "duplicate_alerts_skipped": storage_result.get(
                "skipped", 0
            ),

            "persistent_tracking": {

                "new_records_processed": (
                    threat_analysis.get(
                        "new_records_processed", 0
                    )
                ),

                "records_ignored": (
                    threat_analysis.get(
                        "records_ignored", 0
                    )
                ),

                "threshold": threat_analysis.get(
                    "threshold", 5
                ),

                "window_minutes": threat_analysis.get(
                    "window_minutes", 15
                ),

                "source_counts": threat_analysis.get(
                    "source_counts", {}
                )
            },

            "events": events

        })

    except Exception:

        app.logger.exception(
            "SSH security analysis failed"
        )

        return jsonify({
            "success": False,
            "error": (
                "An internal error occurred during "
                "SSH security analysis."
            )
        }), 500


# ==========================================
# APPLICATION ENTRY POINT
# ==========================================

if __name__ == "__main__":

    app.run(
        debug=True,
        host="127.0.0.1",
        port=5000
    )
