from flask import Flask, render_template, request

from modules.network_discovery import discover_network
from modules.security_monitoring import monitor_network

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


@app.route("/monitoring", methods=["GET", "POST"])
def security_monitoring():

    result = get_latest_monitoring_scan()

    target = "192.168.56.0/24"

    if request.method == "POST":

        target = request.form.get("network", "").strip()

        # Load previous device inventory from SQLite
        previous_devices = get_previous_devices()

        # Execute monitoring
        result = monitor_network(
            target,
            previous_devices
        )

        if result.get("success"):

            # Save current device inventory
            save_devices(
                result["devices"],
                result["monitoring_time"]
            )

            # Save detected security events
            save_security_events(
                result.get("events", [])
            )

            # Save scan history
            save_monitoring_scan(result)

    # Retrieve persistent event history
    events = get_security_events()

    return render_template(
        "monitoring.html",
        result=result,
        target=target,
        events=events
    )


if __name__ == "__main__":

    app.run(
        debug=True,
        host="127.0.0.1",
        port=5000
    )
