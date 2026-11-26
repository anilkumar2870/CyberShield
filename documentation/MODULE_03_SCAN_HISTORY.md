# Module 03 -- Scan History

## 1. Overview

The Scan History module stores and displays previous network monitoring
scans performed by CyberShield. It allows users to review earlier scans,
see summary information, and open an individual scan record to inspect
its discovered devices.

The module is integrated with the Flask application and the project's
SQLite database.

## 2. Objectives

-   Store completed monitoring scan records.
-   Display previously saved scans in a history table.
-   Identify each scan using a unique scan ID.
-   Show the scanned network, number of discovered devices, number of
    security events, scanner, and scan timestamp.
-   Allow users to open a detailed view of an individual scan.
-   Retrieve historical scan information from the SQLite database.

## 3. Implemented Features

### 3.1 Scan History Listing

The Scan History page is available at:

``` text
http://127.0.0.1:5000/history
```

The page displays saved scan records in a table with the following
information:

  Field       Description
  ----------- ------------------------------------------
  Scan ID     Unique identifier for the scan
  Network     Private network range that was monitored
  Devices     Number of discovered devices
  Events      Number of detected security events
  Scanner     Scanning system used
  Scan Time   Timestamp recorded for the scan
  Details     Link to open the individual scan record

The page also displays a message indicating how many scan records were
retrieved.

### 3.2 Individual Scan Details

Each scan has a details link. Selecting it opens the corresponding
historical record.

The detail page displays: - Scan ID - Network range - Number of devices
discovered - Number of security events - Scanner - Scan timestamp -
Discovered device information, including IP address, MAC address, and
status

If a requested scan ID does not exist, the application returns a `404`
response with the message:

``` text
Scan record not found.
```

### 3.3 Database Integration

The module uses the project's SQLite database:

``` text
data/cybershield.db
```

The database contains the following relevant tables:

-   `devices`
-   `monitoring_scans`
-   `security_events`

The `monitoring_scans` table stores scan summary information, including
the network, device total, event count, scanner, monitoring time, and
serialized result data.

The scan history functions are imported into `app.py` from:

``` python
from modules.scan_history import get_scan_history, get_scan_by_id
```

### 3.4 Flask Routes

The following routes are registered in the Flask application:

  --------------------------------------------------------------------------
  Route                      Method                  Purpose
  -------------------------- ----------------------- -----------------------
  `/history`                 GET                     Displays the scan
                                                     history

  `/history/<int:scan_id>`   GET                     Displays details for a
                                                     specific scan
  --------------------------------------------------------------------------

The history listing route calls `get_scan_history()` and renders
`history.html`.

The detail route calls `get_scan_by_id(scan_id)` and renders
`history_detail.html`.

## 4. Application Integration

The Scan History module is integrated with the existing monitoring
workflow.

When a monitoring scan completes successfully, the application saves the
scan summary using:

``` python
save_monitoring_scan(result)
```

The history module then retrieves the saved records for display.

The relevant imports in `app.py` are:

``` python
from modules.scan_history import get_scan_history, get_scan_by_id
```

The routes are:

``` python
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
```

## 5. Testing and Verification

The module was tested through the local Flask application.

### 5.1 Scan History Test

The following URL was opened:

``` text
http://127.0.0.1:5000/history
```

The page successfully retrieved and displayed two scan records.

### 5.2 Verified Results

    Scan ID Network               Devices   Events Scanner
  --------- ------------------- --------- -------- ------------
          1 `192.168.56.0/24`           3        0 Kali Linux
          2 `192.168.56.0/24`           3        0 Kali Linux

The Scan History page confirmed the message:

``` text
Successfully retrieved 2 scan records.
```

### 5.3 Individual Record Test

The individual scan detail page was also opened successfully. It
displayed the historical network information and the three discovered
devices for scan #1.

### 5.4 Database Verification

The database inspection confirmed that the following tables exist:

``` text
devices
monitoring_scans
security_events
sqlite_sequence
```

The scan history retrieval function returned the saved scan information,
including the scan ID, network, device total, event count, scanner,
timestamp, and stored result data.

## 6. Project Structure

The relevant project files for this module are:

``` text
CyberShield/
│
├── app.py
│
├── data/
│   └── cybershield.db
│
├── modules/
│   ├── scan_history.py
│   └── monitoring_database.py
│
└── templates/
    ├── history.html
    └── history_detail.html
```

## 7. Result

Module 03 -- Scan History was implemented and verified successfully.

The application can retrieve multiple saved monitoring scans, display
them in a history table, and open individual scan details. The test
performed on the local application confirmed that two scan records were
available, each showing three discovered devices and zero detected
security events.

## 8. Conclusion

The Scan History module provides a historical record of CyberShield
network monitoring activity. It builds on the Network Discovery and
Security Monitoring modules by making previously completed scans
available for review.

**Module 03 status: Completed and verified.**

------------------------------------------------------------------------

*Project: CyberShield*\
*Module: 03 -- Scan History*\
*Technology: Python, Flask, SQLite, HTML, CSS, Kali Linux*
