# CyberShield -- Module 04: Security Reports

## 1. Module Overview

Module 04 adds a Security Reports feature to CyberShield. It uses
historical network monitoring scans stored in the SQLite database to
present available reports and generate downloadable PDF assessment
reports.

The module is designed to let an administrator select a previous
monitoring scan and produce a report containing the recorded network,
discovered devices, scan details, and security-event summary.

## 2. Objectives

-   Retrieve historical monitoring scan records.
-   Display available reports in the CyberShield dashboard workflow.
-   Allow the user to select a historical scan.
-   Generate a PDF report for the selected scan.
-   Provide a downloadable report with a clear assessment summary.

## 3. Main Features

### 3.1 Security Reports page

The Security Reports page displays historical scan records in a table.
The records include:

-   Report ID
-   Network
-   Number of discovered devices
-   Number of security events
-   Scanner
-   Scan time
-   Action to generate the report

The page also displays a message indicating whether historical records
were retrieved successfully.

### 3.2 PDF report generation

A user can request a PDF report for a selected historical scan. The
report is generated from the stored scan information and returned as a
downloadable PDF.

The report content includes:

-   Report ID
-   Target network
-   Number of discovered devices
-   Number of security events
-   Scanner
-   Scan timestamp
-   Discovered-device inventory, including IP address, MAC address, and
    status
-   Security-event summary
-   Assessment conclusion

The report is a historical monitoring summary. It is not a guarantee
that the network is free from vulnerabilities.

## 4. Application Workflow

1.  The user opens **Security Reports** from the CyberShield dashboard.
2.  Flask calls the report retrieval function.
3.  Historical monitoring scans are read from the SQLite database.
4.  The `reports.html` template displays the available scans.
5.  The user selects **Generate Report** for a scan.
6.  The application retrieves the selected scan by its ID.
7.  The PDF-generation function creates the report.
8.  Flask sends the generated PDF as a file download.

## 5. Project Files

The Module 04 implementation uses the following files:

  -----------------------------------------------------------------------
  File                                Purpose
  ----------------------------------- -----------------------------------
  `app.py`                            Defines the Security Reports page
                                      and PDF download routes.

  `modules/security_reports.py`       Retrieves historical scans that are
                                      available for reporting.

  `modules/pdf_reports.py`            Generates the PDF report from a
                                      selected scan.

  `templates/reports.html`            Displays the list of available
                                      historical reports.

  `templates/report_detail.html`      HTML report layout, if used for
                                      browser-based report viewing.

  `templates/index.html`              Adds the Security Reports
                                      navigation link and dashboard
                                      module card.

  `modules/scan_history.py`           Retrieves scan history and an
                                      individual scan record.

  `modules/monitoring_database.py`    Provides SQLite database access and
                                      monitoring-scan storage.
  -----------------------------------------------------------------------

## 6. Flask Routes

The reports page uses the following route:

``` python
@app.route("/reports")
def security_reports():
    result = get_available_reports()

    return render_template(
        "reports.html",
        result=result
    )
```

The PDF download should use a separate route and endpoint name. For
example:

``` python
@app.route("/reports/<int:scan_id>/download")
def download_report(scan_id):
    scan = get_scan_by_id(scan_id)

    if scan is None:
        return "Scan record not found.", 404

    pdf_buffer = generate_security_report(scan)

    return send_file(
        pdf_buffer,
        mimetype="application/pdf",
        as_attachment=True,
        download_name=f"CyberShield_Report_{scan_id}.pdf"
    )
```

**Important:** Do not define two Flask view functions with the same
endpoint name `report_detail`. Keep the browser-view route and
PDF-download route separate if both are required. The link in
`reports.html` must point to the endpoint used by the PDF download
action.

## 7. Database and Data Source

Module 04 uses the historical monitoring scans stored in the
`monitoring_scans` SQLite table.

The table contains these relevant fields:

-   `id`
-   `network`
-   `total`
-   `event_count`
-   `scanner`
-   `monitoring_time`
-   `result_json`

The `result_json` field stores the scan result, including the
discovered-device information used when preparing the PDF.

The module reads historical data; it does not need to run a new network
discovery just to generate a report.

## 8. Running the Module

1.  Open a terminal in the CyberShield project directory.
2.  Activate the project's virtual environment.
3.  Start the Flask application:

``` powershell
python app.py
```

4.  Open the application in a browser:

``` text
http://127.0.0.1:5000/
```

5.  Select **Open Security Reports** from the dashboard.

## 9. Testing Checklist

-   [ ] The dashboard displays the Security Reports module card.
-   [ ] The Security Reports link opens `/reports`.
-   [ ] Historical scan records are displayed.
-   [ ] Each report row shows the expected scan information.
-   [ ] Selecting a report uses the correct scan ID.
-   [ ] A missing or invalid scan ID returns a not-found response.
-   [ ] The PDF download route returns a PDF file.
-   [ ] The downloaded PDF opens successfully.
-   [ ] The report contains the correct network and scan metadata.
-   [ ] The discovered-device table contains the expected device
    details.
-   [ ] The security-event summary matches the selected scan.

## 10. GitHub Commit

After testing the module, review the changed files and commit the Module
04 work:

``` powershell
git status
git add .
git commit -m "Complete Module 04 Security Reports and PDF generation"
git push origin main
```

Then verify the repository state:

``` powershell
git status
```

A clean working tree and an up-to-date branch indicate that the local
changes have been committed and pushed.

## 11. Security and Usage Notes

-   Generate reports only for networks and monitoring data you are
    authorized to access.
-   Treat generated reports as potentially sensitive because they
    contain network inventory information.
-   Store and share PDF reports appropriately.
-   A scan reporting zero security events only means that no events were
    recorded by that monitoring scan; it does not prove that the network
    is secure.
-   Keep error handling in place for missing scan records and
    PDF-generation failures.

## 12. Module Completion

Module 04 adds historical security-report listing and PDF report
generation to CyberShield. It connects the dashboard, historical scan
data, report retrieval, and PDF-generation workflow.

**Module:** 04 -- Security Reports\
**Project:** CyberShield\
**Primary output:** Downloadable PDF security assessment report
