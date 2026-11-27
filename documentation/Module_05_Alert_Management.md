# Module 05 -- Alert Management and SSH Security Intelligence

## 1. Module Overview

Module 05 adds centralized security alert management and SSH
authentication-log intelligence to **CyberShield -- Unified
Cybersecurity Assessment & Network Intelligence Platform**.

The module brings security events into one dashboard where an operator
can review alerts, understand their severity, track their status, record
investigation notes, and remove selected alerts. It also retrieves SSH
authentication logs from the Kali Linux system and analyzes them for
suspicious login activity.

## 2. Objectives

The main objectives of Module 05 are to:

-   Display security events in a centralized alert dashboard.
-   Classify alerts by severity.
-   Track alert lifecycle status.
-   Allow analysts to acknowledge and resolve alerts.
-   Record investigation notes for individual alerts.
-   Filter alerts by status and severity.
-   Select and delete one or more alerts, with a confirmation prompt.
-   Analyze SSH authentication activity collected from Kali Linux.
-   Detect suspicious SSH login activity, including repeated failed
    login attempts.
-   Avoid inserting duplicate SSH security alerts.

## 3. Technologies Used

  -----------------------------------------------------------------------
  Technology                          Purpose
  ----------------------------------- -----------------------------------
  Python                              Application logic and security
                                      analysis

  Flask                               Web routes and request handling

  Jinja2                              Rendering the alert dashboard

  SQLite                              Persistent storage of alerts and
                                      investigation information

  Kali Linux                          Source system for SSH
                                      authentication logs

  SSH / Paramiko integration          Secure connection to the Kali Linux
                                      system

  HTML and CSS                        Alert dashboard interface

  JavaScript                          Alert selection, bulk-delete
                                      confirmation, and SSH analysis
                                      interaction
  -----------------------------------------------------------------------

## 4. Main Features

### 4.1 Security Alert Dashboard

The alert dashboard displays stored security events. Each alert can
show:

-   Alert ID and event type
-   Severity
-   Current status
-   Event message
-   IP address
-   MAC address
-   Detection timestamp
-   Acknowledgement timestamp, when available
-   Resolution timestamp, when available
-   IP intelligence information, when available

The dashboard also displays summary counts for:

-   Total alerts
-   New alerts
-   Acknowledged alerts
-   Resolved alerts
-   Critical-severity alerts
-   High-severity alerts

The summary values represent the alert totals, while the filter controls
determine which alert cards are displayed.

### 4.2 Severity Classification

Alerts use four severity levels:

  -----------------------------------------------------------------------
  Severity                            Meaning
  ----------------------------------- -----------------------------------
  Critical                            Highest-priority alert requiring
                                      urgent investigation

  High                                Serious security event requiring
                                      prompt attention

  Medium                              Security event that should be
                                      reviewed

  Low                                 Lower-priority event that can be
                                      reviewed as part of routine
                                      monitoring
  -----------------------------------------------------------------------

The dashboard uses separate visual labels for each severity.

### 4.3 Alert Status Management

Each alert has a status that represents its handling progress.

  -----------------------------------------------------------------------
  Status                              Description
  ----------------------------------- -----------------------------------
  New                                 The alert has not yet been
                                      acknowledged

  Acknowledged                        An analyst has reviewed and
                                      accepted responsibility for the
                                      alert

  Resolved                            The alert has been handled and
                                      marked as resolved
  -----------------------------------------------------------------------

Available actions include:

-   **Acknowledge Alert** -- changes an eligible alert to
    `Acknowledged`.
-   **Resolve Alert** -- changes an eligible alert to `Resolved`.

The dashboard displays acknowledgement and resolution timestamps when
those values are stored.

### 4.4 Alert Filtering

The dashboard provides two independent filters:

**Status filter** - All Statuses - New - Acknowledged - Resolved

**Severity filter** - All Severities - Critical - High - Medium - Low

The filters are submitted to the Flask alert-dashboard route using GET
parameters. Both filters can be used together. The Clear Filters link
returns to the unfiltered dashboard.

### 4.5 Select and Delete Alerts

The dashboard supports bulk alert deletion:

1.  Select individual alert checkboxes, or use **Select All Alerts**.
2.  The dashboard displays the number of selected alerts.
3.  The Delete Selected Alerts button becomes enabled when at least one
    alert is selected.
4.  Selecting the delete button displays a confirmation prompt.
5.  If confirmed, the selected alert IDs are submitted to the Flask
    deletion route.

Deletion is permanent for the selected rows. Review the selected alerts
carefully before confirming.

The selection checkboxes are associated with a separate bulk-delete
form. This avoids nesting the bulk-delete form inside the individual
status and investigation-notes forms.

### 4.6 Investigation Notes

Each alert has an Investigation Notes section.

An analyst can:

-   Enter investigation findings.
-   Record actions taken.
-   Save notes for that specific alert.
-   Revisit the saved notes from the alert dashboard.

Investigation notes are stored with the corresponding alert record.

### 4.7 IP Intelligence

When IP intelligence information is available, the alert card displays:

-   IP category
-   Whether the IP is public
-   Geolocation information
-   Reputation information
-   An additional intelligence note, when available

If information has not been collected, the dashboard displays an
appropriate unavailable or not-checked message.

### 4.8 SSH Security Intelligence

The SSH Security Intelligence section provides an action to analyze SSH
authentication activity from Kali Linux.

The analysis workflow is:

1.  Retrieve SSH authentication logs from Kali Linux.
2.  Read the configured approved SSH source IP addresses.
3.  Analyze authentication activity.
4.  Analyze persistent SSH threats using a failed-attempt threshold and
    time window.
5.  Combine the resulting security events.
6.  Store eligible security events in the database.
7.  Return an analysis summary to the dashboard.

The dashboard can display the following analysis results:

-   Number of logs retrieved
-   Successful logins
-   Failed logins
-   Invalid username attempts
-   Security events detected
-   New alerts inserted
-   Duplicate alerts skipped
-   A result message

If new alerts are inserted, the dashboard refreshes so the new alerts
can be displayed.

### 4.9 Duplicate SSH Alert Prevention

The SSH threat-tracking logic checks for an existing matching event
before inserting a new one. This helps prevent repeated analysis of the
same recent SSH activity from creating duplicate alerts.

The database insertion logic also reports how many duplicate events were
skipped.

## 5. Project Files

The Module 05 implementation uses the following project files:

  ------------------------------------------------------------------------
  File                                 Responsibility
  ------------------------------------ -----------------------------------
  `app.py`                             Flask routes for the alert
                                       dashboard, status updates, notes,
                                       deletion, and SSH analysis

  `templates/alerts.html`              Alert dashboard interface, filters,
                                       alert cards, selection controls,
                                       and browser-side interactions

  `modules/monitoring_database.py`     SQLite connection and persistent
                                       alert operations

  `modules/ssh_security_analysis.py`   SSH authentication-log analysis

  `modules/ssh_threat_tracking.py`     Persistent SSH threat analysis and
                                       repeated-attempt detection

  `modules/kali_connector.py`          Existing Kali Linux connection
                                       functionality used to retrieve SSH
                                       logs

  `data/cybershield.db`                SQLite database containing security
                                       events and related alert
                                       information
  ------------------------------------------------------------------------

The exact project structure may include additional files used by earlier
CyberShield modules.

## 6. Main Flask Routes

The Module 05 dashboard uses these routes:

  -----------------------------------------------------------------------------
  Route                         Method                  Purpose
  ----------------------------- ----------------------- -----------------------
  `/alerts`                     GET                     Displays the alert
                                                        dashboard and applies
                                                        status/severity filters

  `/alerts/<alert_id>/status`   POST                    Updates an alert's
                                                        status

  `/alerts/<alert_id>/notes`    POST                    Saves investigation
                                                        notes for an alert

  `/alerts/delete`              POST                    Deletes the selected
                                                        alert records

  `/ssh-security/analyze`       POST                    Retrieves and analyzes
                                                        SSH authentication
                                                        activity
  -----------------------------------------------------------------------------

The dashboard also links back to the main application dashboard.

## 7. Database Information

Security alerts are stored in the SQLite `security_events` table.

The alert-management fields include:

  Field                     Purpose
  ------------------------- -----------------------------------
  `id`                      Unique alert identifier
  `type`                    Security event type
  `severity`                Alert severity
  `ip`                      Related IP address
  `mac`                     Related MAC address
  `message`                 Description of the security event
  `timestamp`               Event detection time
  `status`                  New, Acknowledged, or Resolved
  `acknowledged_at`         Time the alert was acknowledged
  `resolved_at`             Time the alert was resolved
  `investigation_notes`     Analyst investigation notes
  `source_ip_category`      IP classification
  `source_ip_is_public`     Public/private IP indicator
  `source_ip_geolocation`   Geolocation information
  `source_ip_reputation`    Reputation information
  `source_ip_note`          Additional IP intelligence note

The database initialization logic supports adding missing
alert-management and IP-intelligence columns to an existing
`security_events` table.

## 8. How to Use Module 05

### Step 1 -- Open the Alert Dashboard

Start the CyberShield Flask application and open:

`http://127.0.0.1:5000/alerts`

### Step 2 -- Review Alert Summary

Review the summary cards to understand the current alert counts.

### Step 3 -- Filter Alerts

Choose a status, severity, or both, then select **Apply Filters**.

Use **Clear Filters** to return to the complete alert list.

### Step 4 -- Investigate an Alert

Review the event message, IP address, detection time, severity, and
available IP intelligence.

### Step 5 -- Update Alert Status

Use **Acknowledge Alert** after taking responsibility for an alert. Use
**Resolve Alert** when the alert has been handled.

### Step 6 -- Save Investigation Notes

Enter findings or actions taken in the Investigation Notes area and
select **Save Investigation Notes**.

### Step 7 -- Delete Selected Alerts, if Required

Select the alerts to remove and choose **Delete Selected Alerts**.
Confirm the prompt only after reviewing the selection.

### Step 8 -- Analyze SSH Security

Select **Analyze SSH Security** in the SSH Security Intelligence
section. The application connects to Kali Linux, retrieves available SSH
authentication logs, analyzes them, and reports the results.

## 9. Configuration

The SSH analysis workflow reads approved SSH source IP addresses from
the environment variable:

`CYBERSHIELD_APPROVED_SSH_IPS`

The value is a comma-separated list of IP addresses. If no approved IPs
are configured, the analysis is called without an approved-IP list.

The Kali Linux connection settings must also be configured according to
the existing CyberShield Kali connector setup.

Do not place passwords or private SSH keys directly in source code or
commit them to a public repository.

## 10. Testing Checklist

Use this checklist to verify Module 05:

-   [ ] The `/alerts` page opens successfully.
-   [ ] Alert summary cards display counts.
-   [ ] Existing security alerts appear in the dashboard.
-   [ ] Status filtering works.
-   [ ] Severity filtering works.
-   [ ] Both filters work together.
-   [ ] Clear Filters restores the complete alert list.
-   [ ] Alert cards show severity and status.
-   [ ] Acknowledging an alert updates its status.
-   [ ] Resolving an alert updates its status.
-   [ ] Acknowledgement and resolution timestamps display when present.
-   [ ] Investigation notes can be saved and viewed again.
-   [ ] Individual alert selection works.
-   [ ] Select All Alerts works.
-   [ ] The selected-alert count updates correctly.
-   [ ] The delete button remains disabled when no alerts are selected.
-   [ ] The deletion confirmation appears.
-   [ ] Only selected alerts are deleted after confirmation.
-   [ ] SSH analysis returns a result or a clear error message.
-   [ ] SSH analysis reports inserted and duplicate-skipped alert
    counts.
-   [ ] Repeated SSH analysis does not unnecessarily create duplicate
    recent alerts.

## 11. Security and Operational Notes

-   Only analyze systems and SSH logs that you are authorized to access.
-   Protect Kali Linux SSH credentials and connection configuration.
-   Review alerts before permanently deleting them.
-   Deleting an alert removes its corresponding alert record; it should
    not be treated as a substitute for investigating the underlying
    security event.
-   Keep investigation notes factual and avoid storing passwords,
    private keys, or other secrets in notes.
-   Back up the SQLite database before performing maintenance or bulk
    deletion.
-   Confirm that the Flask deletion route validates submitted alert IDs
    and uses parameterized SQL statements.

## 12. Module Outcome

Module 05 provides CyberShield with an alert-management workflow and SSH
security intelligence capability.

It enables an operator to review and prioritize security events, manage
their status, record investigation findings, filter and remove selected
alerts, and analyze SSH authentication activity from Kali Linux while
reducing duplicate SSH alert insertion.

**Module 05 -- Alert Management and SSH Security Intelligence:
Completed.**
