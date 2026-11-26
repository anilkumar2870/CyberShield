# CyberShield -- Module 02: Security Monitoring

## 1. Module Overview

**Module:** 02 -- Security Monitoring\
**Project:** CyberShield -- Unified Cybersecurity Assessment Platform\
**Status:** Implemented and functionally tested in the local lab

The Security Monitoring module monitors an authorized private IPv4
network, displays currently active devices, reports security events
detected during a monitoring run, and stores monitoring results in a
local SQLite database.

## 2. Objectives

-   Provide a dedicated Security Monitoring page.
-   Accept an authorized private IPv4 CIDR range.
-   Run network monitoring through the existing Kali Linux integration.
-   Display active devices found during a monitoring run.
-   Display the number of security events detected.
-   Persist device and monitoring-scan records in SQLite.

## 3. Application Components

  -----------------------------------------------------------------------
  Component                           Responsibility
  ----------------------------------- -----------------------------------
  `app.py`                            Flask application and route
                                      registration, including
                                      `/monitoring`

  `modules/kali_connector.py`         SSH connection to Kali Linux and
                                      remote Nmap execution

  `modules/network_discovery.py`      Network discovery interface used by
                                      the application

  `data/cybershield.db`               SQLite database used for monitoring
                                      data

  `templates/`                        Flask HTML templates

  `static/style.css`                  Application styling
  -----------------------------------------------------------------------

The project also retains Module 01 -- Network Discovery. Module 02 uses
the existing Kali integration rather than replacing the first module.

## 4. Monitoring Workflow

1.  The user opens the Security Monitoring page at `/monitoring`.
2.  The user enters an authorized private network range.
3.  The Flask application processes the monitoring form submission.
4.  The application uses the Kali integration to inspect the target
    network.
5.  The page displays the active devices and security-event count
    returned by the monitoring workflow.
6.  Monitoring and device records are stored in SQLite.

**Lab target used during verification:** `192.168.56.0/24`

Only scan networks that you own or have explicit permission to assess.

## 5. Verified Test Results

The following results were observed during the local test on 26 November
2026.

  Test                                        Observed result
  ------------------------------------------- ------------------------
  Monitoring page                             Loaded successfully
  Monitoring submission                       Completed successfully
  Target network                              `192.168.56.0/24`
  Active devices displayed                    3
  Security events reported                    0
  SQLite device records after test            3
  SQLite security-event records after test    0
  SQLite monitoring-scan records after test   1

### Database verification

The following PowerShell command was used to inspect the SQLite record
counts:

``` powershell
python -c "import sqlite3; c=sqlite3.connect('data/cybershield.db'); print('Devices:', c.execute('SELECT COUNT(*) FROM devices').fetchone()[0]); print('Events:', c.execute('SELECT COUNT(*) FROM security_events').fetchone()[0]); print('Scans:', c.execute('SELECT COUNT(*) FROM monitoring_scans').fetchone()[0]); c.close()"
```

Observed output:

``` text
Devices: 3
Events: 0
Scans: 1
```

This confirms that three device records and one monitoring-scan record
were present in the database after the test. No security-event records
were present.

## 6. Current Limitations and Follow-up Testing

-   The test run reported zero security events. This is a valid observed
    result, but it does not prove that every event-detection scenario
    has been tested.
-   Event detection and event persistence should be tested with
    controlled, authorized lab scenarios before claiming comprehensive
    detection coverage.
-   The current verification confirms database record counts, not every
    field or relationship in each stored record.
-   Scan-history presentation and detailed historical scan views are
    planned for Module 03.

## 7. Module 02 Completion Summary

The Security Monitoring page loaded and completed a monitoring run
against the authorized lab network. It displayed three active devices
and zero detected security events. SQLite verification showed three
device records, zero security-event records, and one monitoring-scan
record.

**Module 02 status:** Core monitoring workflow and database persistence
were demonstrated successfully. Further event-detection testing remains
necessary.

## 8. GitHub -- Add This Report to the Repository

Save this file in the project root as:

``` text
D:\CyberShield\module_02_security_monitoring.md
```

Then open the VS Code PowerShell terminal in `D:\CyberShield` and run:

``` powershell
git status
git add module_02_security_monitoring.md
git commit -m "Add Module 02 Security Monitoring report"
git push origin main
```

To verify the commit:

``` powershell
git status
git log -1 --oneline
```

The working tree should report that it is clean after a successful
commit and push.

### Important repository hygiene

Do not commit: - `.venv/` - `.env` files or passwords - SSH private
keys - Local database files such as `data/cybershield.db`, unless you
have deliberately decided that test data belongs in the repository

Check that `.gitignore` excludes virtual environments, secrets, and
local database files before pushing. If a secret has already been
committed, removing it from the latest working tree is not sufficient;
rotate the credential and clean the Git history as appropriate.
