# CyberShield

## Module 01 -- Network Discovery

**Project:** CyberShield -- Unified Cybersecurity Assessment Platform\
**Module:** 01 -- Network Discovery\
**Status:** Completed and tested in the local lab\
**Application:** Python Flask\
**Scanning host:** Kali Linux\
**Scanner:** Nmap\
**Remote connection:** SSH using Paramiko\
**Repository:** https://github.com/anilkumar2870/CyberShield

------------------------------------------------------------------------

## 1. Overview

Network Discovery is the first module of CyberShield. It discovers
active devices on an authorized private IPv4 network and displays the
results in the CyberShield web dashboard.

The Flask application runs on the Windows development machine. It
connects to Kali Linux over SSH, runs Nmap host discovery on Kali,
receives Nmap XML output, parses the results, and returns the discovered
devices to the dashboard.

This module performs host discovery. It does not, by itself, perform a
vulnerability assessment or determine whether a discovered device is
secure.

## 2. Objectives

-   Connect the Windows-hosted CyberShield application to Kali Linux
    over SSH.
-   Validate user-supplied private IPv4 CIDR ranges.
-   Restrict discovery requests to networks containing no more than 256
    addresses.
-   Run Nmap host discovery remotely on Kali Linux.
-   Parse Nmap XML output.
-   Extract active IPv4 addresses and MAC addresses when available.
-   Display discovered devices and the discovery result in the web
    dashboard.
-   Handle common connection, validation, scanner, and XML errors.

## 3. Technology stack

  Technology                Role
  ------------------------- -----------------------------------------
  Python                    Application and discovery logic
  Flask                     Web application and request handling
  Kali Linux                Remote scanning environment
  Nmap                      Network host discovery
  Paramiko                  SSH client library
  `ipaddress`               IPv4 network validation
  `shlex`                   Safe construction of the remote command
  `xml.etree.ElementTree`   Parsing Nmap XML output
  HTML and CSS              Dashboard structure and presentation
  Git and GitHub            Version control and source hosting

## 4. Project structure

The relevant project files are organized as follows:

``` text
CyberShield/
├── .venv/                     # Local Python virtual environment (not committed)
├── data/
├── logs/
├── modules/
│   ├── kali_connector.py      # SSH connection and remote Nmap execution
│   └── network_discovery.py   # Discovery entry point and input checks
├── reports/
├── static/
│   └── style.css
├── templates/
│   └── index.html
├── .gitignore
├── app.py                     # Flask application
└── requirements.txt
```

## 5. Component responsibilities

### `app.py`

-   Creates the Flask application.
-   Handles `GET` and `POST` requests on the dashboard route.
-   Reads the submitted `network` form field.
-   Calls `discover_network()` from `modules.network_discovery`.
-   Passes the result and submitted target back to `index.html`.

### `modules/network_discovery.py`

-   Provides the discovery function used by the Flask route.
-   Rejects an empty network input.
-   Calls `discover_network_on_kali()` in the Kali connector.
-   Returns the discovery result or error to Flask.

### `modules/kali_connector.py`

-   Reads Kali connection settings from environment variables.
-   Establishes SSH using Paramiko.
-   Verifies the Kali host against locally known SSH host keys.
-   Provides a connection test using `nmap --version`.
-   Validates the requested private IPv4 network and its size.
-   Executes Nmap remotely on Kali.
-   Parses XML output and returns active device details.

### `templates/index.html` and `static/style.css`

-   Render the CyberShield dashboard.
-   Provide the network input and Start Discovery action.
-   Display discovery success or error messages.
-   Display the discovered device inventory.

## 6. Network and SSH configuration

The lab configuration used the following Kali SSH endpoint:

  Setting               Value
  --------------------- -------------------
  Kali host             `192.168.56.101`
  SSH port              `22`
  SSH username          `kali`
  Target test network   `192.168.56.0/24`

The connector reads these environment variables:

-   `CYBERSHIELD_KALI_HOST`
-   `CYBERSHIELD_KALI_PORT`
-   `CYBERSHIELD_KALI_USER`
-   `CYBERSHIELD_KALI_PASSWORD`

Example PowerShell configuration for the non-secret settings:

``` powershell
$env:CYBERSHIELD_KALI_HOST = "192.168.56.101"
$env:CYBERSHIELD_KALI_PORT = "22"
$env:CYBERSHIELD_KALI_USER = "kali"
```

Set the password interactively rather than writing it into source code:

``` powershell
$secure = Read-Host "Enter Kali password" -AsSecureString
$env:CYBERSHIELD_KALI_PASSWORD = [System.Net.NetworkCredential]::new("", $secure).Password
```

These variables are session-specific. Configure them in the same
PowerShell session that runs the Flask application. Do not commit
passwords, private keys, or other credentials to GitHub.

The connector loads system-known SSH host keys and rejects unknown host
keys. The Kali host key must therefore be trusted and present in the
applicable known-hosts file before connecting.

## 7. Network validation

The connector validates the supplied target using Python's
`ipaddress.ip_network()`.

The module's intended validation rules are:

1.  The target must be a valid IPv4 CIDR network.
2.  The network must be private.
3.  The network must contain no more than 256 addresses.
4.  Invalid or unsupported input is returned as an error instead of
    being scanned.

Example test target:

``` text
192.168.56.0/24
```

Only scan networks for which you have explicit authorization.

## 8. Nmap discovery command

The connector executes the following command remotely on Kali Linux:

``` bash
nmap -sn -oX - 192.168.56.0/24
```

  Argument            Meaning
  ------------------- ---------------------------------------------
  `nmap`              Starts Nmap
  `-sn`               Performs host discovery without a port scan
  `-oX`               Selects XML output
  `-`                 Writes XML output to standard output
  `192.168.56.0/24`   Example target network

The connector receives the XML output over SSH and parses it with
`ElementTree`. Hosts whose Nmap status is `up` are included. The result
contains the IPv4 address, MAC address when Nmap provides one, and an
`Active` status.

MAC addresses may not be available for every discovered host.

## 9. End-to-end workflow

1.  The user opens the CyberShield dashboard.
2.  The user enters an authorized private IPv4 CIDR range.
3.  Flask receives the submitted form.
4.  `network_discovery.py` checks that the input is not empty.
5.  `kali_connector.py` validates the network.
6.  Paramiko establishes an SSH connection to Kali Linux.
7.  The connector executes Nmap host discovery on Kali.
8.  Nmap writes XML results to standard output.
9.  The connector reads and parses the XML.
10. Active host details are returned to Flask.
11. The dashboard displays the result and discovered-device table.

## 10. Testing performed

### 10.1 SSH and Nmap availability test

Command used from the CyberShield project directory:

``` powershell
python -c "from modules.kali_connector import test_kali_connection; print(test_kali_connection())"
```

The successful test output reported:

-   `success: True`
-   Host: `192.168.56.101`
-   Username: `kali`
-   Message: `Successfully connected to Kali Linux.`
-   Nmap version: `7.991`

**Result: Passed in the local lab.**

### 10.2 Remote network discovery test

Command used:

``` powershell
python -c "from modules.kali_connector import discover_network_on_kali; print(discover_network_on_kali('192.168.56.0/24'))"
```

The test returned a successful result for `192.168.56.0/24`, with three
active devices and `Kali Linux` identified as the scanner.

**Result: Passed in the local lab.**

### 10.3 Discovery module integration test

Command used:

``` powershell
python -c "from modules.network_discovery import discover_network; print(discover_network('192.168.56.0/24'))"
```

This verified that the network discovery entry point returned the remote
discovery result.

**Result: Passed in the local lab.**

### 10.4 Flask dashboard test

Start the application:

``` powershell
python app.py
```

Open the local dashboard:

``` text
http://127.0.0.1:5000
```

Submit:

``` text
192.168.56.0/24
```

The dashboard displayed a successful discovery message and a table of
three active devices.

**Result: Passed in the local lab.**

## 11. Recorded discovery result

The latest dashboard screenshot supplied during development showed the
following result:

  IP address         MAC address shown     Status   Scanner
  ------------------ --------------------- -------- ------------
  `192.168.56.1`     `0A:00:27:00:00:2D`   Active   Kali Linux
  `192.168.56.100`   `08:00:27:DD:7B:71`   Active   Kali Linux
  `192.168.56.101`   Not available         Active   Kali Linux

**Total active devices displayed: 3**

These values are the results recorded in the supplied lab screenshot.
Discovery results can differ between runs as devices join or leave the
network.

## 12. Error handling

The connector and discovery flow include handling for common failure
cases, including:

-   Empty network input.
-   Invalid network range.
-   Non-private network range.
-   Network larger than the configured 256-address limit.
-   SSH authentication failure.
-   SSH host-key verification failure.
-   SSH connection errors and timeouts.
-   Nmap command failure.
-   Nmap XML parsing failure.

The dashboard displays the returned error when discovery cannot be
completed.

## 13. Security considerations and scope

-   Run discovery only against networks you own or are explicitly
    authorized to assess.
-   Keep Kali credentials out of source files and Git commits.
-   Use SSH host-key verification; do not automatically trust arbitrary
    host keys.
-   Keep the virtual environment and generated cache files out of
    version control.
-   The `-sn` Nmap operation is host discovery, not a port scan.
-   An active host result does not prove that a device is safe,
    vulnerable, or free from compromise.
-   MAC address visibility depends on the network and the information
    Nmap can obtain.

## 14. Known limitations and future improvements

The current module focuses on basic host discovery. The following
capabilities are not claimed as implemented in this module:

-   Continuous or scheduled monitoring.
-   Persistent scan-history storage.
-   Operating-system fingerprinting.
-   Port and service enumeration.
-   Vulnerability assessment.
-   Automated threat detection.
-   PDF security-report generation.

These are potential enhancements or responsibilities for later
CyberShield modules.

## 15. GitHub version control

The project was initialized as a Git repository and the initial project
source was pushed to:

<https://github.com/anilkumar2870/CyberShield>

The `.gitignore` file is configured to exclude the Python virtual
environment and other generated or sensitive files. The project root
`.gitignore` should be the authoritative ignore file.

After saving this report, add and push it with:

``` powershell
git add documentation/MODULE_01_NETWORK_DISCOVERY.md
git commit -m "Add Module 01 Network Discovery documentation"
git push
```

## 16. Conclusion

CyberShield Module 01 -- Network Discovery was implemented and tested in
the local lab.

The Windows-based Flask application successfully communicated with Kali
Linux through Paramiko SSH. Nmap performed host discovery on the
authorized private test network `192.168.56.0/24`. The connector parsed
Nmap XML output and returned active device information to the
CyberShield dashboard.

The latest recorded dashboard test displayed three active devices. This
module establishes the network-discovery foundation for the subsequent
CyberShield modules.

**Module 01 status: Completed and tested in the local lab.**
