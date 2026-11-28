"""
CyberShield - Kali Linux SSH Connector

Provides:
- Verified SSH connection to Kali Linux.
- Nmap availability testing.
- SSH authentication log retrieval.
- Private network discovery.
- Installed Debian package version retrieval.
- Debian distribution and release identification.

IMPORTANT:
Package information retrieved by this module belongs
to the Kali scanner only. It must not be treated as
the installed package information of another target.
"""

import os
import ipaddress
import shlex
import socket
import re
import xml.etree.ElementTree as ET

import paramiko


# ==========================================
# KALI SSH CONFIGURATION
# ==========================================

KALI_HOST = os.getenv(
    "CYBERSHIELD_KALI_HOST",
    "192.168.56.101"
)

KALI_PORT = int(
    os.getenv("CYBERSHIELD_KALI_PORT", "22")
)

KALI_USERNAME = os.getenv(
    "CYBERSHIELD_KALI_USER",
    "kali"
)

KALI_PASSWORD = os.getenv(
    "CYBERSHIELD_KALI_PASSWORD"
)


# ==========================================
# PACKAGE NAME VALIDATION
# ==========================================

PACKAGE_NAME_PATTERN = re.compile(
    r"^[a-z0-9][a-z0-9+.-]{0,127}$"
)


def validate_package_name(package_name):
    """Validate a Debian binary package name."""

    if not isinstance(package_name, str):
        return None

    package_name = package_name.strip().lower()

    if not PACKAGE_NAME_PATTERN.fullmatch(package_name):
        return None

    return package_name


# ==========================================
# CREATE SSH CONNECTION
# ==========================================

def connect_to_kali():

    ssh = paramiko.SSHClient()

    # Trust only hosts whose keys are already known.
    ssh.load_system_host_keys()

    ssh.set_missing_host_key_policy(
        paramiko.RejectPolicy()
    )

    ssh.connect(
        hostname=KALI_HOST,
        port=KALI_PORT,
        username=KALI_USERNAME,
        password=KALI_PASSWORD,
        timeout=10,
        banner_timeout=10,
        auth_timeout=10,
        allow_agent=True,
        look_for_keys=True
    )

    return ssh


# ==========================================
# EXECUTE REMOTE COMMAND
# ==========================================

def execute_kali_command(ssh, command, timeout=30):
    """
    Execute an argument-list command on Kali.

    shlex.join safely quotes command arguments.
    """

    remote_command = shlex.join(command)

    stdin, stdout, stderr = ssh.exec_command(
        remote_command,
        timeout=timeout
    )

    output = stdout.read().decode(
        "utf-8",
        errors="replace"
    )

    error_output = stderr.read().decode(
        "utf-8",
        errors="replace"
    )

    exit_code = stdout.channel.recv_exit_status()

    return {
        "success": exit_code == 0,
        "exit_code": exit_code,
        "output": output.strip(),
        "error": error_output.strip()
    }


# ==========================================
# TEST KALI SSH CONNECTION
# ==========================================

def test_kali_connection():

    ssh = None

    try:

        ssh = connect_to_kali()

        result = execute_kali_command(
            ssh,
            ["nmap", "--version"],
            timeout=15
        )

        if not result["success"]:

            return {
                "success": False,
                "error": (
                    result["error"]
                    or "Unable to execute Nmap."
                )
            }

        return {
            "success": True,
            "host": KALI_HOST,
            "username": KALI_USERNAME,
            "message": "Successfully connected to Kali Linux.",
            "nmap_version": result["output"].splitlines()[0]
        }

    except paramiko.AuthenticationException:

        return {
            "success": False,
            "error": "Kali SSH authentication failed."
        }

    except paramiko.BadHostKeyException:

        return {
            "success": False,
            "error": "Kali SSH host key verification failed."
        }

    except paramiko.SSHException as error:

        return {
            "success": False,
            "error": f"SSH error: {error}"
        }

    except (socket.timeout, TimeoutError):

        return {
            "success": False,
            "error": "Connection to Kali timed out."
        }

    except OSError as error:

        return {
            "success": False,
            "error": f"Network connection error: {error}"
        }

    finally:

        if ssh:
            ssh.close()


# ==========================================
# SSH AUTHENTICATION LOG RETRIEVAL
# ==========================================

def get_kali_ssh_authentication_logs():

    ssh = None

    try:

        ssh = connect_to_kali()

        command = [
            "journalctl",
            "-u", "ssh",
            "--since", "24 hours ago",
            "--no-pager",
            "-o", "short-iso",
            "--lines", "500"
        ]

        result = execute_kali_command(
            ssh,
            command,
            timeout=30
        )

        if not result["success"]:

            return {
                "success": False,
                "error": (
                    result["error"]
                    or "Unable to retrieve Kali SSH logs."
                )
            }

        logs = (
            result["output"].splitlines()
            if result["output"]
            else []
        )

        return {
            "success": True,
            "host": KALI_HOST,
            "source": "Kali Linux systemd journal",
            "period": "Last 24 hours",
            "total": len(logs),
            "logs": logs
        }

    except paramiko.AuthenticationException:

        return {
            "success": False,
            "error": "Kali SSH authentication failed."
        }

    except paramiko.SSHException as error:

        return {
            "success": False,
            "error": f"SSH connection failed: {error}"
        }

    except (socket.timeout, TimeoutError):

        return {
            "success": False,
            "error": "Kali SSH log retrieval timed out."
        }

    except OSError as error:

        return {
            "success": False,
            "error": f"Connection error: {error}"
        }

    finally:

        if ssh:
            ssh.close()


# ==========================================
# NETWORK VALIDATION
# ==========================================

def validate_network(target):

    try:

        network = ipaddress.ip_network(
            target,
            strict=False
        )

        if network.version != 4:

            return None, "Only IPv4 networks are supported."

        if not network.is_private:

            return None, "Only private networks are allowed."

        if network.num_addresses > 256:

            return None, "Maximum network size is 256 addresses."

        return network, None

    except ValueError:

        return None, "Invalid network range."


# ==========================================
# REMOTE NETWORK DISCOVERY
# ==========================================

def discover_network_on_kali(target):

    network, error = validate_network(target)

    if error:
        return {"error": error}

    ssh = None

    try:

        ssh = connect_to_kali()

        command = [
            "nmap",
            "-sn",
            "-oX",
            "-",
            str(network)
        ]

        result = execute_kali_command(
            ssh,
            command,
            timeout=120
        )

        if not result["success"]:

            return {
                "error": (
                    result["error"]
                    or "Nmap execution failed."
                )
            }

        if not result["output"]:

            return {
                "error": "Nmap returned empty XML output."
            }

        root = ET.fromstring(result["output"])

        devices = []

        for host in root.findall("host"):

            status = host.find("status")

            if status is None:
                continue

            if status.get("state") != "up":
                continue

            ip_address = ""
            mac_address = "Not available"

            for address in host.findall("address"):

                if address.get("addrtype") == "ipv4":

                    ip_address = address.get("addr")

                elif address.get("addrtype") == "mac":

                    mac_address = address.get("addr")

            if ip_address:

                devices.append({
                    "ip": ip_address,
                    "mac": mac_address,
                    "status": "Active"
                })

        return {
            "success": True,
            "network": str(network),
            "total": len(devices),
            "devices": devices,
            "scanner": "Kali Linux"
        }

    except paramiko.AuthenticationException:

        return {
            "error": "Kali SSH authentication failed."
        }

    except paramiko.SSHException as error:

        return {
            "error": f"SSH connection failed: {error}"
        }

    except (socket.timeout, TimeoutError):

        return {
            "error": "Kali network discovery timed out."
        }

    except OSError as error:

        return {
            "error": f"Connection error: {error}"
        }

    except ET.ParseError:

        return {
            "error": "Unable to parse Nmap XML output."
        }

    finally:

        if ssh:
            ssh.close()


# ==========================================
# READ KALI DISTRIBUTION INFORMATION
# ==========================================

def get_kali_release_information(ssh):
    """
    Read operating-system information from Kali.

    Returns Debian-compatible distribution information.
    """

    result = execute_kali_command(
        ssh,
        ["cat", "/etc/os-release"],
        timeout=15
    )

    if not result["success"]:

        return {
            "success": False,
            "error": (
                result["error"]
                or "Unable to read /etc/os-release."
            )
        }

    release_data = {}

    for line in result["output"].splitlines():

        if "=" not in line:
            continue

        key, value = line.split("=", 1)

        release_data[key.strip()] = (
            value.strip().strip('"').strip("'")
        )

    return {
        "success": True,
        "distribution_id": release_data.get("ID"),
        "distribution_name": release_data.get("PRETTY_NAME"),
        "version_id": release_data.get("VERSION_ID"),
        "codename": (
            release_data.get("VERSION_CODENAME")
            or release_data.get("DEBIAN_CODENAME")
        )
    }


# ==========================================
# GET INSTALLED DEBIAN PACKAGE INFORMATION
# ==========================================

def get_kali_package_details(
    binary_package="openssh-server",
    expected_source_package=None
):
    """
    Retrieve the actual installed Debian package
    version from the Kali scanner.

    Example:
        get_kali_package_details(
            binary_package="openssh-server",
            expected_source_package="openssh"
        )

    IMPORTANT:
    This retrieves package information from KALI_HOST.
    It does not retrieve information from arbitrary
    network targets.
    """

    binary_package = validate_package_name(
        binary_package
    )

    if not binary_package:

        return {
            "success": False,
            "error": "Invalid binary package name."
        }

    if expected_source_package is not None:

        expected_source_package = validate_package_name(
            expected_source_package
        )

        if not expected_source_package:

            return {
                "success": False,
                "error": "Invalid expected source package name."
            }

    ssh = None

    try:

        ssh = connect_to_kali()

        # ----------------------------------
        # READ INSTALLED PACKAGE DETAILS
        # ----------------------------------

        package_format = (
            "${binary:Package}\\t"
            "${Version}\\t"
            "${source:Package}"
        )

        package_result = execute_kali_command(
            ssh,
            [
                "dpkg-query",
                "-W",
                "-f=" + package_format,
                binary_package
            ],
            timeout=20
        )

        if not package_result["success"]:

            return {
                "success": False,
                "error": (
                    package_result["error"]
                    or (
                        f"Package {binary_package} "
                        "is not installed or could not be queried."
                    )
                )
            }

        fields = package_result["output"].split("\t")

        if len(fields) < 3:

            return {
                "success": False,
                "error": (
                    "Unexpected dpkg-query response. "
                    "Unable to identify the package version "
                    "and source package."
                )
            }

        installed_binary = fields[0].strip()
        installed_version = fields[1].strip()
        source_package = fields[2].strip()

        if not installed_version:

            return {
                "success": False,
                "error": "Installed package version is empty."
            }

        if not source_package:
            source_package = binary_package

        # ----------------------------------
        # CHECK EXPECTED SOURCE PACKAGE
        # ----------------------------------

        if (
            expected_source_package
            and source_package.casefold()
            != expected_source_package.casefold()
        ):

            return {
                "success": False,
                "error": (
                    "Installed binary package belongs to "
                    f"source package '{source_package}', "
                    f"not expected source package "
                    f"'{expected_source_package}'."
                )
            }

        # ----------------------------------
        # READ DISTRIBUTION INFORMATION
        # ----------------------------------

        release_result = get_kali_release_information(
            ssh
        )

        if not release_result.get("success"):

            return {
                "success": False,
                "error": release_result.get(
                    "error",
                    "Unable to identify Kali release."
                )
            }

        return {
            "success": True,

            "host": KALI_HOST,

            "host_role": "Kali scanner",

            "binary_package": installed_binary,

            "source_package": source_package,

            "installed_version": installed_version,

            "distribution_id": release_result.get(
                "distribution_id"
            ),

            "distribution_name": release_result.get(
                "distribution_name"
            ),

            "distribution_version": release_result.get(
                "version_id"
            ),

            "release_codename": release_result.get(
                "codename"
            ),

            "source": "Kali Linux dpkg-query",

            "message": (
                "Installed package information retrieved "
                "from the Kali scanner."
            ),

            "target_verification": (
                "This information applies only to the Kali "
                "scanner host, not to other discovered hosts."
            )
        }

    except paramiko.AuthenticationException:

        return {
            "success": False,
            "error": "Kali SSH authentication failed."
        }

    except paramiko.BadHostKeyException:

        return {
            "success": False,
            "error": "Kali SSH host key verification failed."
        }

    except paramiko.SSHException as error:

        return {
            "success": False,
            "error": f"Kali SSH connection failed: {error}"
        }

    except (socket.timeout, TimeoutError):

        return {
            "success": False,
            "error": "Kali package query timed out."
        }

    except OSError as error:

        return {
            "success": False,
            "error": f"Package query connection error: {error}"
        }

    finally:

        if ssh:
            ssh.close()
