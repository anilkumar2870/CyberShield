import os
import ipaddress
import shlex
import socket
import xml.etree.ElementTree as ET

import paramiko


# ==========================================
# KALi SSH CONFIGURATION
# ==========================================

KALI_HOST = os.getenv("CYBERSHIELD_KALI_HOST", "192.168.56.101")
KALI_PORT = int(os.getenv("CYBERSHIELD_KALI_PORT", "22"))
KALI_USERNAME = os.getenv("CYBERSHIELD_KALI_USER", "kali")
KALI_PASSWORD = os.getenv("CYBERSHIELD_KALI_PASSWORD")


# ==========================================
# CREATE SSH CONNECTION
# ==========================================

def connect_to_kali():

    ssh = paramiko.SSHClient()

    # Trust only hosts whose keys are already known
    ssh.load_system_host_keys()
    ssh.set_missing_host_key_policy(paramiko.RejectPolicy())

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
# TEST KALI SSH CONNECTION
# ==========================================

def test_kali_connection():

    ssh = None

    try:

        ssh = connect_to_kali()

        stdin, stdout, stderr = ssh.exec_command(
            "nmap --version",
            timeout=15
        )

        output = stdout.read().decode("utf-8", errors="replace")
        error = stderr.read().decode("utf-8", errors="replace")

        exit_code = stdout.channel.recv_exit_status()

        if exit_code != 0:
            return {
                "success": False,
                "error": error.strip() or "Unable to execute Nmap."
            }

        return {
            "success": True,
            "host": KALI_HOST,
            "username": KALI_USERNAME,
            "message": "Successfully connected to Kali Linux.",
            "nmap_version": output.splitlines()[0]
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
# NETWORK VALIDATION
# ==========================================

def validate_network(target):

    try:

        network = ipaddress.ip_network(
            target,
            strict=False
        )

        if not network.is_private:
            return None, "Only private networks are allowed."

        if network.num_addresses > 256:
            return None, "Maximum network size is 256 addresses."

        if network.version != 4:
            return None, "Only IPv4 networks are supported."

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

        # Establish SSH connection
        ssh = connect_to_kali()

        # Build Nmap command
        command = [
            "nmap",
            "-sn",
            "-oX",
            "-",
            str(network)
        ]

        remote_command = shlex.join(command)

        # Execute Nmap on Kali
        stdin, stdout, stderr = ssh.exec_command(
            remote_command,
            timeout=120
        )

        # Retrieve output
        xml_output = stdout.read().decode(
            "utf-8",
            errors="replace"
        )

        error_output = stderr.read().decode(
            "utf-8",
            errors="replace"
        )

        exit_code = stdout.channel.recv_exit_status()

        if exit_code != 0:

            return {
                "error": error_output.strip() or "Nmap execution failed."
            }

        # Parse Nmap XML
        root = ET.fromstring(xml_output)

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
