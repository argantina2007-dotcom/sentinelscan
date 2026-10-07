import subprocess
import sys
import xml.etree.ElementTree as ET
import json
import os
import argparse
from datetime import datetime

RISK_RULES = {
    21: {
        "level": "HIGH",
        "reason": "FTP may transmit credentials and data without encryption.",
        "recommendation": "Use SFTP or FTPS instead of plain FTP."
    },
    23: {
        "level": "HIGH",
        "reason": "Telnet transmits data in plaintext.",
        "recommendation": "Disable Telnet and use SSH."
    },
    445: {
        "level": "HIGH",
        "reason": "SMB exposure can increase the attack surface.",
        "recommendation": "Restrict SMB access to trusted networks only."
    },
    3306: {
        "level": "HIGH",
        "reason": "A database service is directly exposed.",
        "recommendation": "Restrict MySQL access with firewall rules and trusted hosts."
    },
    22: {
        "level": "MEDIUM",
        "reason": "SSH is remotely accessible.",
        "recommendation": "Use key-based authentication and disable unnecessary remote access."
    },
    3389: {
        "level": "MEDIUM",
        "reason": "Remote Desktop is exposed.",
        "recommendation": "Restrict RDP access and require strong authentication."
    },
    80: {
        "level": "MEDIUM",
        "reason": "HTTP traffic is not encrypted.",
        "recommendation": "Use HTTPS when transmitting sensitive information."
    },
    8000: {
        "level": "MEDIUM",
        "reason": "An HTTP service is exposed on an alternative web port.",
        "recommendation": "Verify that the service is required and restrict access if necessary."
    },
    443: {
        "level": "LOW",
        "reason": "HTTPS provides encrypted web communication.",
        "recommendation": "Keep TLS configuration and certificates updated."
    }
}


def get_risk(port_number, service_name):
    port_number = int(port_number)

    if port_number in RISK_RULES:
        return RISK_RULES[port_number]

    if service_name.lower() == "http":
        return {
            "level": "MEDIUM",
            "reason": "HTTP service detected without guaranteed encryption.",
            "recommendation": "Consider using HTTPS and restrict unnecessary exposure."
        }

    return {
        "level": "LOW",
        "reason": "No high-risk rule matched this service.",
        "recommendation": "Review whether the service is required and keep it updated."
    }


def run_nmap_scan(target, ports):
    print(f"\n[+] Target: {target}")
    print(f"[+] Ports: {ports}")
    print("[+] Starting Nmap service scan...\n")

    command = [
        "nmap",
        "-sV",
        "-p",
        ports,
        "-oX",
        "-",
        target
    ]

    try:
        result = subprocess.run(
            command,
            capture_output=True,
            text=True,
            check=True
        )

        print("[+] Scan completed successfully.\n")
        return result.stdout

    except FileNotFoundError:
        print("[!] Nmap is not installed or not available in PATH.")
        sys.exit(1)

    except subprocess.CalledProcessError as error:
        print("[!] Nmap scan failed.")
        print(error.stderr)
        sys.exit(1)
def save_json_report(target, score, overall_risk, findings):
    os.makedirs("reports", exist_ok=True)

    timestamp = datetime.now().strftime("%Y-%m-%d_%H-%M-%S")

    safe_target = target.replace("/", "_").replace(":", "_")

    filename = f"reports/scan_{safe_target}_{timestamp}.json"

    report = {
        "target": target,
        "scan_time": datetime.now().isoformat(timespec="seconds"),
        "security_score": score,
        "overall_risk": overall_risk,
        "findings": findings
    }

    with open(filename, "w") as file:
        json.dump(report, file, indent=4)

    print(f"\n[+] JSON report saved: {filename}")


def parse_nmap_xml(xml_data, target):
    root = ET.fromstring(xml_data)

    findings = []
    security_score = 100

    for host in root.findall("host"):
        status = host.find("status")

        if status is not None:
            print(f"Host Status: {status.get('state')}")

        address = host.find("address")

        if address is not None:
            print(f"IP Address: {address.get('addr')}")

        print("\nOpen Ports:")
        print("-" * 85)

        ports = host.find("ports")

        if ports is None:
            print("No ports found.")
            continue

        open_ports_found = False

        for port in ports.findall("port"):
            state = port.find("state")

            if state is None or state.get("state") != "open":
                continue

            open_ports_found = True

            port_number = port.get("portid")
            protocol = port.get("protocol")

            service = port.find("service")

            service_name = "unknown"
            product = ""
            version = ""

            if service is not None:
                service_name = service.get("name", "unknown")
                product = service.get("product", "")
                version = service.get("version", "")

            risk = get_risk(port_number, service_name)

            if risk["level"] == "HIGH":
                security_score -= 25

            elif risk["level"] == "MEDIUM":
                security_score -= 10

            elif risk["level"] == "LOW":
                security_score -= 3

            finding = {
                "port": int(port_number),
                "protocol": protocol,
                "service": service_name,
                "product": product,
                "version": version,
                "risk": risk["level"],
                "reason": risk["reason"],
                "recommendation": risk["recommendation"]
            }

            findings.append(finding)

            print(
                f"{port_number}/{protocol} | "
                f"{service_name} | "
                f"{product} {version} | "
                f"Risk: {risk['level']}"
            )

            print(f"  Reason: {risk['reason']}")
            print(f"  Recommendation: {risk['recommendation']}")
            print("-" * 85)

        if not open_ports_found:
            print("No open ports found.")

    security_score = max(security_score, 0)

    if security_score >= 85:
        overall_risk = "LOW"

    elif security_score >= 60:
        overall_risk = "MEDIUM"

    else:
        overall_risk = "HIGH"

    print("\nSecurity Assessment")
    print("=" * 40)
    print(f"Security Score: {security_score}/100")
    print(f"Overall Risk: {overall_risk}")

    save_json_report(
        target,
        security_score,
        overall_risk,
        findings
    )


def main():
    parser = argparse.ArgumentParser(
        description="SentinelScan - Lightweight Network Security Scanner"
    )

    parser.add_argument(
        "target",
        help="IP address or hostname to scan"
    )

    parser.add_argument(
        "--ports",
        default="1-10000",
        help="Port range to scan (default: 1-10000)"
    )

    args = parser.parse_args()

    print("=" * 55)
    print("                   SentinelScan")
    print("          Network Security Assessment")
    print("=" * 55)

    xml_output = run_nmap_scan(
        args.target,
        args.ports
    )

    parse_nmap_xml(
        xml_output,
        args.target
    )
if __name__ == "__main__":
    main()
