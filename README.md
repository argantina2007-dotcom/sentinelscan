# SentinelScan

SentinelScan is a lightweight Python-based network security assessment tool designed to perform service discovery, analyze exposed services, assign risk levels, calculate a security score, and generate structured JSON reports.

## Features

- Network service discovery using Nmap
- Open port detection
- Service and version identification
- Risk classification: LOW, MEDIUM, HIGH
- Security score from 0 to 100
- Overall risk assessment
- Security recommendations
- Custom port range scanning
- Automatic JSON report generation
- Command-line interface

## Technologies

- Python 3
- Nmap
- XML Parsing
- JSON
- argparse
- Linux / Kali Linux

## Project Structure

```text
SentinelScan/
├── examples/
│   └── example_report.json
├── reports/
├── src/
│   └── sentinelscan.py
├── tests/
├── .gitignore
├── README.md
└── requirements.txt
```

## Requirements

SentinelScan requires:

- Python 3
- Nmap

### Kali Linux

Nmap is usually pre-installed on Kali Linux.

Verify:

```bash
python3 --version
nmap --version
```

If Nmap is not installed:

```bash
sudo apt update
sudo apt install nmap
```

## Usage

Basic scan:

```bash
python3 src/sentinelscan.py 127.0.0.1
```

Scan a custom port range:

```bash
python3 src/sentinelscan.py 127.0.0.1 --ports 1-9000
```

Display help:

```bash
python3 src/sentinelscan.py --help
```

## Example Output

```text
=======================================================
                   SentinelScan
          Network Security Assessment
=======================================================

[+] Target: 127.0.0.1
[+] Ports: 1-9000
[+] Starting Nmap service scan...

[+] Scan completed successfully.

Host Status: up
IP Address: 127.0.0.1

Open Ports:
-------------------------------------------------------------------------------------
8000/tcp | http | SimpleHTTPServer 0.6 | Risk: MEDIUM
  Reason: An HTTP service is exposed on an alternative web port.
  Recommendation: Verify that the service is required and restrict access if necessary.
-------------------------------------------------------------------------------------

Security Assessment
========================================
Security Score: 90/100
Overall Risk: LOW
```

## JSON Report

SentinelScan automatically stores scan results inside the `reports/` directory.

Example:

```json
{
    "target": "127.0.0.1",
    "security_score": 90,
    "overall_risk": "LOW",
    "findings": [
        {
            "port": 8000,
            "protocol": "tcp",
            "service": "http",
            "product": "SimpleHTTPServer",
            "version": "0.6",
            "risk": "MEDIUM"
        }
    ]
}
```

An example report is available at:

```text
examples/example_report.json
```

## Risk Assessment

SentinelScan evaluates services using predefined security rules.

Examples:

| Port | Service | Risk |
|---|---|---|
| 21 | FTP | HIGH |
| 23 | Telnet | HIGH |
| 445 | SMB | HIGH |
| 3306 | MySQL | HIGH |
| 22 | SSH | MEDIUM |
| 80 | HTTP | MEDIUM |
| 3389 | RDP | MEDIUM |
| 443 | HTTPS | LOW |

The security score starts at `100`.

- HIGH finding: -25
- MEDIUM finding: -10
- LOW finding: -3

Overall assessment:

- 85–100: LOW
- 60–84: MEDIUM
- 0–59: HIGH

## Skills Demonstrated

This project demonstrates practical knowledge of:

- Python programming
- Linux
- Network security
- TCP/IP and ports
- Nmap
- Service enumeration
- Security assessment
- Risk analysis
- XML parsing
- JSON reporting
- Command-line application development

## Ethical Use

SentinelScan is intended for educational purposes and authorized security testing only.

Only scan systems that you own or have explicit permission to test.

## Future Improvements

Planned improvements may include:

- HTML reports
- Additional security rules
- Improved risk scoring
- Hostname validation
- Multiple target support
- Automated tests
- CVE enrichment
- Colored terminal output

## Author

Mohammed Alsadoun

Cybersecurity Student
