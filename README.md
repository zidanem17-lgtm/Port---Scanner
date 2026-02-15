# Port---Scanner
# TCP Port Scanner — Network Reconnaissance & Exposure Analysis

A custom-built TCP port scanner developed in Python to identify open network ports, grab service banners, and assess system exposure. Designed to demonstrate real-world network reconnaissance techniques used by security analysts and penetration testers.

## Overview

Ports are communication endpoints for services like web servers, remote desktop, file sharing, and authentication systems. Attackers typically scan ports first to discover entry points into a target system. This tool simulates that process from both an offensive and defensive security perspective — scanning commonly targeted ports, fingerprinting services, and generating an actionable exposure assessment.

## Features

- **TCP port scanning** across 21 commonly targeted ports (SSH, HTTP, HTTPS, SMB, RDP, databases, and more)
- **Service banner grabbing** to fingerprint what’s running on open ports
- **Exposure assessment** with risk ratings and remediation guidance for each discovered service
- **Configurable timeout** for fast or thorough scans
- **Clean terminal output** with real-time results and summary report

## Quick Start

```bash
# Clone the repository
git clone https://github.com/YOUR_USERNAME/port-scanner.git
cd port-scanner

# Scan a target (use only systems you have permission to test)
python port_scanner.py 192.168.1.1

# Scan with a custom timeout (seconds)
python port_scanner.py scanme.nmap.org 0.5
```

> **⚠️ Legal Notice:** Only scan systems you own or have explicit written authorization to test. Unauthorized port scanning can violate computer fraud laws such as the CFAA (US) and the Computer Misuse Act (UK). For safe practice, [scanme.nmap.org](http://scanme.nmap.org/) is a public target that permits scanning.

## Sample Output

```
==============================================================
  PORT SCAN REPORT
  Target : scanme.nmap.org (45.33.32.156)
  Ports  : 21
  Started: 2026-02-14 10:30:00
==============================================================
  PORT       STATE      SERVICE         BANNER
--------------------------------------------------------------
  22         OPEN       SSH             SSH-2.0-OpenSSH_6.6.1p1...
  80         OPEN       HTTP            HTTP/1.1 200 OK...
--------------------------------------------------------------

  SUMMARY
  Open ports : 2 / 21 scanned
  Finished   : 2026-02-14 10:30:18

  EXPOSURE ASSESSMENT
    22/SSH: MEDIUM – Ensure key-based auth, disable root login
    80/HTTP: MEDIUM – Unencrypted, redirect to HTTPS
==============================================================
```

## Ports Scanned

|Port|Service   |Description                        |
|----|----------|-----------------------------------|
|21  |FTP       |File Transfer Protocol             |
|22  |SSH       |Secure Shell                       |
|23  |Telnet    |Unencrypted remote access          |
|25  |SMTP      |Email transmission                 |
|53  |DNS       |Domain Name System                 |
|80  |HTTP      |Web traffic                        |
|110 |POP3      |Email retrieval                    |
|135 |MS-RPC    |Microsoft Remote Procedure Call    |
|139 |NetBIOS   |Network file sharing               |
|143 |IMAP      |Email access                       |
|443 |HTTPS     |Encrypted web traffic              |
|445 |SMB       |Server Message Block (file sharing)|
|993 |IMAPS     |Encrypted IMAP                     |
|995 |POP3S     |Encrypted POP3                     |
|1433|MSSQL     |Microsoft SQL Server               |
|3306|MySQL     |MySQL Database                     |
|3389|RDP       |Remote Desktop Protocol            |
|5432|PostgreSQL|PostgreSQL Database                |
|5900|VNC       |Virtual Network Computing          |
|8080|HTTP-Proxy|HTTP Proxy / Alt HTTP              |
|8443|HTTPS-Alt |Alternative HTTPS                  |

## Skills Demonstrated

**Technical:**
TCP/IP networking fundamentals, socket programming, network reconnaissance, service enumeration, Python scripting and automation

**Security:**
Attack surface identification, exposure assessment, basic penetration testing methodology

## Real-World Application

This is a foundational skill used across multiple cybersecurity domains:

- **SOC Analysis** — identifying unauthorized services on monitored networks
- **Vulnerability Scanning** — discovering exposed services before attackers do
- **Penetration Testing** — initial reconnaissance phase of an engagement
- **Incident Response** — investigating compromised systems for unexpected open ports
- **Network Defense** — validating firewall rules and access controls

## Requirements

- Python 3.10+
- No external dependencies (uses only the standard library)

## License

MIT
