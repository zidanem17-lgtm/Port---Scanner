# “””
TCP Port Scanner — Network Reconnaissance & Exposure Analysis

A custom-built TCP port scanner for identifying open ports,
grabbing service banners, and assessing network exposure.

Usage:
python port_scanner.py <target> [timeout]

Examples:
python port_scanner.py 192.168.1.1
python port_scanner.py scanme.nmap.org 0.5

IMPORTANT: Only scan systems you own or have explicit written
authorization to test. Unauthorized port scanning can violate
computer fraud laws (CFAA, Computer Misuse Act, etc.).
“””

import socket
import sys
from datetime import datetime

# Common ports and their associated services

COMMON_PORTS = {
21: “FTP”,
22: “SSH”,
23: “Telnet”,
25: “SMTP”,
53: “DNS”,
80: “HTTP”,
110: “POP3”,
135: “MS-RPC”,
139: “NetBIOS”,
143: “IMAP”,
443: “HTTPS”,
445: “SMB”,
993: “IMAPS”,
995: “POP3S”,
1433: “MSSQL”,
3306: “MySQL”,
3389: “RDP”,
5432: “PostgreSQL”,
5900: “VNC”,
8080: “HTTP-Proxy”,
8443: “HTTPS-Alt”,
}

# Risk assessments and remediation guidance for common services

RISK_NOTES = {
“Telnet”: “CRITICAL – Unencrypted remote access, replace with SSH”,
“FTP”: “HIGH – Unencrypted file transfer, consider SFTP”,
“SMB”: “HIGH – Common ransomware vector, restrict access”,
“RDP”: “HIGH – Frequent brute-force target, use VPN/MFA”,
“SSH”: “MEDIUM – Ensure key-based auth, disable root login”,
“HTTP”: “MEDIUM – Unencrypted, redirect to HTTPS”,
“MySQL”: “HIGH – Database exposed, restrict to localhost”,
“MSSQL”: “HIGH – Database exposed, restrict to localhost”,
“PostgreSQL”: “HIGH – Database exposed, restrict to localhost”,
“VNC”: “HIGH – Often weak auth, tunnel through SSH”,
“NetBIOS”: “HIGH – Legacy protocol, disable if not needed”,
“MS-RPC”: “MEDIUM – Restrict to internal network only”,
}

def scan_port(target: str, port: int, timeout: float = 1.0) -> bool:
“”“Attempt a TCP connection to a single port.

```
Args:
    target: IP address or hostname of the target.
    port: Port number to scan.
    timeout: Connection timeout in seconds.

Returns:
    True if the port is open (accepting connections), False otherwise.
"""
try:
    with socket.socket(socket.AF_INET, socket.SOCK_STREAM) as sock:
        sock.settimeout(timeout)
        result = sock.connect_ex((target, port))
        return result == 0
except socket.error:
    return False
```

def grab_banner(target: str, port: int, timeout: float = 2.0) -> str:
“”“Attempt to grab a service banner from an open port.

```
Sends a basic HTTP HEAD request and reads the response.
Works well for HTTP services; other services may return
their own banners or nothing at all.

Args:
    target: IP address or hostname of the target.
    port: Open port number to probe.
    timeout: Connection timeout in seconds.

Returns:
    The first 120 characters of the banner, or empty string.
"""
try:
    with socket.socket(socket.AF_INET, socket.SOCK_STREAM) as sock:
        sock.settimeout(timeout)
        sock.connect((target, port))
        sock.sendall(b"HEAD / HTTP/1.1\r\nHost: target\r\n\r\n")
        banner = sock.recv(1024).decode(errors="ignore").strip()
        return banner[:120] if banner else ""
except Exception:
    return ""
```

def resolve_target(target: str) -> str:
“”“Resolve a hostname to an IP address.

```
Args:
    target: Hostname or IP address string.

Returns:
    Resolved IP address as a string.
"""
try:
    return socket.gethostbyname(target)
except socket.gaierror:
    print(f"[!] Cannot resolve hostname: {target}")
    sys.exit(1)
```

def run_scan(
target: str,
ports: dict[int, str] | None = None,
timeout: float = 1.0,
) -> list[tuple[int, str]]:
“”“Run the port scan and display results with exposure assessment.

```
Args:
    target: IP address or hostname of the target.
    ports: Dictionary mapping port numbers to service names.
           Defaults to COMMON_PORTS if not provided.
    timeout: Connection timeout per port in seconds.

Returns:
    List of (port, service) tuples for open ports.
"""
if ports is None:
    ports = COMMON_PORTS

ip = resolve_target(target)

print("=" * 62)
print("  PORT SCAN REPORT")
print(f"  Target : {target} ({ip})")
print(f"  Ports  : {len(ports)}")
print(f"  Started: {datetime.now().strftime('%Y-%m-%d %H:%M:%S')}")
print("=" * 62)
print(f"  {'PORT':<10} {'STATE':<10} {'SERVICE':<15} {'BANNER'}")
print("-" * 62)

open_ports = []

for port, service in sorted(ports.items()):
    is_open = scan_port(ip, port, timeout)
    if is_open:
        open_ports.append((port, service))
        banner = grab_banner(ip, port)
        banner_display = banner[:40] + "..." if len(banner) > 40 else banner
        print(f"  {port:<10} {'OPEN':<10} {service:<15} {banner_display}")

print("-" * 62)

# --- Summary ---
print(f"\n  SUMMARY")
print(f"  Open ports : {len(open_ports)} / {len(ports)} scanned")
print(f"  Finished   : {datetime.now().strftime('%Y-%m-%d %H:%M:%S')}")

# --- Exposure Assessment ---
if open_ports:
    print(f"\n  EXPOSURE ASSESSMENT")
    for port, service in open_ports:
        note = RISK_NOTES.get(service, "Review service necessity")
        print(f"    {port}/{service}: {note}")
else:
    print("\n  No open ports detected. Target may be filtered or offline.")

print("=" * 62)

return open_ports
```

if **name** == “**main**”:
if len(sys.argv) < 2:
print(“Usage: python port_scanner.py <target> [timeout]”)
print()
print(“Examples:”)
print(”  python port_scanner.py 192.168.1.1”)
print(”  python port_scanner.py scanme.nmap.org 0.5”)
sys.exit(1)

```
target_host = sys.argv[1]
scan_timeout = float(sys.argv[2]) if len(sys.argv) > 2 else 1.0

run_scan(target_host, timeout=scan_timeout)
```
