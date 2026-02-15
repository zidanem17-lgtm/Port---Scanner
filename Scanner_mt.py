import socket
from concurrent.futures import ThreadPoolExecutor, as_completed
from datetime import datetime

# Common ports + service labels (extend anytime)
COMMON_PORTS = {
    20: "FTP-DATA", 21: "FTP", 22: "SSH", 23: "TELNET", 25: "SMTP", 53: "DNS",
    80: "HTTP", 110: "POP3", 135: "MSRPC", 139: "NETBIOS", 143: "IMAP",
    443: "HTTPS", 445: "SMB", 3389: "RDP"
}

def check_port(host: str, port: int, timeout: float = 0.6):
    """Return (port, is_open)."""
    with socket.socket(socket.AF_INET, socket.SOCK_STREAM) as s:
        s.settimeout(timeout)
        return port, (s.connect_ex((host, port)) == 0)

def parse_ports(mode: str):
    """
    mode:
      - 'common' => scan COMMON_PORTS keys
      - 'range'  => scan user-provided range like 1-1024
    """
    mode = mode.strip().lower()

    if mode == "common":
        return sorted(COMMON_PORTS.keys())

    if mode == "range":
        raw = input("Enter port range (e.g., 1-1024): ").strip()
        if "-" not in raw:
            raise ValueError("Invalid range format. Use like 1-1024.")
        start_s, end_s = raw.split("-", 1)
        start, end = int(start_s), int(end_s)
        if start < 1 or end > 65535 or start > end:
            raise ValueError("Range must be 1-65535 and start <= end.")
        return list(range(start, end + 1))

    raise ValueError("Mode must be 'common' or 'range'.")

def main():
    host = input("Target IP/Host: ").strip()
    mode = input("Scan mode ('common' or 'range'): ").strip()

    ports = parse_ports(mode)

    # Threading settings
    max_threads = 200 if len(ports) > 500 else 80
    timeout = 0.6

    print(f"\nScan started: {datetime.now().isoformat(timespec='seconds')}")
    print(f"Target: {host}")
    print(f"Ports to scan: {len(ports)}")
    print(f"Threads: {max_threads}, Timeout: {timeout}s\n")

    open_ports = []

    with ThreadPoolExecutor(max_workers=max_threads) as executor:
        futures = [executor.submit(check_port, host, p, timeout) for p in ports]
        for f in as_completed(futures):
            port, is_open = f.result()
            if is_open:
                svc = COMMON_PORTS.get(port, "")
                label = f" ({svc})" if svc else ""
                open_ports.append(port)
                print(f"[OPEN] {port}{label}")

    open_ports.sort()
    print("\n==== SUMMARY ====")
    if open_ports:
        print(f"Open ports ({len(open_ports)}): {open_ports}")
    else:
        print("No open ports found.")

if __name__ == "__main__":
    try:
        main()
    except KeyboardInterrupt:
        print("\nScan cancelled by user.")
    except Exception as e:
        print(f"\nError: {e}")
