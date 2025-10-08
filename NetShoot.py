#!/usr/bin/env python3
"""
NetShoot - Network Troubleshooter
Author: David Rimoun
"""
import re
from datetime import datetime
import os
import platform
import os
import socket
import platform
import time
import sys
from concurrent.futures import ThreadPoolExecutor, as_completed
from datetime import datetime
import subprocess

# ---------------------------
# Configuration
# ---------------------------
DEFAULT_PORT_RANGE = (1, 1024)
MAX_WORKERS = 100
SOCKET_TIMEOUT = 0.4

# ---------------------------
# ASCII / Intro
# ---------------------------
ascii_art = r"""
 _   _      _   _____ _     _ _       _ 
| \ | | ___| |_|_   _| |__ (_) |_ ___| |
|  \| |/ _ \ __|| | | '_ \| | __/ _ \ |
| |\  |  __/ |_ | | | | | | | ||  __/ |
|_| \_|\___|\__||_| |_| |_|_|\__\___|_|
                                        
        NetShoot — Network Troubleshooter
                 made by David Rimoun
"""

def clear():
    os.system('cls' if os.name == 'nt' else 'clear')

def banner():
    clear()
    print(ascii_art)
    print(f"Started: {datetime.now().isoformat(sep=' ', timespec='seconds')}")
    print("-" * 50)
    print("Use responsibly: only scan hosts/networks you own or have permission to test.")
    print("-" * 50)
    time.sleep(0.4)

# ---------------------------
# Utilities
# ---------------------------
def input_safe(prompt):
    try:
        return input(prompt)
    except (KeyboardInterrupt, EOFError):
        print("\nExiting...")
        sys.exit(0)

# ---------------------------
# Network tools
# ---------------------------
def ping_host(host):
    print(f"\n Pinging {host} ...\n")
    try:
        if platform.system().lower().startswith('win'):
            cmd = ["ping", host, "-n", "4"]
        else:
            cmd = ["ping", "-c", "4", host]
        subprocess.run(cmd, check=False)
    except Exception as e:
        print("Ping failed:", e)

def dns_lookup(host):
    print(f"\n DNS lookup for {host}")
    try:
        ips = socket.getaddrinfo(host, None)
        uniq = sorted({ai[4][0] for ai in ips})
        for ip in uniq:
            print(f"  {host} -> {ip}")
    except socket.gaierror:
        print("  DNS lookup failed (host not found).")

def sys_info():
    print("\n System Information")
    print(f"  System:    {platform.system()}")
    print(f"  Node:      {platform.node()}")
    print(f"  Release:   {platform.release()}")
    print(f"  Version:   {platform.version()}")
    print(f"  Machine:   {platform.machine()}")
    print(f"  Processor: {platform.processor()}")

def scan_port(target_ip, port):
    s = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
    s.settimeout(SOCKET_TIMEOUT)
    try:
        result = s.connect_ex((target_ip, port))
        if result == 0:
            return port
    except Exception:
        return None
    finally:
        s.close()
    return None

def scan_ports(target, start_port=1, end_port=1024, workers=50):
    print(f"\n Scanning {target} ports {start_port}-{end_port} (this may take a while)...")
    try:
        target_ip = socket.gethostbyname(target)
    except socket.gaierror:
        print(" Cannot resolve target. Use a valid hostname or IP.")
        return

    open_ports = []
    with ThreadPoolExecutor(max_workers=workers) as ex:
        futures = {ex.submit(scan_port, target_ip, port): port for port in range(start_port, end_port + 1)}
        for fut in as_completed(futures):
            port = futures[fut]
            try:
                res = fut.result()
                if res:
                    print(f"  [+] Port {res} is OPEN")
                    open_ports.append(res)
            except Exception:
                pass

    if not open_ports:
        print("  No open TCP ports found in the scanned range.")
    else:
        print(f"\nFound {len(open_ports)} open port(s).")

# ---------------------------
# Menu
# ---------------------------
def menu():
    print("""
[1] Scan open ports
[2] Ping a host
[3] Show system info
[4] DNS lookup
[0] Exit
""")

def main():
    banner()
    while True:
        menu()
        choice = input_safe("Select option: ").strip()
        if choice == "1":
            target = input_safe("Enter target (IP or domain): ").strip()
            prange = input_safe(f"Port range [{DEFAULT_PORT_RANGE[0]}-{DEFAULT_PORT_RANGE[1]}] (eg 1-1024) or Enter: ").strip()
            workers = input_safe(f"Max workers [{MAX_WORKERS}]: ").strip()
            try:
                if prange:
                    start, end = (int(x) for x in prange.split("-", 1))
                else:
                    start, end = DEFAULT_PORT_RANGE
            except Exception:
                print("Invalid port range. Using default.")
                start, end = DEFAULT_PORT_RANGE
            try:
                workers = int(workers) if workers else MAX_WORKERS
                workers = max(1, min(workers, 500))
            except Exception:
                workers = MAX_WORKERS
            scan_ports(target, start, end, workers)
        elif choice == "2":
            host = input_safe("Enter host (domain or IP): ").strip()
            ping_host(host)
        elif choice == "3":
            sys_info()
        elif choice == "4":
            host = input_safe("Enter domain: ").strip()
            dns_lookup(host)
        elif choice == "0":
            print("\n Exiting NetShoot. Stay ethical and safe.")
            break
        else:
            print("Invalid option. Pick a number from the menu.")

        input_safe("\nPress Enter to return to menu...")
        banner()

if __name__ == "__main__":
    main()
    
    
def sanitize_filename(s: str) -> str:
    """Replace unsafe filename chars with underscores."""
    return re.sub(r'[^A-Za-z0-9._-]', '_', s)

def save_scan_txt(target: str, start: int, end: int, open_ports: list, workers: int, elapsed: float, out_dir: str = None) -> str:
    """
    Save scan results to a timestamped TXT file.
    Returns the full path to the saved file.
    """
    ts = datetime.now().strftime("%Y%m%d_%H%M%S")
    fname = f"netshoot_scan_{sanitize_filename(target)}_{start}-{end}_{ts}.txt"
    if out_dir:
        os.makedirs(out_dir, exist_ok=True)
        path = os.path.join(out_dir, fname)
    else:
        path = os.path.join(os.getcwd(), fname)

    with open(path, "w", encoding="utf-8") as f:
        f.write("NetShoot - Network Troubleshooter\n")
        f.write("Author: David Rimoun\n")
        f.write(f"Timestamp: {datetime.now().isoformat(sep=' ', timespec='seconds')}\n")
        f.write(f"Target: {target}\n")
        f.write(f"Port range: {start}-{end}\n")
        f.write(f"Workers: {workers}\n")
        f.write(f"Scan duration: {elapsed:.2f} seconds\n")
        f.write("-" * 50 + "\n")
        if open_ports:
            f.write(f"Open TCP ports ({len(open_ports)}):\n")
            for p in sorted(open_ports):
                f.write(f"  - {p}\n")
        else:
            f.write("No open TCP ports found in the scanned range.\n")
        f.write("-" * 50 + "\n")
        f.write("System info snapshot:\n")
        f.write(f"  System: {platform.system()} {platform.release()} ({platform.machine()})\n")
        f.write(f"  Node: {platform.node()}\n")

    return path