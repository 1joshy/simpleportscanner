import socket
import threading
import os
import platform
import subprocess
import time
import nmap

# List to store open ports
open_ports = []

# Common service names for well-known ports
PORT_SERVICES = {
    21: "FTP",
    22: "SSH",
    23: "Telnet",
    25: "SMTP",
    53: "DNS",
    80: "HTTP (Web Server)",
    110: "POP3",
    111: "RPC",
    135: "MSRPC",
    139: "NetBIOS",
    143: "IMAP",
    443: "HTTPS",
    445: "SMB",
    631: "IPP",
    993: "IMAPS",
    995: "POP3S",
    1723: "PPTP",
    3306: "MySQL Database",
    3389: "Remote Desktop (RDP)",
    5900: "VNC",
    8080: "HTTP Proxy",
    20005: "OpenWebNet protocol",
}

# Function to scan a single port
def scan_port(target, port):
    try:
        sock = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
        sock.settimeout(1)
        result = sock.connect_ex((target, port))
        if result == 0:
            service = PORT_SERVICES.get(port, "Unknown Service")
            print(f"[+] Port {port} is open ({service})")
            open_ports.append((port, service))
        sock.close()
    except Exception as e:
        print(f"Error scanning port {port}: {e}")

# Function to create multiple threads for faster scanning
def scan_range(target, ports, common_ports=False):
    global open_ports
    open_ports = []

    if common_ports:
        print(f"\nScanning {target} on the top 100 common ports...\n")
    else:
        print(f"\nScanning {target} on {len(ports)} ports...\n")

    threads = []

    for port in ports:
        thread = threading.Thread(target=scan_port, args=(target, port))
        threads.append(thread)
        thread.start()

    for thread in threads:
        thread.join()

    # Summary of results
    print("\nScan Complete!")
    if open_ports:
        print("Open ports found:")
        for port, service in open_ports:
            print(f"  - Port {port}: {service}")
    else:
        print("No open ports found.")

# Function to ping target before scanning
def ping_target(target):
    print(f"\nPinging {target} to check if it's online...")

    try:
        if platform.system().lower() == "windows":
            response = subprocess.run(["ping", "-n", "1", target], capture_output=True, text=True)
        else:
            response = subprocess.run(["ping", "-c", "1", target], capture_output=True, text=True)

        if response.returncode == 0:
            print("✅ Target is online! Starting scan...\n")
            return True
        else:
            print("⚠️ Target did not respond to ping. It may be offline or blocking pings.")
            return False
    except Exception as e:
        print(f"Error running ping: {e}")
        return False

# Function to scan the OS of the target
def scan_os(target):
    print(f"\nScanning {target} for OS information...\n")
    nm = nmap.PortScanner()
    try:
        nm.scan(target, arguments='-O')
        if 'osclass' in nm[target]:
            for osclass in nm[target]['osclass']:
                print(f"OS Type: {osclass['type']}")
                print(f"OS Vendor: {osclass['vendor']}")
                print(f"OS Family: {osclass['osfamily']}")
                print(f"OS Generation: {osclass['osgen']}")
                print(f"OS Accuracy: {osclass['accuracy']}")
        else:
            print("No OS information found.")
    except Exception as e:
        print(f"Error scanning OS: {e}")

# Common port lists
TOP_100_PORTS = [21, 22, 23, 25, 53, 80, 110, 111, 135, 139, 143, 443, 445, 993, 995, 1723, 3306, 3389, 5900, 8080] # Expand as needed

# Main loop to run the scanner
while True:
    # Get user input with error handling
    try:
        target_ip = input("Enter target IP or hostname: ")

        # Ping the target first
        if not ping_target(target_ip):
            user_choice = input("Do you still want to proceed with the scan? (y/n): ").strip().lower()
            if user_choice != 'y':
                print("Scan aborted.")
                time.sleep(3)
                exit()

        print("\nSelect Scan Mode:")
        print("1 - Simple Scan (Top 100 common ports)")
        print("2 - Full Scan (All 65,535 ports)")
        print("3 - Custom Scan (Specify port range)")
        print("4 - Operatying System Scan (Not working, Fixing soon!)")

        choice = input("Enter choice (1/2/3/4): ")

        start_port = 1
        end_port = 65535
        common_ports = False

        if choice == "1":
            ports_to_scan = TOP_100_PORTS
            common_ports = True
        elif choice == "2":
            start_port = 1
            end_port = 65535
            ports_to_scan = range(start_port, end_port + 1)
        elif choice == "3":
            start_port = int(input("Enter starting port: "))
            end_port = int(input("Enter ending port: "))
            if start_port < 1 or end_port > 65535 or start_port > end_port:
                raise ValueError("Invalid port range. Ports must be between 1 and 65535.")
            ports_to_scan = range(start_port, end_port + 1)
        elif choice == "4":
            scan_os(target_ip)
            continue

        scan_range(target_ip, ports_to_scan, common_ports)

    except ValueError as ve:
        print(f"Input Error: {ve}")
    except Exception as e:
        print(f"An unexpected error occured: {e}")
    
    # Ask the user if they want to run the scan again
    run_again = input("Would you like to run the scan again? (y/n): ").strip().lower()
    if run_again != 'y':
        print("Exiting the scanner. Cya!")
        time.sleep(3)
        break