"""
Author: Navjot Kaur Mathoda
Assignment: #2
Description: Port Scanner — A tool that scans a target machine for open network ports
"""

import socket
import threading
import sqlite3
import os
import platform
import datetime

print("Python Version:", platform.python_version())
print("Operating System:", os.name)

# Dictionary mapping common port numbers to their known service names
common_ports = {
    21: "FTP",
    22: "SSH",
    23: "Telnet",
    25: "SMTP",
    53: "DNS",
    80: "HTTP",
    110: "POP3",
    143: "IMAP",
    443: "HTTPS",
    3306: "MySQL",
    3389: "RDP",
    8080: "HTTP-Alt"
}


class NetworkTool:
    def __init__(self, target):
        self.__target = target

    # Q3: What is the benefit of using @property and @target.setter?
    # Using @property and @target.setter lets us control how __target is accessed
    # and modified without exposing the private attribute directly. The setter adds
    # validation logic — like rejecting empty strings — before any value is stored,
    # protecting the object from being put into an invalid state. This is much safer
    # than letting external code write to self.__target directly.
    @property
    def target(self):
        return self.__target

    @target.setter
    def target(self, value):
        if value == "":
            print("Error: Target cannot be empty")
        else:
            self.__target = value

    def __del__(self):
        print("NetworkTool instance destroyed")


# Q1: How does PortScanner reuse code from NetworkTool?
# PortScanner inherits from NetworkTool, which means it automatically gets the
# target property (getter and setter) without rewriting any of that logic.
# For example, calling super().__init__(target) in PortScanner's constructor
# runs NetworkTool's __init__, which sets up self.__target so the @property
# getter and validation setter both work correctly in the child class.
class PortScanner(NetworkTool):
    def __init__(self, target):
        super().__init__(target)
        self.scan_results = []
        self.lock = threading.Lock()

    def __del__(self):
        print("PortScanner instance destroyed")
        super().__del__()

    def scan_port(self, port):
        # Q4: What would happen without try-except here?
        # Without try-except, any connection error or timeout would raise an unhandled
        # exception that crashes the thread immediately. For example, if the target is
        # unreachable, a socket.error would propagate up and terminate the thread without
        # appending any result, leaving the scan silently incomplete. The finally block
        # also ensures the socket is always closed, preventing resource leaks.
        try:
            sock = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
            sock.settimeout(1)
            result = sock.connect_ex((self.target, port))
            status = "Open" if result == 0 else "Closed"
            service_name = common_ports.get(port, "Unknown")
            with self.lock:
                self.scan_results.append((port, status, service_name))
        except socket.error as e:
            print(f"Error scanning port {port}: {e}")
        finally:
            sock.close()

    def get_open_ports(self):
        return [result for result in self.scan_results if result[1] == "Open"]

    # Q2: Why do we use threading instead of scanning one port at a time?
    # Threading allows multiple ports to be scanned simultaneously rather than
    # waiting for each connection attempt to time out before moving to the next.
    # Without threads, scanning 1024 ports with a 1-second timeout each could take
    # over 17 minutes in the worst case. With threads, all ports run in parallel,
    # reducing total scan time to roughly the length of a single timeout.
    def scan_range(self, start_port, end_port):
        threads = []
        for port in range(start_port, end_port + 1):
            t = threading.Thread(target=self.scan_port, args=(port,))
            threads.append(t)
        for t in threads:
            t.start()
        for t in threads:
            t.join()


def save_results(target, results):
    try:
        conn = sqlite3.connect("scan_history.db")
        cursor = conn.cursor()
        cursor.execute("""CREATE TABLE IF NOT EXISTS scans (
            id INTEGER PRIMARY KEY AUTOINCREMENT,
            target TEXT,
            port INTEGER,
            status TEXT,
            service TEXT,
            scan_date TEXT
        )""")
        for result in results:
            cursor.execute(
                "INSERT INTO scans (target, port, status, service, scan_date) VALUES (?, ?, ?, ?, ?)",
                (target, result[0], result[1], result[2], str(datetime.datetime.now()))
            )
        conn.commit()
        conn.close()
    except sqlite3.Error as e:
        print(f"Database error: {e}")


def load_past_scans():
    try:
        conn = sqlite3.connect("scan_history.db")
        cursor = conn.cursor()
        cursor.execute("SELECT * FROM scans")
        rows = cursor.fetchall()
        for row in rows:
            print(f"[{row[5]}] {row[1]} : Port {row[2]} ({row[4]}) - {row[3]}")
        conn.close()
    except sqlite3.Error:
        print("No past scans found.")


if __name__ == "__main__":
    try:
        target = input("Enter target IP address (default 127.0.0.1): ").strip()
        if target == "":
            target = "127.0.0.1"
    except ValueError:
        print("Invalid input. Please enter a valid integer.")
        target = "127.0.0.1"

    try:
        start_port = int(input("Enter start port (1-1024): "))
        if not (1 <= start_port <= 1024):
            print("Port must be between 1 and 1024.")
            exit()
    except ValueError:
        print("Invalid input. Please enter a valid integer.")
        exit()

    try:
        end_port = int(input("Enter end port (1-1024): "))
        if not (1 <= end_port <= 1024):
            print("Port must be between 1 and 1024.")
            exit()
        if end_port < start_port:
            print("End port must be >= start port.")
            exit()
    except ValueError:
        print("Invalid input. Please enter a valid integer.")
        exit()

    scanner = PortScanner(target)
    print(f"Scanning {target} from port {start_port} to {end_port}...")
    scanner.scan_range(start_port, end_port)

    open_ports = scanner.get_open_ports()
    print(f"\n--- Scan Results for {target} ---")
    for port, status, service in open_ports:
        print(f"Port {port}: {status} ({service})")
    print("------")
    print(f"Total open ports found: {len(open_ports)}")

    save_results(target, scanner.scan_results)

    view_history = input("\nWould you like to see past scan history? (yes/no): ").strip().lower()
    if view_history == "yes":
        load_past_scans()

# Q5: New Feature Proposal
# I would add a port risk classifier that labels each open port as "High Risk",
# "Medium Risk", or "Low Risk" based on its service type using a nested if-statement.
# For example, ports like Telnet (23) and FTP (21) would be flagged as High Risk
# because they transmit data unencrypted, while HTTPS (443) would be Low Risk.
# This would help users quickly identify security concerns without needing external tools.
# Diagram: See diagram_101586898.png in the repository root