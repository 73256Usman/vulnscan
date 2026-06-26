# modules/port_scanner.py
# This module is responsible for finding which ports are open on a target
# It uses threading to scan multiple ports simultaneously instead of one at a time

import socket
import threading
from config import SCAN_MODES, TIMEOUT

# This list will store every open port we find
# It's shared across all threads, so we need a lock to protect it
open_ports = []
lock = threading.Lock()  # prevents two threads writing to open_ports at the same time

def scan_port(target, port):
    """
    Tries to connect to a single port on the target.
    If the connection succeeds, the port is open.
    If it fails or times out, the port is closed.
    """
    try:
        # AF_INET = IPv4, SOCK_STREAM = TCP connection
        sock = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
        sock.settimeout(TIMEOUT)  # don't wait more than TIMEOUT seconds

        # connect_ex returns 0 if connection succeeded, anything else means closed
        result = sock.connect_ex((target, port))

        if result == 0:
            # Port is open — safely add it to the shared list
            with lock:
                open_ports.append(port)

        sock.close()

    except socket.error:
        # If anything goes wrong (host unreachable, etc.) just skip this port
        pass

def run_scan(target, mode="Full", progress_callback=None):
    """
    Scans all ports for the chosen mode using threads.
    
    target           = IP address or hostname to scan
    mode             = "Quick", "Full", or "Deep" 
    progress_callback = optional function to update a GUI progress bar
    """

    # Clear results from any previous scan
    global open_ports
    open_ports = []

    # Get the list of ports to scan based on the mode chosen
    ports = SCAN_MODES[mode]
    threads = []

    for port in ports:
        # Create a new thread for each port
        # Each thread runs scan_port() independently and simultaneously
        thread = threading.Thread(target=scan_port, args=(target, port))
        threads.append(thread)
        thread.start()

        # Optional: update a progress bar in the GUI as we go
        if progress_callback:
            progress_callback(port, len(ports))

    # Wait for every thread to finish before returning results
    for thread in threads:
        thread.join()

    # Sort so ports come back in order (22, 80, 443... not random)
    return sorted(open_ports)