# modules/service_detector.py
# This module figures out WHAT is running on each open port
# It does this two ways:
# 1. Banner grabbing — connecting and reading what the service says about itself
# 2. Common port lookup — matching port numbers to known services

import socket
from config import TIMEOUT

# A dictionary of the most common ports and what service runs on them
# This is our fallback if banner grabbing doesn't return anything useful
COMMON_PORTS = {
    21:   "FTP",
    22:   "SSH",
    23:   "Telnet",
    25:   "SMTP",
    53:   "DNS",
    80:   "HTTP",
    110:  "POP3",
    139:  "NetBIOS",
    143:  "IMAP",
    443:  "HTTPS",
    445:  "SMB",
    3306: "MySQL",
    3389: "RDP",
    5900: "VNC",
    8080: "HTTP-Alt",
    8443: "HTTPS-Alt"
}

def grab_banner(target, port):
    """
    Connects to an open port and reads the first thing the service sends back.
    Many services (SSH, FTP, SMTP) immediately announce themselves with a 
    banner like "SSH-2.0-OpenSSH_8.9" — this is how we get version info.
    """
    try:
        sock = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
        sock.settimeout(TIMEOUT)
        sock.connect((target, port))

        # Some services (like HTTP) need us to send something first
        # before they respond, so we send a generic request
        sock.send(b"HEAD / HTTP/1.0\r\n\r\n")

        # Read the response — up to 1024 bytes is enough for a banner
        banner = sock.recv(1024).decode("utf-8", errors="ignore").strip()
        sock.close()

        return banner if banner else None

    except:
        return None

def get_service_name(port):
    """
    Looks up a port number in our COMMON_PORTS dictionary.
    Falls back to Python's built-in service name lookup.
    Returns 'Unknown' if nothing is found.
    """
    if port in COMMON_PORTS:
        return COMMON_PORTS[port]
    
    try:
        # Python has a built-in function that knows many port/service mappings
        return socket.getservbyport(port)
    except:
        return "Unknown"

def detect_services(target, open_ports):
    """
    Runs service detection on every open port found by the scanner.
    Returns a list of dictionaries, one per port, with all the info we have.
    
    Example result:
    [
        {"port": 22,  "service": "SSH",  "banner": "SSH-2.0-OpenSSH_8.9"},
        {"port": 80,  "service": "HTTP", "banner": "Apache/2.4.49"},
        {"port": 443, "service": "HTTPS","banner": None}
    ]
    """
    results = []

    for port in open_ports:
        service = get_service_name(port)
        banner  = grab_banner(target, port)

        results.append({
            "port":    port,
            "service": service,
            "banner":  banner
        })

        # Print live feedback so we can see progress while it runs
        print(f"  Port {port}: {service} — {banner or 'No banner'}")

    return results