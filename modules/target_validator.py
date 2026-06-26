# modules/target_validator.py
# Handles all the different ways a user might enter a target
# Normalizes any input into a clean hostname or IP the scanner can use
# Also handles reading lists of targets from a .txt file

import socket
import re
import os
from urllib.parse import urlparse

def normalize_target(raw_input):
    """
    Takes any input the user types and converts it into a
    clean hostname or IP address the scanner can use.

    Examples:
      "https://google.com/about" → "google.com"
      "http://192.168.1.1:8080"  → "192.168.1.1"
      "scanme.nmap.org"          → "scanme.nmap.org"
      "192.168.1.1"              → "192.168.1.1"
    """
    raw = raw_input.strip()

    # If it looks like a URL (has :// in it), parse out just the hostname
    if "://" in raw:
        parsed = urlparse(raw)
        return parsed.hostname or raw

    # If it has a port attached like "192.168.1.1:8080", strip the port
    if ":" in raw and not raw.count(":") > 1:  # not IPv6
        return raw.split(":")[0]

    # Otherwise return as-is (plain IP or hostname)
    return raw

def validate_target(raw_input):
    """
    Checks whether a target is reachable before we try to scan it.
    Returns (is_valid, clean_target, error_message)

    Example returns:
      (True,  "google.com",    None)
      (False, None,            "Could not resolve hostname: badhost.xyz")
    """
    target = normalize_target(raw_input)

    if not target:
        return False, None, "No target entered."

    try:
        # Try to resolve the hostname to an IP
        # If this fails, the target doesn't exist or isn't reachable
        ip = socket.gethostbyname(target)
        return True, target, None

    except socket.gaierror:
        return False, None, f"Could not resolve hostname: {target}"

def get_target_type(raw_input):
    """
    Identifies what kind of input the user gave.
    Returns "url", "ip", or "hostname"
    This is used in the report to label the target correctly.
    """
    raw = raw_input.strip()

    # Check if it's a URL
    if "://" in raw:
        return "url"

    # Check if it's an IP address (four numbers separated by dots)
    ip_pattern = r"^\d{1,3}\.\d{1,3}\.\d{1,3}\.\d{1,3}$"
    if re.match(ip_pattern, raw):
        return "ip"

    return "hostname"

def load_targets_from_file(filepath):
    """
    Reads a .txt file containing one target per line.
    Skips blank lines and lines starting with # (comments).
    Returns a list of clean targets.

    Example file contents:
        # My home network
        192.168.1.1
        192.168.1.100
        https://mysite.com

    Returns: ["192.168.1.1", "192.168.1.100", "mysite.com"]
    """
    if not os.path.exists(filepath):
        return [], f"File not found: {filepath}"

    targets = []

    with open(filepath, "r") as f:
        for line in f:
            line = line.strip()

            # Skip empty lines and comments
            if not line or line.startswith("#"):
                continue

            target = normalize_target(line)
            if target:
                targets.append(target)

    if not targets:
        return [], "No valid targets found in file."

    return targets, None