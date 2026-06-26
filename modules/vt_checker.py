# modules/vt_checker.py
# Checks URLs, IP addresses, and files against VirusTotal
# API key is loaded from local user settings — never hardcoded

import requests
import hashlib
import os
import time
import base64
from modules.settings_manager import get_vt_api_key

VT_BASE = "https://www.virustotal.com/api/v3"

def _get_headers():
    """
    Builds request headers using the user's locally stored API key.
    Called fresh on each request so key changes take effect immediately.
    """
    key = get_vt_api_key()
    if not key:
        raise ValueError(
            "No VirusTotal API key set. "
            "Go to Settings to add your free key."
        )
    return {"x-apikey": key}


def check_url(url):
    """
    Checks a URL against VirusTotal's database.
    Uses base64 encoded URL as the VT identifier.
    """
    try:
        url_id = base64.urlsafe_b64encode(url.encode()).decode().rstrip("=")

        response = requests.get(
            f"{VT_BASE}/urls/{url_id}",
            headers=_get_headers(),
            timeout=10
        )

        if response.status_code == 404:
            submit = requests.post(
                f"{VT_BASE}/urls",
                headers=_get_headers(),
                data={"url": url},
                timeout=10
            )
            if submit.status_code != 200:
                return _error_result("Failed to submit URL to VirusTotal")

            time.sleep(3)
            response = requests.get(
                f"{VT_BASE}/urls/{url_id}",
                headers=_get_headers(),
                timeout=10
            )

        if response.status_code != 200:
            return _error_result(f"VirusTotal API error: {response.status_code}")

        return _parse_results(response.json(), "url", url)

    except ValueError as e:
        return _error_result(str(e))
    except requests.exceptions.RequestException as e:
        return _error_result(f"Connection error: {str(e)}")


def check_ip(ip):
    """
    Checks an IP address against VirusTotal.
    VT tracks whether IPs have been associated with malicious activity.
    """
    try:
        response = requests.get(
            f"{VT_BASE}/ip_addresses/{ip}",
            headers=_get_headers(),
            timeout=10
        )

        if response.status_code != 200:
            return _error_result(f"VirusTotal API error: {response.status_code}")

        return _parse_results(response.json(), "ip", ip)

    except ValueError as e:
        return _error_result(str(e))
    except requests.exceptions.RequestException as e:
        return _error_result(f"Connection error: {str(e)}")


def check_file(filepath):
    """
    Checks a file against VirusTotal.
    First computes SHA256 hash and checks if VT already knows the file.
    Only uploads if the file is unknown to VT.
    """
    try:
        if not os.path.exists(filepath):
            return _error_result(f"File not found: {filepath}")

        sha256 = _hash_file(filepath)

        response = requests.get(
            f"{VT_BASE}/files/{sha256}",
            headers=_get_headers(),
            timeout=10
        )

        if response.status_code == 200:
            return _parse_results(
                response.json(), "file", os.path.basename(filepath)
            )

        # File unknown — check size then upload
        file_size_mb = os.path.getsize(filepath) / (1024 * 1024)
        if file_size_mb > 32:
            return _error_result(
                f"File too large ({file_size_mb:.1f}MB). "
                f"Free API limit is 32MB."
            )

        with open(filepath, "rb") as f:
            upload = requests.post(
                f"{VT_BASE}/files",
                headers=_get_headers(),
                files={"file": (os.path.basename(filepath), f)},
                timeout=60
            )

        if upload.status_code != 200:
            return _error_result("Failed to upload file to VirusTotal")

        analysis_id = upload.json().get("data", {}).get("id")
        if not analysis_id:
            return _error_result("No analysis ID returned from VirusTotal")

        return _poll_analysis(analysis_id, os.path.basename(filepath))

    except ValueError as e:
        return _error_result(str(e))
    except requests.exceptions.RequestException as e:
        return _error_result(f"Connection error: {str(e)}")


def _poll_analysis(analysis_id, name, max_attempts=10):
    """
    Polls VT until file analysis is complete.
    File analysis takes 30-60 seconds on average.
    """
    for attempt in range(max_attempts):
        time.sleep(8)

        response = requests.get(
            f"{VT_BASE}/analyses/{analysis_id}",
            headers=_get_headers(),
            timeout=10
        )

        if response.status_code != 200:
            continue

        data   = response.json()
        attrs  = data.get("data", {}).get("attributes", {})
        status = attrs.get("status")

        if status == "completed":
            stats = attrs.get("stats", {})
            return _build_result(
                name        = name,
                target_type = "file",
                malicious   = stats.get("malicious",  0),
                suspicious  = stats.get("suspicious", 0),
                harmless    = stats.get("harmless",   0),
                undetected  = stats.get("undetected", 0),
                vendors     = attrs.get("results", {}),
                raw         = data
            )

    return _error_result("Analysis timed out — try again in a few minutes")


def _parse_results(data, target_type, name):
    """Extracts key numbers from a VirusTotal API response."""
    try:
        attrs = data.get("data", {}).get("attributes", {})
        stats = attrs.get("last_analysis_stats", {})

        return _build_result(
            name        = name,
            target_type = target_type,
            malicious   = stats.get("malicious",  0),
            suspicious  = stats.get("suspicious", 0),
            harmless    = stats.get("harmless",   0),
            undetected  = stats.get("undetected", 0),
            vendors     = attrs.get("last_analysis_results", {}),
            raw         = data
        )

    except Exception as e:
        return _error_result(f"Failed to parse VT response: {str(e)}")


def _build_result(name, target_type, malicious, suspicious,
                  harmless, undetected, vendors, raw):
    """Builds a standardized result dictionary from VT data."""
    total = malicious + suspicious + harmless + undetected
    pct   = round((malicious / total * 100), 1) if total > 0 else 0

    if malicious >= 5:
        reputation = "MALICIOUS"
    elif malicious >= 1 or suspicious >= 3:
        reputation = "SUSPICIOUS"
    else:
        reputation = "CLEAN"

    flagged_by = {
        vendor: result.get("result", "")
        for vendor, result in vendors.items()
        if result.get("category") in ("malicious", "suspicious")
    }

    return {
        "success":       True,
        "name":          name,
        "target_type":   target_type,
        "reputation":    reputation,
        "malicious":     malicious,
        "suspicious":    suspicious,
        "harmless":      harmless,
        "undetected":    undetected,
        "total":         total,
        "detection_pct": pct,
        "flagged_by":    flagged_by,
        "error":         None
    }


def _error_result(message):
    """Returns a standardized error result."""
    return {
        "success":       False,
        "reputation":    "UNKNOWN",
        "malicious":     0,
        "suspicious":    0,
        "harmless":      0,
        "undetected":    0,
        "total":         0,
        "detection_pct": 0,
        "flagged_by":    {},
        "error":         message
    }


def run_vt_check(target, target_type, filepath=None):
    """
    Main entry point called by the GUI.
    Routes to the correct check function based on target type.
    """
    if filepath:
        return check_file(filepath)
    elif target_type == "ip":
        return check_ip(target)
    else:
        url = target if "://" in target else f"https://{target}"
        return check_url(url)