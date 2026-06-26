# modules/cve_lookup.py
# This module takes the service and banner info from service_detector
# and queries the NVD (National Vulnerability Database) to find known CVEs
# NVD is maintained by the US government and is the industry standard for CVE data

import requests
import time
from config import NVD_API_URL

def extract_version(banner):
    """
    Tries to pull a clean version number out of a banner string.
    
    Example inputs:
      "SSH-2.0-OpenSSH_8.9p1 Ubuntu-3"  →  "OpenSSH 8.9"
      "Apache/2.4.49 (Unix)"             →  "Apache 2.4.49"
      None                               →  None
    """
    if not banner:
        return None

    # Clean up the banner — remove extra info after common delimiters
    for delimiter in [" Ubuntu", " Debian", " (", "\r\n"]:
        banner = banner.split(delimiter)[0]

    # Replace slashes and underscores with spaces for cleaner API queries
    # "OpenSSH_8.9" becomes "OpenSSH 8.9"
    # "Apache/2.4.49" becomes "Apache 2.4.49"
    banner = banner.replace("/", " ").replace("_", " ")
    banner = banner.replace("SSH-2.0-", "")  # strip SSH protocol prefix

    return banner.strip()

def get_cvss_score(cve_item):
    """
    Pulls the CVSS severity score out of a CVE record.
    CVSS = Common Vulnerability Scoring System (0.0 to 10.0)
    Tries CVSS v3.1 first, then v3.0, then v2 as fallback.
    Returns 0.0 if no score is found.
    """
    try:
        metrics = cve_item["cve"]["metrics"]

        # Try newest scoring version first
        if "cvssMetricV31" in metrics:
            return metrics["cvssMetricV31"][0]["cvssData"]["baseScore"]
        elif "cvssMetricV30" in metrics:
            return metrics["cvssMetricV30"][0]["cvssData"]["baseScore"]
        elif "cvssMetricV2" in metrics:
            return metrics["cvssMetricV2"][0]["cvssData"]["baseScore"]
    except:
        pass

    return 0.0

def lookup_cves(service, banner):
    """
    Searches the NVD database for CVEs matching the service and version.
    Returns a list of CVE dictionaries sorted by severity (worst first).

    Example return value:
    [
        {
            "id":          "CVE-2023-38408",
            "description": "A vulnerability in OpenSSH allows...",
            "cvss_score":  9.8,
            "severity":    "CRITICAL"
        }
    ]
    """
    # Build a search query from what we know about the service
    version = extract_version(banner)
    query   = f"{service} {version}" if version else service

    try:
        # Hit the NVD API with our search query
        response = requests.get(
            NVD_API_URL,
            params={
                "keywordSearch":  query,
                "resultsPerPage": 5      # top 5 most relevant CVEs
            },
            timeout=10
        )

        # If the API returned an error, bail out
        if response.status_code != 200:
            return []

        data = response.json()
        vulnerabilities = data.get("vulnerabilities", [])
        cves = []

        for item in vulnerabilities:
            cve_id    = item["cve"]["id"]
            cvss      = get_cvss_score(item)
            severity  = get_severity_label(cvss)

            # Get the English description of the vulnerability
            descriptions = item["cve"].get("descriptions", [])
            description  = next(
                (d["value"] for d in descriptions if d["lang"] == "en"),
                "No description available"
            )

            cves.append({
                "id":          cve_id,
                "description": description,
                "cvss_score":  cvss,
                "severity":    severity
            })

        # Sort by CVSS score — highest (most dangerous) first
        cves.sort(key=lambda x: x["cvss_score"], reverse=True)

        # NVD rate limits requests — pause briefly between calls
        # to avoid getting blocked
        time.sleep(0.6)

        return cves

    except requests.exceptions.RequestException:
        return []

def get_severity_label(score):
    """
    Converts a CVSS number into a human readable severity label.
    These ranges are the official CVSS v3 standard used by the industry.
    """
    if score >= 9.0: return "CRITICAL"
    if score >= 7.0: return "HIGH"
    if score >= 4.0: return "MEDIUM"
    if score > 0.0:  return "LOW"
    return "NONE"

def scan_for_cves(service_results):
    """
    Runs CVE lookup on every service found during scanning.
    Takes the output from detect_services() and adds CVE data to each entry.

    Returns the same list but with a 'cves' key added to each item.
    """
    print("\nLooking up CVEs...")

    for item in service_results:
        service = item["service"]
        banner  = item["banner"]
        port    = item["port"]

        print(f"  Checking {service} on port {port}...")
        cves = lookup_cves(service, banner)
        item["cves"] = cves

        if cves:
            print(f"    Found {len(cves)} CVE(s) — worst: {cves[0]['id']} ({cves[0]['severity']} {cves[0]['cvss_score']})")
        else:
            print(f"    No CVEs found")

    return service_results