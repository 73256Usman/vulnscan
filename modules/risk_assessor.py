# modules/risk_assessor.py
# This module takes all the scan results and produces an overall risk assessment
# It answers the question: "How dangerous is this target overall?"
# This is what separates a real security tool from just a port lister

from modules.cve_lookup import get_severity_label

# Risk level definitions — each has a label, color code, and description
# The color codes will be used by the GUI to visually highlight findings
RISK_LEVELS = {
    "CRITICAL": {
        "color":       "#FF0000",   # red
        "priority":    1,
        "description": "Immediate action required. Actively exploitable vulnerabilities present."
    },
    "HIGH": {
        "color":       "#FF6600",   # orange
        "priority":    2,
        "description": "Urgent attention needed. High severity vulnerabilities detected."
    },
    "MEDIUM": {
        "color":       "#FFAA00",   # yellow
        "priority":    3,
        "description": "Should be addressed soon. Medium severity vulnerabilities present."
    },
    "LOW": {
        "color":       "#00AA00",   # green
        "priority":    4,
        "description": "Low risk. Minor vulnerabilities or informational findings only."
    },
    "NONE": {
        "color":       "#00CC00",   # bright green
        "priority":    5,
        "description": "No vulnerabilities detected on scanned ports."
    }
}

def assess_risk(scan_results):
    """
    Takes the full scan results and computes:
    - Overall risk level for the target
    - Total CVE count
    - Highest CVSS score found
    - A prioritized list of what to fix first
    - A human readable summary

    This is what gets printed in the report and shown in the GUI.
    """

    total_cves      = 0
    highest_score   = 0.0
    all_cves        = []
    critical_count  = 0
    high_count      = 0
    medium_count    = 0
    low_count       = 0

    # Loop through every service and collect all CVE data
    for item in scan_results:
        cves = item.get("cves", [])
        total_cves += len(cves)

        for cve in cves:
            score = cve["cvss_score"]
            all_cves.append({
                "port":    item["port"],
                "service": item["service"],
                **cve         # spreads all CVE fields into this dict
            })

            # Track the highest score we've seen
            if score > highest_score:
                highest_score = score

            # Count by severity level
            severity = cve["severity"]
            if severity == "CRITICAL": critical_count += 1
            elif severity == "HIGH":   high_count     += 1
            elif severity == "MEDIUM": medium_count   += 1
            elif severity == "LOW":    low_count      += 1

    # Determine overall risk based on the worst thing we found
    overall_risk = get_severity_label(highest_score)

    # Sort all CVEs by score so the most dangerous appear first
    all_cves.sort(key=lambda x: x["cvss_score"], reverse=True)

    # Build a human readable summary paragraph
    summary = build_summary(
        scan_results,
        total_cves,
        overall_risk,
        highest_score,
        critical_count,
        high_count,
        medium_count,
        low_count
    )

    return {
        "overall_risk":   overall_risk,
        "risk_color":     RISK_LEVELS[overall_risk]["color"],
        "risk_detail":    RISK_LEVELS[overall_risk]["description"],
        "highest_score":  highest_score,
        "total_cves":     total_cves,
        "critical_count": critical_count,
        "high_count":     high_count,
        "medium_count":   medium_count,
        "low_count":      low_count,
        "all_cves":       all_cves,
        "summary":        summary
    }

def build_summary(scan_results, total_cves, overall_risk, highest_score,
                  critical_count, high_count, medium_count, low_count):
    """
    Builds a plain English summary of the scan findings.
    This goes at the top of the PDF report.
    """
    open_port_count = len(scan_results)
    services        = [item["service"] for item in scan_results]

    summary  = f"Scan identified {open_port_count} open port(s) running the following "
    summary += f"services: {', '.join(services)}.\n\n"

    if total_cves == 0:
        summary += "No known CVEs were identified for the detected services. "
        summary += "This does not guarantee the target is secure - always keep "
        summary += "software up to date and follow security best practices."
    else:
        summary += f"A total of {total_cves} CVE(s) were identified across all services. "
        summary += f"The highest CVSS score found was {highest_score} ({overall_risk}). "

        if critical_count > 0:
            summary += f"\n\n{critical_count} CRITICAL vulnerability(s) require immediate attention. "
        if high_count > 0:
            summary += f"{high_count} HIGH severity finding(s) should be addressed urgently. "
        if medium_count > 0:
            summary += f"{medium_count} MEDIUM severity finding(s) should be scheduled for remediation. "
        if low_count > 0:
            summary += f"{low_count} LOW severity finding(s) noted for awareness."

    return summary