# config.py
import os

APP_NAME    = "VulnScan"
APP_VERSION = "1.0.0"
APP_AUTHOR  = "Usman Zaffar"

DEFAULT_TARGET = "scanme.nmap.org"

SCAN_MODES = {
    "Quick": [21, 22, 23, 25, 53, 80, 110, 139, 143, 443, 445, 3306, 3389, 8080, 8443],
    "Full":  list(range(1, 1025)),
    "Deep":  list(range(1, 65536))
}

TIMEOUT = 1

NVD_API_URL = "https://services.nvd.nist.gov/rest/json/cves/2.0"

VT_API_KEY = None

SETTINGS_PATH = os.path.join(
    os.path.expanduser("~"),
    ".vulnscan_settings.json"
)

BASE_DIR    = os.path.dirname(os.path.abspath(__file__))
REPORTS_DIR = os.path.join(BASE_DIR, "reports")
DB_PATH     = os.path.join(BASE_DIR, "vulnscan.db")

os.makedirs(REPORTS_DIR, exist_ok=True)