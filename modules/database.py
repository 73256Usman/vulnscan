# modules/database.py
# This module handles storing and retrieving scan history
# We use SQLite — a lightweight database that saves to a single file
# No server needed, no setup — it just works, even inside a .exe
# This is what makes the tool feel professional vs a one-and-done script

import sqlite3
import json
from datetime import datetime
from config import DB_PATH

def get_connection():
    """
    Opens a connection to the SQLite database file.
    If the file doesn't exist yet, SQLite creates it automatically.
    """
    return sqlite3.connect(DB_PATH)

def initialize_db():
    """
    Creates the database tables if they don't already exist.
    This runs every time the app starts — if tables exist, nothing happens.
    Think of this as the database version of 'mkdir if not exists'.
    """
    conn = get_connection()
    cursor = conn.cursor()

    # scans table — one row per scan, stores top level info
    cursor.execute("""
        CREATE TABLE IF NOT EXISTS scans (
            id           INTEGER PRIMARY KEY AUTOINCREMENT,
            target       TEXT NOT NULL,
            scan_mode    TEXT NOT NULL,
            scan_date    TEXT NOT NULL,
            overall_risk TEXT,
            total_cves   INTEGER,
            highest_cvss REAL,
            open_ports   TEXT,    -- stored as JSON e.g. "[22, 80, 443]"
            summary      TEXT
        )
    """)

    # findings table — one row per open port found in a scan
    # links back to scans table via scan_id (foreign key relationship)
    cursor.execute("""
        CREATE TABLE IF NOT EXISTS findings (
            id          INTEGER PRIMARY KEY AUTOINCREMENT,
            scan_id     INTEGER NOT NULL,
            port        INTEGER,
            service     TEXT,
            banner      TEXT,
            cves        TEXT,     -- stored as JSON list of CVE dicts
            FOREIGN KEY (scan_id) REFERENCES scans(id)
        )
    """)

    conn.commit()
    conn.close()

def save_scan(target, mode, scan_results, assessment):
    """
    Saves a completed scan to the database.
    
    target       = the IP or hostname that was scanned
    mode         = Quick / Full / Deep
    scan_results = the list of services from service_detector
    assessment   = the risk assessment from risk_assessor
    
    Returns the scan ID so we can reference this scan later.
    """
    conn   = get_connection()
    cursor = conn.cursor()

    # Get current date and time as a readable string
    scan_date  = datetime.now().strftime("%Y-%m-%d %H:%M:%S")
    open_ports = [item["port"] for item in scan_results]

    # Insert the top level scan record
    cursor.execute("""
        INSERT INTO scans 
        (target, scan_mode, scan_date, overall_risk, total_cves, highest_cvss, open_ports, summary)
        VALUES (?, ?, ?, ?, ?, ?, ?, ?)
    """, (
        target,
        mode,
        scan_date,
        assessment["overall_risk"],
        assessment["total_cves"],
        assessment["highest_score"],
        json.dumps(open_ports),              # convert list to JSON string for storage
        assessment["summary"]
    ))

    # Get the ID that was just assigned to this scan
    scan_id = cursor.lastrowid

    # Insert one row per open port found
    for item in scan_results:
        cursor.execute("""
            INSERT INTO findings (scan_id, port, service, banner, cves)
            VALUES (?, ?, ?, ?, ?)
        """, (
            scan_id,
            item["port"],
            item["service"],
            item["banner"],
            json.dumps(item["cves"])         # convert CVE list to JSON string
        ))

    conn.commit()
    conn.close()

    print(f"Scan saved to database with ID: {scan_id}")
    return scan_id

def get_scan_history():
    """
    Returns all previous scans as a list — newest first.
    Used to populate the scan history panel in the GUI.
    """
    conn   = get_connection()
    cursor = conn.cursor()

    cursor.execute("""
        SELECT id, target, scan_mode, scan_date, overall_risk, total_cves, highest_cvss
        FROM scans
        ORDER BY id DESC
    """)

    rows = cursor.fetchall()
    conn.close()

    # Convert each row tuple into a readable dictionary
    history = []
    for row in rows:
        history.append({
            "id":           row[0],
            "target":       row[1],
            "scan_mode":    row[2],
            "scan_date":    row[3],
            "overall_risk": row[4],
            "total_cves":   row[5],
            "highest_cvss": row[6]
        })

    return history

def get_scan_by_id(scan_id):
    """
    Retrieves a single scan and all its findings by ID.
    Used when a user clicks a past scan to view its details.
    """
    conn   = get_connection()
    cursor = conn.cursor()

    # Get the top level scan info
    cursor.execute("SELECT * FROM scans WHERE id = ?", (scan_id,))
    scan = cursor.fetchone()

    # Get all the port findings for this scan
    cursor.execute("SELECT * FROM findings WHERE scan_id = ?", (scan_id,))
    findings = cursor.fetchall()

    conn.close()

    if not scan:
        return None

    return {
        "id":           scan[0],
        "target":       scan[1],
        "scan_mode":    scan[2],
        "scan_date":    scan[3],
        "overall_risk": scan[4],
        "total_cves":   scan[5],
        "highest_cvss": scan[6],
        "open_ports":   json.loads(scan[7]),
        "summary":      scan[8],
        "findings":     findings
    }