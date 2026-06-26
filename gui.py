# gui.py — Dashboard layout

import tkinter as tk
from tkinter import ttk, scrolledtext, messagebox, filedialog
import threading
import os
import sys
import subprocess
from datetime import datetime

from modules.port_scanner      import run_scan
from modules.service_detector  import detect_services
from modules.cve_lookup        import scan_for_cves
from modules.risk_assessor     import assess_risk, RISK_LEVELS
from modules.database          import initialize_db, save_scan, get_scan_history
from modules.reporter          import generate_report
from modules.target_validator  import validate_target, get_target_type, load_targets_from_file
from config                    import APP_NAME, APP_VERSION, APP_AUTHOR, DEFAULT_TARGET

C = {
    "bg":       "#0a0a0f",
    "panel":    "#111118",
    "card":     "#15151e",
    "border":   "#1e1e2a",
    "blue":     "#1a6ef5",
    "blue2":    "#4a8fff",
    "text":     "#e8e8f0",
    "sub":      "#5a5a70",
    "CRITICAL": "#ff3b3b",
    "HIGH":     "#ff6a00",
    "MEDIUM":   "#f5a623",
    "LOW":      "#34c759",
    "NONE":     "#34c759",
    "success":  "#34c759",
    "warning":  "#f5a623",
    "error":    "#ff3b3b",
}

RISK_ORDER = ["NONE", "LOW", "MEDIUM", "HIGH", "CRITICAL"]


class VulnScanGUI:
    def __init__(self, root):
        self.root = root
        self.root.title(f"{APP_NAME} v{APP_VERSION} — by {APP_AUTHOR}")
        self.root.geometry("1120x780")
        self.root.configure(bg=C["bg"])
        self.root.resizable(True, True)
        self.root.minsize(900, 640)

        self.current_results    = None
        self.current_assessment = None
        self.current_target     = None
        self.current_mode       = None
        self._pending_file      = None

        self.m_ports = None
        self.m_cves  = None
        self.m_cvss  = None
        self.m_risk  = None
        self.m_vt    = None

        self._setup_styles()
        self._build_header()
        self._build_stats_row()
        self._build_body()
        self._build_bottom_bar()

        self.root.after(400, self._show_disclaimer)
        self._refresh_history()

    # ── TTK STYLES ────────────────────────────────────────────────────────────

    def _setup_styles(self):
        style = ttk.Style()
        style.theme_use("default")
        style.configure("CVE.Treeview",
            background      = C["card"],
            foreground      = C["text"],
            fieldbackground = C["card"],
            borderwidth     = 0,
            rowheight       = 26,
            font            = ("Helvetica", 9)
        )
        style.configure("CVE.Treeview.Heading",
            background  = C["panel"],
            foreground  = C["sub"],
            borderwidth = 0,
            font        = ("Helvetica", 9, "bold"),
            relief      = "flat"
        )
        style.map("CVE.Treeview",
            background = [("selected", C["blue"])],
            foreground = [("selected", "#ffffff")]
        )
        style.configure("Blue.Horizontal.TProgressbar",
            troughcolor = C["panel"],
            background  = C["blue"],
            borderwidth = 0
        )

    # ── DISCLAIMER ────────────────────────────────────────────────────────────

    def _show_disclaimer(self):
        d = tk.Toplevel(self.root)
        d.title("Legal Notice")
        d.geometry("460x260")
        d.configure(bg=C["bg"])
        d.resizable(False, False)
        d.grab_set()
        d.update_idletasks()
        x = (d.winfo_screenwidth()  // 2) - 230
        y = (d.winfo_screenheight() // 2) - 130
        d.geometry(f"+{x}+{y}")

        tk.Label(d, text="Legal Notice",
                 font=("Helvetica", 14, "bold"),
                 bg=C["bg"], fg=C["blue"]).pack(pady=(22, 8))

        tk.Label(d,
                 text=(
                     "This tool is for authorized security testing only.\n"
                     "Only scan systems you own or have written permission to test.\n"
                     "Unauthorized scanning may violate applicable laws.\n\n"
                     "Demo target: scanme.nmap.org is pre-loaded."
                 ),
                 font=("Helvetica", 10),
                 bg=C["bg"], fg=C["text"],
                 justify="center").pack(pady=4)

        row = tk.Frame(d, bg=C["bg"])
        row.pack(pady=16)

        tk.Button(row, text="I Understand",
                  command=d.destroy,
                  bg=C["blue"], fg="#ffffff",
                  font=("Helvetica", 10, "bold"),
                  relief="flat", padx=20, pady=7,
                  cursor="hand2").pack(side="left", padx=8)

        tk.Button(row, text="Exit",
                  command=self.root.destroy,
                  bg=C["card"], fg=C["sub"],
                  font=("Helvetica", 10),
                  relief="flat", padx=20, pady=7,
                  cursor="hand2").pack(side="left", padx=8)

    # ── SETTINGS ──────────────────────────────────────────────────────────────

    def _open_settings(self):
        from modules.settings_manager import (
            get_vt_api_key, save_vt_api_key, clear_vt_api_key
        )

        win = tk.Toplevel(self.root)
        win.title("Settings")
        win.geometry("500x260")
        win.configure(bg=C["bg"])
        win.resizable(False, False)
        win.grab_set()
        win.update_idletasks()
        x = (win.winfo_screenwidth()  // 2) - 250
        y = (win.winfo_screenheight() // 2) - 130
        win.geometry(f"+{x}+{y}")

        tk.Label(win, text="Settings",
                 font=("Helvetica", 14, "bold"),
                 bg=C["bg"], fg=C["blue"]).pack(anchor="w", padx=24, pady=(20, 4))

        tk.Label(win, text="VirusTotal API Key",
                 font=("Helvetica", 10, "bold"),
                 bg=C["bg"], fg=C["text"]).pack(anchor="w", padx=24, pady=(10, 2))

        tk.Label(win,
                 text="Get your free key at virustotal.com > Profile > API Key",
                 font=("Helvetica", 9),
                 bg=C["bg"], fg=C["sub"]).pack(anchor="w", padx=24)

        key_var   = tk.StringVar(value=get_vt_api_key() or "")
        key_entry = tk.Entry(win, textvariable=key_var,
                             font=("Courier", 10),
                             bg=C["card"], fg=C["text"],
                             insertbackground=C["text"],
                             relief="flat", bd=8, show="*",
                             justify="left")
        key_entry.pack(fill="x", padx=24, pady=(6, 2))

        show_var = tk.BooleanVar(value=False)
        def toggle():
            key_entry.configure(show="" if show_var.get() else "*")
        tk.Checkbutton(win, text="Show key",
                       variable=show_var, command=toggle,
                       bg=C["bg"], fg=C["sub"],
                       selectcolor=C["card"],
                       activebackground=C["bg"],
                       font=("Helvetica", 9)).pack(anchor="w", padx=24)

        status_var = tk.StringVar()
        tk.Label(win, textvariable=status_var,
                 font=("Helvetica", 9),
                 bg=C["bg"], fg=C["success"]).pack(pady=(4, 0))

        def save():
            k = key_var.get().strip()
            if not k:
                status_var.set("Please enter an API key.")
                return
            if len(k) < 32:
                status_var.set("That doesn't look like a valid key.")
                return
            save_vt_api_key(k)
            status_var.set("Key saved.")

        def clear():
            clear_vt_api_key()
            key_var.set("")
            status_var.set("Key cleared.")

        row = tk.Frame(win, bg=C["bg"])
        row.pack(pady=10)
        for txt, cmd, bg in [
            ("Save",  save,        C["blue"]),
            ("Clear", clear,       C["card"]),
            ("Close", win.destroy, C["card"]),
        ]:
            tk.Button(row, text=txt, command=cmd,
                      bg=bg, fg=C["text"],
                      font=("Helvetica", 10),
                      relief="flat", padx=14, pady=6,
                      cursor="hand2").pack(side="left", padx=5)

    # ── HEADER ────────────────────────────────────────────────────────────────

    def _build_header(self):
        h = tk.Frame(self.root, bg=C["panel"], height=58)
        h.pack(fill="x")
        h.pack_propagate(False)

        tk.Frame(h, bg=C["blue"], width=4).pack(side="left", fill="y")

        tk.Label(h, text=APP_NAME,
                 font=("Helvetica", 16, "bold"),
                 bg=C["panel"], fg=C["blue"]).pack(side="left", padx=(14, 6))

        tk.Label(h, text=f"v{APP_VERSION}",
                 font=("Helvetica", 9),
                 bg=C["panel"], fg=C["sub"]).pack(side="left", padx=(0, 16))

        tk.Frame(h, bg=C["border"], width=1).pack(
            side="left", fill="y", pady=12)

        self.target_var   = tk.StringVar(value=DEFAULT_TARGET)
        self.target_entry = tk.Entry(h,
                                     textvariable=self.target_var,
                                     font=("Helvetica", 11),
                                     bg=C["bg"], fg=C["text"],
                                     insertbackground=C["text"],
                                     relief="flat", bd=10,
                                     justify="left")
        self.target_entry.pack(side="left", fill="both",
                               expand=True, padx=12, pady=10)
        self.target_entry.bind(
            "<FocusIn>", lambda e: self.target_entry.icursor("end")
        )

        tk.Frame(h, bg=C["border"], width=1).pack(
            side="left", fill="y", pady=12)

        mode_wrap = tk.Frame(h, bg=C["panel"])
        mode_wrap.pack(side="left", padx=10)
        self.mode_var = tk.StringVar(value="Quick")
        for m in ["Quick", "Full", "Deep"]:
            tk.Radiobutton(mode_wrap, text=m,
                           variable=self.mode_var, value=m,
                           bg=C["panel"], fg=C["text"],
                           selectcolor=C["bg"],
                           activebackground=C["panel"],
                           activeforeground=C["text"],
                           font=("Helvetica", 9)).pack(side="left", padx=5)

        tk.Frame(h, bg=C["border"], width=1).pack(
            side="left", fill="y", pady=12)

        btns = tk.Frame(h, bg=C["panel"])
        btns.pack(side="left", padx=12)

        self.scan_btn = tk.Button(btns,
                                  text="Scan",
                                  command=self._start_scan,
                                  bg=C["blue"], fg="#ffffff",
                                  font=("Helvetica", 11, "bold"),
                                  relief="flat", padx=22, pady=4,
                                  cursor="hand2")
        self.scan_btn.pack(side="left", padx=(0, 6))

        tk.Button(btns, text="Load File",
                  command=self._load_target_file,
                  bg=C["card"], fg=C["sub"],
                  font=("Helvetica", 9),
                  relief="flat", padx=10, pady=4,
                  cursor="hand2").pack(side="left", padx=(0, 6))

        tk.Button(btns, text="Settings",
                  command=self._open_settings,
                  bg=C["card"], fg=C["sub"],
                  font=("Helvetica", 9),
                  relief="flat", padx=10, pady=4,
                  cursor="hand2").pack(side="left")

    # ── STATS ROW ─────────────────────────────────────────────────────────────

    def _build_stats_row(self):
        outer = tk.Frame(self.root, bg=C["bg"])
        outer.pack(fill="x", padx=16, pady=(12, 0))

        for i in range(5):
            outer.columnconfigure(i, weight=1, uniform="stat")

        labels = [
            ("Open Ports",    "m_ports"),
            ("CVEs Found",    "m_cves"),
            ("Highest CVSS",  "m_cvss"),
            ("Overall Risk",  "m_risk"),
            ("VT Reputation", "m_vt"),
        ]

        for i, (label, attr) in enumerate(labels):
            card = tk.Frame(outer, bg=C["card"],
                            highlightbackground=C["border"],
                            highlightthickness=1)
            card.grid(row=0, column=i, sticky="nsew",
                      padx=(0, 8) if i < 4 else 0)

            tk.Frame(card, bg=C["blue"], height=2).pack(fill="x")

            tk.Label(card, text=label,
                     font=("Helvetica", 8, "bold"),
                     bg=C["card"], fg=C["sub"]).pack(
                         anchor="w", padx=12, pady=(8, 2))

            val = tk.Label(card, text="—",
                           font=("Helvetica", 17, "bold"),
                           bg=C["card"], fg=C["sub"],
                           anchor="w")
            val.pack(fill="x", padx=12, pady=(0, 10))
            setattr(self, attr, val)

    def _update_stats(self, assessment, vt_rep=None):
        cve_risk = assessment["overall_risk"]

        vt_risk_map = {
            "MALICIOUS":  "CRITICAL",
            "SUSPICIOUS": "HIGH",
            "CLEAN":      "NONE",
        }
        vt_as_risk = vt_risk_map.get(vt_rep, None) if vt_rep else None

        if vt_as_risk and \
           RISK_ORDER.index(vt_as_risk) > RISK_ORDER.index(cve_risk):
            display_risk = vt_as_risk
            risk_label   = f"{display_risk}*"
        else:
            display_risk = cve_risk
            risk_label   = display_risk

        risk_color = C.get(display_risk, C["text"])
        total_cves = assessment["total_cves"]

        self.m_ports.configure(
            text=str(len(self.current_results or [])),
            fg=C["blue2"]
        )
        self.m_cves.configure(
            text=str(total_cves),
            fg=C["CRITICAL"] if total_cves > 0 else C["success"]
        )
        self.m_cvss.configure(
            text=str(assessment["highest_score"]),
            fg=risk_color
        )
        self.m_risk.configure(text=risk_label, fg=risk_color)
        if vt_rep:
            self.m_vt.configure(
                text=vt_rep,
                fg=C["error"]   if vt_rep == "MALICIOUS"  else
                   C["warning"] if vt_rep == "SUSPICIOUS"  else
                   C["success"]
            )
        else:
            self.m_vt.configure(text="N/A", fg=C["sub"])

    def _reset_stats(self):
        for attr in ("m_ports", "m_cves", "m_cvss", "m_risk", "m_vt"):
            getattr(self, attr).configure(text="—", fg=C["sub"])

    # ── BODY ──────────────────────────────────────────────────────────────────

    def _build_body(self):
        body = tk.Frame(self.root, bg=C["bg"])
        body.pack(fill="both", expand=True, padx=16, pady=12)

        left = tk.Frame(body, bg=C["bg"])
        left.pack(side="left", fill="both", expand=True, padx=(0, 12))

        self._build_output_area(left)
        self._build_findings_table(left)

        right = tk.Frame(body, bg=C["card"],
                         highlightbackground=C["border"],
                         highlightthickness=1,
                         width=255)
        right.pack(side="right", fill="y")
        right.pack_propagate(False)
        self._build_history_panel(right)

    # ── OUTPUT AREA ───────────────────────────────────────────────────────────

    def _build_output_area(self, parent):
        panel = tk.Frame(parent, bg=C["card"],
                         highlightbackground=C["border"],
                         highlightthickness=1)
        panel.pack(fill="both", expand=True, pady=(0, 8))

        tk.Frame(panel, bg=C["blue"], height=2).pack(fill="x")

        top = tk.Frame(panel, bg=C["card"])
        top.pack(fill="x", padx=12, pady=(8, 4))

        tk.Label(top, text="SCAN OUTPUT",
                 font=("Helvetica", 9, "bold"),
                 bg=C["card"], fg=C["sub"]).pack(side="left")

        self.progress = ttk.Progressbar(
            top, style="Blue.Horizontal.TProgressbar",
            mode="indeterminate", length=120
        )
        self.progress.pack(side="right")

        self.output = scrolledtext.ScrolledText(
            panel,
            font=("Courier", 9),
            bg=C["bg"], fg=C["text"],
            insertbackground=C["text"],
            relief="flat", padx=12, pady=8,
            state="disabled", height=11
        )
        self.output.pack(fill="both", expand=True, padx=4, pady=(0, 4))

        for tag, color in [
            ("header",   C["blue"]),
            ("success",  C["success"]),
            ("warning",  C["warning"]),
            ("error",    C["error"]),
            ("sub",      C["sub"]),
            ("CRITICAL", C["CRITICAL"]),
            ("HIGH",     C["HIGH"]),
            ("MEDIUM",   C["MEDIUM"]),
            ("LOW",      C["LOW"]),
            ("NONE",     C["NONE"]),
        ]:
            self.output.tag_config(tag, foreground=color)

    # ── FINDINGS TABLE ────────────────────────────────────────────────────────

    def _build_findings_table(self, parent):
        panel = tk.Frame(parent, bg=C["card"],
                         highlightbackground=C["border"],
                         highlightthickness=1)
        panel.pack(fill="both", expand=True)

        tk.Frame(panel, bg=C["blue"], height=2).pack(fill="x")

        top = tk.Frame(panel, bg=C["card"])
        top.pack(fill="x", padx=12, pady=(8, 4))
        tk.Label(top, text="FINDINGS",
                 font=("Helvetica", 9, "bold"),
                 bg=C["card"], fg=C["sub"]).pack(side="left")

        # Treeview
        tree_frame = tk.Frame(panel, bg=C["card"])
        tree_frame.pack(fill="both", expand=True, padx=4, pady=(0, 0))

        cols = ("type", "detail", "port", "service", "info")
        self.cve_tree = ttk.Treeview(tree_frame,
                                     columns=cols,
                                     show="headings",
                                     style="CVE.Treeview",
                                     height=8)

        self.cve_tree.heading("type",    text="TYPE")
        self.cve_tree.heading("detail",  text="DETAIL")
        self.cve_tree.heading("port",    text="PORT")
        self.cve_tree.heading("service", text="SERVICE")
        self.cve_tree.heading("info",    text="INFO")

        self.cve_tree.column("type",    width=80,  minwidth=60,  anchor="center")
        self.cve_tree.column("detail",  width=160, minwidth=120, anchor="w")
        self.cve_tree.column("port",    width=55,  minwidth=50,  anchor="center")
        self.cve_tree.column("service", width=85,  minwidth=70,  anchor="w")
        self.cve_tree.column("info",    width=460, minwidth=200, anchor="w")

        self.cve_tree.tag_configure("CRITICAL", foreground=C["CRITICAL"])
        self.cve_tree.tag_configure("HIGH",     foreground=C["HIGH"])
        self.cve_tree.tag_configure("MEDIUM",   foreground=C["MEDIUM"])
        self.cve_tree.tag_configure("LOW",      foreground=C["LOW"])
        self.cve_tree.tag_configure("NONE",     foreground=C["success"])
        self.cve_tree.tag_configure("PORT",     foreground=C["blue2"])
        self.cve_tree.tag_configure("VT",       foreground=C["warning"])

        sb = ttk.Scrollbar(tree_frame, orient="vertical",
                           command=self.cve_tree.yview)
        self.cve_tree.configure(yscrollcommand=sb.set)
        self.cve_tree.pack(side="left", fill="both", expand=True)
        sb.pack(side="right", fill="y")

        # Detail panel — shows full text of selected row
        detail_bar = tk.Frame(panel, bg=C["panel"],
                              highlightbackground=C["border"],
                              highlightthickness=1,
                              height=46)
        detail_bar.pack(fill="x", padx=4, pady=(2, 4))
        detail_bar.pack_propagate(False)

        tk.Label(detail_bar, text="DETAIL:",
                 font=("Helvetica", 8, "bold"),
                 bg=C["panel"], fg=C["sub"]).pack(
                     side="left", padx=(10, 6), pady=6)

        self.detail_var = tk.StringVar(
            value="Click any row to see the full description"
        )
        tk.Label(detail_bar,
                 textvariable=self.detail_var,
                 font=("Helvetica", 9),
                 bg=C["panel"], fg=C["text"],
                 wraplength=820,
                 justify="left",
                 anchor="w").pack(side="left", fill="x",
                                  expand=True, padx=(0, 10))

        # Bind row click to detail panel
        self.cve_tree.bind("<<TreeviewSelect>>", self._on_row_select)

    def _on_row_select(self, event):
        """Shows full INFO text of the clicked row in the detail panel."""
        selected = self.cve_tree.selection()
        if not selected:
            return
        values = self.cve_tree.item(selected[0]).get("values", [])
        if len(values) >= 5:
            row_type = values[0]
            detail   = values[1]
            info     = values[4]
            self.detail_var.set(f"[{row_type}]  {detail}  —  {info}")

    def _populate_findings_table(self, scan_results, vt_rep=None):
        for row in self.cve_tree.get_children():
            self.cve_tree.delete(row)

        self.detail_var.set("Click any row to see the full description")

        # VT result row
        if vt_rep:
            vt_tag = "CRITICAL" if vt_rep == "MALICIOUS"  else \
                     "HIGH"     if vt_rep == "SUSPICIOUS"  else "NONE"
            self.cve_tree.insert("", "end",
                values=(
                    "VT CHECK",
                    "VirusTotal Reputation",
                    "—",
                    "Reputation",
                    f"Target flagged as {vt_rep} across security vendors"
                ),
                tags=(vt_tag,)
            )

        if not scan_results:
            self.cve_tree.insert("", "end",
                values=(
                    "PORT",
                    "No open ports",
                    "—", "—",
                    "No open ports were found on this target"
                ),
                tags=("NONE",)
            )
            return

        for item in scan_results:
            port    = item["port"]
            service = item["service"]
            banner  = (item["banner"] or "No banner captured")
            banner  = banner.split("\n")[0].strip()
            cves    = item.get("cves", [])

            # Port row
            self.cve_tree.insert("", "end",
                values=(
                    "PORT",
                    f"Port {port} Open",
                    str(port),
                    service,
                    f"Banner: {banner}"
                ),
                tags=("PORT",)
            )

            if not cves:
                self.cve_tree.insert("", "end",
                    values=(
                        "CLEAN",
                        "No CVEs found",
                        str(port),
                        service,
                        "No known vulnerabilities detected for this service"
                    ),
                    tags=("NONE",)
                )
            else:
                for cve in cves:
                    # Store full description — detail panel shows it on click
                    desc = cve["description"].replace("\n", " ").strip()
                    # Truncate for the table column only
                    short = desc[:85] + "..." if len(desc) > 85 else desc
                    self.cve_tree.insert("", "end",
                        values=(
                            cve["severity"],
                            cve["id"],
                            str(port),
                            service,
                            short
                        ),
                        # Store full desc as hidden tag data via iid trick
                        tags=(cve["severity"],)
                    )
                    # Store full description for detail panel
                    iid = self.cve_tree.get_children()[-1]
                    self.cve_tree.set(iid, "info", desc)

    # ── HISTORY SIDEBAR ───────────────────────────────────────────────────────

    def _build_history_panel(self, parent):
        tk.Frame(parent, bg=C["blue"], height=2).pack(fill="x")

        tk.Label(parent, text="SCAN HISTORY",
                 font=("Helvetica", 9, "bold"),
                 bg=C["card"], fg=C["sub"]).pack(
                     anchor="w", padx=14, pady=(10, 6))

        self.history_frame = tk.Frame(parent, bg=C["card"])
        self.history_frame.pack(fill="both", expand=True, padx=6)

        tk.Button(parent, text="Refresh",
                  command=self._refresh_history,
                  bg=C["bg"], fg=C["sub"],
                  font=("Helvetica", 9),
                  relief="flat", padx=8, pady=4,
                  cursor="hand2").pack(pady=8)

    def _refresh_history(self):
        for w in self.history_frame.winfo_children():
            w.destroy()

        history = get_scan_history()
        if not history:
            tk.Label(self.history_frame, text="No scans yet",
                     font=("Helvetica", 9),
                     bg=C["card"], fg=C["sub"]).pack(pady=20)
            return

        for scan in history[:15]:
            self._history_card(scan)

    def _history_card(self, scan):
        risk  = scan["overall_risk"]
        color = C.get(risk, C["sub"])

        card = tk.Frame(self.history_frame,
                        bg=C["bg"],
                        highlightbackground=C["border"],
                        highlightthickness=1)
        card.pack(fill="x", pady=2, padx=2)

        tk.Frame(card, bg=color, width=3).pack(side="left", fill="y")

        info = tk.Frame(card, bg=C["bg"])
        info.pack(side="left", fill="x", expand=True, padx=8, pady=5)

        tk.Label(info, text=scan["target"],
                 font=("Helvetica", 9, "bold"),
                 bg=C["bg"], fg=C["text"]).pack(anchor="w")

        tk.Label(info,
                 text=f"{scan['scan_date']}  |  {scan['scan_mode']}",
                 font=("Helvetica", 7),
                 bg=C["bg"], fg=C["sub"]).pack(anchor="w")

        tk.Label(info,
                 text=f"{risk}  |  {scan['total_cves']} CVE(s)",
                 font=("Helvetica", 8, "bold"),
                 bg=C["bg"], fg=color).pack(anchor="w")

    # ── BOTTOM BAR ────────────────────────────────────────────────────────────

    def _build_bottom_bar(self):
        bar = tk.Frame(self.root, bg=C["panel"], height=42)
        bar.pack(fill="x", side="bottom")
        bar.pack_propagate(False)

        tk.Frame(bar, bg=C["blue"], width=4).pack(side="left", fill="y")

        self.export_btn = tk.Button(bar,
                                    text="Export PDF",
                                    command=self._export_pdf,
                                    bg=C["blue"], fg="#ffffff",
                                    font=("Helvetica", 10, "bold"),
                                    relief="flat", padx=16, pady=6,
                                    cursor="hand2", state="disabled")
        self.export_btn.pack(side="left", padx=(12, 6), pady=6)

        tk.Button(bar, text="Clear",
                  command=self._clear_output,
                  bg=C["card"], fg=C["sub"],
                  font=("Helvetica", 10),
                  relief="flat", padx=14, pady=6,
                  cursor="hand2").pack(side="left", pady=6)

        self.status_var = tk.StringVar(value="Ready")
        tk.Label(bar, textvariable=self.status_var,
                 font=("Helvetica", 9),
                 bg=C["panel"], fg=C["sub"]).pack(side="right", padx=16)

    # ── OUTPUT HELPERS ────────────────────────────────────────────────────────

    def _log(self, text, tag=None):
        self.output.configure(state="normal")
        self.output.insert("end", text + "\n", tag or "")
        self.output.configure(state="disabled")
        self.output.see("end")

    def _log_safe(self, text, tag=None):
        self.root.after(0, self._log, text, tag)

    def _set_status(self, text):
        self.root.after(0, lambda: self.status_var.set(text))

    def _clear_output(self):
        self.output.configure(state="normal")
        self.output.delete("1.0", "end")
        self.output.configure(state="disabled")
        for row in self.cve_tree.get_children():
            self.cve_tree.delete(row)
        self._reset_stats()
        self.detail_var.set("Click any row to see the full description")

    # ── SCANNING ──────────────────────────────────────────────────────────────

    def _start_scan(self):
        raw = self.target_var.get().strip()
        if not raw:
            messagebox.showwarning("No Target", "Please enter a target.")
            return

        valid, target, error = validate_target(raw)
        if not valid:
            messagebox.showerror("Invalid Target", error)
            return

        self.scan_btn.configure(state="disabled", text="Scanning...")
        self.export_btn.configure(state="disabled")
        self.progress.start(10)
        self._clear_output()
        self.current_target = target
        self.current_mode   = self.mode_var.get()

        threading.Thread(
            target=self._run_scan_thread,
            args=(target, self.mode_var.get()),
            daemon=True
        ).start()

    def _run_scan_thread(self, target, mode, filepath=None):
        vt_rep = None
        try:
            from modules.vt_checker import run_vt_check
            target_type = get_target_type(target)
            now = datetime.now().strftime("%Y-%m-%d %H:%M:%S")

            self._log_safe(f"{'─'*54}", "sub")
            self._log_safe(f"  {now}  |  {target}  |  {mode}", "header")
            self._log_safe(f"{'─'*54}", "sub")
            self._set_status(f"Scanning {target}...")

            # Phase 0 — VirusTotal
            self._log_safe("\n[ Phase 0 ]  VirusTotal Reputation", "header")
            vt = run_vt_check(target, target_type, filepath)

            if not vt["success"]:
                self._log_safe(f"  {vt['error']}", "warning")
            else:
                vt_rep = vt["reputation"]
                tag    = "error"   if vt_rep == "MALICIOUS"  else \
                         "warning" if vt_rep == "SUSPICIOUS"  else "success"
                self._log_safe(
                    f"  {vt_rep}  —  {vt['malicious']} malicious, "
                    f"{vt['suspicious']} suspicious / {vt['total']} vendors",
                    tag
                )
                if vt["flagged_by"]:
                    for v, verdict in list(vt["flagged_by"].items())[:5]:
                        self._log_safe(f"    - {v}: {verdict}", "warning")

            # Phase 1 — Port scan
            self._log_safe("\n[ Phase 1 ]  Port Scanning", "header")
            open_ports = run_scan(target, mode)

            if not open_ports:
                self._log_safe("  No open ports found.", "warning")
                self._finish_scan([], None, vt_rep)
                return

            self._log_safe(
                f"  {len(open_ports)} open port(s): {open_ports}", "success"
            )

            # Phase 2 — Services
            self._log_safe("\n[ Phase 2 ]  Service Detection", "header")
            scan_results = detect_services(target, open_ports)
            for item in scan_results:
                banner = (item["banner"] or "").split("\n")[0].strip()[:55]
                self._log_safe(
                    f"  {item['port']:<6}  {item['service']:<10}  {banner}"
                )

            # Phase 3 — CVEs
            self._log_safe("\n[ Phase 3 ]  CVE Lookup", "header")
            scan_results = scan_for_cves(scan_results)
            for item in scan_results:
                cves = item.get("cves", [])
                if cves:
                    worst = cves[0]
                    self._log_safe(
                        f"  {item['port']:<6}  {item['service']:<10}  "
                        f"{len(cves)} CVE(s)  "
                        f"worst: {worst['id']}  CVSS {worst['cvss_score']}",
                        worst["severity"]
                    )
                else:
                    self._log_safe(
                        f"  {item['port']:<6}  {item['service']:<10}  Clean",
                        "sub"
                    )

            # Phase 4 — Risk
            self._log_safe("\n[ Phase 4 ]  Risk Assessment", "header")
            assessment = assess_risk(scan_results)
            risk = assessment["overall_risk"]
            self._log_safe(
                f"  Risk: {risk}  |  CVSS: {assessment['highest_score']}  |  "
                f"CVEs: {assessment['total_cves']}  "
                f"(Crit:{assessment['critical_count']} "
                f"High:{assessment['high_count']} "
                f"Med:{assessment['medium_count']})",
                risk
            )

            save_scan(target, mode, scan_results, assessment)
            self._log_safe("\n  Saved to history.", "success")
            self._log_safe(f"{'─'*54}", "sub")

            self.current_results    = scan_results
            self.current_assessment = assessment

            self._finish_scan(scan_results, assessment, vt_rep)

        except Exception as e:
            self._log_safe(f"\n  Error: {str(e)}", "error")
            self._finish_scan(None, None, vt_rep)

    def _finish_scan(self, results, assessment, vt_rep=None):
        def update():
            self.progress.stop()
            self.scan_btn.configure(state="normal", text="Scan")
            if results and assessment:
                self.export_btn.configure(state="normal")
                self.status_var.set(f"Done — {len(results)} port(s) found")
                self._populate_findings_table(results, vt_rep)
                self._update_stats(assessment, vt_rep)
            else:
                self.status_var.set("Done — no open ports found")
                self._populate_findings_table([], vt_rep)
            self._refresh_history()
        self.root.after(0, update)

    # ── FILE LOADING ──────────────────────────────────────────────────────────

    def _load_target_file(self):
        path = filedialog.askopenfilename(
            title="Select a target list (.txt) or file to scan",
            filetypes=[
                ("All files",   "*.*"),
                ("Text files",  "*.txt"),
                ("Executables", "*.exe"),
            ]
        )
        if not path:
            return

        if path.lower().endswith(".txt"):
            targets, error = load_targets_from_file(path)
            if error:
                messagebox.showerror("File Error", error)
                return
            self.target_var.set(targets[0])
            self._clear_output()
            self._log(f"Loaded {len(targets)} target(s):", "header")
            for i, t in enumerate(targets, 1):
                self._log(f"  {i}. {t}")
            self._log("\nClick Scan to begin.", "success")
        else:
            fname = os.path.basename(path)
            self._clear_output()
            self._log(f"File: {fname}", "header")
            self._log("Click Scan to check via VirusTotal.", "success")
            self.target_var.set(fname)
            self._pending_file = path
            self.scan_btn.configure(
                command=lambda: self._start_file_scan(path)
            )

    def _start_file_scan(self, filepath):
        self.scan_btn.configure(state="disabled", text="Scanning...")
        self.progress.start(10)
        self._clear_output()

        def run():
            try:
                from modules.vt_checker import check_file
                fname = os.path.basename(filepath)
                self._log_safe(f"{'─'*54}", "sub")
                self._log_safe(f"  File: {fname}", "header")
                self._log_safe(f"{'─'*54}", "sub")
                self._log_safe(
                    "\n[ Phase 0 ]  VirusTotal File Analysis", "header"
                )
                self._log_safe(
                    "  Computing hash + querying AV engines...", "sub"
                )

                result = check_file(filepath)

                if not result["success"]:
                    self._log_safe(f"  Error: {result['error']}", "error")
                else:
                    rep = result["reputation"]
                    tag = "error"   if rep == "MALICIOUS"  else \
                          "warning" if rep == "SUSPICIOUS"  else "success"
                    self._log_safe(
                        f"  {rep}  —  {result['malicious']} malicious, "
                        f"{result['suspicious']} suspicious "
                        f"/ {result['total']} vendors "
                        f"({result['detection_pct']}%)",
                        tag
                    )
                    if result["flagged_by"]:
                        for v, verdict in list(
                            result["flagged_by"].items()
                        )[:8]:
                            self._log_safe(
                                f"    - {v}: {verdict}", "warning"
                            )
                    else:
                        self._log_safe(
                            "  No vendors flagged this file.", "success"
                        )

                    vt_color = C["error"]   if rep == "MALICIOUS"  else \
                               C["warning"] if rep == "SUSPICIOUS"  else \
                               C["success"]
                    self.root.after(
                        0, lambda: self.m_vt.configure(
                            text=rep, fg=vt_color
                        )
                    )
                    self.root.after(
                        0, lambda r=rep: self._populate_findings_table([], r)
                    )

                self._log_safe(f"\n{'─'*54}", "sub")

            except Exception as e:
                self._log_safe(f"  Error: {str(e)}", "error")
            finally:
                def reset():
                    self.progress.stop()
                    self.scan_btn.configure(
                        state="normal", text="Scan",
                        command=self._start_scan
                    )
                    self.status_var.set("File scan complete")
                self.root.after(0, reset)

        threading.Thread(target=run, daemon=True).start()

    # ── PDF EXPORT ────────────────────────────────────────────────────────────

    def _export_pdf(self):
        if not self.current_results or not self.current_assessment:
            messagebox.showwarning("No Results", "Run a scan first.")
            return
        try:
            path = generate_report(
                self.current_target,
                self.current_mode,
                self.current_results,
                self.current_assessment
            )
            self._log(f"\nPDF saved: {path}", "success")

            # Auto-open the PDF
            if sys.platform == "win32":
                os.startfile(path)
            elif sys.platform == "darwin":
                subprocess.run(["open", path])
            else:
                subprocess.run(["xdg-open", path])

        except Exception as e:
            messagebox.showerror("Export Error", str(e))


# ── LAUNCH ────────────────────────────────────────────────────────────────────

def launch_gui():
    root = tk.Tk()
    VulnScanGUI(root)
    root.mainloop()

if __name__ == "__main__":
    launch_gui()