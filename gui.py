# -*- coding: utf-8 -*-
"""
gui.py
Tkinter graphical interface of the application (fallback when the modern
web interface cannot start). Dark theme consistent with the PDF report,
designed for everyday use:
  - scanning with real progress (percentage, not just "it is running"),
    interruptible;
  - table filterable by text and severity, with sortable columns;
  - freely resizable table/detail panes;
  - double-click an issue to open its file straight away;
  - baseline (ignore/restore) and continuous mode (watches the folder);
  - PDF report generation.
"""

import logging
import os
import queue
import subprocess
import sys
import threading
import time
import webbrowser
from datetime import datetime
from types import SimpleNamespace
from tkinter import (
    Tk, Toplevel, Frame, Label, StringVar, BooleanVar,
    Text, END, DISABLED, NORMAL, WORD, filedialog, messagebox,
)
from tkinter import ttk

import baseline as baseline_mod
import config as config_mod
import scanner
import dependency_scan
from report import render_report

log = logging.getLogger(__name__)

# --------------------------------------------------------------------------
# Palette (consistent with the PDF report)
# --------------------------------------------------------------------------
BG = "#0f1117"
PANEL = "#171a23"
PANEL_2 = "#1f2330"
PANEL_3 = "#242939"
TEXT = "#e6e8ef"
TEXT_DIM = "#9aa0b4"
BORDER = "#2a2e3d"
ACCENT = "#6c8cff"
ACCENT_HOVER = "#8aa4ff"
GOOD = "#4caf7a"
BAD = "#e05353"

SEVERITY_COLORS = {
    "CRITICAL": "#e05353", "HIGH": "#f2a341", "MEDIUM": "#ecd05c",
    "LOW": "#5fbf82", "INFO": "#5c8cf2",
}
SEVERITY_LABELS = {
    "CRITICAL": "Critical", "HIGH": "High", "MEDIUM": "Medium",
    "LOW": "Low", "INFO": "Info",
}
SEVERITY_ORDER = {"CRITICAL": 0, "HIGH": 1, "MEDIUM": 2, "LOW": 3, "INFO": 4}
CONFIDENCE_LABELS = {
    "confirmed": "Confirmed", "unknown": "Potential", "safe": "Info",
}

APP_TITLE = "Nyxtral"
WATCH_POLL_SECONDS = 3

COLUMNS = ("severity", "confidence", "file", "line", "rule")
COLUMN_LABELS = {
    "severity": "Severity", "confidence": "Confidence",
    "file": "File", "line": "Line", "rule": "Issue",
}


def _apply_dark_titlebar(root):
    """
    On Windows 10/11 the native title bar is light by default, even if the
    rest of the window is dark: it creates an annoying white strip at the
    top. This call (Windows DWM API) forces it to the dark theme. If we are
    not on Windows, or the API is unavailable (old Windows versions), it
    fails harmlessly (logged at debug level) and the window remains fully
    usable, just with the default title bar.
    """
    if not sys.platform.startswith("win"):
        return
    try:
        import ctypes
        root.update_idletasks()
        hwnd = ctypes.windll.user32.GetParent(root.winfo_id())
        value = ctypes.c_int(1)
        for attribute in (20, 19):  # 20: Windows 10 1903+/11 · 19: earlier Windows 10 builds
            result = ctypes.windll.dwmapi.DwmSetWindowAttribute(
                hwnd, attribute, ctypes.byref(value), ctypes.sizeof(value)
            )
            if result == 0:
                break
    except Exception as exc:
        log.debug("Could not apply the dark title bar (cosmetic only): %s", exc)


def make_checkbox(parent, text, variable, command=None, bg=None, fg=None):
    """
    Hand-drawn checkbox (coloured ☐/☑) used instead of the native
    ttk.Checkbutton, whose look on the Windows/clam themes is rather dated.
    Returns the container Frame, to be placed with the usual .pack()/.grid().
    """
    bg = bg or BG
    fg = fg or TEXT
    frame = Frame(parent, bg=bg, cursor="hand2")
    box_lbl = Label(frame, text="", bg=bg, fg=ACCENT, font=("Segoe UI", 13), width=2)
    text_lbl = Label(frame, text=text, bg=bg, fg=fg, font=("Segoe UI", 10), cursor="hand2")

    def render():
        checked = variable.get()
        box_lbl.config(text="☑" if checked else "☐", fg=(ACCENT if checked else TEXT_DIM))

    def toggle(_event=None):
        variable.set(not variable.get())
        render()
        if command:
            command()

    box_lbl.pack(side="left", padx=(0, 6))
    text_lbl.pack(side="left")
    for widget in (frame, box_lbl, text_lbl):
        widget.bind("<Button-1>", toggle)
    render()
    return frame


class App:
    def __init__(self, initial_dir=None):
        self.root = Tk()
        self.root.title(APP_TITLE)
        self.root.geometry("1600x960")
        self.root.minsize(1140, 720)
        _apply_dark_titlebar(self.root)
        try:
            self.root.state("zoomed")  # Windows/some Linux: opens maximized
        except Exception:
            try:
                w = self.root.winfo_screenwidth()
                h = self.root.winfo_screenheight()
                self.root.geometry(f"{w}x{h}+0+0")
            except Exception as exc:
                log.debug("Could not maximize the window (cosmetic only): %s", exc)
        _apply_dark_titlebar(self.root)  # called again after maximizing: more reliable on some builds
        self.root.configure(bg=BG)

        self.folder_var = StringVar(value=initial_dir or "")
        self.watch_var = BooleanVar(value=False)
        self.status_var = StringVar(value="Ready. Choose a folder to analyze.")
        self.score_var = StringVar(value="—")
        self.search_var = StringVar(value="")
        self.show_suppressed_var = BooleanVar(value=False)
        self.severity_vars = {sev: BooleanVar(value=True) for sev in SEVERITY_COLORS}

        self.findings = []
        self.findings_by_iid = {}
        self.files_scanned = 0
        self.files_from_cache = 0
        self.last_report_path = None
        self.sort_column = "severity"
        self.sort_reverse = False

        self.scan_thread = None
        self.watch_thread = None
        self.watch_stop = threading.Event()
        self.stop_flag = SimpleNamespace(stop=False)
        self.ui_queue = queue.Queue()

        self._apply_theme()
        self._build_layout()
        self.root.after(120, self._poll_queue)

        if initial_dir:
            self.root.after(300, self.start_scan)

    # ------------------------------------------------------------------ theme
    def _apply_theme(self):
        style = ttk.Style(self.root)
        try:
            style.theme_use("clam")
        except Exception as exc:
            log.warning("The 'clam' ttk theme is not available (%s); the interface will use the default theme "
                        "and may look different than intended.", exc)

        style.configure(".", background=BG, foreground=TEXT, fieldbackground=PANEL_2, borderwidth=0)
        style.configure("TFrame", background=BG)
        style.configure("Panel.TFrame", background=PANEL)
        style.configure("TLabel", background=BG, foreground=TEXT, font=("Segoe UI", 11))
        style.configure("Dim.TLabel", background=BG, foreground=TEXT_DIM, font=("Segoe UI", 10))
        style.configure("PanelDim.TLabel", background=PANEL, foreground=TEXT_DIM, font=("Segoe UI", 10))
        style.configure("Header.TLabel", background=BG, foreground=TEXT, font=("Segoe UI Semibold", 19))
        style.configure("Score.TLabel", background=PANEL, foreground=ACCENT, font=("Segoe UI Semibold", 36))

        style.configure("TButton", background=PANEL_2, foreground=TEXT, font=("Segoe UI", 10), padding=9, borderwidth=0)
        style.map("TButton", background=[("active", PANEL_3), ("disabled", PANEL)],
                  foreground=[("disabled", TEXT_DIM)])
        style.configure("Accent.TButton", background=ACCENT, foreground="#0b0e18", font=("Segoe UI Semibold", 10), padding=10)
        style.map("Accent.TButton", background=[("active", ACCENT_HOVER), ("disabled", PANEL_2)])
        style.configure("Danger.TButton", background="#3a1f22", foreground="#ff9b9b", font=("Segoe UI", 10), padding=9)
        style.map("Danger.TButton", background=[("active", "#4d2528")])

        style.configure("TCheckbutton", background=BG, foreground=TEXT, font=("Segoe UI", 10))
        style.map("TCheckbutton", background=[("active", BG)])
        style.configure("Panel.TCheckbutton", background=PANEL, foreground=TEXT, font=("Segoe UI", 10))
        style.map("Panel.TCheckbutton", background=[("active", PANEL)])

        style.configure("TEntry", fieldbackground=PANEL_2, foreground=TEXT, insertcolor=TEXT, padding=7)

        style.configure("Treeview", background=PANEL, fieldbackground=PANEL, foreground=TEXT,
                         rowheight=34, font=("Segoe UI", 11), borderwidth=0)
        style.configure("Treeview.Heading", background=PANEL_2, foreground=TEXT_DIM,
                         font=("Segoe UI Semibold", 10), borderwidth=0, padding=9)
        style.map("Treeview.Heading", background=[("active", PANEL_3)])
        style.map("Treeview", background=[("selected", "#2a3557")], foreground=[("selected", TEXT)])

        style.configure("TProgressbar", background=ACCENT, troughcolor=PANEL_2, borderwidth=0, thickness=10)

        style.configure("TPanedwindow", background=BG)
        style.configure("Sash", background=BG)

    # ------------------------------------------------------------- layout
    def _build_layout(self):
        PAD = 28

        header = Frame(self.root, bg=BG)
        header.pack(fill="x", padx=PAD, pady=(24, 16))

        brand = Frame(header, bg=BG)
        brand.pack(side="left")
        Label(brand, text="🔒", bg=BG, fg=ACCENT, font=("Segoe UI", 28)).pack(side="left", padx=(0, 12))
        title_box = Frame(brand, bg=BG)
        title_box.pack(side="left")
        ttk.Label(title_box, text=APP_TITLE, style="Header.TLabel").pack(anchor="w")
        ttk.Label(title_box, text="Continuous static analysis · AST + patterns",
                  style="Dim.TLabel").pack(anchor="w", pady=(3, 0))


        # ---- Folder row ---------------------------------------------------
        folder_row = Frame(self.root, bg=BG)
        folder_row.pack(fill="x", padx=PAD, pady=(0, 12))
        ttk.Entry(folder_row, textvariable=self.folder_var).pack(side="left", fill="x", expand=True, ipady=7)
        ttk.Button(folder_row, text="Browse…", command=self.browse_folder).pack(side="left", padx=(10, 0))
        self.scan_btn = ttk.Button(folder_row, text="▶  Scan", style="Accent.TButton", command=self.start_scan)
        self.scan_btn.pack(side="left", padx=(10, 0))
        self.stop_btn = ttk.Button(folder_row, text="⏹  Stop", style="Danger.TButton", command=self.stop_scan)
        make_checkbox(folder_row, "Continuous mode (watch the folder)",
                       self.watch_var, command=self.toggle_watch).pack(side="left", padx=(20, 0))

        # ---- Filter row --------------------------------------------------------
        filter_row = Frame(self.root, bg=BG)
        filter_row.pack(fill="x", padx=PAD, pady=(0, 12))
        ttk.Label(filter_row, text="🔎", style="Dim.TLabel").pack(side="left")
        search_entry = ttk.Entry(filter_row, textvariable=self.search_var, width=28)
        search_entry.pack(side="left", padx=(6, 18), ipady=5)
        search_entry.bind("<KeyRelease>", lambda e: self._refresh_table())

        for sev in ["CRITICAL", "HIGH", "MEDIUM", "LOW", "INFO"]:
            make_checkbox(filter_row, SEVERITY_LABELS[sev], self.severity_vars[sev],
                          command=self._refresh_table).pack(side="left", padx=(0, 16))

        make_checkbox(filter_row, "Also show ignored issues", self.show_suppressed_var,
                       command=self._refresh_table).pack(side="left", padx=(14, 0))

        # ---- Status / progress row ------------------------------------------
        status_row = Frame(self.root, bg=BG)
        status_row.pack(fill="x", padx=PAD, pady=(0, 14))
        self.progress = ttk.Progressbar(status_row, mode="determinate", maximum=100, length=260)
        ttk.Label(status_row, textvariable=self.status_var, style="Dim.TLabel").pack(side="left")

        # ---- Body --------------------------------------------------------------
        body = Frame(self.root, bg=BG)
        body.pack(fill="both", expand=True, padx=PAD, pady=(0, 24))

        score_panel = Frame(body, bg=PANEL, width=250)
        score_panel.pack(side="left", fill="y", padx=(0, 20))
        score_panel.pack_propagate(False)
        Frame(score_panel, bg=PANEL, height=24).pack()
        ttk.Label(score_panel, text="SCORE", style="PanelDim.TLabel").pack()
        ttk.Label(score_panel, textvariable=self.score_var, style="Score.TLabel").pack(pady=(4, 20))
        self.summary_box = Frame(score_panel, bg=PANEL)
        self.summary_box.pack(fill="x", padx=22)
        self.summary_labels = {}
        for sev in ["CRITICAL", "HIGH", "MEDIUM", "LOW", "INFO"]:
            row = Frame(self.summary_box, bg=PANEL)
            row.pack(fill="x", pady=5)
            Label(row, text="●", fg=SEVERITY_COLORS[sev], bg=PANEL, font=("Segoe UI", 11)).pack(side="left")
            Label(row, text=f" {SEVERITY_LABELS[sev]}", fg=TEXT_DIM, bg=PANEL, font=("Segoe UI", 10)).pack(side="left")
            count_lbl = Label(row, text="0", fg=TEXT, bg=PANEL, font=("Segoe UI Semibold", 11))
            count_lbl.pack(side="right")
            self.summary_labels[sev] = count_lbl

        Frame(score_panel, bg=BORDER, height=1).pack(fill="x", padx=22, pady=20)
        ttk.Button(score_panel, text="📄  Generate PDF report", command=self.generate_report).pack(
            fill="x", padx=22, pady=(0, 8))
        self.dep_btn = ttk.Button(score_panel, text="🌐  Dependencies", command=self.check_dependencies)
        self.dep_btn.pack(fill="x", padx=22, pady=(0, 8))
        ttk.Label(score_panel, text="Requires internet (OSV.dev).\nChecks requirements.txt / package.json.",
                  style="PanelDim.TLabel", justify="center", wraplength=195).pack(pady=(2, 8))
        Frame(score_panel, bg=BORDER, height=1).pack(fill="x", padx=22, pady=(14, 14))
        ttk.Label(score_panel, text="Double-click a row\nto open the file.",
                  style="PanelDim.TLabel", justify="center").pack(pady=(0, 0))

        # ---- Table + detail, resizable --------------------------
        paned = ttk.PanedWindow(body, orient="vertical")
        paned.pack(side="left", fill="both", expand=True)

        tree_frame = Frame(paned, bg=BG)
        self.tree = ttk.Treeview(tree_frame, columns=COLUMNS, show="headings", selectmode="browse")
        for col in COLUMNS:
            self.tree.heading(col, text=COLUMN_LABELS[col], command=lambda c=col: self._sort_by(c))
        self.tree.column("severity", width=100, anchor="center")
        self.tree.column("confidence", width=130, anchor="center")
        self.tree.column("file", width=300)
        self.tree.column("line", width=70, anchor="center")
        self.tree.column("rule", width=520)

        vsb = ttk.Scrollbar(tree_frame, orient="vertical", command=self.tree.yview)
        self.tree.configure(yscrollcommand=vsb.set)
        self.tree.pack(side="left", fill="both", expand=True)
        vsb.pack(side="right", fill="y")

        self.tree.bind("<<TreeviewSelect>>", self.on_select_finding)
        self.tree.bind("<Double-1>", self.on_double_click)

        for sev, color in SEVERITY_COLORS.items():
            self.tree.tag_configure(sev, foreground=color)
        self.tree.tag_configure("suppressed", foreground=TEXT_DIM)

        detail = Frame(paned, bg=PANEL)
        self.detail_title = Label(detail, text="Select an issue from the list",
                                   bg=PANEL, fg=TEXT, font=("Segoe UI Semibold", 13), anchor="w")
        self.detail_title.pack(fill="x", padx=22, pady=(18, 6))

        self.detail_text = Text(detail, height=8, bg=PANEL_2, fg=TEXT, wrap=WORD, relief="flat",
                                 font=("Segoe UI", 11), padx=16, pady=14, spacing2=3, spacing3=6)
        self.detail_text.pack(fill="both", expand=True, padx=22, pady=(4, 12))
        self.detail_text.configure(state=DISABLED)

        detail_btns = Frame(detail, bg=PANEL)
        detail_btns.pack(fill="x", padx=22, pady=(0, 18))
        self.suppress_btn = ttk.Button(detail_btns, text="🙈  Ignore (baseline)", command=self.suppress_selected)
        self.suppress_btn.pack(side="left", padx=(10, 0))
        self.unsuppress_btn = ttk.Button(detail_btns, text="↩  Restore", command=self.unsuppress_selected)
        self.unsuppress_btn.pack(side="left", padx=(10, 0))
        ttk.Button(detail_btns, text="📂  Open file", command=self.open_selected_file).pack(side="left", padx=(10, 0))

        paned.add(tree_frame, weight=3)
        paned.add(detail, weight=2)

    # ---------------------------------------------------------------- actions
    def browse_folder(self):
        chosen = filedialog.askdirectory(title="Choose the project folder to analyze")
        if chosen:
            self.folder_var.set(chosen)

    def _validate_folder(self, target):
        """Show an explanatory warning and return False if `target` is not a usable folder."""
        if not target:
            messagebox.showwarning(APP_TITLE, "No folder selected.\n\nClick 'Browse…' and choose the project folder to analyze.")
            return False
        if not os.path.isdir(target):
            log.warning("Folder does not exist or is not a directory: '%s'", target)
            messagebox.showwarning(
                APP_TITLE,
                f"The folder does not exist or is not a directory:\n{target}\n\n"
                "It may have been moved, renamed or deleted, or a network drive may be disconnected.")
            return False
        if not os.access(target, os.R_OK):
            log.warning("Folder is not readable: '%s'", target)
            messagebox.showwarning(APP_TITLE, f"The folder cannot be read:\n{target}\n\nCheck that you have permission to open it.")
            return False
        return True

    def start_scan(self):
        target = self.folder_var.get().strip()
        if not self._validate_folder(target):
            return
        if self.scan_thread and self.scan_thread.is_alive():
            return

        self.stop_flag = SimpleNamespace(stop=False)
        self.scan_btn.state(["disabled"])
        self.stop_btn.pack(side="left", padx=(8, 0))
        self.progress.pack(side="right")
        self.progress["value"] = 0
        self.status_var.set("Analysis in progress…")

        def worker():
            def progress_cb(current, total, rel_path, from_cache):
                self.ui_queue.put(("progress", (current, total, rel_path, from_cache)))

            try:
                findings, scanned, from_cache = scanner.scan_directory(
                    target, progress_callback=progress_cb, stop_flag=self.stop_flag)
                score = scanner.compute_score(findings)
                interrupted = getattr(self.stop_flag, "stop", False)
                self.ui_queue.put(("scan_done", (findings, scanned, from_cache, score, target, interrupted)))
            except Exception as exc:
                log.exception("The scan of '%s' failed unexpectedly", target)
                self.ui_queue.put(("scan_error", str(exc)))

        self.scan_thread = threading.Thread(target=worker, daemon=True)
        self.scan_thread.start()

    def stop_scan(self):
        self.stop_flag.stop = True
        self.status_var.set("Stopping the scan…")

    def check_dependencies(self):
        target = self.folder_var.get().strip()
        if not self._validate_folder(target):
            return
        if not self.findings:
            messagebox.showinfo(APP_TITLE, "Run a code scan first, then check the dependencies.")
            return

        self.dep_btn.state(["disabled"])
        self.status_var.set("Checking dependencies on OSV.dev…")

        def worker():
            def progress_cb(current, total, name):
                self.ui_queue.put(("dep_progress", (current, total, name)))

            try:
                findings, checked, skipped, error = dependency_scan.check_dependencies(target)
            except Exception as exc:
                log.exception("Dependency check failed")
                findings, checked, skipped = [], 0, 0
                error = (f"The dependency check failed unexpectedly: {exc}\n\n"
                         "Check your internet connection and try again; see the log file for details.")
            self.ui_queue.put(("dep_done", (findings, checked, skipped, error)))

        threading.Thread(target=worker, daemon=True).start()

    def toggle_watch(self):
        if self.watch_var.get():
            target = self.folder_var.get().strip()
            if not self._validate_folder(target):
                self.watch_var.set(False)
                return
            self.watch_stop.clear()
            self.watch_thread = threading.Thread(target=self._watch_loop, args=(target,), daemon=True)
            self.watch_thread.start()
            self.status_var.set("Continuous mode active: the folder is being watched.")
        else:
            self.watch_stop.set()

    def _watch_loop(self, target):
        last_snapshot = self._snapshot_mtimes(target)
        while not self.watch_stop.is_set():
            time.sleep(WATCH_POLL_SECONDS)
            if self.watch_stop.is_set():
                break
            snapshot = self._snapshot_mtimes(target)
            if snapshot != last_snapshot:
                last_snapshot = snapshot
                self.ui_queue.put(("watch_trigger", None))

    @staticmethod
    def _snapshot_mtimes(target):
        snap = {}
        try:
            for full_path, filename in scanner.iter_source_files(target):
                if filename in scanner.INTERNAL_FILENAMES:
                    continue
                try:
                    snap[full_path] = os.path.getmtime(full_path)
                except OSError as exc:
                    log.debug("Watch mode: cannot stat '%s': %s", full_path, exc)
        except OSError as exc:
            log.warning("Watch mode: could not read the folder '%s' (%s). Change detection may be "
                        "incomplete until it is accessible again.", target, exc)
        return snap

    def generate_report(self):
        if not self.findings:
            messagebox.showinfo(APP_TITLE, "There are no results to export. Run a scan first.")
            return
        target = self.folder_var.get().strip()
        score = scanner.compute_score(self.findings)
        try:
            pdf_bytes = render_report(target, self.findings, self.files_scanned, score, self.files_from_cache)
        except Exception as exc:
            log.exception("PDF report generation failed")
            messagebox.showerror(APP_TITLE, f"The PDF report could not be generated:\n{exc}\n\n"
                                            "Make sure the 'reportlab' package is installed; see the log file for details.")
            return
        timestamp = datetime.now().strftime("%Y%m%d_%H%M%S")
        report_path = os.path.join(target, f"security_report_{timestamp}.pdf")
        try:
            with open(report_path, "wb") as f:
                f.write(pdf_bytes)
        except OSError as exc:
            log.warning("Could not save the report in '%s' (%s); trying the home folder instead.", target, exc)
            report_path = os.path.join(os.path.expanduser("~"), f"security_report_{timestamp}.pdf")
            try:
                with open(report_path, "wb") as f:
                    f.write(pdf_bytes)
            except OSError as exc2:
                log.error("Could not save the PDF report to '%s': %s", report_path, exc2)
                messagebox.showerror(APP_TITLE, f"The report could not be saved, neither in the project folder nor in your home folder:\n{exc2}\n\n"
                                                "Check the folder permissions and the free disk space, and make sure no previous report is open in another program.")
                return
        self.last_report_path = report_path
        self._open_path(report_path)
        self.status_var.set(f"PDF report saved to: {report_path}")

    @staticmethod
    def _open_path(path):
        try:
            if sys.platform.startswith("win"):
                os.startfile(path)  # noqa: only exists on Windows
            elif sys.platform == "darwin":
                subprocess.Popen(["open", path], stdout=subprocess.DEVNULL, stderr=subprocess.DEVNULL)
            else:
                subprocess.Popen(["xdg-open", path], stdout=subprocess.DEVNULL, stderr=subprocess.DEVNULL)
        except Exception as exc:
            log.warning("Could not open '%s' with the default application (%s); trying the web browser.", path, exc)
            try:
                webbrowser.open(f"file://{path}")
            except Exception as exc2:
                log.error("Could not open '%s' at all: %s", path, exc2)
                messagebox.showwarning(APP_TITLE, f"Could not open the file automatically.\nOpen it manually at:\n{path}")

    def open_selected_file(self):
        selection = self.tree.selection()
        if not selection:
            messagebox.showinfo(APP_TITLE, "Select an issue from the list first.")
            return
        f = self.findings_by_iid.get(selection[0])
        if not f:
            return
        target = self.folder_var.get().strip()
        full_path = os.path.join(target, f["file"])
        if os.path.isfile(full_path):
            self._open_path(full_path)
        else:
            messagebox.showwarning(APP_TITLE, f"File not found:\n{full_path}\n\nIt may have been moved or deleted since the scan.")

    def on_double_click(self, _event):
        self.open_selected_file()

    def on_select_finding(self, _event):
        selection = self.tree.selection()
        if not selection:
            return
        f = self.findings_by_iid.get(selection[0])
        if f:
            self._show_detail(f)

    def _show_detail(self, f):
        self.detail_title.config(text=f"{f['name']}  ·  {f['file']}:{f['line'] or '-'}")
        self.detail_text.configure(state=NORMAL)
        self.detail_text.delete("1.0", END)
        body = (
            f"Confidence: {CONFIDENCE_LABELS.get(f.get('confidence','unknown'))}\n\n"
            f"Snippet: {f['snippet']}\n\n"
            f"What it means: {f['description']}\n\n"
            f"What you risk in practice: {f.get('impact', '')}\n\n"
            f"How to fix it: {f['recommendation']}"
        )
        self.detail_text.insert("1.0", body)
        self.detail_text.configure(state=DISABLED)

    def suppress_selected(self):
        selection = self.tree.selection()
        if not selection:
            return
        f = self.findings_by_iid.get(selection[0])
        if not f:
            return
        baseline_mod.suppress(self.folder_var.get().strip(), f, reason="Ignored by the user")
        f["suppressed"] = True
        self._refresh_table(reselect=f)
        self._update_score_panel()

    def unsuppress_selected(self):
        selection = self.tree.selection()
        if not selection:
            return
        f = self.findings_by_iid.get(selection[0])
        if not f:
            return
        baseline_mod.unsuppress(self.folder_var.get().strip(), f)
        f["suppressed"] = False
        self._refresh_table(reselect=f)
        self._update_score_panel()

    # ------------------------------------------------------------ filter/sort
    def _sort_by(self, column):
        if self.sort_column == column:
            self.sort_reverse = not self.sort_reverse
        else:
            self.sort_column = column
            self.sort_reverse = False
        self._refresh_table()

    def _sort_key(self, f):
        col = self.sort_column
        if col == "severity":
            return SEVERITY_ORDER.get(f["severity"], 99)
        if col == "confidence":
            return f.get("confidence", "")
        if col == "line":
            return f["line"] or 0
        if col == "file":
            return f["file"].lower()
        return f["name"].lower()

    def _matches_filter(self, f):
        if f.get("suppressed") and not self.show_suppressed_var.get():
            return False
        if not self.severity_vars[f["severity"]].get():
            return False
        query = self.search_var.get().strip().lower()
        if query and query not in f["name"].lower() and query not in f["file"].lower() \
                and query not in f["id"].lower():
            return False
        return True

    # ----------------------------------------------------------- rendering
    def _refresh_table(self, reselect=None):
        self.tree.delete(*self.tree.get_children())
        self.findings_by_iid.clear()

        filtered = [f for f in self.findings if self._matches_filter(f)]
        filtered.sort(key=self._sort_key, reverse=self.sort_reverse)

        reselect_iid = None
        for i, f in enumerate(filtered):
            iid = f"row{i}"
            tags = (f["severity"],) if not f.get("suppressed") else ("suppressed",)
            values = (
                SEVERITY_LABELS.get(f["severity"], f["severity"]),
                ("Ignored" if f.get("suppressed") else CONFIDENCE_LABELS.get(f.get("confidence", "unknown"))),
                f["file"], f["line"] or "-", f["name"],
            )
            self.tree.insert("", "end", iid=iid, values=values, tags=tags)
            self.findings_by_iid[iid] = f
            if reselect is not None and f is reselect:
                reselect_iid = iid

        if reselect_iid:
            self.tree.selection_set(reselect_iid)
            self.tree.see(reselect_iid)

        for col in COLUMNS:
            base = COLUMN_LABELS[col]
            arrow = ""
            if col == self.sort_column:
                arrow = " ▲" if not self.sort_reverse else " ▼"
            self.tree.heading(col, text=base + arrow, command=lambda c=col: self._sort_by(c))

    def _update_score_panel(self):
        active = [f for f in self.findings if not f.get("suppressed")]
        score = scanner.compute_score(self.findings)
        self.score_var.set(str(score))
        counts = {sev: 0 for sev in SEVERITY_COLORS}
        for f in active:
            counts[f["severity"]] = counts.get(f["severity"], 0) + 1
        for sev, lbl in self.summary_labels.items():
            lbl.config(text=str(counts.get(sev, 0)))

    # ------------------------------------------------------------- polling
    def _poll_queue(self):
        try:
            while True:
                kind, payload = self.ui_queue.get_nowait()
                if kind == "progress":
                    current, total, rel_path, from_cache = payload
                    pct = int(current / total * 100) if total else 100
                    self.progress["value"] = pct
                    tag = "cache" if from_cache else "analysis"
                    self.status_var.set(f"{pct}% ({current}/{total}) — {tag}: {rel_path}")
                elif kind == "scan_done":
                    findings, scanned, from_cache, score, target, interrupted = payload
                    self.findings = findings
                    self.files_scanned = scanned
                    self.files_from_cache = from_cache
                    self._refresh_table()
                    self._update_score_panel()
                    self.progress.pack_forget()
                    self.scan_btn.state(["!disabled"])
                    self.stop_btn.pack_forget()
                    active = len([f for f in findings if not f.get("suppressed")])
                    prefix = "Scan stopped (partial results)" if interrupted else "Scan complete"
                    self.status_var.set(
                        f"{prefix}: {scanned} files analyzed, {from_cache} from cache, "
                        f"{active} active issues in {target}."
                    )
                elif kind == "scan_error":
                    self.progress.pack_forget()
                    self.scan_btn.state(["!disabled"])
                    self.stop_btn.pack_forget()
                    self.status_var.set("The scan failed.")
                    messagebox.showerror(APP_TITLE, f"The scan failed unexpectedly:\n{payload}\n\n"
                                                    "Details were written to the log file. Try again, or exclude the file that causes the problem.")
                elif kind == "watch_trigger":
                    self.status_var.set("Changes detected: re-scanning…")
                    self.start_scan()
                elif kind == "dep_progress":
                    current, total, name = payload
                    self.status_var.set(f"Checking dependencies: {current}/{total} — {name}")
                elif kind == "dep_done":
                    new_findings, checked, skipped, error = payload
                    self.dep_btn.state(["!disabled"])
                    # Remove any results from a previous check, to avoid duplicates
                    self.findings = [f for f in self.findings if f.get("engine") != "dependency"]
                    if new_findings:
                        target = self.folder_var.get().strip()
                        baseline_data = baseline_mod.load_baseline(target)
                        baseline_mod.annotate(new_findings, baseline_data)
                        self.findings.extend(new_findings)
                    self._refresh_table()
                    self._update_score_panel()
                    if error:
                        self.status_var.set("Dependency check failed.")
                        messagebox.showerror(APP_TITLE, error)
                    else:
                        vulnerable = len(new_findings)
                        skip_note = f", {skipped} could not be verified (version not pinned)" if skipped else ""
                        self.status_var.set(
                            f"Dependency check complete: {checked} packages verified, "
                            f"{vulnerable} with known vulnerabilities{skip_note}."
                        )
        except queue.Empty:
            pass
        self.root.after(120, self._poll_queue)

    def run(self):
        self.root.mainloop()
