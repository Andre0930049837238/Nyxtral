# -*- coding: utf-8 -*-
"""
webview_app.py
================
Entry point of the modern interface (HTML/CSS/JS shown in a lightweight
native window through pywebview, with no need for Node.js or Electron).
The analysis engine (scanner, ast_engine, pattern_engine, dependency_scan,
baseline, cache, exclusions, report) is EXACTLY the same as in the
Tkinter version: only the "face" of the app changes here, not the logic.

Architecture:
  - webui/index.html + style.css: structure and look of the interface;
  - webui/app.js: "frontend" logic (fills the table, handles the context
    menu, the filters...);
  - Api (this class): exposed to JavaScript as `pywebview.api`. Every public
    method can be called from app.js with `await pywebview.api.name(...)`.
    Long-running operations (scan, dependency check) run in a
    separate thread and report their result back to JavaScript by calling
    global functions via `window.evaluate_js(...)`, so the window does not
    freeze while they work.
"""

import gc
import json
import logging
import os
import subprocess
import sys
import threading
import time
from datetime import datetime
from pathlib import Path
from types import SimpleNamespace

import webview

import baseline as baseline_mod
import cache as cache_mod
import config as config_mod
import dependency_scan
import exclusions as exclusions_mod
import scanner
from report import render_report

log = logging.getLogger(__name__)


def _base_dir():
    """Folder that contains 'webui': next to the sources, or inside the PyInstaller executable."""
    if getattr(sys, "frozen", False):
        return getattr(sys, "_MEIPASS", os.path.dirname(sys.executable))
    return os.path.dirname(os.path.abspath(__file__))


WEBUI_DIR = os.path.join(_base_dir(), "webui")
WATCH_POLL_SECONDS = 5
WATCH_MIN_INTERVAL = 20   # minimum seconds between two automatic scans


def _push(window, js_function, payload):
    """Call a global JS function, passing the payload as JSON. Non-blocking."""
    try:
        window.evaluate_js(f"{js_function}({json.dumps(payload)})")
    except Exception as exc:
        # The window may already have been closed: not a fatal error, but worth a trace.
        log.debug("Could not deliver '%s' to the interface (window closed or not ready?): %s", js_function, exc)


class Api:
    # IMPORTANT: pywebview recursively walks every PUBLIC attribute of this object to
    # expose it to JavaScript. If one is a large or circular object (the native window, the findings...)
    # the walk never ends and RAM fills up at startup. That is why all state attributes
    # start with "_" (ignored by pywebview): only the methods are public here.
    def __init__(self):
        self._window = None
        self._current_folder = None
        self._findings = []
        self._files_scanned = 0
        self._files_from_cache = 0
        self._stop_flag = SimpleNamespace(stop=False)
        self._watch_gen = 0
        self._maximized = False
        self._scan_lock = threading.Lock()
        self._is_scanning = False

    def set_window(self, window):
        self._window = window

    # ------------------------------------------------------------ window
    def minimize_window(self):
        self._window.minimize()

    def toggle_maximize_window(self):
        try:
            if self._maximized:
                self._window.restore()
                self._maximized = False
            else:
                self._window.maximize()
                self._maximized = True
        except Exception as exc:
            log.warning("Could not maximize/restore the window: %s", exc)

    def close_window(self):
        self._watch_gen += 1
        self._window.destroy()

    # ------------------------------------------------------------ folder
    def browse_folder(self):
        result = self._window.create_file_dialog(webview.FOLDER_DIALOG)
        if result:
            return result[0]
        return None

    # ------------------------------------------------------------ scan
    def start_scan(self, folder):
        if not folder:
            return {"error": "No folder selected. Click 'Browse' and choose the project folder to scan."}
        if not os.path.isdir(folder):
            log.warning("Scan requested for a folder that does not exist: '%s'", folder)
            return {"error": f"The folder '{folder}' does not exist or is not a directory. "
                             "It may have been moved, renamed or deleted, or a network drive may be disconnected."}
        if not os.access(folder, os.R_OK):
            log.warning("Scan requested for a folder that is not readable: '%s'", folder)
            return {"error": f"The folder '{folder}' cannot be read. Check that you have permission to open it."}

        with self._scan_lock:
            if self._is_scanning:
                # We do not queue a second scan: this was exactly the flaw that made
                # threads (and RAM) pile up without limit when continuous mode
                # detected changes faster than a long scan could complete.
                return {"error": "A scan is already in progress. Wait for it to finish or stop it first.",
                        "alreadyRunning": True}
            self._is_scanning = True

        self._current_folder = folder
        self._stop_flag = SimpleNamespace(stop=False)

        def worker():
            try:
                last_push = [0.0]

                def progress_cb(current, total, rel_path, from_cache):
                    # one message to JavaScript per file saturates CPU and memory on large projects:
                    # we send at most ~8 per second (and always the last one)
                    now = time.monotonic()
                    if current < total and now - last_push[0] < 0.12:
                        return
                    last_push[0] = now
                    _push(self._window, "onScanProgress", {
                        "current": current, "total": total, "relPath": rel_path, "fromCache": from_cache,
                    })

                findings, scanned, from_cache = scanner.scan_directory(
                    folder, progress_callback=progress_cb, stop_flag=self._stop_flag,
                    include_quality=config_mod.get_quality_enabled())
                score = scanner.compute_score(findings)
                quality = scanner.compute_quality_score(findings)
                self._findings = findings
                self._files_scanned = scanned
                self._files_from_cache = from_cache
                slim, templates, truncated = scanner.slim_findings(findings)
                _push(self._window, "onScanDone", {
                    "findings": slim, "templates": templates, "truncated": truncated, "filesScanned": scanned, "filesFromCache": from_cache,
                    "score": score, "qualityScore": quality, "folder": folder, "interrupted": getattr(self._stop_flag, "stop", False),
                })
            except Exception as exc:
                log.exception("The scan of '%s' failed unexpectedly", folder)
                _push(self._window, "onScanError", {
                    "error": f"The scan failed unexpectedly: {exc}. Details were written to the log file "
                             f"({config_mod.LOG_FILENAME}). Try scanning again, or exclude the file that causes the problem."})
            finally:
                with self._scan_lock:
                    self._is_scanning = False
                gc.collect()

        threading.Thread(target=worker, daemon=True).start()
        return {"started": True}

    def stop_scan(self):
        self._stop_flag.stop = True
        return {"stopped": True}

    # ------------------------------------------------------------ continuous (watch) mode
    def start_watch(self, folder):
        # every start invalidates the previous thread (generation counter): no accumulated threads
        self._watch_gen += 1
        gen = self._watch_gen

        def loop():
            last = self._signature(folder)
            pending, last_scan = False, 0.0
            while self._watch_gen == gen:
                time.sleep(WATCH_POLL_SECONDS)
                if self._watch_gen != gen:
                    break
                sig = self._signature(folder)
                if sig != last:
                    last, pending = sig, True   # a change was detected: wait for it to settle
                    continue
                if pending and not self._is_scanning and time.monotonic() - last_scan >= WATCH_MIN_INTERVAL:
                    pending, last_scan = False, time.monotonic()
                    _push(self._window, "onWatchTrigger", {})

        threading.Thread(target=loop, daemon=True).start()
        return {"started": True}

    def stop_watch(self):
        self._watch_gen += 1
        return {"stopped": True}

    @staticmethod
    def _signature(folder):
        """Folder fingerprint computed in streaming fashion (no file list kept in memory)."""
        count, newest, total = 0, 0.0, 0.0
        exclusions = exclusions_mod.load_exclusions(folder)
        try:
            for full_path, filename in scanner.iter_source_files(folder):
                if filename in scanner.INTERNAL_FILENAMES:
                    continue
                if scanner.detect_extension(filename) not in scanner.TEXT_EXTENSIONS:
                    continue
                if exclusions and exclusions_mod.is_excluded(os.path.relpath(full_path, folder), exclusions):
                    continue
                try:
                    m = os.path.getmtime(full_path)
                except OSError:
                    continue
                count += 1
                total += m
                newest = max(newest, m)
        except OSError as exc:
            log.warning("Watch mode: could not fully read the folder '%s' (%s). "
                        "Change detection may be incomplete until the folder is accessible again.", folder, exc)
        return (count, newest, round(total, 3))

    # ------------------------------------------------------------ baseline / exclusions
    def suppress_finding(self, finding):
        baseline_mod.suppress(self._current_folder, finding, reason="Ignored by the user")
        return {"ok": True}

    def unsuppress_finding(self, finding):
        baseline_mod.unsuppress(self._current_folder, finding)
        return {"ok": True}

    def exclude_file(self, rel_path):
        exclusions_mod.exclude_path(self._current_folder, rel_path)
        return {"ok": True}

    def include_file(self, rel_path):
        exclusions_mod.include_path(self._current_folder, rel_path)
        return {"ok": True}

    def list_exclusions(self):
        return exclusions_mod.load_exclusions(self._current_folder) if self._current_folder else []

    # ------------------------------------------------------------ files
    def open_file(self, rel_path):
        full_path = os.path.join(self._current_folder, rel_path)
        if not os.path.isfile(full_path):
            log.warning("Cannot open '%s': file not found", full_path)
            return {"error": f"File not found: '{rel_path}'. It may have been moved or deleted since the scan."}
        try:
            if sys.platform.startswith("win"):
                os.startfile(full_path)  # noqa: esiste solo su Windows
            elif sys.platform == "darwin":
                subprocess.Popen(["open", full_path], stdout=subprocess.DEVNULL, stderr=subprocess.DEVNULL)
            else:
                subprocess.Popen(["xdg-open", full_path], stdout=subprocess.DEVNULL, stderr=subprocess.DEVNULL)
        except Exception as exc:
            log.error("Could not open '%s' with the default application: %s", full_path, exc)
            return {"error": f"Could not open the file with your default application ({exc}). "
                             f"Open it manually at: {full_path}"}
        return {"ok": True}

    # ------------------------------------------------------------ PDF report
    def generate_report(self):
        if not self._findings:
            return {"error": "There are no results to export. Run a scan first."}
        score = scanner.compute_score(self._findings)
        try:
            pdf_bytes = render_report(self._current_folder, self._findings, self._files_scanned,
                                      score, self._files_from_cache)
        except Exception as exc:
            log.exception("PDF report generation failed")
            return {"error": f"The PDF report could not be generated ({exc}). "
                             "Make sure the 'reportlab' package is installed; see the log file for details."}
        timestamp = datetime.now().strftime("%Y%m%d_%H%M%S")
        report_path = os.path.join(self._current_folder, f"security_report_{timestamp}.pdf")
        try:
            with open(report_path, "wb") as f:
                f.write(pdf_bytes)
        except OSError as exc:
            log.warning("Could not save the report in the project folder '%s' (%s); "
                        "trying your home folder instead.", self._current_folder, exc)
            report_path = os.path.join(os.path.expanduser("~"), f"security_report_{timestamp}.pdf")
            try:
                with open(report_path, "wb") as f:
                    f.write(pdf_bytes)
            except OSError as exc2:
                log.error("Could not save the PDF report to '%s': %s", report_path, exc2)
                return {"error": f"The report could not be saved, neither in the project folder nor in "
                                 f"'{os.path.expanduser('~')}' ({exc2}). Check the folder permissions and "
                                 "the free disk space, and make sure no previous report is open in another program."}
        try:
            if sys.platform.startswith("win"):
                os.startfile(report_path)
            elif sys.platform == "darwin":
                subprocess.Popen(["open", report_path])
            else:
                subprocess.Popen(["xdg-open", report_path])
        except Exception as exc:
            log.warning("Report saved to '%s' but it could not be opened automatically: %s", report_path, exc)
        return {"path": report_path}

    # ------------------------------------------------------------ dependencies (online)
    def check_dependencies(self):
        if not self._current_folder:
            return {"error": "No folder selected. Choose a project folder first."}
        folder = self._current_folder

        def worker():
            def progress_cb(current, total, name):
                _push(self._window, "onDepProgress", {"current": current, "total": total, "name": name})

            try:
                new_findings, checked, skipped, error = dependency_scan.check_dependencies(folder)
            except Exception as exc:
                log.exception("Dependency check failed")
                _push(self._window, "onDepDone", {
                    "findings": [], "templates": {}, "checked": 0, "skipped": 0, "vulnerable": 0,
                    "error": f"The dependency check failed unexpectedly: {exc}. Check your internet "
                             "connection and try again; see the log file for details."})
                return
            if error:
                log.warning("Dependency check reported a problem: %s", error)
            self._findings = [f for f in self._findings if f.get("engine") != "dependency"]
            if new_findings:
                baseline_data = baseline_mod.load_baseline(folder)
                baseline_mod.annotate(new_findings, baseline_data)
                self._findings.extend(new_findings)
            slim, templates, _ = scanner.slim_findings(new_findings)
            _push(self._window, "onDepDone", {
                "findings": slim, "templates": templates, "checked": checked, "skipped": skipped, "error": error,
                "vulnerable": len(new_findings),
            })

        threading.Thread(target=worker, daemon=True).start()
        return {"started": True}

    # ------------------------------------------------------------ settings page
    def list_baseline(self):
        if not self._current_folder:
            return []
        data = baseline_mod.load_baseline(self._current_folder)
        return [dict(v, fingerprint=k) for k, v in data.items()]

    def remove_baseline(self, fingerprint):
        data = baseline_mod.load_baseline(self._current_folder)
        data.pop(fingerprint, None)
        baseline_mod.save_baseline(self._current_folder, data)
        return {"ok": True}

    def clear_cache(self):
        if not self._current_folder:
            return {"error": "No folder selected. Choose a project folder first."}
        path = os.path.join(self._current_folder, cache_mod.CACHE_FILENAME)
        try:
            if os.path.isfile(path):
                os.remove(path)
        except OSError as exc:
            log.error("Could not delete the cache file '%s': %s", path, exc)
            return {"error": f"The cache could not be cleared ({exc}). Check that the file '{path}' "
                             "is not in use and that you have permission to delete it."}
        return {"ok": True}

    def app_info(self):
        data_dir = config_mod.app_data_dir()
        return {"dataDir": data_dir, "crashLog": os.path.join(data_dir, "crash.log"),
                "logFile": config_mod.log_path()}

    def open_data_dir(self):
        path = config_mod.app_data_dir()
        try:
            if sys.platform.startswith("win"):
                os.startfile(path)
            else:
                subprocess.Popen(["open" if sys.platform == "darwin" else "xdg-open", path])
        except Exception as exc:
            log.error("Could not open the data folder '%s': %s", path, exc)
            return {"error": f"Could not open the data folder ({exc}). You can open it manually at: {path}"}
        return {"ok": True}

    def get_quality_enabled(self):
        return config_mod.get_quality_enabled()

    def set_quality_enabled(self, value):
        config_mod.set_quality_enabled(bool(value))
        return {"ok": True}

    def open_external(self, url):
        import webbrowser
        webbrowser.open(url)


def run(initial_dir=None):
    api = Api()
    index_path = os.path.join(WEBUI_DIR, "index.html")
    window = webview.create_window(
        "Nyxtral",
        url=Path(index_path).as_uri(),
        js_api=api,
        width=1440, height=900, min_size=(1100, 700),
        frameless=True, easy_drag=False,
        background_color="#0f1117",
    )
    api.set_window(window)

    if initial_dir:
        def send_initial():
            time.sleep(0.6)
            _push(window, "setInitialFolder", initial_dir)
        threading.Thread(target=send_initial, daemon=True).start()

    webview.start()
