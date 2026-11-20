# -*- coding: utf-8 -*-
"""
Nyxtral — application entry point.

Usage:
    Nyxtral.exe                     -> opens the window; choose the folder inside the app
    Nyxtral.exe "C:\\path\\to\\project"  -> opens the window with that folder preselected
                                                    and immediately starts the first scan
"""

import logging
import os
import sys
import traceback
from datetime import datetime

log = logging.getLogger("main")


def _log_path():
    import config
    return os.path.join(config.app_data_dir(), "crash.log")


def _write_crash_log(context):
    """Append the current traceback to crash.log and echo it to the console. Returns the text written."""
    text = f"\n--- {datetime.now().isoformat()} — {context} ---\n{traceback.format_exc()}"
    print(text)
    try:
        with open(_log_path(), "a", encoding="utf-8") as f:
            f.write(text)
    except OSError as exc:
        print(f"WARNING: could not write the crash log '{_log_path()}': {exc}. "
              "The error details above are only available in this console.")
    return text


def _report_crash(context):
    _write_crash_log(context)
    log.critical("Unexpected error during: %s", context, exc_info=True)
    try:
        import tkinter.messagebox as messagebox
        messagebox.showerror(
            "Nyxtral — Error",
            f"An unexpected error occurred during: {context}.\n\n"
            f"What happened: the application hit a problem it could not recover from "
            f"and had to stop.\n\n"
            f"Details were saved to:\n{_log_path()}\n\n"
            f"What you can try:\n"
            f"  • Restart the application.\n"
            f"  • Make sure the project folder exists and you have permission to read it.\n"
            f"  • If the problem persists, report it and attach the file above "
            f"(it contains the technical details needed to diagnose the problem).",
        )
    except Exception as exc:
        # No GUI toolkit available: the details are already in the console and in the log files.
        log.error("Could not show the error dialog (%s). See '%s' for the error details.", exc, _log_path())


def _log_only(context):
    """Write the error to crash.log without showing a popup (used when a fallback is available)."""
    _write_crash_log(context)
    log.error("Error during: %s (see crash.log for the full traceback)", context)


def main():
    try:
        import config
        config.setup_logging()
    except Exception as exc:
        print(f"WARNING: logging could not be initialised ({exc}). Continuing without a log file.")

    initial_dir = sys.argv[1] if len(sys.argv) > 1 else None
    if initial_dir and not os.path.isdir(initial_dir):
        log.warning("The folder passed on the command line does not exist or is not a directory: '%s'. "
                    "Choose a folder inside the application instead.", initial_dir)

    # 1) Modern interface (HTML/CSS in a native window, via pywebview)
    try:
        import webview_app
        webview_app.run(initial_dir)
        return
    except Exception:
        _log_only("starting the modern interface (webview): falling back to Tkinter")
        log.warning("The modern interface could not start (is the WebView2 runtime installed? "
                    "is pywebview installed?). Falling back to the basic Tkinter interface.")

    # 2) Fallback: Tkinter interface, if the first one fails to start
    #    (e.g. WebView2 not available on a very old Windows version)
    try:
        from gui import App
    except Exception:
        _report_crash("starting the application (import)")
        sys.exit(1)

    try:
        app = App(initial_dir=initial_dir)
        app.run()
    except Exception:
        _report_crash("running the application")
        sys.exit(1)


if __name__ == "__main__":
    main()
