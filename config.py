# -*- coding: utf-8 -*-
"""
config.py
Manages the application's local configuration (currently: the code-quality toggle). It is stored in a file inside
the user's data directory, NEVER in the source code and NEVER inside the
scanned project folder (so it cannot accidentally end up in a Git repository).

Transparency note: this is not a secure vault (it is not encrypted with a
password), it is merely stored outside the repository. On a machine shared by
several people, consider entering the key every time instead of saving it.

This module also hosts the central logging setup (see ``setup_logging``).
"""

import json
import logging
import logging.handlers
import os
import sys

APP_DIR_NAME = "Nyxtral"
CONFIG_FILENAME = "config.json"
LOG_FILENAME = "scanner.log"

log = logging.getLogger(__name__)
_logging_configured = False


def app_data_dir():
    """Application data folder, in the conventional location for each operating system."""
    if sys.platform.startswith("win"):
        base = os.environ.get("APPDATA") or os.path.expanduser("~")
    elif sys.platform == "darwin":
        base = os.path.expanduser("~/Library/Application Support")
    else:
        base = os.environ.get("XDG_CONFIG_HOME") or os.path.expanduser("~/.config")
    path = os.path.join(base, APP_DIR_NAME)
    os.makedirs(path, exist_ok=True)
    return path


def log_path():
    """Full path of the rotating application log file."""
    return os.path.join(app_data_dir(), LOG_FILENAME)


def setup_logging(level=logging.INFO):
    """Configure application-wide logging: a rotating file (scanner.log) plus the console.

    Safe to call more than once (subsequent calls are no-ops). If the log file
    cannot be created (read-only profile, full disk, permissions), the
    application keeps running with console logging only and prints a warning.
    """
    global _logging_configured
    if _logging_configured:
        return
    _logging_configured = True

    root = logging.getLogger()
    root.setLevel(level)
    formatter = logging.Formatter("%(asctime)s [%(levelname)s] %(name)s: %(message)s")

    console = logging.StreamHandler()
    console.setFormatter(formatter)
    root.addHandler(console)

    try:
        file_handler = logging.handlers.RotatingFileHandler(
            log_path(), maxBytes=1_000_000, backupCount=3, encoding="utf-8")
        file_handler.setFormatter(formatter)
        root.addHandler(file_handler)
    except OSError as exc:
        root.warning(
            "Could not open the log file '%s' (%s). Logging to the console only. "
            "Check that the folder exists and that you have write permission to it.",
            LOG_FILENAME, exc)


def _config_path():
    return os.path.join(app_data_dir(), CONFIG_FILENAME)


def load_config():
    path = _config_path()
    if not os.path.isfile(path):
        return {}
    try:
        with open(path, "r", encoding="utf-8") as f:
            return json.load(f)
    except json.JSONDecodeError as exc:
        log.warning(
            "The configuration file '%s' is corrupted (%s). Default settings will be used; "
            "saving new settings will overwrite it. Delete the file to silence this warning.",
            path, exc)
        return {}
    except OSError as exc:
        log.warning(
            "The configuration file '%s' could not be read (%s). Default settings will be used. "
            "Check the file permissions.", path, exc)
        return {}


def save_config(data):
    path = _config_path()
    try:
        with open(path, "w", encoding="utf-8") as f:
            json.dump(data, f, ensure_ascii=False, indent=2)
    except OSError as exc:
        log.error(
            "Could not save the configuration file '%s' (%s). Your settings will not persist "
            "after the application closes. Check that the folder is writable and the disk is not full.",
            path, exc)


def get_quality_enabled():
    """The code-quality check is enabled by default."""
    return bool(load_config().get("quality_enabled", True))


def set_quality_enabled(value):
    data = load_config()
    data["quality_enabled"] = bool(value)
    save_config(data)
