# -*- coding: utf-8 -*-
"""
exclusions.py
================
List of files/folders excluded from scanning, managed by the user (e.g. via
the "Ignore this file" context menu in the results table).

Difference from baseline.py:
  - baseline.py suppresses a SINGLE finding that was already reported (the
    file is still scanned; only that specific finding is no longer shown as
    active);
  - exclusions.py prevents a file from being READ and analyzed at all on the
    next scan (useful for test files, fake data, fixtures and generated
    folders that are not worth analyzing).

An excluded path can be a specific file ("tests/fixtures/fake.py") or a
folder (in which case everything beneath it is excluded).
"""

import json
import logging
import os

log = logging.getLogger(__name__)

EXCLUSIONS_FILENAME = ".nyxtral_exclusions.json"


def _path(root_dir):
    return os.path.join(root_dir, EXCLUSIONS_FILENAME)


def load_exclusions(root_dir):
    """Return the sorted list of excluded relative paths (files or folders)."""
    path = _path(root_dir)
    if not os.path.isfile(path):
        return []
    try:
        with open(path, "r", encoding="utf-8") as f:
            data = json.load(f)
        paths = data.get("excluded", [])
        return sorted(set(p.replace("\\", "/") for p in paths))
    except json.JSONDecodeError as exc:
        log.warning(
            "The exclusions file '%s' is not valid JSON (%s). It will be ignored and no files "
            "will be excluded. Fix or delete the file to restore your exclusions.", path, exc)
        return []
    except OSError as exc:
        log.warning(
            "Could not read the exclusions file '%s' (%s). No files will be excluded. "
            "Check that the file exists and that you have read permission.", path, exc)
        return []
    except (AttributeError, TypeError) as exc:
        log.warning(
            "The exclusions file '%s' has an unexpected structure (%s). It will be ignored. "
            "Expected format: {\"excluded\": [\"path/one\", \"path/two\"]}.", path, exc)
        return []


def save_exclusions(root_dir, paths):
    path = _path(root_dir)
    try:
        with open(path, "w", encoding="utf-8") as f:
            json.dump({"excluded": sorted(set(paths))}, f, ensure_ascii=False, indent=2)
    except OSError as exc:
        log.error(
            "Could not save the exclusions file '%s' (%s). Your exclusion changes were NOT "
            "persisted. Check that the project folder is writable and the disk is not full.",
            path, exc)


def exclude_path(root_dir, rel_path):
    """Add a file or folder (relative path) to the exclusion list."""
    rel_path = rel_path.replace("\\", "/")
    current = load_exclusions(root_dir)
    if rel_path not in current:
        current.append(rel_path)
        save_exclusions(root_dir, current)
    return current


def include_path(root_dir, rel_path):
    """Remove a path from the exclusion list (it will be scanned again)."""
    rel_path = rel_path.replace("\\", "/")
    current = [p for p in load_exclusions(root_dir) if p != rel_path]
    save_exclusions(root_dir, current)
    return current


def is_excluded(rel_path, exclusions):
    """
    True if rel_path is explicitly excluded, or lives inside an excluded
    folder. `exclusions` is the list returned by load_exclusions().
    """
    rel_path = rel_path.replace("\\", "/")
    for excluded in exclusions:
        if rel_path == excluded:
            return True
        if rel_path.startswith(excluded.rstrip("/") + "/"):
            return True
    return False
