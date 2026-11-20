# -*- coding: utf-8 -*-
"""
baseline.py
Lets the user mark a finding as "already reviewed / accepted false positive"
so that later scans do not show it again as new. Essential for day-to-day
use: without a baseline, every scan would re-report everything you already
evaluated yesterday.

A finding's fingerprint is computed from (rule_id, file_path, snippet) and
NOT from the line number: if you add code above it and the line shifts, the
finding is still recognized as "already seen".
"""

import hashlib
import json
import logging
import os

log = logging.getLogger(__name__)

BASELINE_FILENAME = ".nyxtral_baseline.json"


def _baseline_path(root_dir):
    return os.path.join(root_dir, BASELINE_FILENAME)


def fingerprint(finding):
    raw = f"{finding['id']}|{finding['file']}|{finding.get('snippet','')}"
    return hashlib.sha256(raw.encode("utf-8", errors="ignore")).hexdigest()


def load_baseline(root_dir):
    path = _baseline_path(root_dir)
    if not os.path.isfile(path):
        return {}
    try:
        with open(path, "r", encoding="utf-8") as f:
            return json.load(f)
    except json.JSONDecodeError as exc:
        log.warning(
            "The baseline file '%s' is not valid JSON (%s). Suppressed findings will be shown "
            "as active again. Fix or delete the file to rebuild the baseline.", path, exc)
        return {}
    except OSError as exc:
        log.warning(
            "Could not read the baseline file '%s' (%s). Suppressed findings will be shown as "
            "active again. Check the file permissions.", path, exc)
        return {}


def save_baseline(root_dir, baseline_data):
    path = _baseline_path(root_dir)
    try:
        with open(path, "w", encoding="utf-8") as f:
            json.dump(baseline_data, f, ensure_ascii=False, indent=2)
    except OSError as exc:
        log.error(
            "Could not save the baseline file '%s' (%s). The suppression was NOT persisted and "
            "will be lost. Check that the project folder is writable and the disk is not full.",
            path, exc)


def suppress(root_dir, finding, reason=""):
    baseline_data = load_baseline(root_dir)
    baseline_data[fingerprint(finding)] = {
        "rule": finding["id"],
        "file": finding["file"],
        "name": finding["name"],
        "reason": reason or "Ignored by the user",
    }
    save_baseline(root_dir, baseline_data)


def unsuppress(root_dir, finding):
    baseline_data = load_baseline(root_dir)
    baseline_data.pop(fingerprint(finding), None)
    save_baseline(root_dir, baseline_data)


def annotate(findings, baseline_data):
    """Add the 'fingerprint' and 'suppressed' (bool) fields to every finding."""
    for f in findings:
        fp = fingerprint(f)
        f["fingerprint"] = fp
        f["suppressed"] = fp in baseline_data
    return findings
