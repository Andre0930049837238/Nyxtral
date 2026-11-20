# -*- coding: utf-8 -*-
"""
dependency_scan.py
=====================
Checks whether the dependencies declared by the project (requirements.txt
for Python, package.json for Node) have known vulnerabilities, by querying
the free public OSV.dev database (Open Source Vulnerabilities — the same
database used by GitHub for Dependabot alerts). No API key required.

Unlike the AST/pattern engines (which read the code), this engine only reads
the files that declare dependencies and makes a network request for each
package. For this reason it is a SEPARATE, on-demand check (dedicated button
in the GUI), not part of the automatic scan_directory run: it requires
internet access, and on a project with many dependencies it may take a few
extra seconds.

Honest limitations:
  - It only checks EXACT versions. For requirements.txt/package.json entries
    with a "range" requirement (e.g. "requests>=2.0"), we try to resolve the
    version that is ACTUALLY installed by looking, in order, at: a
    package-lock.json/npm-shrinkwrap.json next to the package.json, or a
    venv/.venv/env folder containing the already-installed Python packages.
    If nothing is found, the package stays "unverifiable" instead of being
    guessed;
  - It covers requirements.txt, package.json, package-lock.json/
    npm-shrinkwrap.json, Cargo.lock and local virtualenvs (not
    pyproject.toml, nor poetry.lock/Pipfile.lock, for now);
  - A package with no known vulnerabilities in OSV.dev is not an absolute
    guarantee of safety, only that there are no public reports.
"""

import json
import logging
import os
import re
import urllib.error
import urllib.request

log = logging.getLogger(__name__)

OSV_QUERY_URL = "https://api.osv.dev/v1/query"
OSV_BATCH_URL = "https://api.osv.dev/v1/querybatch"
MAX_PACKAGES_TOTAL = 1500     # overall limit of packages checked in batches
MAX_PACKAGES_CHECKED = 150   # safety limit to avoid long blocking on huge repositories
REQUEST_TIMEOUT = 8


class DependencyScanError(Exception):
    pass


# ---------------------------------------------------------------------------
# Parsing dependency files
# ---------------------------------------------------------------------------

_EXTRAS = r"(?:\[[^\]]*\])?"   # e.g. flask[async]==2.0.1
_REQ_LINE_RE = re.compile(r"^\s*([A-Za-z0-9_.\-]+)" + _EXTRAS + r"\s*==\s*([A-Za-z0-9_.\-]+)\s*(?:;.*)?$")
_REQ_RANGE_RE = re.compile(r"^\s*([A-Za-z0-9_.\-]+)" + _EXTRAS + r"\s*([<>=!~].*)$")
_REQ_BARE_NAME_RE = re.compile(r"^\s*([A-Za-z0-9_.\-]+)\s*$")


def parse_requirements_txt(path):
    """Return (pinned, non_pinned): packages with an exact version, and names with a range/unverifiable."""
    pinned, non_pinned = [], []
    try:
        with open(path, "r", encoding="utf-8", errors="ignore") as f:
            lines = f.read().splitlines()
    except OSError as exc:
        log.warning("Could not read '%s' (%s). Its dependencies will not be checked. "
                    "Verify that the file exists and that you have read permission.", path, exc)
        return pinned, non_pinned

    for line in lines:
        line = re.sub(r"\s+#.*$", "", line).rstrip("\\ \t").strip()   # trailing comment, "\" line continuation
        line = re.sub(r"\s+--hash=\S+", "", line).strip()           # verification hash (pip --require-hashes)
        if not line or line.startswith("#") or line.startswith("-"):
            continue
        m = _REQ_LINE_RE.match(line)
        if m:
            pinned.append((m.group(1), m.group(2)))
            continue
        m2 = _REQ_RANGE_RE.match(line)
        if m2:
            non_pinned.append(m2.group(1))
            continue
        m3 = _REQ_BARE_NAME_RE.match(line)
        if m3:
            non_pinned.append(m3.group(1))
    return pinned, non_pinned


_SEMVER_PREFIX_RE = re.compile(r"^[^\d]*")


def parse_package_json(path):
    """Return (pinned, non_pinned) for the npm dependencies declared in package.json."""
    pinned, non_pinned = [], []
    try:
        with open(path, "r", encoding="utf-8", errors="ignore") as f:
            data = json.load(f)
    except OSError as exc:
        log.warning("Could not read '%s' (%s). Its dependencies will not be checked. "
                    "Verify that the file exists and that you have read permission.", path, exc)
        return pinned, non_pinned
    except json.JSONDecodeError as exc:
        log.warning("'%s' is not valid JSON (%s). Its dependencies will not be checked. "
                    "Fix the syntax error (often a trailing comma or a merge-conflict marker) "
                    "and run the dependency check again.", path, exc)
        return pinned, non_pinned

    deps = {}
    for key in ("dependencies", "devDependencies"):
        deps.update(data.get(key) or {})

    for name, version_spec in deps.items():
        if not isinstance(version_spec, str):
            continue
        if re.match(r"^(?:[a-z+]+:|[\w.\-]+/[\w.\-]+$)", version_spec):   # git+https:, file:, workspace:, npm:, user/repo
            non_pinned.append(name)
            continue
        if version_spec.startswith(("^", "~", ">", "<", "*", "x")) or version_spec in ("latest", "") \
                or "||" in version_spec or " - " in version_spec:
            non_pinned.append(name)
            continue
        clean = _SEMVER_PREFIX_RE.sub("", version_spec).strip()
        if re.match(r"^\d+(\.\d+){0,2}", clean):
            pinned.append((name, clean))
        else:
            non_pinned.append(name)
    return pinned, non_pinned


def parse_cargo_lock(path):
    """
    Read a Cargo.lock and return [(name, version)] for the packages downloaded from the registry
    (crates.io): these are the versions actually used, hence exact. Local (path) and git
    packages are ignored.
    """
    pinned = []
    try:
        with open(path, "r", encoding="utf-8", errors="ignore") as f:
            text = f.read()
    except OSError as exc:
        log.warning("Could not read '%s' (%s). Its Rust dependencies will not be checked. "
                    "Verify that the file exists and that you have read permission.", path, exc)
        return pinned
    for block in re.split(r"(?m)^\[\[package\]\]\s*$", text)[1:]:
        name = re.search(r'(?m)^name\s*=\s*"([^"]+)"', block)
        version = re.search(r'(?m)^version\s*=\s*"([^"]+)"', block)
        source = re.search(r'(?m)^source\s*=\s*"([^"]+)"', block)
        if name and version and source and source.group(1).startswith("registry+"):
            pinned.append((name.group(1), version.group(1)))
    return pinned


def _query_osv_batch(items, timeout=30):
    """Query OSV in batches (items: [(name, version, ecosystem)]). Returns the subset of items that have vulnerabilities."""
    vulnerable = []
    for start in range(0, len(items), 500):
        chunk = items[start:start + 500]
        payload = {"queries": [{"package": {"name": n, "ecosystem": e}, "version": v} for n, v, e in chunk]}
        req = urllib.request.Request(OSV_BATCH_URL, data=json.dumps(payload).encode("utf-8"),
                                     headers={"Content-Type": "application/json"}, method="POST")
        with urllib.request.urlopen(req, timeout=timeout) as resp:
            results = json.loads(resp.read().decode("utf-8")).get("results", [])
        for item, res in zip(chunk, results):
            if res.get("vulns"):
                vulnerable.append(item)
    return vulnerable


def find_dependency_files(root_dir):
    """Find requirements*.txt, package.json and Cargo.lock in the folder (does not descend into node_modules/venv)."""
    import scanner as scanner_mod  # local import: avoids a module-level import cycle
    found = []
    for current_dir, dirnames, filenames in os.walk(root_dir):
        keep = []
        for d in dirnames:
            if scanner_mod._is_ignored_dir(d):
                continue
            full = os.path.join(current_dir, d)
            if os.path.islink(full):
                continue
            keep.append(d)
        dirnames[:] = keep
        for filename in filenames:
            if filename in ("package.json", "Cargo.lock") or (filename.startswith("requirements") and filename.endswith(".txt")):
                found.append(os.path.join(current_dir, filename))
    return found


def parse_package_lock(path):
    """
    Read a package-lock.json or npm-shrinkwrap.json and return {name: version}
    with the versions ACTUALLY resolved by npm — far more reliable than the
    ranges declared in package.json. Handles both the npm v7+ format
    ("packages") and the older v5/v6 format ("dependencies", nested recursively).
    """
    resolved = {}
    try:
        with open(path, "r", encoding="utf-8", errors="ignore") as f:
            data = json.load(f)
    except OSError as exc:
        log.warning("Could not read lock file '%s' (%s). Range-based npm dependencies will be "
                    "reported as unverifiable.", path, exc)
        return resolved
    except json.JSONDecodeError as exc:
        log.warning("Lock file '%s' is not valid JSON (%s). Range-based npm dependencies will be "
                    "reported as unverifiable. Regenerate it with 'npm install'.", path, exc)
        return resolved

    if isinstance(data.get("packages"), dict):
        for key, info in data["packages"].items():
            if not key or not isinstance(info, dict):
                continue
            version = info.get("version")
            if not version:
                continue
            name = key.rsplit("node_modules/", 1)[-1]
            resolved[name] = version
    elif isinstance(data.get("dependencies"), dict):
        def walk(deps):
            for name, info in deps.items():
                if not isinstance(info, dict):
                    continue
                version = info.get("version")
                if version:
                    resolved[name] = version
                nested = info.get("dependencies")
                if isinstance(nested, dict):
                    walk(nested)
        walk(data["dependencies"])

    return resolved


_DIST_INFO_RE = re.compile(r"^([A-Za-z0-9_.\-]+)-([0-9][A-Za-z0-9_.\-]*?)(?:\.dist-info|\.egg-info)$")


def find_venv_packages(root_dir):
    """
    Look for a Python virtualenv inside the project (venv/.venv/env) and read
    the packages ACTUALLY installed from the *.dist-info folders in
    site-packages — this gives the exact version regardless of what
    requirements.txt says. Returns {normalized_name: version}.
    """
    resolved = {}
    for venv_name in ("venv", ".venv", "env", ".env"):
        venv_path = os.path.join(root_dir, venv_name)
        if not os.path.isdir(venv_path):
            continue
        for site_packages in _find_site_packages_dirs(venv_path):
            try:
                entries = os.listdir(site_packages)
            except OSError as exc:
                log.warning("Could not list the virtualenv folder '%s' (%s). Installed versions "
                            "from this environment will not be used.", site_packages, exc)
                continue
            for entry in entries:
                m = _DIST_INFO_RE.match(entry)
                if m:
                    norm_name = m.group(1).lower().replace("_", "-")
                    resolved[norm_name] = m.group(2)
    return resolved


def _find_site_packages_dirs(venv_path):
    paths = []
    win_path = os.path.join(venv_path, "Lib", "site-packages")  # Windows venv
    if os.path.isdir(win_path):
        paths.append(win_path)
    lib_dir = os.path.join(venv_path, "lib")  # macOS/Linux venv: lib/pythonX.Y/site-packages
    if os.path.isdir(lib_dir):
        try:
            for entry in os.listdir(lib_dir):
                sp = os.path.join(lib_dir, entry, "site-packages")
                if os.path.isdir(sp):
                    paths.append(sp)
        except OSError as exc:
            log.warning("Could not list '%s' (%s). Packages from this virtualenv will not be used.", lib_dir, exc)
    return paths


# ---------------------------------------------------------------------------
# Querying OSV.dev
# ---------------------------------------------------------------------------

def _query_osv(name, version, ecosystem, timeout=REQUEST_TIMEOUT):
    payload = {"package": {"name": name, "ecosystem": ecosystem}, "version": version}
    req = urllib.request.Request(
        OSV_QUERY_URL,
        data=json.dumps(payload).encode("utf-8"),
        headers={"Content-Type": "application/json"},
        method="POST",
    )
    with urllib.request.urlopen(req, timeout=timeout) as resp:
        return json.loads(resp.read().decode("utf-8"))


def _cvss3_score(vector):
    """CVSS v3.x base score computed from the vector (e.g. CVSS:3.1/AV:N/AC:L/PR:N/UI:N/S:U/C:H/I:H/A:H); None if it is not v3."""
    if not vector.startswith(("CVSS:3.0/", "CVSS:3.1/")):
        return None
    m = dict(p.split(":", 1) for p in vector.split("/")[1:] if ":" in p)
    try:
        changed = m["S"] == "C"
        av = {"N": 0.85, "A": 0.62, "L": 0.55, "P": 0.2}[m["AV"]]
        ac = {"L": 0.77, "H": 0.44}[m["AC"]]
        pr = {"N": 0.85, "L": 0.68 if changed else 0.62, "H": 0.5 if changed else 0.27}[m["PR"]]
        ui = {"N": 0.85, "R": 0.62}[m["UI"]]
        cia = {"H": 0.56, "L": 0.22, "N": 0.0}
        iss = 1 - (1 - cia[m["C"]]) * (1 - cia[m["I"]]) * (1 - cia[m["A"]])
    except KeyError:
        return None
    impact = 7.52 * (iss - 0.029) - 3.25 * (iss - 0.02) ** 15 if changed else 6.42 * iss
    if impact <= 0:
        return 0.0
    expl = 8.22 * av * ac * pr * ui
    raw = min((1.08 if changed else 1.0) * (impact + expl), 10)
    return float(int(raw * 10 + 0.9999)) / 10   # round up to 1 decimal place


def _severity_from_score(score):
    if score >= 9.0:
        return "CRITICAL"
    if score >= 7.0:
        return "HIGH"
    if score >= 4.0:
        return "MEDIUM"
    return "LOW"


_SEV_RANK = {"CRITICAL": 0, "HIGH": 1, "MEDIUM": 2, "LOW": 3}


def _severity_from_vuln(vuln):
    """Severity of an OSV vulnerability: computed CVSS v3 score, otherwise the database label (GHSA), otherwise a cautious default."""
    label = ((vuln.get("database_specific") or {}).get("severity") or "").upper()
    for sev in vuln.get("severity", []) or []:
        vec = sev.get("score", "")
        score = _cvss3_score(vec)
        if score is None and re.fullmatch(r"\d+(\.\d+)?", vec.strip()):
            score = float(vec)
        if score is not None:
            return _severity_from_score(score)
    if label in ("CRITICAL", "HIGH", "LOW"):
        return label
    if label == "MODERATE" or label == "MEDIUM":
        return "MEDIUM"
    return "HIGH"   # no score available (or CVSS v4): better to report cautiously than to ignore


def _network_message(exc):
    if isinstance(exc, urllib.error.HTTPError):
        if exc.code == 429:
            return "OSV.dev is rate-limiting requests: wait a few minutes and try again."
        return (f"OSV.dev responded with an error (HTTP {exc.code}): this is usually temporary, "
                "try again later.")
    return ("Could not contact OSV.dev: check your internet connection, proxy or firewall settings. "
            f"Details: {getattr(exc, 'reason', exc)}")


def check_dependencies(root_dir, progress_callback=None, stop_flag=None):
    """
    Check the project dependencies against OSV.dev.
    Returns (findings, checked_count, skipped_count, error_message_or_None).
    error_message_or_None is set only for a GENERAL error (e.g. no
    connection), not for individual packages that fail.
    """
    dep_files = find_dependency_files(root_dir)
    if not dep_files:
        return [], 0, 0, None

    venv_packages = find_venv_packages(root_dir)  # {} if the project has no virtualenv

    to_check = []   # (name, version, ecosystem, rel_file)
    skipped_names = []

    for path in dep_files:
        rel_path = os.path.relpath(path, root_dir)
        filename = os.path.basename(path)

        if filename == "package.json":
            pinned, non_pinned = parse_package_json(path)
            ecosystem = "npm"
            lock_resolved = {}
            for lock_name in ("package-lock.json", "npm-shrinkwrap.json"):
                lock_path = os.path.join(os.path.dirname(path), lock_name)
                if os.path.isfile(lock_path):
                    lock_resolved = parse_package_lock(lock_path)
                    break
            for name in non_pinned:
                if name in lock_resolved:
                    pinned.append((name, lock_resolved[name]))
                else:
                    skipped_names.append(name)
        elif filename == "Cargo.lock":
            pinned, non_pinned = parse_cargo_lock(path), []
            ecosystem = "crates.io"
        else:
            pinned, non_pinned = parse_requirements_txt(path)
            ecosystem = "PyPI"
            for name in non_pinned:
                norm_name = name.lower().replace("_", "-")
                if norm_name in venv_packages:
                    pinned.append((name, venv_packages[norm_name]))
                else:
                    skipped_names.append(name)

        for name, version in pinned:
            to_check.append((name, version, ecosystem, rel_path))

    skipped_count = len(skipped_names)
    all_items = list(dict.fromkeys(to_check))   # de-duplicated (same package, same version, same file)
    if len(all_items) > MAX_PACKAGES_TOTAL:     # beyond the limit: we do not pretend they were checked
        log.warning("The project declares %d packages; only the first %d will be checked and the "
                    "rest are counted as skipped.", len(all_items), MAX_PACKAGES_TOTAL)
        skipped_count += len(all_items) - MAX_PACKAGES_TOTAL
        all_items = all_items[:MAX_PACKAGES_TOTAL]

    findings = []
    checked = 0
    network_error = None
    to_check = []

    if all_items:   # first a fast batch check, then the details only for vulnerable packages
        try:
            vulnerable = _query_osv_batch([(n, v, e) for n, v, e, _ in all_items])
            vset = {(n, v, e) for n, v, e in vulnerable}
            to_check = [x for x in all_items if (x[0], x[1], x[2]) in vset]
            checked += len(all_items) - len(to_check)
        except urllib.error.URLError as exc:
            network_error = _network_message(exc)
            log.warning("Dependency check aborted: %s", network_error)
        except Exception as exc:
            log.warning("The batch query to OSV.dev failed (%s: %s); falling back to one-by-one "
                        "queries for up to %d packages.", type(exc).__name__, exc, MAX_PACKAGES_CHECKED)
            to_check = all_items[:MAX_PACKAGES_CHECKED]   # the batch failed: query one by one, within the limit
            skipped_count += len(all_items) - len(to_check)

    for i, (name, version, ecosystem, rel_path) in enumerate(to_check if not network_error else [], start=1):
        if stop_flag is not None and getattr(stop_flag, "stop", False):
            break
        if progress_callback:
            progress_callback(i, len(to_check), name)
        try:
            result = _query_osv(name, version, ecosystem)
        except urllib.error.HTTPError as exc:
            if exc.code == 429:
                network_error = "OSV.dev is rate-limiting requests: wait a few minutes and try again."
                log.warning("Dependency check stopped: %s", network_error)
                break
            log.warning("OSV.dev returned HTTP %s for %s %s; the package was skipped.", exc.code, name, version)
            skipped_count += 1   # server error on this package: it is not "checked and clean"
            continue
        except urllib.error.URLError as exc:
            network_error = _network_message(exc)
            log.warning("Dependency check stopped: %s", network_error)
            break
        except Exception as exc:
            log.warning("Unexpected error while checking %s %s (%s: %s); the package was skipped.",
                        name, version, type(exc).__name__, exc)
            skipped_count += 1
            continue

        checked += 1
        vulns = result.get("vulns") or []
        if not vulns:
            continue

        vulns_sorted = sorted(vulns, key=lambda v: _SEV_RANK.get(_severity_from_vuln(v), 9))
        worst = vulns_sorted[0]
        severity = _severity_from_vuln(worst)
        ids = ", ".join(v.get("id", "?") for v in vulns[:5])
        summary = worst.get("summary") or (worst.get("details", "") or "")[:200] \
            or "Known vulnerability, no summary available."

        findings.append({
            "id": "DEP-VULN",
            "name": f"Dependency with a known vulnerability: {name} {version}",
            "severity": severity,
            "confidence": "confirmed",
            "confidence_label": "Confirmed: exact match in the public OSV.dev database",
            "file": rel_path,
            "line": 0,
            "snippet": f"{name} == {version}",
            "description": f"{summary} (ID: {ids})",
            "impact": "This library, in this exact version, has a publicly known and documented "
                      "vulnerability. If you use it in production, anyone who knows about that "
                      "vulnerability (it is public, anyone can look it up) already knows how to try to "
                      "exploit it.",
            "recommendation": f"Update {name} to a newer version that fixes the vulnerability "
                               f"(check the package's release notes), or search for {ids} for "
                               f"details and a possible workaround.",
            "engine": "dependency",
        })

    return findings, checked, skipped_count, network_error
