# -*- coding: utf-8 -*-
"""
cache.py
Incremental cache: stores, for every file, the content hash and the findings
produced by the last scan. If a file has not changed, its content is not
re-analyzed on the next scan: the stored findings are reused.

Essential for continuous use on large projects: the first scan is complete
(as slow as it needs to be), while all later scans analyze only what has
actually changed.

The cache file is saved inside the scanned folder as a hidden file, so it
travels with the project (you may also add it to .gitignore).
"""

import hashlib
import json
import logging
import os

log = logging.getLogger(__name__)

CACHE_FILENAME = ".nyxtral_cache.json"
CACHE_VERSION = 3  # v3: Python AST analysis is project-level (separate cache)


def _cache_path(root_dir):
    return os.path.join(root_dir, CACHE_FILENAME)


def load_cache(root_dir):
    path = _cache_path(root_dir)
    if not os.path.isfile(path):
        return {"version": CACHE_VERSION, "files": {}}
    try:
        with open(path, "r", encoding="utf-8") as f:
            data = json.load(f)
        if data.get("version") != CACHE_VERSION:
            log.info(
                "The cache file '%s' was created by a different version (found %r, expected %r). "
                "It will be rebuilt; this scan will be a full scan.",
                path, data.get("version"), CACHE_VERSION)
            return {"version": CACHE_VERSION, "files": {}}
        return data
    except json.JSONDecodeError as exc:
        log.warning(
            "The cache file '%s' is corrupt (%s). It will be discarded and rebuilt; this scan "
            "will be a full scan.", path, exc)
        return {"version": CACHE_VERSION, "files": {}}
    except (OSError, AttributeError) as exc:
        log.warning(
            "Could not read the cache file '%s' (%s). Continuing without cache; this scan will "
            "be a full scan.", path, exc)
        return {"version": CACHE_VERSION, "files": {}}


def save_cache(root_dir, cache_data):
    path = _cache_path(root_dir)
    try:
        with open(path, "w", encoding="utf-8") as f:
            json.dump(cache_data, f, ensure_ascii=False)
    except OSError as exc:
        # The cache is only an optimization: if it cannot be written, carry on without it.
        log.warning(
            "Could not write the cache file '%s' (%s). The scan results are unaffected, but the "
            "next scan will not be incremental. Check that the folder is writable.", path, exc)


def content_hash(content):
    return hashlib.sha256(content.encode("utf-8", errors="ignore")).hexdigest()


def get_cached_findings(cache_data, rel_path, content):
    """Return the cached findings if the file is unchanged, otherwise None."""
    entry = cache_data.get("files", {}).get(rel_path)
    if entry is None:
        return None
    if entry.get("hash") != content_hash(content):
        return None
    return entry.get("findings", [])


def update_cache(cache_data, rel_path, content, findings):
    cache_data.setdefault("files", {})[rel_path] = {
        "hash": content_hash(content),
        "findings": findings,
    }


def prune_cache(cache_data, existing_rel_paths):
    """Remove from the cache the files that no longer exist in the project."""
    files = cache_data.get("files", {})
    for rel_path in list(files.keys()):
        if rel_path not in existing_rel_paths:
            del files[rel_path]
