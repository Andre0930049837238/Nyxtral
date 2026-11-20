# -*- coding: utf-8 -*-
"""Tests for the dependency check, WITHOUT network access (OSV.dev is mocked). Run: python tools/test_dependency_scan.py"""
import json, os, sys, tempfile, urllib.error
sys.path.insert(0, os.path.join(os.path.dirname(os.path.abspath(__file__)), ".."))
import dependency_scan as D

bad = 0
def check(name, got, exp):
    global bad
    ok = got == exp; bad += not ok
    print(("OK   " if ok else "FAIL ") + name + ("" if ok else f"   expected={exp!r} got={got!r}"))

def write(root, rel, text):
    p = os.path.join(root, rel); os.makedirs(os.path.dirname(p), exist_ok=True)
    open(p, "w", encoding="utf-8").write(text); return p

t = tempfile.mkdtemp()
p = write(t, "requirements.txt", "requests==2.19.0  # old\nflask[async]==2.0.1\nurllib3==1.26.0 ; python_version>'3'\n"
          "Django>=3.0\nnumpy==1.0.* \nfoo==1.0 \\\n    --hash=sha256:abc\n-r other.txt\n# comment\n")
check("requirements: comments, extras, markers, hashes", D.parse_requirements_txt(p),
      ([("requests", "2.19.0"), ("flask", "2.0.1"), ("urllib3", "1.26.0"), ("foo", "1.0")], ["Django", "numpy"]))

pj = write(t, "package.json", json.dumps({"dependencies": {"a": "1.2.3", "b": "^2.0.0", "c": "git+https://x/y.git#1.0",
      "d": "file:../d", "e": "workspace:*", "f": "user/repo", "g": "npm:h@1.0.0"}}))
check("package.json: exact versions only", D.parse_package_json(pj), ([("a", "1.2.3")], ["b", "c", "d", "e", "f", "g"]))

check("severity: LOW ranks below MEDIUM", sorted(["LOW", "MEDIUM", "HIGH", "CRITICAL"], key=lambda s: D._SEV_RANK[s]),
      ["CRITICAL", "HIGH", "MEDIUM", "LOW"])
check("CVSS 9.8", D._cvss3_score("CVSS:3.1/AV:N/AC:L/PR:N/UI:N/S:U/C:H/I:H/A:H"), 9.8)

class Resp:
    def __init__(s, d): s.d = json.dumps(d).encode()
    def read(s): return s.d
    def __enter__(s): return s
    def __exit__(s, *a): pass

VULN = {"id": "GHSA-x", "summary": "flaw", "severity": [], "database_specific": {"severity": "MODERATE"}}
LOW = {"id": "GHSA-l", "summary": "minor", "severity": [], "database_specific": {"severity": "LOW"}}
def fake(vulnerable_names, mode="ok"):
    def urlopen(req, timeout=0):
        body = json.loads(req.data.decode())
        if mode == "net": raise urllib.error.URLError("offline")
        if mode == "429": raise urllib.error.HTTPError(req.full_url, 429, "x", {}, None)
        if req.full_url.endswith("querybatch"):
            return Resp({"results": [{"vulns": [{"id": "x"}]} if q["package"]["name"] in vulnerable_names else {} for q in body["queries"]]})
        return Resp({"vulns": [LOW, VULN] if body["package"]["name"] in vulnerable_names else []})
    return urlopen

import urllib.request
real = urllib.request.urlopen
root = tempfile.mkdtemp()
write(root, "requirements.txt", "requests==2.19.0  # old\nflask[async]==2.0.1\nDjango>=3.0\n")
try:
    urllib.request.urlopen = fake({"requests"})
    f, checked, skipped, err = D.check_dependencies(root)
    check("dependencies: 1 vulnerable + 1 clean checked, 1 unverifiable", (len(f), checked, skipped, err), (1, 2, 1, None))
    check("dependencies: the 'worst' severity is MEDIUM, not LOW", f[0]["severity"], "MEDIUM")
    urllib.request.urlopen = fake(set(), "net")
    check("dependencies: network unavailable", D.check_dependencies(root)[3].startswith("Could not contact"), True)
    urllib.request.urlopen = fake(set(), "429")
    check("dependencies: rate limit", D.check_dependencies(root)[3], "OSV.dev is rate-limiting requests: wait a few minutes and try again.")
    D.MAX_PACKAGES_TOTAL = 1
    urllib.request.urlopen = fake(set())
    f, checked, skipped, err = D.check_dependencies(root)
    check("dependencies: packages beyond the limit count as unchecked", (checked, skipped), (1, 2))
finally:
    urllib.request.urlopen = real

print(f"\n{'all tests passed' if not bad else str(bad) + ' tests FAILED (see the FAIL lines above)'}")
sys.exit(1 if bad else 0)
