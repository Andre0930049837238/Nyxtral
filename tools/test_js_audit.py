# -*- coding: utf-8 -*-
"""Tests for the audit pass of JS/TS: (name, extension, code, expected CWE types). Run: python tools/test_js_audit.py"""
import os, sys
sys.path.insert(0, os.path.join(os.path.dirname(os.path.abspath(__file__)), ".."))
import js_audit as A

CASES = [
 # ---- MUST be reported ----
 ("non-constant fs", ".js", "const fs = require('fs');\nfunction f(p) { return fs.readFile(p, cb); }\n", {"CWE-22"}),
 ("non-constant exec", ".js", "const cp = require('child_process');\nfunction f(c) { cp.exec(c); }\n", {"CWE-78"}),
 ("non-constant eval", ".js", "function f(c) { eval(c); }\n", {"CWE-95"}),
 ("non-constant RegExp", ".js", "function f(p) { return new RegExp(p); }\n", {"CWE-1333"}),
 ("innerHTML from field", ".js", "function f(o) { el.innerHTML = o.html; }\n", {"CWE-79"}),
 ("dangerouslySetInnerHTML field", ".jsx", "function C(p) { return <div dangerouslySetInnerHTML={{__html: p.body}} />; }\n", {"CWE-79"}),
 ("variable href on <a>", ".jsx", "function C(p) { return <a href={p.url}>x</a>; }\n", {"CWE-79"}),
 ("rejectUnauthorized false", ".js", "const o = { rejectUnauthorized: false };\n", {"CWE-295"}),
 ("shell true", ".js", "const cp = require('child_process');\ncp.spawn('ls', [], { shell: true });\n", {"CWE-78"}),
 ("insecure gRPC", ".js", "const c = grpc.credentials.createInsecure();\n", {"CWE-319"}),
 ("noent true", ".js", "libxml.parseXml(x, { noent: true });\n", {"CWE-611"}),
 ("HTML template with variable", ".js", "function f(n) { return `<p>${n}</p>`; }\n", {"CWE-79"}),
 ("TLS disabled via env", ".js", "process.env.NODE_TLS_REJECT_UNAUTHORIZED = '0';\n", {"CWE-295"}),
 # ---- MUST NOT be reported ----
 ("constant fs", ".js", "const fs = require('fs');\nfs.readFile('/etc/app.conf', cb);\n", set()),
 ("exec constant", ".js", "const cp = require('child_process');\ncp.exec('ls -la');\n", set()),
 ("eval constant", ".js", "eval('1+1');\n", set()),
 ("constant innerHTML", ".js", "el.innerHTML = '<b>hello</b>';\n", set()),
 ("sanitized innerHTML", ".js", "function f(h) { el.innerHTML = DOMPurify.sanitize(h); }\n", set()),
 ("dangerouslySetInnerHTML simple identifier", ".jsx", "function C(p) { const h = clean(p.body); return <div dangerouslySetInnerHTML={{__html: h}} />; }\n", set()),
 ("constant href", ".jsx", "function C() { return <a href=\"/home\">x</a>; }\n", set()),
 ("href with #", ".jsx", "function C(p) { return <a href={'#' + p.id}>x</a>; }\n", set()),
 ("rejectUnauthorized true", ".js", "const o = { rejectUnauthorized: true };\n", set()),
 ("noent false", ".js", "libxml.parseXml(x, { noent: false });\n", set()),
 ("template without HTML", ".js", "function f(n) { return `hello ${n}`; }\n", set()),
 ("fs without fs import", ".js", "function f(p) { return db.readFile(p); }\n", set()),
]

def main():
    if not A.AVAILABLE:
        print("WARNING: tree-sitter JS grammar is not installed, so no tests were run. Install it with: pip install tree-sitter tree-sitter-javascript tree-sitter-typescript"); return 0
    bad = 0
    for name, ext, code, exp in CASES:
        got = {f["cwe"] for f in A.analyze_js_audit("src/app" + ext, ext, code)}
        ok = got == exp; bad += not ok
        print(("OK   " if ok else "FAIL ") + name + ("" if ok else f"   expected={sorted(exp)} got={sorted(got)}"))
    print(f"\n{len(CASES) - bad}/{len(CASES)} tests passed")
    return 1 if bad else 0

if __name__ == "__main__":
    sys.exit(main())
