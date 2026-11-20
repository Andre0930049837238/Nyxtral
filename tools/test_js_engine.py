# -*- coding: utf-8 -*-
"""Regression tests for the JS/TS engine: (name, extension, code, expected ids among the CONFIRMED findings). Run: python tools/test_js_engine.py"""
import os, sys
sys.path.insert(0, os.path.join(os.path.dirname(os.path.abspath(__file__)), ".."))
import js_engine as J

H = "const express = require('express');\nconst { exec } = require('child_process');\nconst fs = require('fs');\nconst app = express();\n"
def route(body): return H + "app.get('/a', (req, res) => {\n" + body + "\n});\n"
CASES = [
 # ---- MUST be reported ----
 ("cmd concat", ".js", route("exec('ls ' + req.query.d);"), {"AST-JS-002"}),
 ("cmd template", ".js", route("exec(`ls ${req.body.d}`);"), {"AST-JS-002"}),
 ("sql template", ".js", route("db.query(`SELECT * FROM t WHERE id = ${req.query.id}`);"), {"AST-JS-003"}),
 ("sql concat via variable", ".js", route("const q = 'SELECT * FROM t WHERE n=' + req.params.n; db.query(q);"), {"AST-JS-003"}),
 ("path traversal", ".js", route("fs.readFile('/data/' + req.params.f, cb);"), {"AST-JS-004"}),
 ("ssrf axios", ".js", "const axios = require('axios');\n" + route("axios.get(req.query.url);"), {"AST-JS-005"}),
 ("ssrf fetch obj", ".js", route("fetch(req.body.target);"), {"AST-JS-005"}),
 ("open redirect", ".js", route("res.redirect(req.query.next);"), {"AST-JS-006"}),
 ("xss res.send", ".js", route("res.send('<p>' + req.query.name + '</p>');"), {"AST-JS-007"}),
 ("xss innerHTML from location", ".js", "document.getElementById('x').innerHTML = location.hash;\n", {"AST-JS-007"}),
 ("eval", ".js", route("eval(req.body.code);"), {"AST-JS-001"}),
 ("ssti pug", ".js", "const pug = require('pug');\n" + route("pug.compile(req.body.tpl);"), {"AST-JS-008"}),
 ("deser yaml", ".js", "const yaml = require('js-yaml');\n" + route("yaml.load(req.body.y);"), {"AST-JS-009"}),
 ("across functions", ".js", H + "function run(c) { exec(c); }\napp.get('/a', (req, res) => { run(req.query.c); });\n", {"AST-JS-002"}),
 ("destructuring", ".js", route("const { id } = req.query; db.query('SELECT * FROM t WHERE id=' + id);"), {"AST-JS-003"}),
 ("lambda handler", ".js", "const { exec } = require('child_process');\nexports.handler = async (event) => { exec('echo ' + event.name); };\n", {"AST-JS-002"}),
 ("typed ts", ".ts", H + "app.get('/a', (req: Request, res: Response) => { exec('ls ' + (req.query.d as string)); });\n", {"AST-JS-002"}),
 ("react dangerouslySetInnerHTML tainted", ".jsx", "function C() { const h = location.search; return <div dangerouslySetInnerHTML={{__html: h}} />; }\n", {"AST-JS-007"}),
 ("jwt none", ".js", "const jwt = require('jsonwebtoken');\njwt.verify(t, k, { algorithms: ['none'] });\n", {"AST-JS-013"}),
 ("md5", ".js", "const crypto = require('crypto');\ncrypto.createHash('md5').update(p);\n", {"AST-JS-014"}),
 ("postMessage without origin", ".js", "window.addEventListener('message', function (e) { go(e.data); });\n", set()),   # potential: not confirmed
 # ---- MUST NOT be reported ----
 ("constant cmd", ".js", route("exec('ls -la');"), set()),
 ("sql parameterized", ".js", route("db.query('SELECT * FROM t WHERE id = ?', [req.query.id]);"), set()),
 ("parseInt sanitizes", ".js", route("const id = parseInt(req.query.id); db.query('SELECT * FROM t WHERE id=' + id);"), set()),
 ("escape-html", ".js", "const escapeHtml = require('escape-html');\n" + route("res.send('<p>' + escapeHtml(req.query.n) + '</p>');"), set()),
 ("basename", ".js", "const path = require('path');\n" + route("fs.readFile(path.basename(req.params.f), cb);"), set()),
 ("includes allowlist", ".js", route("const c = req.query.c; if (!['a', 'b'].includes(c)) return res.end(); exec('x ' + c);"), set()),
 ("fixed-host redirect", ".js", route("res.redirect('https://example.com/' + req.query.p);"), set()),
 ("fixed-host ssrf", ".js", route("fetch(`https://api.example.com/v1/${req.query.id}`);"), set()),
 ("process.env redirect", ".js", route("res.redirect(process.env.BASE + '/home');"), set()),
 ("clean branch", ".js", route("let c = req.query.c; c = 'ls'; exec(c);"), set()),
 ("res.json", ".js", route("res.json({ q: req.query.q });"), set()),
 ("sendFile with root", ".js", route("res.sendFile(req.params.f, { root: '/srv' });"), set()),
]
PROJECT_CASES = [
 ("project: relative require", {
    "lib/shell.js": "const { exec } = require('child_process');\nmodule.exports.run = function (c) { exec('echo ' + c); };\nmodule.exports.clean = (x) => x;\n",
    "app.js": "const express = require('express');\nconst sh = require('./lib/shell');\nconst app = express();\n"
              "app.get('/a', (req, res) => { sh.run(sh.clean(req.query.x)); });\n"}, {("app.js", "AST-JS-002")}),
 ("project: ES import", {
    "util/q.ts": "export function runQuery(db, s) { return db.query('SELECT * FROM t WHERE n=' + s); }\n",
    "routes.ts": "import { runQuery } from './util/q';\napp.get('/u', (req, res) => { runQuery(db, req.query.n); });\n"}, {("routes.ts", "AST-JS-003")}),
 ("project: call with a constant", {
    "lib/shell.js": "const { exec } = require('child_process');\nmodule.exports.run = (c) => { exec('echo ' + c); };\n",
    "app.js": "const { run } = require('./lib/shell');\nrun('ls');\n"}, set()),
 ("project: sanitizer across files", {
    "lib/san.js": "const quote = require('shell-quote').quote;\nmodule.exports = (x) => quote([x]);\n",
    "lib/sh.js": "const { exec } = require('child_process');\nmodule.exports.run = (c) => { exec('echo ' + c); };\n",
    "app.js": "const san = require('./lib/san');\nconst { run } = require('./lib/sh');\napp.get('/a', (req, res) => { run(san(req.query.x)); });\n"}, {("app.js", "AST-JS-002")}),
]

def main():
    if not J.AVAILABLE:
        print("WARNING: tree-sitter is not installed, so no tests were run. Install it with: pip install tree-sitter tree-sitter-javascript tree-sitter-typescript"); return 0
    bad = 0
    for name, ext, code, exp in CASES:
        got = {f["id"] for f in J.analyze_js_source("app" + ext, ext, code) if f["confidence"] == "confirmed"}
        ok = got == exp; bad += not ok
        print(("OK   " if ok else "FAIL ") + name + ("" if ok else f"   expected={sorted(exp)} got={sorted(got)}"))
    for name, files, exp in PROJECT_CASES:
        res = J.analyze_js_project({p: (os.path.splitext(p)[1], t) for p, t in files.items()})
        got = {(r, f["id"]) for r, fs in res.items() for f in fs if f["confidence"] == "confirmed"}
        ok = got == exp; bad += not ok
        print(("OK   " if ok else "FAIL ") + name + ("" if ok else f"   expected={sorted(exp)} got={sorted(got)}"))
    total = len(CASES) + len(PROJECT_CASES)
    print(f"\n{total - bad}/{total} tests passed")
    return 1 if bad else 0

if __name__ == "__main__":
    sys.exit(main())
