# -*- coding: utf-8 -*-
"""Regression tests for the Python engine: (name, code, expected ids). Run: python tools/test_python_engine.py"""
import os, sys
sys.path.insert(0, os.path.join(os.path.dirname(os.path.abspath(__file__)), ".."))
from ast_engine import analyze_python_source

H = "from flask import Flask, request\nimport os, subprocess, sqlite3, pickle, yaml, requests, shlex, html\napp = Flask(__name__)\n"
CASES = [
 # ---- MUST be reported ----
 ("direct cmd", H + "@app.route('/a')\ndef a():\n    os.system('ls ' + request.args['d'])\n", {"AST-PY-003"}),
 ("cmd across functions", H + "def run(c):\n    os.system(c)\n@app.route('/a')\ndef a():\n    run(request.args['d'])\n", {"AST-PY-003"}),
 ("cmd 2-level chain", H + "def inner(c):\n    subprocess.run(c, shell=True)\ndef mid(x):\n    inner('echo ' + x)\n@app.route('/a')\ndef a(q):\n    mid(q)\n", {"AST-PY-005"}),
 ("cmd from method", H + "class S:\n    def go(self, c):\n        os.system(c)\n    def h(self):\n        self.go(input())\n", {"AST-PY-003"}),
 ("sql f-string", H + "@app.route('/u/<n>')\ndef u(n):\n    sqlite3.connect('d').execute(f\"SELECT * FROM t WHERE n='{n}'\")\n", {"AST-PY-008"}),
 ("sql built variable", H + "def f(c, n):\n    q = \"SELECT * FROM t WHERE n='\" + n + \"'\"\n    c.execute(q)\n", {"AST-PY-008"}),
 ("sql after if/else", H + "@app.route('/a')\ndef a():\n    n = request.args['n']\n    if n:\n        q = 'x' + n\n    else:\n        q = 'ok'\n    sqlite3.connect('d').execute(q)\n", {"AST-PY-008"}),
 ("eval", "def f():\n    return eval(input())\n", {"AST-PY-001"}),
 ("alias import", "import subprocess as sp\nimport sys\nsp.call(sys.argv[1], shell=True)\n", {"AST-PY-005"}),
 ("from import", "from os import system\nimport sys\nsystem(sys.argv[1])\n", {"AST-PY-003"}),
 ("pickle", H + "@app.route('/p', methods=['POST'])\ndef p():\n    return pickle.loads(request.data)\n", {"AST-PY-004"}),
 ("yaml.load", "import yaml\ndef f(s):\n    return yaml.load(s)\n", {"AST-PY-006"}),
 ("path traversal", H + "@app.route('/f')\ndef f():\n    return open('/data/' + request.args['n']).read()\n", {"AST-PY-009"}),
 ("ssrf", H + "@app.route('/f')\ndef f():\n    return requests.get(request.args['u']).text\n", {"AST-PY-010"}),
 ("redirect", H + "from flask import redirect\n@app.route('/r')\ndef r():\n    return redirect(request.args['next'])\n", {"AST-PY-011"}),
 ("ssti", H + "from flask import render_template_string\n@app.route('/t')\ndef t():\n    return render_template_string('Hello ' + request.args['n'])\n", {"AST-PY-012"}),
 ("xss mark_safe", "from django.utils.safestring import mark_safe\ndef v(request):\n    return mark_safe(request.GET['x'])\n", {"AST-PY-013"}),
 ("xxe lxml", "from lxml import etree\ndef v(request):\n    return etree.fromstring(request.body)\n", {"AST-PY-014"}),
 ("flask debug", H + "app.run(debug=True)\n", {"AST-PY-017"}),
 ("jwt without verification", "import jwt\ndef f(t):\n    return jwt.decode(t, options={'verify_signature': False})\n", {"AST-PY-023"}),
 ("token with random", "import random\ndef f():\n    token = ''.join(random.choice('abc') for _ in range(8))\n    return token\n", {"AST-PY-019"}),
 ("md5", "import hashlib\nh = hashlib.md5(b'x')\n", {"AST-PY-007"}),
 ("tar extractall", "import tarfile\ndef f(p):\n    tarfile.open(p).extractall('/tmp/x')\n", {"AST-PY-015"}),
 ("django view param", "import os\ndef view(request, name):\n    os.system('cat ' + name)\n", {"AST-PY-003"}),
 ("loop accumulates", H + "@app.route('/a')\ndef a():\n    q = 'x'\n    for p in request.args.getlist('p'):\n        q = q + p\n    os.system(q)\n", {"AST-PY-003"}),
 ("request.form.get", H + "@app.route('/a', methods=['POST'])\ndef a():\n    d = request.form.get('d', '')\n    return pickle.loads(d.encode())\n", {"AST-PY-004"}),
 ("request.args.get in sql", H + "@app.route('/a')\ndef a():\n    n = request.args.get('n')\n    sqlite3.connect('d').execute('SELECT * FROM t WHERE n=' + n)\n", {"AST-PY-008"}),
 ("request.get_json", H + "@app.route('/a', methods=['POST'])\ndef a():\n    os.system(request.get_json()['cmd'])\n", {"AST-PY-003"}),
 ("b64decode propagates", H + "import base64\n@app.route('/a', methods=['POST'])\ndef a():\n    return pickle.loads(base64.b64decode(request.form['d']))\n", {"AST-PY-004"}),
 ("get with constant default", H + "CFG = {'a': 'ls'}\ndef f():\n    os.system(CFG.get('a', 'pwd'))\n", set()),
 ("sanitizer in a helper function", H + "def safe(x):\n    return shlex.quote(x)\n@app.route('/a')\ndef a():\n    os.system('ls ' + safe(request.args['d']))\n", set()),
 # ---- MUST NOT be reported ----
 ("constant cmd", "import os\nos.system('ls -la')\n", set()),
 ("sql parameterized", H + "@app.route('/u/<n>')\ndef u(n):\n    sqlite3.connect('d').execute('SELECT * FROM t WHERE n=?', (n,))\n", set()),
 ("sql constant query in a variable", "def f(c):\n    q = 'SELECT 1'\n    c.execute(q)\n", set()),
 ("shlex.quote", H + "@app.route('/a')\ndef a():\n    os.system('ls ' + shlex.quote(request.args['d']))\n", set()),
 ("int() sanifica", H + "@app.route('/a')\ndef a():\n    n = int(request.args['n'])\n    sqlite3.connect('d').execute(f'SELECT * FROM t WHERE id={n}')\n", set()),
 ("isdigit validation", H + "@app.route('/a')\ndef a():\n    n = request.args['n']\n    if not n.isdigit():\n        return 'no'\n    os.system('echo ' + n)\n", set()),
 ("allowlist in", H + "@app.route('/a')\ndef a():\n    c = request.args['c']\n    if c not in ('start', 'stop'):\n        return 'no'\n    os.system('service x ' + c)\n", set()),
 ("constant dictionary", H + "CMDS = {'a': 'ls', 'b': 'pwd'}\n@app.route('/a')\ndef a():\n    os.system(CMDS[request.args['k']])\n", set()),
 ("clean branch overwrites", H + "@app.route('/a')\ndef a():\n    c = request.args['c']\n    c = 'ls'\n    os.system(c)\n", set()),
 ("html.escape + render", "import html\nfrom django.utils.safestring import mark_safe\ndef v(request):\n    return mark_safe(html.escape(request.GET['x']))\n", set()),
 ("basename path", H + "@app.route('/f')\ndef f():\n    return open('/data/' + os.path.basename(request.args['n'])).read()\n", set()),
 ("yaml.safe_load", "import yaml\ndef f(s):\n    return yaml.safe_load(s)\n", set()),
 ("yaml SafeLoader", "import yaml\ndef f(s):\n    return yaml.load(s, Loader=yaml.SafeLoader)\n", set()),
 ("secrets token", "import secrets\ndef f():\n    token = secrets.token_urlsafe(16)\n    return token\n", set()),
 ("non-security md5", "import hashlib\nh = hashlib.md5(b'x', usedforsecurity=False)\n", set()),
 ("function never called with tainted data", "import os\ndef run(c):\n    os.system(c)\ndef main():\n    run('ls')\n", {"AST-PY-003"}),  # potential: unverifiable parameter
 ("subprocess list", "import subprocess, sys\nsubprocess.run(['ls', sys.argv[1]])\n", set()),
 ("constant redirect", H + "from flask import redirect\n@app.route('/r')\ndef r():\n    return redirect('/home')\n", set()),
]

PROJECT_CASES = [
 ("project: relative import + pass-through", {
    "app/util/shell.py": "import os\ndef run_cmd(c):\n    os.system('echo ' + c)\ndef passthrough(x):\n    return x\n",
    "app/util/__init__.py": "",
    "app/views.py": "from flask import Flask, request\nfrom .util.shell import run_cmd, passthrough\napp = Flask(__name__)\n"
                    "@app.route('/a')\ndef a():\n    run_cmd(passthrough(request.args['x']))\n"}, {("app/views.py", "AST-PY-003")}),
 ("project: call with a constant = no confirmed finding", {
    "m/helpers.py": "import subprocess\ndef go(c):\n    subprocess.run(c, shell=True)\n",
    "m/main.py": "from m.helpers import go\ndef f():\n    go('ls')\n"}, set()),
 ("project: sanitizer across files", {
    "m/san.py": "import shlex\ndef safe(x):\n    return shlex.quote(x)\n",
    "m/sink.py": "import os\ndef run(c):\n    os.system('echo ' + c)\n",
    "m/main.py": "import sys\nfrom m.san import safe\nfrom m.sink import run\ndef f():\n    run(safe(sys.argv[1]))\n"}, set()),
]

def project_main():
    from ast_engine import analyze_python_project
    bad = 0
    for name, files, expected in PROJECT_CASES:
        res = analyze_python_project(files)
        got = {(r, f["id"]) for r, fs in res.items() for f in fs if f["confidence"] == "confirmed"}
        ok = got == expected
        bad += not ok
        print(("OK   " if ok else "FAIL ") + name + ("" if ok else f"   expected={sorted(expected)} got={sorted(got)}"))
    return bad

def main():
    bad = 0
    for name, code, expected in CASES:
        got = {f["id"] for f in analyze_python_source("app.py", code)}
        ok = got == expected
        bad += not ok
        print(("OK   " if ok else "FAIL ") + name + ("" if ok else f"   expected={sorted(expected)} got={sorted(got)}"))
    pbad = project_main()
    total = len(CASES) + len(PROJECT_CASES)
    print(f"\n{total - bad - pbad}/{total} tests passed")
    return 1 if (bad or pbad) else 0

if __name__ == "__main__":
    sys.exit(main())
