# -*- coding: utf-8 -*-
"""Tests for the audit pass of Python: (name, code, expected CWE types). Run: python tools/test_py_audit.py"""
import os, sys
sys.path.insert(0, os.path.join(os.path.dirname(os.path.abspath(__file__)), ".."))
import py_audit as A

CASES = [
 # ---- MUST be reported ----
 ("SSLv3", "import ssl\nctx = ssl.SSLContext(ssl.PROTOCOL_SSLv3)\n", {"CWE-326"}),
 ("TLSv1", "import ssl\nc = ssl.SSLContext(ssl.PROTOCOL_TLSv1)\n", {"CWE-326"}),
 ("wrap_socket", "import ssl\ns = ssl.wrap_socket(sock)\n", {"CWE-326"}),
 ("yaml.load without loader", "import yaml\nd = yaml.load(s)\n", {"CWE-502"}),
 ("yaml.unsafe_load", "import yaml\nd = yaml.unsafe_load(s)\n", {"CWE-502"}),
 ("os.system variable", "import os\ndef f(c):\n    os.system(c)\n", {"CWE-78"}),
 ("subprocess shell", "import subprocess\ndef f(c):\n    subprocess.run(c, shell=True)\n", {"CWE-78"}),
 ("alias getattr os.system", "import os\nfn = getattr(os, 'system')\nfn(cmd)\n", {"CWE-78"}),
 ("eval variable", "def f(x):\n    return eval(x)\n", {"CWE-95"}),
 ("exec variable", "def f(x):\n    exec(x)\n", {"CWE-95"}),
 ("dynamic globals", "def f(n):\n    return globals()[n]()\n", {"CWE-95"}),
 ("xml.etree", "import xml.etree.ElementTree as ET\n", {"CWE-611"}),
 ("RSA 1024", "from cryptography.hazmat.primitives.asymmetric import rsa\nk = rsa.generate_private_key(public_exponent=65537, key_size=1024)\n", {"CWE-326"}),
 ("uuid1", "import uuid\nu = uuid.uuid1()\n", {"CWE-330"}),
 ("sha224", "import hashlib\nh = hashlib.sha224(b'x')\n", {"CWE-328"}),
 ("template .txt with values", "from flask import render_template, request\ndef f():\n    return render_template('a.txt', n=request.args.get('n'))\n", {"CWE-79"}),
 ("make_response variable", "from flask import make_response\ndef f(x):\n    return make_response(x)\n", {"CWE-79"}),
 ("locals as context", "from django.shortcuts import render\ndef v(request):\n    a = 1\n    return render(request, 't.html', locals())\n", {"CWE-79"}),
 ("formatted format_html", "from django.utils.html import format_html\ndef f(n):\n    return format_html(f'<b>{n}</b>')\n", {"CWE-79"}),
 ("Django extra with variable", "def f(q, s):\n    return q.extra(where=[s]) if False else q.raw(s)\n", {"CWE-89"}),
 ("formatted BashOperator", "def f(x):\n    return BashOperator(task_id='a', bash_command=f'echo {x}')\n", {"CWE-78"}),
 ("jinja2 without autoescape", "import jinja2\ne = jinja2.Environment(loader=l)\n", {"CWE-79"}),
 # ---- MUST NOT be reported ----
 ("TLS 1.2", "import ssl\nc = ssl.create_default_context()\n", set()),
 ("yaml.safe_load", "import yaml\nd = yaml.safe_load(s)\n", set()),
 ("yaml.load SafeLoader", "import yaml\nd = yaml.load(s, Loader=yaml.SafeLoader)\n", set()),
 ("os.system constant", "import os\nos.system('ls')\n", set()),
 ("subprocess list", "import subprocess\ndef f(a):\n    subprocess.run(['ls', a])\n", set()),
 ("eval constant", "eval('1+1')\n", set()),
 ("RSA 4096", "from cryptography.hazmat.primitives.asymmetric import rsa\nk = rsa.generate_private_key(public_exponent=65537, key_size=4096)\n", set()),
 ("uuid4", "import uuid\nu = uuid.uuid4()\n", set()),
 ("sha256", "import hashlib\nh = hashlib.sha256(b'x')\n", set()),
 ("template .html", "from flask import render_template, request\ndef f():\n    return render_template('a.html', n=request.args.get('n'))\n", set()),
 ("make_response render", "from flask import make_response, render_template\ndef f():\n    return make_response(render_template('a.html'))\n", set()),
 ("jinja2 with autoescape", "import jinja2\ne = jinja2.Environment(loader=l, autoescape=True)\n", set()),
]

def main():
    bad = 0
    for name, code, exp in CASES:
        got = {f["cwe"] for f in A.analyze_py_audit("app/main.py", code)}
        ok = got == exp; bad += not ok
        print(("OK   " if ok else "FAIL ") + name + ("" if ok else f"   expected={sorted(exp)} got={sorted(got)}"))
    print(f"\n{len(CASES) - bad}/{len(CASES)} tests passed")
    return 1 if bad else 0

if __name__ == "__main__":
    sys.exit(main())
