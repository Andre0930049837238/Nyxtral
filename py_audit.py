# -*- coding: utf-8 -*-
"""
py_audit.py
============
Complementary pass to the Python engine (ast_engine.py). The engine tracks untrusted data and reports what it can
prove; this pass reports constructs that a code review wants to look at anyway, recognisable from the shape of the
code alone (same criterion as Semgrep's "audit" rules): obsolete SSL/TLS protocols, yaml.load without a safe loader,
system and execution calls with a non-constant argument, short RSA/DSA keys, uuid1, SHA-224, templates and HTTP
responses built from variable values, Django (extra/raw, locals() as context, is_safe filters, SafeString),
Jinja2/Mako used directly, XML without defusedxml, BashOperator with a formatted string.

It uses only the standard library ast module: no dependencies. Every finding is "Potential" (to be verified) or
"Detected with certainty" when the usage is insecure in itself. If the main engine already reported the same line,
scanner.py discards this one.
"""

import ast
import logging
import re

log = logging.getLogger(__name__)

AVAILABLE = True
AUDIT_ID = "AST-PY-050"

KINDS = {
    "ssl": ("CWE-326", "HIGH", "fixed", "Obsolete SSL/TLS protocol or deprecated function",
            "{n} uses an obsolete SSL/TLS protocol (SSLv2, SSLv3, TLS 1.0/1.1) or a deprecated function: the connection can be decrypted or downgraded.",
            "Use ssl.create_default_context() and set minimum_version = ssl.TLSVersion.TLSv1_2."),
    "yaml": ("CWE-502", "HIGH", "fixed", "yaml.load without a safe loader",
             "{n} can build arbitrary Python objects from a YAML file: a crafted file can execute code.",
             "Use yaml.safe_load (or Loader=yaml.SafeLoader)."),
    "cmd": ("CWE-78", "HIGH", "unknown", "System command built at runtime",
            "{n} runs a non-constant command: if any part comes from outside, arbitrary commands can be executed.",
            "Use subprocess with an argument list and without a shell, plus an allowlist of permitted commands."),
    "code": ("CWE-95", "HIGH", "unknown", "Code execution with non-constant text",
             "{n} executes non-constant text as code: if it comes from outside, arbitrary code can be executed.",
             "Avoid eval/exec: use ast.literal_eval or fixed functions."),
    "globals": ("CWE-95", "MEDIUM", "unknown", "Dynamic access to globals()/locals()",
                "{n} chooses a variable or function name dynamically: if it comes from outside, an attacker can run whatever they want.",
                "Use a dictionary of allowed functions instead of globals()."),
    "xml": ("CWE-611", "LOW", "fixed", "Standard library XML parser",
            "{n}: the standard XML parser is vulnerable to external entities and expansion bombs.",
            "Use defusedxml instead of the xml.* modules and xmlrpc."),
    "rsa": ("CWE-326", "MEDIUM", "fixed", "RSA/DSA key too short",
            "{n} generates a key shorter than 2048 bits: it can be broken today.",
            "Use at least 2048 bits (preferably 3072) for RSA and DSA."),
    "uuid": ("CWE-330", "MEDIUM", "fixed", "uuid1 leaks data and is predictable",
             "{n} includes the machine address and the time: it is not suitable for identifiers or secret tokens.",
             "Use uuid.uuid4() or the secrets module."),
    "sha224": ("CWE-328", "LOW", "fixed", "SHA-224 not recommended",
               "{n} uses SHA-224, a rarely used and non-recommended algorithm.",
               "Use SHA-256 or SHA-3."),
    "html": ("CWE-79", "MEDIUM", "unknown", "HTML content or template built from variable values",
             "{n} builds a response or a template from a variable value: if it comes from outside, it can run code in the browser.",
             "Use automatic template escaping and do not build HTML with format or concatenation."),
    "htmlfixed": ("CWE-79", "HIGH", "fixed", "Variable content marked as 'safe'",
                  "{n} marks content built from variable values as safe, disabling automatic sanitisation.",
                  "Use format_html with separate arguments, not with an already formatted string."),
    "sql": ("CWE-89", "HIGH", "unknown", "Hand-built SQL query or expression",
            "{n} builds SQL from non-constant text: if a value comes from outside, this is SQL injection.",
            "Use parameters (params=[...]) instead of inserting values into the SQL text."),
    "bash": ("CWE-78", "HIGH", "fixed", "BashOperator with a formatted string",
             "{n} builds the command with a formatted string: if a value comes from outside, arbitrary commands are executed.",
             "Pass values as environment variables (env=...) or as template parameters."),
    "secret": ("CWE-321", "MEDIUM", "fixed", "Application secret key used as a salt",
               "{n} uses the application's secret key as a salt: if the salt is discovered, the key is discovered too.",
               "Use a value separate from the secret key."),
}

SSL_ATTRS = re.compile(r"^(PROTOCOL_(SSLv2|SSLv3|SSLv23|TLSv1|TLSv1_1|TLS)|SSLv2_METHOD|SSLv3_METHOD|SSLv23_METHOD|TLSv1_METHOD|TLSv1_1_METHOD)$")
XML_MODULES = ("xml.etree", "xml.dom", "xml.sax", "xml.parsers", "xmlrpc", "lxml_NO")
SUBPROCESS_FUNCS = {"call", "run", "Popen", "check_output", "check_call", "getoutput", "getstatusoutput"}
OS_EXEC = re.compile(r"^(spawn[lv]p?e?|exec[lv]p?e?|startfile|popen[234]?|system)$")


def _dotted(n):
    if isinstance(n, ast.Name):
        return n.id
    if isinstance(n, ast.Attribute):
        d = _dotted(n.value)
        return (d + "." if d else "") + n.attr
    if isinstance(n, ast.Call):
        return _dotted(n.func) + "()"
    return ""


def _const_str(n):
    return isinstance(n, ast.Constant) and isinstance(n.value, str)


def _is_const(n):
    if isinstance(n, ast.Constant):
        return True
    if isinstance(n, (ast.List, ast.Tuple)):
        return all(_is_const(e) for e in n.elts)
    if isinstance(n, ast.JoinedStr):
        return not any(isinstance(v, ast.FormattedValue) for v in n.values)
    return False


def _dynamic_string(n):
    """f-string with values, concatenation/% formatting, .format(): text built at runtime."""
    if isinstance(n, ast.JoinedStr):
        return any(isinstance(v, ast.FormattedValue) for v in n.values)
    if isinstance(n, ast.BinOp) and isinstance(n.op, (ast.Mod, ast.Add)):
        return not (_is_const(n.left) and _is_const(n.right))
    if isinstance(n, ast.Call) and isinstance(n.func, ast.Attribute) and n.func.attr == "format" and _const_str(n.func.value):
        return bool(n.args or n.keywords)
    return False


def _kw(call, name):
    for k in call.keywords:
        if k.arg == name:
            return k.value
    return None


class _Visitor(ast.NodeVisitor):
    def __init__(self, rel, lines):
        self.rel, self.lines, self.out, self.seen = rel, lines, [], set()
        self.jinja_names = set()
        self.alias = {}             # name -> dangerous function (e.g. fn = getattr(os, "system"))

    def add(self, kind, node, name):
        line = getattr(node, "lineno", 1)
        key = (kind, line)
        if key in self.seen:
            return
        self.seen.add(key)
        cwe, sev, conf, title, desc, rec = KINDS[kind]
        snip = self.lines[line - 1].strip() if 0 < line <= len(self.lines) else ""
        label = {"fixed": "Detected with certainty in the code: inherently unsafe usage",
                 "unknown": "Potential: the argument is not a constant, but it is not proven that it comes from outside"}[conf]
        self.out.append({"id": AUDIT_ID, "name": title, "severity": sev, "confidence": "confirmed" if conf == "fixed" else "unknown",
                         "confidence_label": label, "file": self.rel, "line": line,
                         "snippet": snip[:160] + (" …" if len(snip) > 160 else ""), "description": desc.format(n=name),
                         "recommendation": rec, "engine": "py_audit", "cwe": cwe})

    # ---- imports ---------------------------------------------------------------------------------------
    def visit_Import(self, node):
        for a in node.names:
            if a.name.startswith(XML_MODULES) and not a.name.startswith("lxml"):
                self.add("xml", node, f"import {a.name}")
        self.generic_visit(node)

    def visit_ImportFrom(self, node):
        m = node.module or ""
        if m.startswith(XML_MODULES) and not m.startswith("lxml"):
            self.add("xml", node, f"from {m} import")
        self.generic_visit(node)

    # ---- attributes ----------------------------------------------------------------------------------------
    def visit_Attribute(self, node):
        if SSL_ATTRS.match(node.attr):
            self.add("ssl", node, _dotted(node))
        self.generic_visit(node)

    # ---- classes -----------------------------------------------------------------------------------------
    def visit_ClassDef(self, node):
        bases = {_dotted(b).split(".")[-1] for b in node.bases}
        if bases & {"SafeString", "SafeText", "SafeData", "SafeBytes"}:
            self.add("htmlfixed", node, f"class {node.name}")
        if bases & {"Func", "Expression", "Transform", "Lookup"}:
            for st in node.body:
                if isinstance(st, ast.Assign) and any(isinstance(t, ast.Name) and t.id == "template" for t in st.targets) and isinstance(st.value, ast.Constant):
                    if "%(" in str(st.value.value) and "'" in str(st.value.value):
                        self.add("sql", node, f"class {node.name}(template)")
        self.generic_visit(node)

    def visit_FunctionDef(self, node):
        for d in node.decorator_list:
            if isinstance(d, ast.Call) and _dotted(d.func).endswith(("filter", "simple_tag", "inclusion_tag")):
                v = _kw(d, "is_safe")
                if isinstance(v, ast.Constant) and v.value is True:
                    self.add("html", node, "filter with is_safe=True")
        self.generic_visit(node)

    visit_AsyncFunctionDef = visit_FunctionDef

    # ---- subscripts: globals()[x] -----------------------------------------------------------------------------
    def visit_Subscript(self, node):
        if isinstance(node.value, ast.Call) and _dotted(node.value.func) in ("globals", "locals") and not isinstance(node.slice, ast.Constant):
            self.add("globals", node, _dotted(node.value.func) + "()[...]")
        self.generic_visit(node)

    # ---- calls ------------------------------------------------------------------------------------------
    @staticmethod
    def _getattr_target(call):
        """getattr(os, "system") -> 'os.system'."""
        if isinstance(call, ast.Call) and _dotted(call.func) == "getattr" and len(call.args) >= 2 and isinstance(call.args[1], ast.Constant) \
                and isinstance(call.args[1].value, str):
            base = _dotted(call.args[0])
            return f"{base}.{call.args[1].value}" if base else None
        return None

    def visit_Assign(self, node):
        tgt = self._getattr_target(node.value) or (_dotted(node.value) if isinstance(node.value, ast.Attribute) else None)
        if tgt and re.match(r"^(os|subprocess|commands)\.", tgt):
            for t in node.targets:
                if isinstance(t, ast.Name):
                    self.alias[t.id] = tgt
        self.generic_visit(node)

    def visit_Call(self, node):
        f = _dotted(node.func)
        if f in self.alias:
            f = self.alias[f]
        elif isinstance(node.func, ast.Call):
            f = self._getattr_target(node.func) or f
        last = f.split(".")[-1]
        a0 = node.args[0] if node.args else None
        nonconst0 = a0 is not None and not _is_const(a0)

        if f in ("ssl.wrap_socket", "wrap_socket"):
            self.add("ssl", node, f)
        if f in ("yaml.load", "yaml.load_all", "yaml.unsafe_load", "yaml.full_load"):
            ld = _kw(node, "Loader") or (node.args[1] if len(node.args) > 1 else None)
            if f in ("yaml.unsafe_load", "yaml.full_load") or ld is None or "Safe" not in _dotted(ld) and "CSafe" not in _dotted(ld):
                self.add("yaml", node, f)
        if f == "os.system" or f == "os.popen" or re.match(r"^os\.(spawn|exec|popen|startfile)", f):
            if node.args and any(not _is_const(a) for a in node.args):
                self.add("cmd", node, f)
        elif f.startswith("subprocess.") and last in SUBPROCESS_FUNCS and nonconst0:
            sh = _kw(node, "shell")
            if (isinstance(sh, ast.Constant) and sh.value is True) or _dynamic_string(a0) or isinstance(a0, (ast.Name, ast.Attribute, ast.Call, ast.Subscript)):
                self.add("cmd", node, f)
        elif f in ("commands.getoutput", "commands.getstatusoutput") and nonconst0:
            self.add("cmd", node, f)
        if f in ("eval", "exec") and nonconst0:
            self.add("code", node, f)
        if last in ("runsource", "runcode", "push", "interact") and re.search(r"(?i)(interpreter|console|code\.)", f) and nonconst0:
            self.add("code", node, f)
        if f in ("getattr", "setattr", "delattr") and node.args and isinstance(node.args[0], ast.Call) and _dotted(node.args[0].func) in ("globals", "locals") \
                and len(node.args) > 1 and not _is_const(node.args[1]):
            self.add("globals", node, f"{f}(globals(), ...)")

        # RSA/DSA and weak curves
        if re.search(r"(^|\.)(rsa|dsa|RSA|DSA)\.generate(_private_key)?$", f) or f in ("generate_private_key",):
            ks = _kw(node, "key_size") or _kw(node, "bits")
            if ks is None and node.args:
                ks = node.args[0] if re.search(r"\.generate$", f) else (node.args[1] if len(node.args) > 1 else None)
            if isinstance(ks, ast.Constant) and isinstance(ks.value, int) and ks.value < 2048:
                self.add("rsa", ks, f)
        if f in ("uuid.uuid1", "uuid1"):
            self.add("uuid", node, f)
        if f in ("hashlib.sha224", "hashlib.sha3_224") or (f == "hashlib.new" and a0 is not None and isinstance(a0, ast.Constant) and "224" in str(a0.value)):
            self.add("sha224", node, f)

        # templates and responses
        if f in ("render_template",) and a0 is not None and _const_str(a0):
            ext = re.search(r"\.([A-Za-z0-9]+)$", a0.value)
            if (ext is None or ext.group(1).lower() not in ("html", "htm", "xml", "xhtml")) and (node.keywords or len(node.args) > 1):
                if any(not _is_const(k.value) for k in node.keywords) or any(not _is_const(x) for x in node.args[1:]):
                    self.add("html", node, f"render_template('{a0.value}')")
        if last in ("render", "render_to_response", "render_template") and any(
                isinstance(x, ast.Call) and _dotted(x.func) in ("locals", "globals") for x in list(node.args) + [k.value for k in node.keywords]):
            self.add("html", node, f"{f}(..., locals())")
        if last in ("make_response", "HttpResponse", "Response", "HttpResponseBadRequest", "HttpResponseNotFound") and nonconst0 and \
                not (isinstance(a0, ast.Call) and _dotted(a0.func).split(".")[-1] in ("render_template", "jsonify", "dumps", "render", "render_to_string", "json_encode", "escape", "str_escape")):
            if _dynamic_string(a0) or isinstance(a0, (ast.Name, ast.Attribute, ast.Subscript, ast.Call)):
                self.add("html", node, f)
        if last == "format_html" and a0 is not None and _dynamic_string(a0):
            self.add("htmlfixed", node, f)
        if last in ("mark_safe", "SafeString") and a0 is not None and _dynamic_string(a0):
            self.add("htmlfixed", node, f)
        if f in ("jinja2.Environment", "Environment"):
            ae = _kw(node, "autoescape")
            if ae is None or (isinstance(ae, ast.Constant) and ae.value is False):
                self.add("html", node, f)
        if f in ("jinja2.Template", "Template", "mako.template.Template", "Template_NO") and nonconst0 and ("jinja2" in f or "mako" in f or f == "Template"):
            self.add("html", node, f)
        if "mako" in f.lower() and last in ("Template", "TemplateLookup"):
            self.add("html", node, f)

        # ORM Django
        if last in ("extra", "raw") and nonconst0 and not f.startswith(("self.", "os.")) and isinstance(node.func, ast.Attribute):
            if _dynamic_string(a0) or isinstance(a0, (ast.Name, ast.Attribute, ast.Subscript)):
                self.add("sql", node, f)
        if last == "RawSQL" and nonconst0:
            self.add("sql", node, f)
        if last == "BashOperator":
            bc = _kw(node, "bash_command")
            if bc is not None and _dynamic_string(bc):
                self.add("bash", node, f)
        if last == "Hashids":
            sl = _kw(node, "salt")
            if sl is not None and re.search(r"(?i)secret", ast.dump(sl)):
                self.add("secret", node, f)
        self.generic_visit(node)


def analyze_py_audit(rel_path, text):
    if len(text) > 800_000:
        log.info("py_audit: '%s' skipped (%d characters exceed the 800,000-character limit).", rel_path, len(text))
        return []
    try:
        tree = ast.parse(text)
    except (SyntaxError, ValueError, RecursionError) as exc:
        log.warning("py_audit: '%s' could not be parsed (%s: %s); the file was skipped. "
                    "Check it for syntax errors or Python-version-specific syntax.", rel_path, type(exc).__name__, exc)
        return []
    v = _Visitor(rel_path, text.splitlines())
    try:
        v.visit(tree)
    except RecursionError:
        log.warning("py_audit: '%s' is nested too deeply; the analysis was cut short and findings may be incomplete.", rel_path)
    if re.search(r"(^|/)(tests?|testing|testdata|examples?|docs?)(/|$)|(^|/)test_[^/]*\.py$|_test\.py$|(^|/)conftest\.py$", rel_path.replace("\\", "/")):
        return [f for f in v.out if f["confidence"] == "confirmed" and f["cwe"] in ("CWE-502", "CWE-326")]   # in tests only the inherently insecure usages are kept
    return v.out
