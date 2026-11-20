# -*- coding: utf-8 -*-
"""
js_audit.py
============
Complementary pass to the JS/TS engine (js_engine.py): the engine follows untrusted data to the dangerous sinks and
reports only what it can prove; this pass reports, as "potential" and at low/medium severity, sensitive calls (file
system, system commands, code execution, regular expressions) whose argument is NOT a constant: these are the cases
that a manual review wants to look at anyway (same criterion as Semgrep's "audit" rules).

Honest limitations: it does not know where the value comes from; that is why every finding is "potential". If the
main engine has already reported the same line, the audit finding is discarded (see scanner.py).
"""

import logging
import re

log = logging.getLogger(__name__)

try:
    import js_engine as _je
    AVAILABLE = _je.AVAILABLE
except Exception as _exc:                           # pragma: no cover
    log.warning("The JavaScript engine could not be loaded (%s): js_audit is disabled. "
                "Check that tree-sitter and its JavaScript/TypeScript grammars are installed.", _exc)
    _je = None
    AVAILABLE = False

_warned_unavailable = False
AUDIT_ID = "AST-JS-018"
FS_FUNCS = {"readFile", "readFileSync", "writeFile", "writeFileSync", "appendFile", "appendFileSync", "createReadStream", "createWriteStream",
            "readdir", "readdirSync", "unlink", "unlinkSync", "rm", "rmSync", "rmdir", "rmdirSync", "mkdir", "mkdirSync", "stat", "statSync",
            "open", "openSync", "copyFile", "copyFileSync", "rename", "renameSync", "access", "accessSync", "truncate", "truncateSync",
            "chmod", "chmodSync", "readlink", "lstat", "lstatSync", "existsSync", "opendir", "opendirSync", "cp", "cpSync", "symlink"}
CP_FUNCS = {"exec", "execSync", "spawn", "spawnSync", "execFile", "execFileSync", "fork"}
VM_FUNCS = {"runInContext", "runInNewContext", "runInThisContext", "compileFunction"}
FS_IMPORT = re.compile(r"""require\(\s*['"](node:)?fs(/promises|-extra)?['"]\s*\)|from\s+['"](node:)?fs(/promises|-extra)?['"]""")
CP_IMPORT = re.compile(r"""require\(\s*['"](node:)?child_process['"]\s*\)|from\s+['"](node:)?child_process['"]|require\(\s*['"]shelljs['"]\s*\)""")
VM_IMPORT = re.compile(r"""require\(\s*['"](node:)?vm2?['"]\s*\)|from\s+['"](node:)?vm2?['"]""")
LITERAL_TYPES = {"string", "number", "true", "false", "null", "undefined", "regex"}
INFO = {
    "fs": ("CWE-22", "MEDIUM", "A non-constant file path must be checked: if it comes from outside, it allows reading or writing arbitrary files.",
           "Normalize the path (path.resolve) and verify that it stays inside the allowed folder; use path.basename on the file name."),
    "cp": ("CWE-78", "HIGH", "A system command built at runtime must be checked: if any part comes from outside, arbitrary commands can be executed.",
           "Use execFile/spawn with separate arguments and an allowlist of permitted commands, without a shell."),
    "code": ("CWE-95", "HIGH", "Non-constant text executed as code must be checked: if it comes from outside, arbitrary code can be executed.",
             "Avoid eval/new Function/vm with untrusted input: use allowlists of permitted values or data parsing (JSON)."),
    "html": ("CWE-79", "MEDIUM", "Non-constant HTML content inserted into the page must be checked: if it comes from outside, it can run code in the visitor's browser.",
             "Use textContent or React's automatic rendering; if HTML is needed, sanitize it with DOMPurify."),
    "href": ("CWE-79", "LOW", "A non-constant address in a link can be 'javascript:...': if it comes from outside, it allows code execution on click.",
             "Check that the address starts with http:// or https:// (or is relative) before using it."),
    "redirect": ("CWE-601", "MEDIUM", "A non-constant redirect address must be checked: if it comes from outside, it sends the user to a fake site.",
                 "Accept only internal paths or hosts from an allowlist."),
    "tls": ("CWE-295", "HIGH", "TLS certificate verification is disabled: the connection accepts any server.",
            "Leave rejectUnauthorized set to true (or do not set it) and do not use NODE_TLS_REJECT_UNAUTHORIZED=0."),
    "shell": ("CWE-78", "HIGH", "The shell: true option makes the shell interpret the arguments: an untrusted value becomes a command.",
              "Remove shell: true and pass the arguments as a list."),
    "grpc": ("CWE-319", "MEDIUM", "The gRPC connection is created without encryption: data travels in clear text.",
             "Use grpc.credentials.createSsl() or TLS certificates."),
    "tmpl": ("CWE-79", "MEDIUM", "An HTML string built from variable values can inject code into the page if a value comes from outside.",
             "Use a template engine with automatic escaping or encode every value before inserting it."),
    "devtools": ("CWE-668", "HIGH", "Remote browser debugging is open: anyone who can reach the port can control the browser.",
                 "Do not enable --remote-debugging-port in production."),
    "serial": ("CWE-79", "HIGH", "serialize-javascript with unsafe: true lets dangerous characters through into the page.",
               "Remove the unsafe option."),
    "jq": ("CWE-79", "MEDIUM", "A jQuery method that inserts HTML with a non-constant value can run code in the page if the value comes from outside.",
           "Use .text() or sanitize the HTML (DOMPurify) before inserting it."),
    "noent": ("CWE-611", "HIGH", "noent: true enables external entity substitution: a crafted XML document can read files on the server.",
              "Set noent: false."),
    "angular": ("CWE-79", "MEDIUM", "A non-constant address for templates or styles can load content from any site into the app.",
                "Use only constant paths written in the code."),
    "intercom": ("CWE-287", "MEDIUM", "Intercom without user_hash: anyone can impersonate another chat user.",
                 "Compute user_hash (HMAC) on the server side and pass it together with user_id."),
    "gitclone": ("CWE-78", "HIGH", "git clone with a non-constant address can run dangerous options or protocols.",
                 "Validate the address and use '--' before the value."),
    "ssrf": ("CWE-918", "LOW", "A non-constant address passed to the automated browser must be checked: if it comes from outside, internal services can be reached.",
             "Accept only hosts from an allowlist."),
    "jwt": ("CWE-345", "HIGH", "The JWT is accepted without verifying the signature or with the 'none' algorithm: anyone can forge a valid one.",
            "Use verify with a key and a list of strong algorithms, without 'none' and without noVerify."),
    "redos": ("CWE-1333", "LOW", "A regular expression built at runtime can be exploited to hang the program (ReDoS).",
              "Do not build regexes from external input: use an escape (lodash.escapeRegExp) or a library with a time limit."),
}


def _is_literal(n):
    t = n.type
    if t in LITERAL_TYPES:
        return True
    if t == "template_string":
        return not any(c.type == "template_substitution" for c in n.children)
    if t == "parenthesized_expression" and n.named_children:
        return _is_literal(n.named_children[0])
    return False


def _finding(rel, kind, n, name, lines):
    cwe, sev, why, rec = INFO[kind]
    line = n.start_point[0] + 1
    snip = lines[line - 1].strip() if 0 < line <= len(lines) else ""
    return {"id": AUDIT_ID, "name": "Sensitive call with a non-constant argument (to be verified)", "severity": sev, "confidence": "unknown",
            "confidence_label": "Potential: the argument is not a constant, but it is not proven that it comes from outside",
            "file": rel, "line": line, "snippet": snip[:160] + (" …" if len(snip) > 160 else ""),
            "description": f"{name}() receives a non-constant value. {why}", "recommendation": rec, "engine": "js_audit", "cwe": cwe}


SAFE_RHS = re.compile(r"sanitiz|escape|DOMPurify|encodeURI|textContent|htmlEncode|xss\(", re.I)


COMPLEX = ("member_expression", "call_expression", "subscript_expression", "binary_expression", "template_string", "await_expression", "ternary_expression")


def _complex(n):
    """A simple identifier is often already sanitized; expressions (fields, calls, concatenations) are reported."""
    return n is not None and n.type in COMPLEX and not _is_literal(n)


def _safe_href(v):
    t = v.text.decode("utf-8", "ignore")
    if v.type == "binary_expression":
        left = v.child_by_field_name("left")
        if left is not None and left.type == "string" and left.text.decode("utf-8", "ignore").strip("'\"")[:1] in ("#", "/"):
            return True
    if v.type == "template_string" and t[1:2] in ("#", "/"):
        return True
    p = v.parent
    while p is not None:
        if p.type == "if_statement":
            c = p.child_by_field_name("condition")
            if c is not None and re.search(r"startsWith|\.test\(|new URL|indexOf", c.text.decode("utf-8", "ignore")):
                return True
        p = p.parent
    return False


def _nonliteral(n):
    return n is not None and not _is_literal(n) and n.type not in ("arrow_function", "function", "function_expression", "object", "array")


def analyze_js_audit(rel_path, ext, text):
    global _warned_unavailable
    if not AVAILABLE:
        if _warned_unavailable:
            return []
        _warned_unavailable = True
        log.warning("js_audit is disabled: the tree-sitter JavaScript/TypeScript grammar is not installed "
                    "(install 'tree-sitter-javascript' and 'tree-sitter-typescript'). Only pattern rules will run.")
        return []
    if len(text) > 600_000:
        log.info("js_audit: '%s' skipped (%d characters exceed the 600,000-character limit).", rel_path, len(text))
        return []
    try:
        root = _je._parse(ext, text)
    except Exception as exc:
        log.warning("js_audit: '%s' could not be parsed (%s); the file was skipped. "
                    "It may contain a syntax error or unsupported syntax.", rel_path, exc)
        return []
    if root is None:
        log.warning("js_audit: no syntax tree was produced for '%s'; the file was skipped.", rel_path)
        return []
    root = getattr(root, "root_node", root)
    fs_ok, cp_ok, vm_ok = bool(FS_IMPORT.search(text)), bool(CP_IMPORT.search(text)), bool(VM_IMPORT.search(text))
    lines = text.splitlines()
    out, seen = [], set()
    stack = [root]
    while stack:
        n = stack.pop()
        stack.extend(reversed(n.children))
        t0 = n.type
        if t0 == "template_string":
            tx = n.text.decode("utf-8", "ignore")
            if re.search(r"<\s*[a-zA-Z][^>]*>", tx) and any(c.type == "template_substitution" for c in n.children):
                if not SAFE_RHS.search(tx) and not any(x.type == "call_expression" and x.child_by_field_name("function") is not None and x.child_by_field_name("function").text.decode().split(".")[-1] in ("html", "css", "gql", "sql") for x in [n.parent] if x is not None):
                    out.append(_finding(rel_path, "tmpl", n, "template with HTML", lines))
            continue
        if t0 == "assignment_expression":
            l = n.child_by_field_name("left")
            rr = n.child_by_field_name("right")
            if l is not None and rr is not None and re.search(r"intercomSettings$", l.text.decode("utf-8", "ignore")) and rr.type == "object":
                rt = rr.text.decode("utf-8", "ignore")
                if re.search(r"user_id|email", rt) and "user_hash" not in rt:
                    out.append(_finding(rel_path, "intercom", n, "intercomSettings", lines))
            if l is not None and re.search(r"NODE_TLS_REJECT_UNAUTHORIZED$", l.text.decode("utf-8", "ignore")) and re.fullmatch(r"['\"]?0['\"]?|false", (n.child_by_field_name("right").text.decode() if n.child_by_field_name("right") is not None else "")):
                out.append(_finding(rel_path, "tls", n, "NODE_TLS_REJECT_UNAUTHORIZED", lines))
        if t0 == "pair":
            k, v = n.child_by_field_name("key"), n.child_by_field_name("value")
            kt = k.text.decode("utf-8", "ignore").strip("'\"") if k is not None else ""
            vt = v.text.decode("utf-8", "ignore").strip() if v is not None else ""
            if kt == "algorithms" and v is not None and re.search(r"['\"]none['\"]", vt, re.I):
                out.append(_finding(rel_path, "jwt", n, "algorithms: ['none']", lines))
                continue
            if kt == "rejectUnauthorized" and vt == "false":
                out.append(_finding(rel_path, "tls", n, "rejectUnauthorized: false", lines))
                continue
            if kt == "shell" and vt == "true":
                out.append(_finding(rel_path, "shell", n, "shell: true", lines))
                continue
            if kt == "noent" and vt == "true":
                out.append(_finding(rel_path, "noent", n, "noent: true", lines))
                continue
            if kt in ("templateUrl", "styleUrl", "styleUrls") and _nonliteral(v) and v.type != "array":
                out.append(_finding(rel_path, "angular", n, kt, lines))
                continue
            if kt == "unsafe" and vt == "true" and "serialize" in text:
                out.append(_finding(rel_path, "serial", n, "serialize unsafe: true", lines))
                continue
            if kt == "dangerouslySetInnerHTML" and v is not None and v.type == "object":
                inner = next((c.child_by_field_name("value") for c in v.named_children if c.type == "pair" and (c.child_by_field_name("key").text.decode().strip("'\"") == "__html")), None)
                if _complex(inner) and not SAFE_RHS.search(inner.text.decode("utf-8", "ignore")):
                    out.append(_finding(rel_path, "html", n, "dangerouslySetInnerHTML", lines))
            elif kt == "href" and _nonliteral(v) and "react" in text.lower() and ("createElement" in text) and not SAFE_RHS.search(v.text.decode("utf-8", "ignore")) and not _safe_href(v):
                out.append(_finding(rel_path, "href", n, "href", lines))
            elif kt == "url" and _nonliteral(v) and "@Redirect" in text and n.parent is not None and n.parent.parent is not None and n.parent.parent.type == "return_statement":
                out.append(_finding(rel_path, "redirect", n, "@Redirect url", lines))
            continue
        if t0 == "jsx_attribute":
            nm = n.children[0].text.decode("utf-8", "ignore") if n.children else ""
            ex = next((c for c in n.children if c.type == "jsx_expression"), None)
            inner = ex.named_children[0] if ex is not None and ex.named_children else None
            if nm == "dangerouslySetInnerHTML" and inner is not None and inner.type == "object":
                h = next((c.child_by_field_name("value") for c in inner.named_children if c.type == "pair" and c.child_by_field_name("key").text.decode().strip("'\"") == "__html"), None)
                if _complex(h) and not SAFE_RHS.search(h.text.decode("utf-8", "ignore")):
                    out.append(_finding(rel_path, "html", n, "dangerouslySetInnerHTML", lines))
            elif nm == "href" and _nonliteral(inner) and not SAFE_RHS.search(inner.text.decode("utf-8", "ignore")) and not _safe_href(inner):
                par = n.parent
                tag = par.named_children[0].text.decode("utf-8", "ignore") if par is not None and par.named_children else ""
                if tag == "a":
                    out.append(_finding(rel_path, "href", n, "href", lines))
            continue
        if t0 in ("jsx_opening_element", "jsx_self_closing_element"):
            tag = n.named_children[0].text.decode("utf-8", "ignore") if n.named_children else ""
            tx = n.text.decode("utf-8", "ignore")
            if tag == "ReactMarkdown" and re.search(r"allowDangerousHtml|escapeHtml\s*=\s*\{\s*false|rehypeRaw|parseHtml", tx):
                out.append(_finding(rel_path, "html", n, "ReactMarkdown with raw HTML", lines))
            continue
        if t0 == "assignment_expression":
            l, r = n.child_by_field_name("left"), n.child_by_field_name("right")
            if l is not None and l.type == "member_expression" and l.child_by_field_name("property") is not None and \
                    l.child_by_field_name("property").text.decode("utf-8", "ignore") in ("innerHTML", "outerHTML") and _nonliteral(r) \
                    and not SAFE_RHS.search(r.text.decode("utf-8", "ignore")):
                out.append(_finding(rel_path, "html", n, l.text.decode("utf-8", "ignore"), lines))
            continue
        if n.type not in ("call_expression", "new_expression"):
            continue
        fn = n.child_by_field_name("function") or n.child_by_field_name("constructor")
        args_n = n.child_by_field_name("arguments")
        if n.type == "call_expression" and fn is not None and re.search(r"(^|\.)credentials\.createInsecure$", fn.text.decode("utf-8", "ignore")):
            out.append(_finding(rel_path, "grpc", n, fn.text.decode("utf-8", "ignore"), lines))
            continue
        if fn is None or args_n is None or not args_n.named_children:
            continue
        callee0 = fn.text.decode("utf-8", "ignore") if fn is not None else ""
        ctext = n.text.decode("utf-8", "ignore")
        if n.type == "call_expression" and callee0 == "require" and re.fullmatch(r"\(\s*['\"]grpc['\"]\s*\)", args_n.text.decode("utf-8", "ignore").strip()):
            out.append(_finding(rel_path, "grpc", n, "require('grpc')", lines))
            continue
        if n.type == "call_expression" and callee0.split(".")[-1] == "resourceUrlWhitelist" and "'**'" in ctext.replace('"', "'"):
            out.append(_finding(rel_path, "angular", n, callee0, lines))
            continue
        if n.type == "call_expression" and callee0.split(".")[-1] in ("trustAsHtml", "trustAsUrl", "trustAsCss", "trustAsJs", "trustAsResourceUrl") \
                and args_n.named_children and _nonliteral(args_n.named_children[0]):
            out.append(_finding(rel_path, "angular", n, callee0, lines))
            continue
        if n.type == "call_expression" and re.search(r"(^|\.)credentials\.createInsecure$", callee0):
            out.append(_finding(rel_path, "grpc", n, callee0, lines))
            continue
        if n.type == "call_expression" and callee0 == "Intercom" and re.search(r"['\"](boot|update)['\"]", ctext) and re.search(r"user_id|email", ctext) and "user_hash" not in ctext:
            out.append(_finding(rel_path, "intercom", n, "Intercom", lines))
            continue
        if n.type == "call_expression" and re.search(r"(^|\.)launch$", callee0) and "--remote-debugging" in ctext:
            out.append(_finding(rel_path, "devtools", n, callee0, lines))
            continue
        if n.type == "call_expression" and callee0.split(".")[-1] in ("html", "append", "prepend", "before", "after", "wrap", "wrapAll", "replaceWith", "appendTo", "prependTo") \
                and args_n.named_children and re.search(r"\$|jQuery", callee0.split(".")[0] + ctext[:40]) and _complex(args_n.named_children[0]) \
                and not SAFE_RHS.search(args_n.named_children[0].text.decode("utf-8", "ignore")):
            out.append(_finding(rel_path, "jq", n, callee0, lines))
            continue
        if n.type == "call_expression" and callee0.split(".")[-1] == "goto" and args_n.named_children and _nonliteral(args_n.named_children[0]):
            out.append(_finding(rel_path, "ssrf", n, callee0, lines))
            continue
        if n.type == "call_expression" and callee0.split(".")[-1] == "decode" and len(args_n.named_children) >= 3 and args_n.named_children[2].text.decode() == "true":
            out.append(_finding(rel_path, "jwt", n, callee0, lines))
            continue
        if n.type == "call_expression" and callee0.split(".")[-1] in ("run", "runFile") and vm_ok and args_n.named_children and _nonliteral(args_n.named_children[0]):
            out.append(_finding(rel_path, "code", n, callee0, lines))
            continue
        if n.type == "call_expression" and callee0.split(".")[-1] in ("open", "evaluate", "evaluateJavaScript", "setContent", "render", "renderBase64") \
                and re.search(r"require\(\s*['\"]phantom['\"]|from\s+['\"]phantom['\"]", text) and args_n.named_children and _nonliteral(args_n.named_children[0]):
            out.append(_finding(rel_path, "code", n, callee0, lines))
            continue
        if n.type == "call_expression" and callee0.split(".")[-1] in ("wkhtmltopdf", "wkhtmltoimage") and args_n.named_children and _nonliteral(args_n.named_children[0]):
            out.append(_finding(rel_path, "cp", n, callee0, lines))
            continue
        if n.type == "call_expression" and callee0.split(".")[-1] in ("spawn", "spawnSync", "execFile") and re.search(r"['\"]git['\"]", ctext) and re.search(r"['\"]clone['\"]", ctext):
            arr = next((c for c in args_n.named_children if c.type == "array"), None)
            if arr is not None and any(_nonliteral(c) for c in arr.named_children):
                out.append(_finding(rel_path, "gitclone", n, callee0, lines))
                continue
        if n.type == "call_expression" and callee0.split(".")[-1] == "insertAdjacentHTML" and len(args_n.named_children) >= 2:
            a1 = args_n.named_children[1]
            if _nonliteral(a1) and not SAFE_RHS.search(a1.text.decode("utf-8", "ignore")):
                out.append(_finding(rel_path, "html", n, callee0, lines))
            continue
        if n.type == "call_expression" and callee0 in ("document.write", "document.writeln") and _complex(args_n.named_children[0]) \
                and not SAFE_RHS.search(args_n.named_children[0].text.decode("utf-8", "ignore")):
            out.append(_finding(rel_path, "html", n, callee0, lines))
            continue
        a0 = args_n.named_children[0]
        if _is_literal(a0) or a0.type in ("arrow_function", "function", "function_expression", "object", "array", "spread_element"):
            continue
        callee = fn.text.decode("utf-8", "ignore")
        simple = callee.split(".")[-1]
        kind = None
        if n.type == "call_expression":
            if simple in FS_FUNCS and fs_ok and (callee == simple or callee.split(".")[0] in ("fs", "fsp", "fsPromises", "promises", "fse") or ".promises" in callee):
                kind = "fs"
            elif simple in CP_FUNCS and cp_ok and (callee == simple or callee.split(".")[0] in ("child_process", "cp", "shell", "shelljs")):
                kind = "cp"
            elif callee == "eval" or (simple in VM_FUNCS and vm_ok):
                kind = "code"
        elif callee == "Function":
            kind = "code"
        elif callee == "RegExp":
            kind = "redos"
        if kind is None:
            continue
        key = (kind, n.start_point[0])
        if key in seen:
            continue
        seen.add(key)
        out.append(_finding(rel_path, kind, n, callee, lines))
    return out
