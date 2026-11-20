# -*- coding: utf-8 -*-
"""
js_engine.py
=============
Security engine for JavaScript and TypeScript (.js .jsx .mjs .cjs .ts .tsx) based on a real parser
(tree-sitter, error tolerant) and on data-flow ("taint") analysis across functions and across
project files: the same architecture as the Python engine (ast_engine.py).

  - Sources: req.query/body/params/headers/cookies (Express, Koa, Fastify, Next, Lambda, NestJS),
    location.search/hash, document.cookie/referrer/URL, window.name, message event.data,
    process.argv and process.env.
  - Sinks: eval/Function/vm, child_process, SQL, file system, HTTP requests (SSRF), redirects, XSS
    (res.send, innerHTML, jQuery, React, Angular), templates (SSTI), deserialization, XML, RegExp (ReDoS),
    prototype pollution, JWT, cookies, weak cryptography, postMessage without origin checks.
  - Sanitizers per risk type (encodeURIComponent, escape-html, DOMPurify, path.basename,
    mysql.escape, shell-quote...), validations (includes, test, startsWith, typeof), branches and loops.
  - Per-function summaries shared between files (relative require / import).

Known limitations: types are not resolved (obj.method() on unknown objects stays opaque), frameworks are
recognized by name (there is no real call graph of Express/Nest), and the code is never executed.
If tree-sitter is not installed, analyze_* returns [] and only the pattern engine remains active.
"""

import logging
import os
import re

from ast_engine import (CONF_LABEL, CONST, NOP, OTHER, PARAM, SEV_DOWN, TAINT, TEST_PATH_RE,
                        V_CONST, V_OTHER, V_TAINT, M, join)

log = logging.getLogger(__name__)

try:
    import tree_sitter_javascript as _tsj
    import tree_sitter_typescript as _tst
    from tree_sitter import Language, Parser
    _LANGS = {}
    for _exts, _loader in (((".js", ".jsx", ".mjs", ".cjs"), _tsj.language), ((".ts",), _tst.language_typescript),
                           ((".tsx",), _tst.language_tsx)):
        _lang = Language(_loader())
        for _e in _exts:
            _LANGS[_e] = _lang
    AVAILABLE = True
except Exception as _exc:   # missing packages: only the pattern engine remains
    AVAILABLE = False
    _LANGS = {}
    log.warning("JavaScript/TypeScript AST analysis is disabled: tree-sitter or its JS/TS grammars could not be loaded "
                "(%s: %s). Only the pattern-based rules will run for .js/.ts files. "
                "Install the missing packages with: pip install tree-sitter tree-sitter-javascript tree-sitter-typescript",
                type(_exc).__name__, _exc)

SUPPORTED = (".js", ".jsx", ".mjs", ".cjs", ".ts", ".tsx")
_PARSERS = {}


def _parser(ext):
    p = _PARSERS.get(ext)
    if p is None:
        p = _PARSERS[ext] = Parser(_LANGS[ext])
    return p


# ---------------------------------------------------------------------------
# Node helpers
# ---------------------------------------------------------------------------
def _t(n):
    return n.text.decode("utf-8", "ignore")


def _line(n):
    return n.start_point[0] + 1


def _f(n, name):
    return n.child_by_field_name(name)


def _strval(n):
    s = _t(n)
    return s[1:-1] if len(s) >= 2 and s[0] in "'\"`" else s


def _named(n):
    return [c for c in n.named_children if c.type != "comment"]


TRANSPARENT = ("parenthesized_expression", "non_null_expression", "as_expression", "satisfies_expression",
               "type_assertion", "await_expression")


def _unwrap(n):
    while n is not None and n.type in TRANSPARENT:
        kids = _named(n)
        if not kids:
            break
        n = kids[0] if n.type != "type_assertion" else kids[-1]
    return n


def dotted(n):
    n = _unwrap(n)
    if n is None:
        return None
    t = n.type
    if t in ("identifier", "this", "property_identifier", "shorthand_property_identifier", "super"):
        return _t(n)
    if t == "member_expression":
        o, p = dotted(_f(n, "object")), _f(n, "property")
        return f"{o}.{_t(p)}" if o and p is not None else None
    if t == "subscript_expression":
        o, i = dotted(_f(n, "object")), _f(n, "index")
        if o and i is not None and i.type == "string":
            return f"{o}.{_strval(i)}"
    return None


def _skeleton(n):
    """Text of a composed string with \\x00 in place of the variable parts."""
    n = _unwrap(n)
    if n is None:
        return ""
    if n.type == "string":
        return _strval(n)
    if n.type == "template_string":
        out = []
        for c in n.children:
            if c.type == "template_substitution":
                out.append("\x00")
            elif c.type in ("string_fragment", "escape_sequence"):
                out.append(_t(c))
        return "".join(out)
    if n.type == "binary_expression" and _t(_f(n, "operator")) == "+":
        return _skeleton(_f(n, "left")) + _skeleton(_f(n, "right"))
    if n.type == "number":
        return _t(n)
    return "\x00"


# ---------------------------------------------------------------------------
# Tables
# ---------------------------------------------------------------------------
SOURCE_PREFIXES = ("location.search", "location.hash", "location.href", "location.pathname", "document.URL",
                   "document.documentURI", "document.referrer", "document.cookie", "document.location.search",
                   "document.location.hash", "document.location.href", "window.name", "name", "process.argv", "process.env")
REQ_PARAMS = {"req", "request", "ctx"}
REQ_KEYS = {"query", "body", "params", "headers", "cookies", "url", "originalUrl", "hostname", "files", "signedCookies"}
REQ_ALLOWED = REQ_KEYS | {"get", "header", "param", "file", "files", "rawBody", "raw", "payload", "input", "all", "post", "cookie", "args", "form", "json"}
REQ_LOCAL = {"method", "path", "protocol", "secure", "route", "baseUrl"}
REQ_LOCAL_V = (TAINT, frozenset({"redirect", "ssrf"}), NOP)
ENV_V = (TAINT, frozenset({"redirect", "ssrf", "path", "xss", "ssti"}), NOP)   # process.env: set by whoever administers the system, not by the attacker
FS_READ = {"fs.readFile", "fs.readFileSync", "fs.promises.readFile", "fs-extra.readFile", "fs-extra.readJson", "readFile", "readFileSync"}
NEST_PARAM_DECORATORS = {"Body", "Query", "Param", "Headers", "Req", "Request", "Cookies", "UploadedFile", "UploadedFiles"}
STR_METHODS = {"toString", "trim", "trimStart", "trimEnd", "toLowerCase", "toUpperCase", "replace", "replaceAll", "split",
               "slice", "substring", "substr", "concat", "join", "charAt", "padStart", "padEnd", "repeat", "normalize",
               "get", "getAll", "has", "map", "filter", "reduce", "flat", "toLocaleLowerCase", "toLocaleUpperCase", "at"}
PURE_NAMES = {"String", "JSON.parse", "decodeURIComponent", "decodeURI", "path.join", "path.resolve", "path.normalize",
              "path.dirname", "path.extname", "Object.assign", "Object.keys", "Object.values", "Object.entries",
              "Array.from", "Array.isArray", "Buffer.from", "util.format", "require"}
ALL_K = frozenset(("code", "cmd", "sql", "path", "ssrf", "redirect", "xss", "ssti", "deser", "xml", "redos", "proto"))
SANITIZERS = {
    **{n: {"*"} for n in ("parseInt", "parseFloat", "Number", "Boolean", "isNaN", "isFinite", "Number.parseInt",
                          "Number.parseFloat", "uuid.v4", "uuidv4", "crypto.randomUUID", "crypto.randomBytes", "Math.floor",
                          "Math.ceil", "Math.round", "Math.max", "Math.min", "Math.abs")},
    "encodeURIComponent": {"xss", "ssrf", "redirect", "path"}, "escape-html": {"xss", "ssti"}, "escapeHtml": {"xss", "ssti"},
    "lodash.escape": {"xss"}, "_.escape": {"xss"}, "he.encode": {"xss"}, "he.escape": {"xss"}, "validator.escape": {"xss"},
    "xss": {"xss"}, "sanitize-html": {"xss"}, "sanitizeHtml": {"xss"}, "DOMPurify.sanitize": {"xss"}, "dompurify.sanitize": {"xss"},
    "sanitizer.escape": {"xss"}, "JSON.stringify": {"xss", "cmd"},
    "mysql.escape": {"sql"}, "mysql.escapeId": {"sql"}, "sqlstring.escape": {"sql"}, "SqlString.escape": {"sql"},
    "connection.escape": {"sql"}, "pool.escape": {"sql"}, "db.escape": {"sql"},
    "shell-quote.quote": {"cmd"}, "shellescape": {"cmd"}, "shell-escape": {"cmd"},
    "path.basename": {"path"}, "sanitize-filename": {"path"}, "sanitizeFilename": {"path"},
}
SQL_RE = re.compile(r"\b(select|insert\s+into|update|delete\s+from|drop\s+table|create\s+table|alter\s+table|where|values|union)\b", re.I)
HTML_RE = re.compile(r"<[a-zA-Z/!]")
SEC_ASSERT = None

KIND_INFO = {   # kind -> (sid, title, severity if confirmed, severity if potential, cwe, short explanation, remedy, impact)
    "code": ("AST-JS-001", "Code execution from untrusted data", "CRITICAL", "MEDIUM", "CWE-95",
             "a string that depends on external data is executed as code.",
             "Avoid eval/Function/vm with external data; for structured data use JSON.parse.",
             "Whoever controls the data can run their own code on the server (or in visitors' browsers)."),
    "cmd": ("AST-JS-002", "System command from untrusted data", "CRITICAL", "HIGH", "CWE-78",
            "a shell command is composed with data that depends on external input.",
            "Use execFile/spawn with an argument list (no shell) and validate every argument against an allow-list.",
            "Whoever controls the data can run arbitrary commands on the server (delete files, install software)."),
    "sql": ("AST-JS-003", "SQL query built with untrusted data", "CRITICAL", "HIGH", "CWE-89",
            "the query is composed by concatenating or interpolating non-constant data.",
            "Use parameterized queries: placeholders (? or $1) with values passed separately, never concatenated into the string.",
            "A crafted value alters the query: it can read, modify or delete data it should not touch."),
    "path": ("AST-JS-004", "User-controlled file path (path traversal)", "HIGH", None, "CWE-22",
             "a file path depends on external data: with '../' it is possible to escape the intended directory.",
             "Use a fixed base directory, normalize with path.resolve and verify that the result stays inside the base; "
             "for file names use path.basename.",
             "Whoever controls the path can read or overwrite files they should not touch (keys, configuration)."),
    "ssrf": ("AST-JS-005", "Request to a user-chosen address (SSRF)", "HIGH", None, "CWE-918",
             "the URL (or its host) of an HTTP request depends on external data.",
             "Allow only hosts from an allow-list, or build the URL from fixed parts.",
             "Your server becomes a bridge to internal services (databases, admin panels, cloud metadata)."),
    "redirect": ("AST-JS-006", "Redirect to a user-chosen address", "MEDIUM", None, "CWE-601",
                 "the destination of a redirect depends on external data (open redirect).",
                 "Redirect only to internal paths or to domains from an allow-list.",
                 "A link that looks like it belongs to your site leads the victim to a fake site (phishing)."),
    "xss": ("AST-JS-007", "Unsanitized content inserted into the page (XSS)", "HIGH", None, "CWE-79",
            "external data ends up in the HTML without being sanitized.",
            "Use textContent or the template engine's escaping; if HTML is needed, sanitize it with DOMPurify.",
            "A user can inject a script that runs in visitors' browsers and steals sessions or data."),
    "ssti": ("AST-JS-008", "Template built from user data (SSTI)", "CRITICAL", None, "CWE-1336",
             "the template text depends on external data.",
             "Use fixed templates (files) and pass data as variables, never inside the template text.",
             "The user can write template-engine instructions that execute code on the server."),
    "deser": ("AST-JS-009", "Unsafe deserialization", "HIGH", None, "CWE-502",
              "untrusted data is deserialized with a function that can execute code.",
              "Use JSON.parse; for YAML use safeLoad / a safe schema.", "A crafted payload executes code on the server."),
    "xml": ("AST-JS-010", "XML parsing with external entities (XXE)", "HIGH", None, "CWE-611",
            "XML that depends on external data is parsed with a parser that resolves external entities.",
            "Disable external entities (noent: false) or use a safe parser.",
            "A crafted XML document can make the server read local files or contact internal addresses."),
    "redos": ("AST-JS-011", "Regular expression from untrusted data (ReDoS)", "MEDIUM", None, "CWE-1333",
              "external data is used to build a regular expression.",
              "Escape the value (e.g. lodash.escapeRegExp) or do not build regexes from input.",
              "A crafted value can block the process for minutes (denial of service)."),
    "proto": ("AST-JS-012", "Possible prototype pollution", "HIGH", None, "CWE-1321",
              "user-controlled keys or objects are merged or assigned into objects without checking for '__proto__'.",
              "Block the __proto__, constructor and prototype keys, or use Object.create(null) / Map.",
              "The attacker changes the behavior of every object in the application (potentially up to code execution)."),
}
PLAIN = {
    "jwt_decode": M("AST-JS-013", "JWT token read without verifying the signature", "MEDIUM", None, "-", 0,
                    "jwt.decode does not verify the signature: the content may have been forged.",
                    "Use jwt.verify with explicitly allowed algorithms.", "CWE-345",
                    "An attacker can forge a token with any role they want and the system treats it as valid."),
    "jwt_none": M("AST-JS-013", "JWT with the 'none' algorithm or verification disabled", "HIGH", None, "-", 0,
                  "The 'none' algorithm (or noVerify) accepts unsigned tokens.", "Allow only strong algorithms (HS256/RS256...).",
                  "CWE-347", "Anyone can forge a valid token."),
    "jwt_exp": M("AST-JS-013", "JWT: expiration ignored", "MEDIUM", None, "-", 0, "ignoreExpiration: true accepts expired tokens.",
                 "Remove ignoreExpiration.", "CWE-613", "A stolen token remains valid forever."),
    "crypto_hash": M("AST-JS-014", "Weak hash (MD5/SHA1)", "MEDIUM", None, "-", 0,
                     "MD5 and SHA1 are weak algorithms, unsuitable for protecting passwords.",
                     "For passwords use bcrypt/argon2/scrypt; for general-purpose hashes use SHA-256 or stronger.", "CWE-327"),
    "crypto_cipher": M("AST-JS-014", "Weak encryption or missing IV", "MEDIUM", None, "-", 0,
                       "createCipher is deprecated (no IV) or DES/RC4/ECB is being used.",
                       "Use crypto.createCipheriv with AES-256-GCM and a random IV.", "CWE-327"),
    "random": M("AST-JS-015", "Insecure randomness", "MEDIUM", None, "-", 0,
                "pseudoRandomBytes/Math.random are not cryptographically secure.",
                "Use crypto.randomBytes / crypto.randomUUID for tokens and secrets.", "CWE-338",
                "An attacker can predict the generated values (tokens, codes, session IDs)."),
    "cookie": M("AST-JS-016", "Cookie without protections (httpOnly/secure disabled)", "MEDIUM", None, "-", 0,
                "The cookie is readable by scripts or is also sent over unencrypted connections.",
                "Set httpOnly: true, secure: true and sameSite.", "CWE-1004", "An XSS flaw or an untrusted network allows the session to be stolen."),
    "origin": M("AST-JS-017", "postMessage messages without origin check", "MEDIUM", None, "-", 0,
                "The 'message' listener does not verify event.origin: any site can send it data.",
                "Check event.origin against a list of trusted origins before using event.data.", "CWE-345",
                "A malicious page can drive your application by sending it messages."),
    "post_star": M("AST-JS-017", "postMessage to any origin ('*')", "MEDIUM", None, "-", 0,
                   "postMessage with targetOrigin '*' delivers the message to any site that embeds the page.",
                   "Specify the recipient's exact origin instead of '*'.", "CWE-345",
                   "Sensitive data can reach a malicious page."),
    "redos_lit": M("AST-JS-011", "Regular expression vulnerable to ReDoS", "MEDIUM", None, "-", 0,
                   "The regex has nested quantifiers: with crafted input the computation time explodes.",
                   "Simplify the regex and avoid nested repetitions.", "CWE-1333", "A single input can block the process (denial of service)."),
    "eval_assert": None,
}
PLAIN.pop("eval_assert")

# resolved name -> (kind, argument)   argument: index, "any", "url", "last"
NAME_SINKS = {
    "eval": ("code", 0), "Function": ("code", "any"), "execScript": ("code", 0), "setImmediate": ("code", 0),
    "vm.runInContext": ("code", 0), "vm.runInNewContext": ("code", 0), "vm.runInThisContext": ("code", 0),
    "vm.compileFunction": ("code", 0), "vm.Script": ("code", 0), "VM.run": ("code", 0), "vm2.VM": ("code", 0),
    **{f"child_process.{n}": ("cmd", 0) for n in ("exec", "execSync", "spawn", "spawnSync", "execFile", "execFileSync", "fork")},
    "shelljs.exec": ("cmd", 0), "execa": ("cmd", 0), "execa.command": ("cmd", 0), "execa.shell": ("cmd", 0), "exec": ("cmd", 0),
    **{f"fs.{n}": ("path", 0) for n in ("readFile", "readFileSync", "writeFile", "writeFileSync", "appendFile", "appendFileSync",
                                         "createReadStream", "createWriteStream", "readdir", "readdirSync", "unlink", "unlinkSync",
                                         "rm", "rmSync", "rmdir", "rmdirSync", "mkdir", "mkdirSync", "stat", "statSync", "open",
                                         "openSync", "opendir", "copyFile", "copyFileSync", "rename", "renameSync", "access",
                                         "accessSync", "existsSync", "truncate", "chmod", "readlink", "lstat")},
    **{f"fs.promises.{n}": ("path", 0) for n in ("readFile", "writeFile", "appendFile", "readdir", "unlink", "rm", "mkdir", "stat",
                                                  "open", "copyFile", "rename", "access")},
    **{f"fs-extra.{n}": ("path", 0) for n in ("readFile", "writeFile", "remove", "copy", "move", "readJson", "outputFile", "ensureDir")},
    **{n: ("ssrf", "url") for n in ("axios", "axios.get", "axios.post", "axios.put", "axios.patch", "axios.delete", "axios.head",
                                     "axios.request", "fetch", "node-fetch", "got", "got.get", "got.post", "got.put", "got.delete",
                                     "request", "request.get", "request.post", "needle", "needle.get", "needle.post", "superagent.get",
                                     "superagent.post", "http.get", "http.request", "https.get", "https.request", "ky", "ky.get",
                                     "ky.post", "undici.request", "undici.fetch", "$.ajax", "$.get", "$.post", "$.getJSON", "jQuery.ajax",
                                     "jQuery.get", "jQuery.post", "WebSocket", "net.connect", "net.createConnection", "XMLHttpRequest.open",
                                     "bent", "phin", "wreck.get", "wreck.request", "urllib.request")},
    "document.write": ("xss", 0), "document.writeln": ("xss", 0), "$": ("xss", 0, "jq"), "jQuery": ("xss", 0, "jq"),
    "ejs.render": ("ssti", 0), "pug.compile": ("ssti", 0), "pug.render": ("ssti", 0), "handlebars.compile": ("ssti", 0),
    "Handlebars.compile": ("ssti", 0), "mustache.render": ("ssti", 0), "Mustache.render": ("ssti", 0), "_.template": ("ssti", 0),
    "lodash.template": ("ssti", 0), "hogan.compile": ("ssti", 0), "Hogan.compile": ("ssti", 0), "doT.template": ("ssti", 0),
    "nunjucks.renderString": ("ssti", 0), "nunjucks.compile": ("ssti", 0), "dot.template": ("ssti", 0), "dot.compile": ("ssti", 0),
    "Eta.render": ("ssti", 0), "eta.render": ("ssti", 0), "Sqrl.render": ("ssti", 0), "squirrelly.render": ("ssti", 0),
    "hogan.js.compile": ("ssti", 0), "ejs.compile": ("ssti", 0), "mustache.render": ("ssti", 0), "handlebars.compile": ("ssti", 0), "dust.compile": ("ssti", 0), "jade.compile": ("ssti", 0), "jade.render": ("ssti", 0),
    "dompurify.sanitize": None,
    "serialize.unserialize": ("deser", 0), "node-serialize.unserialize": ("deser", 0), "unserialize": ("deser", 0),
    "yaml.load": ("deser", 0), "js-yaml.load": ("deser", 0), "v8.deserialize": ("deser", 0), "funcster.deepDeserialize": ("deser", 0),
    "RegExp": ("redos", 0),
    "_.merge": ("proto", "any"), "lodash.merge": ("proto", "any"), "_.defaultsDeep": ("proto", "any"), "lodash.defaultsDeep": ("proto", "any"),
    "_.set": ("proto", "any"), "lodash.set": ("proto", "any"), "_.setWith": ("proto", "any"), "$.extend": ("proto", "any"),
    "jQuery.extend": ("proto", "any"), "merge": ("proto", "any"), "deepmerge": ("proto", "any"), "mixin-deep": ("proto", "any"),
    "sanitize": None,
}
NAME_SINKS = {k: v for k, v in NAME_SINKS.items() if v}
PROP_POT = {"bypassSecurityTrustHtml": "MEDIUM", "bypassSecurityTrustScript": "MEDIUM", "bypassSecurityTrustUrl": "MEDIUM",
            "bypassSecurityTrustResourceUrl": "MEDIUM", "bypassSecurityTrustStyle": "MEDIUM", "trustAsHtml": "MEDIUM", "trustAsJs": "MEDIUM",
            "trustAsResourceUrl": "MEDIUM", "trustAs": "MEDIUM", "insertAdjacentHTML": "MEDIUM"}
PROP_SINKS = {   # method name -> (kind, argument, receiver constraint)
    "redirect": ("redirect", "any", "res"), "location": ("redirect", 0, "res"), "sendFile": ("path", 0, "res"), "sendfile": ("path", 0, "res"),
    "download": ("path", 0, "res"), "send": ("xss", 0, "res"), "write": ("xss", 0, "res"), "end": ("xss", 0, "res"),
    "html": ("xss", 0, "jq"), "append": ("xss", 0, "jq"), "prepend": ("xss", 0, "jq"), "after": ("xss", 0, "jq"),
    "before": ("xss", 0, "jq"), "replaceWith": ("xss", 0, "jq"), "wrap": ("xss", 0, "jq"),
    "insertAdjacentHTML": ("xss", 1, None), "bypassSecurityTrustHtml": ("xss", 0, None), "bypassSecurityTrustScript": ("xss", 0, None),
    "bypassSecurityTrustUrl": ("xss", 0, None), "bypassSecurityTrustResourceUrl": ("xss", 0, None), "bypassSecurityTrustStyle": ("xss", 0, None),
    "trustAsHtml": ("xss", 0, None), "trustAsJs": ("xss", 0, None), "trustAsResourceUrl": ("xss", 0, None), "trustAs": ("xss", 1, None), "setContent": ("xss", 0, None),
    "evaluate": ("code", 0, None), "evaluateHandle": ("code", 0, None), "evaluateOnNewDocument": ("code", 0, None),
    "goto": ("ssrf", 0, None), "navigate": ("ssrf", 0, None), "open": ("ssrf", 0, "page"),
    "runInContext": ("code", 0, None), "runInNewContext": ("code", 0, None), "runInThisContext": ("code", 0, None),
    "assign": ("redirect", 0, "loc"), "replace": ("redirect", 0, "loc"),
    "$queryRawUnsafe": ("sql", 0, None), "$executeRawUnsafe": ("sql", 0, None), "literal": ("sql", 0, None),
    "parseXml": ("xml", 0, "xml"), "parseXmlString": ("xml", 0, "xml"),
    "compileScript": ("code", "any", None), "evaluateJavaScript": ("code", 0, "page"), "property": ("xss", 1, "page"),
    "renderHtml": ("xss", 0, "page"), "parse": ("xml", 0, "parser"), "parseString": ("xml", 0, "parser"),
    "callFunctionOn": ("code", "any", None), "exposeFunction": ("code", "any", None), "addScriptTag": ("code", "any", None),
    "addStyleTag": ("xss", "any", None), "setRequestInterception_NO": ("ssrf", 0, None),
}
SQL_ATTRS = {"query", "execute", "raw", "run", "all", "get", "each", "exec", "prepare", "queryRaw", "executeRaw", "select"}
FS_SENSITIVE_OK_ROOT = "root"
DOM_SINK_PROPS = {"innerHTML": "xss", "outerHTML": "xss", "srcdoc": "xss", "insertAdjacentHTML": "xss"}
LOC_OBJECTS = ("location", "window.location", "document.location", "self.location", "top.location")


class Project:
    def __init__(self):
        self.modules, self.summaries = {}, {}

    def add(self, mod, analyzer_key):
        self.modules[mod] = analyzer_key
        if mod.endswith("/index"):
            self.modules[mod[:-6]] = analyzer_key


def module_id(rel_path):
    p = rel_path.replace("\\", "/")
    return os.path.splitext(p)[0]


class JsAnalyzer:
    def __init__(self, rel_path, ext, root, project=None):
        self.rel_path, self.ext, self.root, self.project = rel_path, ext, root, project
        self.mod = module_id(rel_path)
        self.findings, self.seen = [], set()
        self.is_test = bool(TEST_PATH_RE.search(rel_path.replace("\\", "/").lower())) or bool(
            re.search(r"\.(test|spec)\.[jt]sx?$", rel_path.lower()))
        self.aliases, self.registry, self.summaries, self.sigs = {}, {}, {}, {}
        self.module_env = {}
        self.cur, self.cur_class, self.report, self.loop_depth = None, None, True, 0
        self.msg_cb = False
        self.name_hint = None

    # ----------------------------------------------------------- preparation
    def _rel_module(self, spec):
        if not spec.startswith("."):
            return spec
        base = os.path.dirname(self.mod)
        return os.path.normpath(os.path.join(base, spec)).replace("\\", "/")

    def _alias_target(self, spec, member=None):
        if spec.startswith("."):
            return "@" + self._rel_module(spec) + ":" + (member or "")
        return spec + ("." + member if member else "")

    def _bind_pattern(self, pat, spec):
        """const {a, b: c} = require('x')  /  import {a as c} from 'x'"""
        if pat.type == "identifier":
            self.aliases[_t(pat)] = self._alias_target(spec)
        elif pat.type == "object_pattern":
            for c in _named(pat):
                if c.type == "shorthand_property_identifier_pattern":
                    self.aliases[_t(c)] = self._alias_target(spec, _t(c))
                elif c.type == "pair_pattern":
                    k, v = _f(c, "key"), _f(c, "value")
                    if v is not None and v.type == "identifier":
                        self.aliases[_t(v)] = self._alias_target(spec, _t(k))

    def prepare(self):
        stack = [self.root]
        while stack:
            n = stack.pop()
            t = n.type
            if t == "variable_declarator":
                v = _f(n, "value")
                v = _unwrap(v) if v is not None else None
                if v is not None and v.type == "call_expression":
                    fn = _f(v, "function")
                    args = _f(v, "arguments")
                    if fn is not None and _t(fn) == "require" and args is not None and _named(args) and _named(args)[0].type == "string":
                        self._bind_pattern(_f(n, "name"), _strval(_named(args)[0]))
            elif t == "import_statement":
                src = _f(n, "source")
                if src is not None:
                    spec = _strval(src)
                    for c in n.children:
                        if c.type == "import_clause":
                            for cc in c.children:
                                if cc.type == "identifier":
                                    self.aliases[_t(cc)] = self._alias_target(spec)
                                elif cc.type == "namespace_import":
                                    for x in cc.children:
                                        if x.type == "identifier":
                                            self.aliases[_t(x)] = self._alias_target(spec)
                                elif cc.type == "named_imports":
                                    for sp in cc.children:
                                        if sp.type == "import_specifier":
                                            nm, al = _f(sp, "name"), _f(sp, "alias")
                                            self.aliases[_t(al if al is not None else nm)] = self._alias_target(spec, _t(nm))
            stack.extend(n.children)
        for c in _named(self.root):
            self._collect(c)

    def _collect(self, n):
        t = n.type
        if t == "export_statement":
            decl = _f(n, "declaration") or _f(n, "value")
            if decl is not None:
                if n.text.startswith(b"export default") and decl.type in ("function_declaration", "function_expression", "arrow_function",
                                                                          "generator_function_declaration"):
                    self.registry["default"] = (decl, None)
                self._collect(decl)
            return
        if t in ("function_declaration", "generator_function_declaration"):
            nm = _f(n, "name")
            if nm is not None:
                self.registry[_t(nm)] = (n, None)
        elif t in ("lexical_declaration", "variable_declaration"):
            for d in _named(n):
                nm, v = _f(d, "name"), _f(d, "value")
                v = _unwrap(v) if v is not None else None
                if nm is not None and nm.type == "identifier" and v is not None and v.type in ("arrow_function", "function_expression", "function"):
                    self.registry[_t(nm)] = (v, None)
        elif t == "class_declaration":
            nm, body = _f(n, "name"), _f(n, "body")
            if nm is not None and body is not None:
                for m in _named(body):
                    if m.type == "method_definition":
                        self.registry[f"{_t(nm)}.{_t(_f(m, 'name'))}"] = (m, _t(nm))
        elif t == "expression_statement":
            e = _named(n)[0] if _named(n) else None
            if e is not None and e.type == "assignment_expression":
                left, right = dotted(_f(e, "left")), _unwrap(_f(e, "right"))
                if left in ("module.exports", "exports.default") and right is not None:
                    if right.type in ("function_expression", "arrow_function", "function"):
                        self.registry["default"] = (right, None)
                    elif right.type == "object":
                        for p in _named(right):
                            if p.type == "pair":
                                v = _unwrap(_f(p, "value"))
                                if v is not None and v.type in ("function_expression", "arrow_function", "function"):
                                    self.registry[_t(_f(p, "key"))] = (v, None)
                            elif p.type == "method_definition":
                                self.registry[_t(_f(p, "name"))] = (p, None)
                            elif p.type == "shorthand_property_identifier":
                                nm = _t(p)
                                if nm in self.registry:
                                    pass
                elif left and (left.startswith("module.exports.") or left.startswith("exports.")) and right is not None and \
                        right.type in ("function_expression", "arrow_function", "function"):
                    self.registry[left.split(".")[-1]] = (right, None)

    def update_summaries(self):
        changed = False
        for key, (node, cls) in self.registry.items():
            s = self._run_function(node, key, cls, False)
            sig = (tuple(sorted((i, tuple(sorted(m))) for i, m in s["hits"].items())),
                   (s["ret"][0], tuple(sorted(s["ret"][1])), tuple(sorted(s["ret"][2]))))
            changed |= self.sigs.get(key) != sig
            self.sigs[key] = sig
            self.summaries[key] = s
            if self.project is not None:
                self.project.summaries[(self.mod, key)] = s
        return changed

    def finish(self):
        self.report, self.cur = True, None
        self._walk(_named(self.root), self.module_env)
        return self.findings

    def run(self):
        self.prepare()
        for _ in range(3):
            if not self.update_summaries():
                break
        return self.finish()

    # ----------------------------------------------------------- name resolution
    def resolve(self, dn):
        if not dn:
            return None
        head, _, rest = dn.partition(".")
        full = self.aliases.get(head)
        if full is None:
            return dn
        if full.startswith("@"):
            return full + ("." + rest if rest else "")
        return full + ("." + rest if rest else "")

    def _global_key(self, rn):
        if not rn or self.project is None or not rn.startswith("@"):
            return None
        mod, _, rest = rn[1:].partition(":")
        key_mod = self.project.modules.get(mod)
        if key_mod is None:
            return None
        rest = rest.lstrip(".")
        key = rest.split(".")[0] if rest else "default"
        k = (key_mod, key)
        return k if k in self.project.summaries else ((key_mod, "default") if not rest and (key_mod, "default") in self.project.summaries else None)

    def _local_key(self, fn):
        if fn is None:
            return None, 0
        fn = _unwrap(fn)
        if fn.type == "identifier" and _t(fn) in self.registry:
            return _t(fn), 0
        if fn.type == "member_expression":
            o, p = _f(fn, "object"), _f(fn, "property")
            if o is not None and o.type == "this" and self.cur_class:
                k = f"{self.cur_class}.{_t(p)}"
                return (k, 0) if k in self.registry else (None, 0)
            if o is not None and o.type == "identifier":
                k = f"{_t(o)}.{_t(p)}"
                if k in self.registry:
                    return k, 0
        return None, 0

    # ----------------------------------------------------------- reporting
    def _snippet(self, line):
        try:
            t = self.root.text.split(b"\n")[line - 1].decode("utf-8", "ignore").strip()
        except Exception:
            return ""
        return t[:160] + (" …" if len(t) > 160 else "")

    def _add(self, sid, name, sev, conf, line, desc, rec, cwe, impact=None, via=None):
        key = (sid, line)
        if key in self.seen:
            return
        self.seen.add(key)
        if via:
            desc += f" (the data flows through the function '{via}')"
        if self.is_test:
            sev = SEV_DOWN.get(sev, sev)
            desc += " [Test file: severity reduced.]"
        f = {"id": sid, "name": name, "severity": sev, "confidence": "confirmed" if conf == "fixed" else conf,
             "confidence_label": CONF_LABEL[conf], "file": self.rel_path, "line": line, "snippet": self._snippet(line),
             "description": desc, "recommendation": rec, "engine": "js_ast", "cwe": cwe}
        if impact:
            f["impact"] = impact
        self.findings.append(f)

    def _meta(self, kind, label):
        sid, name, sev, pot, cwe, what, rec, impact = KIND_INFO[kind]
        return {"sid": sid, "name": name, "sev": sev, "pot": pot, "kind": kind, "cwe": cwe,
                "desc": f"{label}: {what}", "rec": rec, "impact": impact, "key": f"{sid}|{label}"}

    def _hit(self, kind, label, val, node, via=None, only_confirmed=False, record_only=False, sev=None, pot=None):
        lvl = CONST if kind in val[1] else val[0]
        if lvl == CONST:
            return
        meta = self._meta(kind, label)
        if val[2] and self.cur is not None:
            for p in val[2]:
                self.cur["hits"].setdefault(p, {})[meta["key"]] = (kind, label)
        if not self.report or record_only:
            return
        if lvl == TAINT:
            self._add(meta["sid"], meta["name"], sev or meta["sev"], "confirmed", _line(node), meta["desc"], meta["rec"], meta["cwe"], meta["impact"], via)
        elif (pot or meta["pot"]) and not only_confirmed:
            self._add(meta["sid"], meta["name"], pot or meta["pot"], "unknown", _line(node), meta["desc"], meta["rec"], meta["cwe"], meta["impact"], via)

    def _plain(self, key, node, conf="fixed"):
        if self.report:
            m = PLAIN[key]
            self._add(m["sid"], m["name"], m["sev"], conf, _line(node), m["desc"], m["rec"], m["cwe"], m.get("impact"))

    # ----------------------------------------------------------- functions
    def _param_names(self, p):
        """Names declared by a parameter/pattern."""
        t = p.type
        if t == "identifier":
            return [_t(p)]
        if t in ("required_parameter", "optional_parameter"):
            pat = _f(p, "pattern")
            return self._param_names(pat) if pat is not None else []
        if t == "assignment_pattern":
            return self._param_names(_f(p, "left"))
        if t == "rest_pattern" or t == "rest_element":
            k = _named(p)
            return self._param_names(k[0]) if k else []
        if t in ("object_pattern", "array_pattern"):
            out = []
            for c in _named(p):
                if c.type == "shorthand_property_identifier_pattern":
                    out.append(_t(c))
                elif c.type == "pair_pattern":
                    out += self._param_names(_f(c, "value"))
                else:
                    out += self._param_names(c)
            return out
        return []

    def _params(self, node):
        ps = _f(node, "parameters")
        if ps is None:
            p = _f(node, "parameter")
            return [p] if p is not None else []
        return [c for c in _named(ps)]

    def _decorators(self, p):
        return [_t(d).lstrip("@").split("(")[0] for d in p.children if d.type == "decorator"]

    def _run_function(self, node, name, cls, report, base_env=None, msg_cb=False):
        saved = (self.cur, self.report, self.cur_class, self.loop_depth)
        self.report, self.loop_depth = report, 0
        if cls:
            self.cur_class = cls
        params = self._params(node)
        pnames = [(self._param_names(p) or [None])[0] for p in params]
        fname = name or ""
        handler = bool(pnames) and (pnames[0] in REQ_PARAMS or (len(pnames) > 1 and pnames[1] in ("res", "response", "reply")) or (pnames[0] == "event" and "handler" in fname.lower()) or
                                    (pnames[0] in ("context", "ctx") and fname in ("getServerSideProps", "getInitialProps")) or msg_cb)
        env = dict(base_env) if base_env is not None else {k: v for k, v in self.module_env.items() if not isinstance(k, tuple) and v[0] == CONST}
        for i, p in enumerate(params):
            deco = set(self._decorators(p))
            nest = bool(deco & NEST_PARAM_DECORATORS)
            names = self._param_names(p)
            is_req = (i == 0 and handler and not msg_cb)
            if i == 1 and len(pnames) > 1 and pnames[1] == "args" and pnames[0] in ("parent", "_", "root", "obj", "source", "__"):
                val = (TAINT, NOP, frozenset({i}))   # GraphQL resolver: the arguments come from the client
            elif msg_cb and i == 0:
                val = (TAINT, NOP, frozenset({i}))
            elif is_req or nest:
                val = (TAINT, NOP, frozenset({i}))
            else:
                val = (PARAM, NOP, frozenset({i}))
            pat = _f(p, "pattern") if p.type in ("required_parameter", "optional_parameter") else p
            if is_req and not nest and pat is not None and pat.type == "object_pattern":
                for nm in names:   # ({ params, query, session }): only the request keys are user data
                    env[nm] = val if nm in REQ_ALLOWED else V_OTHER
            else:
                for nm in names:
                    env[nm] = val
        ctx = {"hits": {}, "rets": [], "handler": handler}
        self.cur = ctx
        body = _f(node, "body")
        if body is not None:
            if body.type == "statement_block":
                self._walk(_named(body), env)
            else:
                ctx["rets"].append(self.eval(body, env))
        ret = join(ctx["rets"]) if ctx["rets"] else V_CONST
        self.cur, self.report, self.cur_class, self.loop_depth = saved
        return {"hits": ctx["hits"], "ret": ret, "params": pnames}

    def _apply_summary(self, s, key, offset, node, vals, kw=None):
        argmap = {j + offset: v for j, v in enumerate(vals)}
        for idx, metas in s["hits"].items():
            v = argmap.get(idx)
            if v is not None:
                for kind, label in metas.values():
                    self._hit(kind, label, v, node, via=key.split(".")[-1], only_confirmed=True)
        ret = s["ret"]
        parts = []
        if ret[0] >= OTHER:
            parts.append((ret[0], ret[1], NOP))
        parts += [(argmap[p][0], argmap[p][1] | ret[1], argmap[p][2]) for p in ret[2] if p in argmap]
        return join(parts) if parts else V_CONST

    # ----------------------------------------------------------- expressions
    def eval(self, n, env):
        if n is None:
            return V_CONST
        t = n.type
        if t in ("string", "number", "true", "false", "null", "undefined", "regex", "this", "template_literal_type"):
            if t == "regex":
                self._regex_literal(n)
            return V_CONST if t != "this" else env.get("this", V_OTHER)
        if t == "identifier":
            nm = _t(n)
            if nm in env:
                return env[nm]
            if nm == "undefined":
                return V_CONST
            return V_CONST if nm in self.aliases else V_OTHER
        if t in TRANSPARENT:
            kids = _named(n)
            return self.eval(kids[0] if t != "type_assertion" else kids[-1], env) if kids else V_OTHER
        if t == "member_expression":
            return self._member(n, env)
        if t == "subscript_expression":
            vv = self.eval(_f(n, "object"), env)
            sv = self.eval(_f(n, "index"), env)
            if vv[0] == CONST:
                return vv
            return join([vv, sv]) if _f(n, "index") is not None and _f(n, "index").type != "string" else vv
        if t == "call_expression":
            return self._call(n, env)
        if t == "new_expression":
            return self._call(n, env, True)
        if t == "template_string":
            subs = [self.eval(_named(c)[0], env) for c in n.children if c.type == "template_substitution" and _named(c)]
            v = join(subs) if subs else V_CONST
            self._str_checks(n, v)
            return v
        if t == "binary_expression":
            op = _t(_f(n, "operator"))
            lv, rv = self.eval(_f(n, "left"), env), self.eval(_f(n, "right"), env)
            if op in ("==", "===", "!=", "!==", "<", ">", "<=", ">=", "instanceof", "in", "-", "*", "/", "%", "**", "&", "|", "^", "<<", ">>", ">>>"):
                return V_CONST
            v = join([lv, rv])
            if op == "+":
                self._str_checks(n, v)
            return v
        if t == "unary_expression":
            op = _t(_f(n, "operator"))
            v = self.eval(_f(n, "argument"), env)
            return V_CONST if op in ("!", "typeof", "void", "-", "+", "~", "delete") else v
        if t == "ternary_expression":
            self.eval(_f(n, "condition"), env)
            return join([self.eval(_f(n, "consequence"), env), self.eval(_f(n, "alternative"), env)])
        if t == "assignment_expression":
            return self._assign_expr(n, env)
        if t == "augmented_assignment_expression":
            return self._assign_expr(n, env, aug=True)
        if t == "sequence_expression":
            vals = [self.eval(c, env) for c in _named(n)]
            return vals[-1] if vals else V_OTHER
        if t in ("array", "object"):
            return self._literal(n, env)
        if t == "spread_element":
            k = _named(n)
            return self.eval(k[0], env) if k else V_OTHER
        if t in ("arrow_function", "function_expression", "function", "generator_function"):
            nm, self.name_hint = self.name_hint, None
            self._run_function(n, nm, None, self.report, env, msg_cb=self.msg_cb)
            self.msg_cb = False
            return V_CONST
        if t == "class":
            return V_CONST
        if t in ("jsx_element", "jsx_self_closing_element", "jsx_fragment"):
            return self._jsx(n, env)
        if t == "jsx_expression":
            k = _named(n)
            return self.eval(k[0], env) if k else V_OTHER
        if t == "yield_expression":
            k = _named(n)
            return self.eval(k[0], env) if k else V_OTHER
        return V_OTHER

    def _literal(self, n, env):
        vals = []
        for c in _named(n):
            if c.type == "pair":
                vals.append(self.eval(_f(c, "value"), env))
            elif c.type == "shorthand_property_identifier":
                vals.append(env.get(_t(c), V_OTHER))
            elif c.type == "method_definition":
                self._run_function(c, _t(_f(c, "name")), None, self.report, env)
            elif c.type == "spread_element":
                vals.append(self.eval(c, env))
            else:
                vals.append(self.eval(c, env))
        return join(vals) if vals else V_CONST

    REDOS_RE = re.compile(r"\((?:[^()\\]|\\.)*[+*](?:[^()\\]|\\.)*\)[+*{]")

    def _regex_literal(self, n):
        if self.report and self.REDOS_RE.search(_t(n)):
            self._plain("redos_lit", n, "unknown")

    def _jsx(self, n, env):
        vals = []
        elements = [n] if n.type == "jsx_self_closing_element" else [c for c in n.children if c.type == "jsx_opening_element"]
        for el in elements:
            for a in el.children:
                if a.type == "jsx_attribute":
                    k = _named(a)
                    if k and _t(k[0]) == "dangerouslySetInnerHTML" and len(k) > 1:
                        hv = self.eval(k[1], env)
                        # potential only if the value depends on the component's parameters/props (not on unknown globals)
                        self._hit("xss", "dangerouslySetInnerHTML", hv, a, pot="MEDIUM" if hv[0] == PARAM else None)
                    elif len(k) > 1:
                        self.eval(k[1], env)
        for c in n.children:
            if c.type in ("jsx_element", "jsx_self_closing_element", "jsx_expression"):
                vals.append(self.eval(c, env))
        return join(vals) if vals else V_CONST

    def _member(self, n, env):
        dn = dotted(n)
        obj, prop = _f(n, "object"), _f(n, "property")
        pname = _t(prop) if prop is not None else ""
        if dn:
            if dn in env:
                return env[dn]
            root = dn.split(".")[0]
            if root not in env:
                rn = self.resolve(dn)
                r2 = rn[7:] if rn.startswith("window.") else rn
                if r2.startswith("process.env"):
                    return ENV_V
                if r2.startswith(SOURCE_PREFIXES):
                    return V_TAINT
                if root in self.aliases:
                    return V_CONST
        if n.type == "subscript_expression":
            return self.eval(n, env)
        ov = self.eval(obj, env)
        if pname == "length":
            return V_CONST
        if ov[0] == TAINT and dn and dn.count(".") == 1 and dn.split(".")[0] in ("req", "request") and pname not in REQ_ALLOWED:
            return V_OTHER   # req.app, req.session, req.foo: not user-chosen data
        if ov[0] == TAINT and pname in REQ_LOCAL and dn and dn.split(".")[0] in REQ_PARAMS:
            return REQ_LOCAL_V
        return ov

    # ----------------------------------------------------------- strings
    def _str_checks(self, node, v):
        if not self.report or v[0] < PARAM:
            return
        par = node.parent
        if par is not None and par.type == "arguments" and par.parent is not None:
            fnn = _f(par.parent, "function")
            if fnn is not None and (dotted(fnn) or "").startswith("console."):
                return
        sk = _skeleton(node)
        if v[0] != TAINT:
            if "\x00" in sk and HTML_RE.search(sk) and "xss" not in v[1]:
                self._hit("xss", "HTML built from non-constant values", v, node, pot="LOW")
            return
        if "ssrf" not in v[1] and re.search(r"https?://\x00", sk):
            self._hit("ssrf", "URL host built from user data", v, node)
        if "xss" not in v[1] and "\x00" in sk and HTML_RE.search(sk) and not (self.cur and self.cur.get("in_sql")):
            self._hit("xss", "HTML built with user data", v, node)

    def _building(self, n, env):
        n = _unwrap(n)
        if n is None:
            return False
        if n.type == "template_string":
            return any(c.type == "template_substitution" for c in n.children)
        if n.type == "binary_expression" and _t(_f(n, "operator")) == "+":
            sk = _skeleton(n)
            return "\x00" in sk
        if n.type == "identifier":
            return bool(env.get(("built", _t(n))))
        if n.type == "call_expression":
            d = dotted(_f(n, "function")) or ""
            return d.endswith((".concat", "util.format", ".format")) and bool(_named(_f(n, "arguments")))
        return False

    # ----------------------------------------------------------- assignments
    def _assign_expr(self, n, env, aug=False):
        left, right = _f(n, "left"), _f(n, "right")
        self.name_hint = dotted(left)
        v = self.eval(right, env)
        self.name_hint = None
        lu = _unwrap(left)
        if aug and lu is not None and lu.type == "identifier":
            v = join([env.get(_t(lu), V_OTHER), v])
        built = v[0] > CONST and self._building(right, env)
        self._store(lu, v, env, built, n, right)
        return v

    def _store(self, target, v, env, built, node=None, right=None):
        if target is None:
            return
        t = target.type
        if t == "identifier":
            nm = _t(target)
            env[nm] = v
            if built:
                env[("built", nm)] = True
            else:
                env.pop(("built", nm), None)
            if right is not None and re.match(r"https?://[^/\x00]+/", _skeleton(right)):
                env[("hostfixed", nm)] = True
            else:
                env.pop(("hostfixed", nm), None)
        elif t in ("object_pattern", "array_pattern"):
            for nm in self._param_names(target):
                env[nm] = v
        elif t == "member_expression":
            prop = _f(target, "property")
            pname = _t(prop) if prop is not None else ""
            obj = _f(target, "object")
            od = dotted(obj) or ""
            if node is not None:
                fixed = right is not None and (re.match(r"https?://[^/\x00]+/", _skeleton(right)) or self._prefix_fixed(right, env))
                if pname in ("href", "location") and (od in LOC_OBJECTS or od in ("window", "document", "self", "top")) and v[0] >= PARAM:
                    if not fixed:
                        self._hit("redirect", f"{od}.{pname}", v, node, pot="LOW")
                elif pname in DOM_SINK_PROPS:
                    self._hit(DOM_SINK_PROPS[pname], pname, v, node, pot="MEDIUM" if (right is not None and self._building(right, env)) else None)
                elif pname in ("href", "location") and (od in LOC_OBJECTS or od in ("window", "document", "self", "top")):
                    self._hit("redirect", f"{od}.{pname}", v, node)
                elif pname == "location" or (pname == "href" and od in LOC_OBJECTS):
                    if not fixed:
                        self._hit("redirect", pname, v, node)
            dn = dotted(target)
            if dn:
                env[dn] = v
            root = target
            while root is not None and root.type in ("member_expression", "subscript_expression"):
                root = _unwrap(_f(root, "object"))
            if root is not None and root.type == "identifier":
                env[_t(root)] = join([env.get(_t(root), V_CONST), v])
        elif t == "subscript_expression":
            idx, obj = _f(target, "index"), _f(target, "object")
            if node is not None and idx is not None:
                iv = self.eval(idx, env)
                inner = _unwrap(obj)
                if iv[0] == TAINT and inner is not None and inner.type == "subscript_expression":   # a[k1][k2] = v
                    k1 = self.eval(_f(inner, "index"), env)
                    if k1[0] == TAINT:
                        self._hit("proto", "Assignment with nested user-controlled keys", join([iv, k1]), node)
            root = target
            while root is not None and root.type in ("member_expression", "subscript_expression"):
                root = _unwrap(_f(root, "object"))
            if root is not None and root.type == "identifier":
                env[_t(root)] = join([env.get(_t(root), V_CONST), v])

    # ----------------------------------------------------------- calls
    def _prefix_fixed(self, node, env):
        """True if the initial part of the URL (the host) is not chosen by the user: a non-dangerous variable/config at the start."""
        a = _unwrap(node)
        if a is None:
            return False
        if a.type == "template_string":
            for c in a.children:
                if c.type == "string_fragment":
                    return bool(re.match(r"https?://[^/]+/", _skeleton(a)))
                if c.type == "template_substitution":
                    k = _named(c)
                    return bool(k) and self.eval(k[0], env)[0] < TAINT
            return False
        if a.type == "binary_expression" and _t(_f(a, "operator")) == "+":
            left = _unwrap(_f(a, "left"))
            while left is not None and left.type == "binary_expression" and _t(_f(left, "operator")) == "+":
                left = _unwrap(_f(left, "left"))
            if left is None or left.type == "string":
                return False
            return left.type in ("identifier", "member_expression", "template_string") and self.eval(left, env)[0] < TAINT
        return False

    def _url_value(self, node, val, env):
        """For HTTP requests: if the argument is an object only url/host matter; if the host is fixed it is not SSRF."""
        a = _unwrap(node)
        if a is None:
            return None
        if a.type == "object":
            vals = []
            for c in _named(a):
                if c.type == "pair" and _t(_f(c, "key")).strip("'\"") in ("url", "uri", "host", "hostname", "baseURL", "baseUrl", "proxy"):
                    vals.append(self.eval(_f(c, "value"), env))
                elif c.type == "shorthand_property_identifier" and _t(c) in ("url", "uri", "host"):
                    vals.append(env.get(_t(c), V_OTHER))
            return join(vals) if vals else None
        if re.match(r"https?://[^/\x00]+/", _skeleton(a)) or (a.type == "identifier" and env.get(("hostfixed", _t(a)))) or \
                self._prefix_fixed(a, env):
            return None
        return val

    def _call(self, n, env, is_new=False):
        fn = _f(n, "constructor" if is_new else "function")
        argn = _f(n, "arguments")
        fnu = _unwrap(fn) if fn is not None else None
        dn = dotted(fn) if fn is not None else None
        rn = self.resolve(dn) if dn else None
        attr = None
        recv = None
        recv_n = None
        if fnu is not None and fnu.type == "member_expression":
            recv_n = _f(fnu, "object")
            attr = _t(_f(fnu, "property"))
        # tagged template: sql`...` => parameterized
        if argn is not None and argn.type == "template_string":
            subs = [self.eval(_named(c)[0], env) for c in argn.children if c.type == "template_substitution" and _named(c)]
            return V_CONST if (dn or "").split(".")[-1].lower() in ("sql", "gql", "css", "html", "styled") or True else join(subs)
        args = _named(argn) if argn is not None and argn.type == "arguments" else []
        if (attr in ("addEventListener", "on") or rn == "addEventListener") and args and args[0].type == "string" and _strval(args[0]) == "message":
            self.msg_cb = True
            self._check_origin(n, args)
        elif attr in ("tool", "registerTool", "setRequestHandler", "addTool", "prompt", "resource") and args:
            self.msg_cb = True   # MCP server: the tool arguments come from the client/model
        vals = []
        for a in args:
            vals.append(self.eval(a, env))
        self.msg_cb = False
        if recv_n is not None:
            recv = self.eval(recv_n, env)
        elif fnu is not None and fnu.type not in ("identifier", "super", "import"):
            recv = self.eval(fnu, env)
        self._sinks(n, fnu, rn, attr, recv_n, args, vals, env, is_new)
        allv = vals
        # direct sources
        if rn in ("require",) or (fnu is not None and fnu.type == "import"):
            return V_CONST
        san = SANITIZERS.get(rn) or (SANITIZERS.get(attr) if attr in ("escape", "escapeHtml", "sanitize") else None)
        last = (rn or attr or "").split(".")[-1]
        if san is None and re.match(r"(sanitize|escape|encode|purify|clean)[A-Z_]?", last.lstrip("$_"), re.I) and last not in ("encode", "encodeURI") :
            san = {"xss", "redirect", "ssrf", "path", "ssti"}
        if san is None and attr in ("replace", "replaceAll") and args and args[0].type == "regex" and b"\\.\\." in args[0].text:
            base = join(([recv] if recv else []) + allv)
            return (base[0], base[1] | frozenset({"path"}), base[2]) if base[0] else V_CONST
        if san is None and rn and rn.startswith("Math."):
            san = {"*"}
        if san:
            if "*" in san:
                return V_CONST
            base = join(allv + ([recv] if recv else []))
            return (base[0], base[1] | frozenset(san), base[2]) if base[0] else V_CONST
        if rn in FS_READ or (attr in ("readFile", "readFileSync") and recv is not None):
            return V_OTHER   # a file's content does not inherit suspicion from its path
        key, off = self._local_key(fnu)
        if key in self.summaries:
            return self._apply_summary(self.summaries[key], key, off, n, vals)
        gk = self._global_key(rn)
        if gk:
            return self._apply_summary(self.project.summaries[gk], gk[1], 0, n, vals)
        if attr in STR_METHODS:
            return join(([recv] if recv else []) + allv)
        if rn in PURE_NAMES:
            return join(allv)
        res = join(allv + ([recv] if recv else []))
        return V_OTHER if res[0] == CONST else res

    def _check_origin(self, n, args):
        if len(args) < 2 or not self.report:
            return
        cb = _unwrap(args[1])
        if cb is not None and cb.type in ("arrow_function", "function_expression", "function"):
            if not re.search(rb"\.origin\b|\.source\b|origin\s*[=!]=", cb.text):
                self._plain("origin", n, "unknown")

    def _sinks(self, n, fn, rn, attr, recv_n, args, vals, env, is_new):
        rdn = dotted(recv_n) if recv_n is not None else None
        rroot = (rdn or "").split(".")[0]
        # --- by resolved name
        spec = NAME_SINKS.get(rn) if rn else None
        if spec is None and rn and rn.startswith("window."):
            spec = NAME_SINKS.get(rn[7:])
        if spec is None and rn in ("setTimeout", "setInterval", "window.setTimeout", "window.setInterval"):
            if args and _unwrap(args[0]).type not in ("arrow_function", "function_expression", "function", "identifier", "member_expression"):
                spec = ("code", 0)
        if spec:
            kind, a = spec[0], spec[1]
            sub = spec[2] if len(spec) > 2 else None
            v = None
            if a == "any":
                v = join(vals) if vals else None
                if rn in ("Function",) or kind == "proto":
                    v = join(vals[-1:]) if vals and rn == "Function" else v
            elif a == "url":
                v = self._url_value(args[0], vals[0], env) if args else None
                if v is None and len(args) > 1 and rn in ("XMLHttpRequest.open",):
                    v = vals[1]
            elif isinstance(a, int) and len(vals) > a:
                v = vals[a]
            if v is not None and sub == "jq" and rn in ("$", "jQuery"):
                # $(x): only a dynamic selector/HTML counts; $(document)/$(function) do not
                if not (vals and (_skeleton(args[0]) and "\x00" not in _skeleton(args[0]))):
                    self._hit("xss", "jQuery selector/HTML from the user", v, n, pot="LOW" if self._building(args[0], env) else None)
            elif v is not None:
                if kind == "cmd" and rn in ("child_process.spawn", "child_process.spawnSync", "child_process.execFile", "child_process.execFileSync"):
                    shell = any(re.search(rb"shell\s*:\s*true", a_.text) for a_ in args[1:] if a_.type == "object")
                    prog = vals[0]
                    if shell or prog[0] == TAINT:
                        self._hit("cmd", rn, prog, n)
                elif kind == "path" and rn and rn.endswith("existsSync"):
                    pass
                else:
                    self._hit(kind, rn, v, n)
        # --- path.join / resolve with untrusted data
        if rn in ("path.join", "path.resolve") and vals:
            self._hit("path", rn, join(vals), n, only_confirmed=True, sev="MEDIUM")
        # --- by method name
        if attr:
            ps = PROP_SINKS.get(attr)
            if ps and args:
                kind, a, cons = ps
                ok = True
                if cons == "res":
                    ok = rroot in ("res", "response", "reply", "ctx") or (rdn or "").endswith((".res", ".response"))
                elif cons == "jq":
                    ok = rroot in ("$", "jQuery") or (recv_n is not None and _unwrap(recv_n).type in ("call_expression",)) \
                        or rroot.startswith("$") or rroot.endswith("$")
                elif cons == "loc":
                    ok = (rdn or "") in LOC_OBJECTS
                elif cons == "page":
                    ok = "page" in (rdn or "").lower() or "phantom" in (rdn or "").lower()
                elif cons == "xml":
                    ok = "xml" in (rdn or "").lower() or "libxml" in (self.resolve(rdn) or "").lower() or True
                elif cons == "parser":
                    ok = "parser" in (rdn or "").lower() or "expat" in (self.resolve(rdn) or "").lower()
                if ok:
                    if kind == "path" and attr in ("sendFile", "sendfile", "download"):
                        opts = [x for x in args[1:] if (x.type == "object" and re.search(rb"\broot\b", x.text)) or x.type != "object"]
                        if opts:
                            ok = False
                    if kind == "xml" and cons != "parser":
                        ok = any(re.search(rb"noent\s*:\s*true", x.text) for x in args[1:] if x.type == "object")
                    if kind == "xss" and cons == "res" and attr in ("send", "write", "end"):
                        # reflected XSS: composed string or direct data (JSON.stringify/escape already sanitize)
                        pass
                    if ok:
                        idx = a
                        v = join(vals) if a == "any" else (vals[idx] if len(vals) > idx else None)
                        if v is not None and kind == "redirect" and attr == "redirect":
                            keep = [(x, an) for x, an in zip(vals, args) if an.type != "number"]
                            keep = [(x, an) for x, an in keep if not (re.match(r"https?://[^/\x00]+/", _skeleton(an)) or self._prefix_fixed(an, env)
                                                                    or (an.type == "identifier" and env.get(("hostfixed", _t(an)))))]
                            v = join([x for x, _ in keep]) if keep else None
                        if v is not None:
                            self._hit(kind, f"{(rdn or '?')}.{attr}", v, n, pot=PROP_POT.get(attr))
            if attr in SQL_ATTRS and args:
                v = vals[0]
                sk = _skeleton(args[0])
                sqlish = bool(SQL_RE.search(sk))
                lvl = CONST if "sql" in v[1] else v[0]
                if lvl > CONST and (self._building(args[0], env) and (sqlish or attr in ("query", "execute", "raw", "queryRaw", "executeRaw"))
                                    or (lvl == TAINT and attr in ("query", "execute", "raw", "queryRaw", "executeRaw") and _unwrap(args[0]).type != "object")):
                    self._hit("sql", f"{(rdn or '?')}.{attr}", v, n)
                elif lvl > CONST:
                    self._hit("sql", f"{(rdn or '?')}.{attr}", v, n, record_only=True)
        # --- RegExp / Function
        if is_new:
            nm = dotted(fn) or ""
            if nm == "RegExp" and vals:
                self._hit("redos", "new RegExp", vals[0], n)
                if args and args[0].type == "string" and self.report and self.REDOS_RE.search(_strval(args[0])):
                    self._plain("redos_lit", n, "unknown")
            elif nm == "Function" and vals:
                self._hit("code", "new Function", join(vals), n)
            elif nm == "Script" and vals and (self.resolve(nm) or "").startswith("vm"):
                self._hit("code", "vm.Script", vals[0], n)
        if attr == "postMessage" and len(args) > 1 and args[1].type == "string" and _strval(args[1]) == "*":
            self._plain("post_star", n)
        # --- cryptography / jwt / cookie / random (configuration)
        self._config_checks(n, rn, attr, args, vals, rdn)

    def _config_checks(self, n, rn, attr, args, vals, rdn):
        if not self.report:
            return
        last = (rn or attr or "").split(".")[-1]
        if rn in ("crypto.createHash", "crypto.createHmac") and args and args[0].type == "string" and \
                _strval(args[0]).lower() in ("md5", "sha1", "md4", "sha-1", "md2", "ripemd160", "ripemd"):
            self._plain("crypto_hash", n)
        elif rn in ("crypto.createCipher", "crypto.createDecipher"):
            self._plain("crypto_cipher", n)
        elif rn in ("crypto.createCipheriv", "crypto.createDecipheriv") and args and args[0].type == "string" and \
                re.search(r"ecb|des|rc4", _strval(args[0]), re.I):
            self._plain("crypto_cipher", n)
        elif rn in ("crypto.pseudoRandomBytes", "pseudoRandomBytes"):
            self._plain("random", n)
        elif rn and (rn.split(".")[-1] in ("MD5", "SHA1") and rn.startswith(("CryptoJS", "crypto-js"))) or \
                (rn and rn.startswith(("CryptoJS.DES", "CryptoJS.RC4", "CryptoJS.TripleDES"))):
            self._plain("crypto_hash", n)
        if last in ("decode",) and (rn or "").split(".")[0] in ("jwt", "jsonwebtoken", "jose", "jwt-simple", "jwtDecode"):
            third = args[2] if len(args) > 2 else None
            if rn.startswith("jwt-simple") and third is not None and _t(third) == "true":
                self._plain("jwt_none", n)
            elif not rn.startswith("jwt-simple"):
                self._plain("jwt_decode", n)
        if rn in ("jwt_decode", "jwt-decode", "jwtDecode"):
            self._plain("jwt_decode", n)
        for a in args:
            if a.type == "object":
                txt = a.text
                if re.search(rb"algorithms?\s*:\s*\[?\s*['\"]none['\"]", txt, re.I):
                    self._plain("jwt_none", n)
                if re.search(rb"ignoreExpiration\s*:\s*true", txt):
                    self._plain("jwt_exp", n)
        if (attr == "cookie" or rn in ("session", "cookieSession", "express-session", "cookie-session")) and args:
            for a in args:
                if a.type == "object" and re.search(rb"\b(httpOnly|secure)\s*:\s*false", a.text):
                    self._plain("cookie", n)
                    break

    # ----------------------------------------------------------- statements
    def _walk(self, stmts, env):
        for s in stmts:
            self._stmt(s, env)

    @staticmethod
    def _terminates(body_nodes):
        if not body_nodes:
            return False
        last = body_nodes[-1]
        if last.type == "statement_block":
            return JsAnalyzer._terminates(_named(last))
        return last.type in ("return_statement", "throw_statement", "continue_statement", "break_statement")

    def _body(self, n):
        if n is None:
            return []
        return _named(n) if n.type == "statement_block" else [n]

    def _stmt(self, s, env):
        t = s.type
        if t == "expression_statement":
            for c in _named(s):
                self.eval(c, env)
        elif t in ("lexical_declaration", "variable_declaration"):
            for d in _named(s):
                if d.type != "variable_declarator":
                    continue
                nm, val = _f(d, "name"), _f(d, "value")
                self.name_hint = _t(nm) if nm is not None and nm.type == "identifier" else None
                v = self.eval(val, env) if val is not None else V_OTHER
                self.name_hint = None
                built = v[0] > CONST and val is not None and self._building(val, env)
                self._store(nm, v, env, built, None, val)
                if nm is not None and nm.type == "identifier" and val is not None and \
                        re.match(r"https?://[^/\x00]+/", _skeleton(val)):
                    env[("hostfixed", _t(nm))] = True
        elif t in ("function_declaration", "generator_function_declaration"):
            nm = _f(s, "name")
            self._run_function(s, _t(nm) if nm is not None else None, None, self.report, env if self.cur is not None else None)
        elif t == "class_declaration":
            nm, body = _f(s, "name"), _f(s, "body")
            prev = self.cur_class
            self.cur_class = _t(nm) if nm is not None else None
            if body is not None:
                for m in _named(body):
                    if m.type == "method_definition":
                        self._run_function(m, _t(_f(m, "name")), self.cur_class, self.report, env if self.cur is not None else None)
            self.cur_class = prev
        elif t == "export_statement":
            for c in _named(s):
                self._stmt(c, env) if c.type.endswith(("declaration", "statement")) else self.eval(c, env)
        elif t == "return_statement":
            k = _named(s)
            v = self.eval(k[0], env) if k else V_CONST
            if self.cur is not None:
                self.cur["rets"].append(v)
        elif t == "throw_statement":
            for c in _named(s):
                self.eval(c, env)
        elif t == "if_statement":
            self._if(s, env)
        elif t in ("for_statement", "for_in_statement", "while_statement", "do_statement"):
            self._loop(s, env)
        elif t == "switch_statement":
            self.eval(_f(s, "value"), env)
            body = _f(s, "body")
            outs, pre = [], dict(env)
            if body is not None:
                for c in _named(body):
                    e = dict(env)
                    self._walk([x for x in _named(c) if x is not _f(c, "value")], e)
                    outs.append(e)
            for o in outs:
                env.update(self._merge(env, o, pre))
        elif t == "try_statement":
            self._try(s, env)
        elif t == "statement_block":
            self._walk(_named(s), env)
        elif t == "labeled_statement":
            for c in _named(s)[1:]:
                self._stmt(c, env)
        elif t in ("with_statement",):
            self._walk(self._body(_f(s, "body")), env)

    def _merge(self, a, b, pre):
        out = {}
        for k in set(a) | set(b):
            if isinstance(k, tuple):
                out[k] = True
            else:
                out[k] = join([a.get(k, pre.get(k, V_OTHER)), b.get(k, pre.get(k, V_OTHER))])
        return out

    def _guards(self, c):
        """(names that are safe if true, if false): dict name -> neutralized kinds."""
        c = _unwrap(c)
        if c is None:
            return {}, {}
        t = c.type
        if t == "unary_expression" and _t(_f(c, "operator")) == "!":
            a, b = self._guards(_f(c, "argument"))
            return b, a
        if t == "binary_expression":
            op = _t(_f(c, "operator"))
            if op in ("&&", "||"):
                pa, pb = self._guards(_f(c, "left")), self._guards(_f(c, "right"))
                side = 0 if op == "&&" else 1
                out = {}
                for p in (pa, pb):
                    for k, v in p[side].items():
                        out[k] = out.get(k, NOP) | v
                return (out, {}) if side == 0 else ({}, out)
            l, r = _unwrap(_f(c, "left")), _unwrap(_f(c, "right"))
            if op in ("===", "==", "!==", "!=") and l is not None and l.type == "identifier" and r is not None and r.type in ("string", "number", "null", "true", "false"):
                return ({_t(l): ALL_K}, {}) if op in ("===", "==") else ({}, {_t(l): ALL_K})
            if op in ("===", "==", "!==", "!=") and l is not None and l.type == "call_expression" and r is not None and r.type in ("number", "unary_expression"):
                ln = _t(_f(l, "function")) if _f(l, "function") is not None else ""
                if ln.endswith(".indexOf"):
                    a0 = _named(_f(l, "arguments"))
                    if a0 and a0[0].type == "identifier":
                        return ({}, {_t(a0[0]): ALL_K}) if op in ("===", "==") else ({_t(a0[0]): ALL_K}, {})
            if op == "in" and l is not None and l.type == "identifier":
                return {_t(l): ALL_K}, {}
            if op in ("===", "==") and l is not None and l.type == "unary_expression" and r is not None and r.type == "string":
                arg = _unwrap(_f(l, "argument"))
                if _t(l).startswith("typeof") and arg is not None and arg.type == "identifier" and _strval(r) in ("number", "boolean"):
                    return {_t(arg): ALL_K}, {}
        if t == "call_expression":
            fn = _unwrap(_f(c, "function"))
            args = _named(_f(c, "arguments")) if _f(c, "arguments") is not None else []
            nm = dotted(fn) or ""
            first = _unwrap(args[0]) if args else None
            fid = first.type == "identifier" if first is not None else False
            if fn is not None and fn.type == "member_expression":
                recv, prop = _unwrap(_f(fn, "object")), _t(_f(fn, "property"))
                if prop in ("startsWith",) and recv is not None and recv.type == "identifier" and args:
                    return {_t(recv): frozenset({"redirect"})}, {}
                if prop in ("includes", "has", "indexOf") and fid and prop != "indexOf":
                    return {_t(first): ALL_K}, {}
                if prop == "test" and fid and recv is not None and recv.type == "regex":
                    return {_t(first): ALL_K}, {}
                if prop in ("isInt", "isNumeric", "isAlphanumeric", "isAlpha", "isUUID", "isEmail", "isURL", "isIP", "isHexadecimal", "isBoolean",
                            "isLength", "isIn", "isInteger", "isFinite", "isSafeInteger") and fid:
                    return {_t(first): ALL_K}, {}
            if fid and nm in ("isNaN", "Number.isInteger", "Number.isFinite", "Number.isSafeInteger", "isFinite", "isUuid", "isInt"):
                return ({}, {_t(first): ALL_K}) if nm == "isNaN" else ({_t(first): ALL_K}, {})
        return {}, {}

    @staticmethod
    def _apply_clean(env, mapping):
        for k, kinds in mapping.items():
            cur = env.get(k, V_OTHER)
            env[k] = V_CONST if kinds == ALL_K else (cur[0], cur[1] | kinds, cur[2])

    def _if(self, s, env):
        cond = _f(s, "condition")
        self.eval(cond, env)
        tclean, fclean = self._guards(cond)
        e1, e2 = dict(env), dict(env)
        self._apply_clean(e1, tclean)
        self._apply_clean(e2, fclean)
        cons, alt = _f(s, "consequence"), _f(s, "alternative")
        b1 = self._body(cons)
        b2 = []
        if alt is not None:
            k = _named(alt)
            b2 = self._body(k[0]) if k else []
        self._walk(b1, e1)
        self._walk(b2, e2)
        t1, t2 = self._terminates(b1), bool(b2) and self._terminates(b2)
        new = e2 if (t1 and not t2) else e1 if (t2 and not t1) else self._merge(e1, e2, env)
        env.clear()
        env.update(new)

    def _loop(self, s, env):
        t = s.type
        itv = V_OTHER
        if t == "for_in_statement":
            itv = self.eval(_f(s, "right"), env)
        elif t == "for_statement":
            init = _f(s, "initializer")
            if init is not None:
                self._stmt(init, env) if init.type.endswith(("declaration", "statement")) else self.eval(init, env)
            if _f(s, "condition") is not None:
                for c in _named(_f(s, "condition")):
                    self.eval(c, env)
        else:
            cond = _f(s, "condition")
            if cond is not None:
                self.eval(cond, env)
        passes = 2 if self.loop_depth < 2 else 1
        self.loop_depth += 1
        cur = dict(env)
        for _ in range(passes):
            e = dict(cur)
            if t == "for_in_statement":
                left = _f(s, "left")
                if left is not None:
                    self._store(left if left.type != "variable_declarator" else _f(left, "name"), itv, e, False)
            self._walk(self._body(_f(s, "body")), e)
            cur = self._merge(cur, e, env)
        self.loop_depth -= 1
        env.clear()
        env.update(cur)

    def _try(self, s, env):
        pre, e = dict(env), dict(env)
        self._walk(self._body(_f(s, "body")), e)
        outs = [e]
        h = _f(s, "handler")
        if h is not None:
            he = self._merge(pre, e, pre)
            p = _f(h, "parameter")
            if p is not None:
                for nm in self._param_names(p):
                    he[nm] = V_OTHER
            hb = self._body(_f(h, "body"))
            self._walk(hb, he)
            if not self._terminates(hb):
                outs.append(he)
        final = outs[0]
        for o in outs[1:]:
            final = self._merge(final, o, pre)
        fin = _f(s, "finalizer")
        if fin is not None:
            self._walk(self._body(_f(fin, "body")), final)
        env.clear()
        env.update(final)


ALL = ALL_K


# ---------------------------------------------------------------------------
# Public API
# ---------------------------------------------------------------------------
def _parse(ext, text):
    return _parser(ext).parse(text.encode("utf-8", "ignore")).root_node


def analyze_js_source(rel_path, ext, text):
    """Analyze a single JS/TS file (without project context)."""
    if not AVAILABLE or ext not in SUPPORTED:
        return []
    a = None
    try:
        root = _parse(ext, text)
        a = JsAnalyzer(rel_path, ext, root)
        return a.run()
    except RecursionError:
        log.warning("Analysis of '%s' stopped early because of extremely nested code (RecursionError); "
                    "returning the findings collected so far.", rel_path)
        return a.findings if a is not None else []
    except Exception as exc:
        log.warning("Could not analyze '%s' (%s: %s); the file was skipped by the JS/TS AST engine. "
                    "The file may contain syntax the parser cannot handle; pattern-based rules still apply.",
                    rel_path, type(exc).__name__, exc)
        return []


MAX_PROJECT_BYTES = 20 * 1024 * 1024
MAX_PROJECT_FILES = 2000


def analyze_js_project(sources):
    """
    sources: {relative_path: (extension, text)}. Returns {path: [findings]}.
    Dangerous data is also followed across require/import between files.
    """
    if not AVAILABLE:
        return {}
    total = sum(len(t) for _, t in sources.values())
    if len(sources) > MAX_PROJECT_FILES or total > MAX_PROJECT_BYTES:
        log.warning("Project is too large for cross-file JS/TS analysis (%d files, %.1f MB; limits: %d files, %.0f MB). "
                    "Falling back to file-by-file analysis: data flows across files will not be tracked.",
                    len(sources), total / (1024 * 1024), MAX_PROJECT_FILES, MAX_PROJECT_BYTES / (1024 * 1024))
        return {p: analyze_js_source(p, e, t) for p, (e, t) in sources.items()}
    proj, analyzers, out = Project(), {}, {}
    for rel, (ext, text) in sources.items():
        try:
            root = _parse(ext, text)
            a = JsAnalyzer(rel, ext, root, proj)
        except Exception as exc:
            log.warning("Could not parse '%s' (%s: %s); the file was skipped by the JS/TS AST engine.",
                        rel, type(exc).__name__, exc)
            out[rel] = []
            continue
        proj.add(a.mod, a.mod)
        analyzers[rel] = a
    try:
        for a in analyzers.values():
            a.prepare()
        for _ in range(3):
            if not any([a.update_summaries() for a in analyzers.values()]):
                break
        for rel, a in analyzers.items():
            out[rel] = a.finish()
            a.root = None
    except RecursionError:
        log.warning("Cross-file JS/TS analysis aborted because of extremely nested code (RecursionError); "
                    "returning the findings collected so far. Results may be incomplete.")
        for rel, a in analyzers.items():
            out.setdefault(rel, a.findings)
    except Exception as exc:
        log.exception("Cross-file JS/TS analysis failed unexpectedly (%s); returning the findings collected so far. "
                      "Results may be incomplete.", type(exc).__name__)
        for rel, a in analyzers.items():
            out.setdefault(rel, a.findings)
    return out
