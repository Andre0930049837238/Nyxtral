# -*- coding: utf-8 -*-
"""
swift_engine.py
================
Security engine for Swift (.swift: iOS/macOS apps and Vapor servers) built on a real parser (tree-sitter-swift) and
data-flow analysis on top of the shared core in lang_core.py.

Vulnerability classes covered: command injection (Process/NSTask, system), SQL injection (SQLite C API, GRDB, SQLite.swift, FMDB),
weak cryptography (CommonCrypto MD5/SHA-1/DES/RC4/ECB, CryptoKit Insecure) and hardcoded keys, disabled TLS verification,
sensitive data in UserDefaults / logs / without Keychain protection, WebView, path traversal, SSRF and URLs opened from
external data, insecure deserialization (NSKeyedUnarchiver), weak random numbers (rand, random, drand48), cleartext http
connections.

Known limitations: no type checker; methods are recognized by name. Int.random and arc4random are cryptographically secure on
Apple platforms and are NOT reported (unlike some generic rules). The code under analysis is never executed.
"""

import logging
import re

import lang_core as C
from lang_core import Sink, Fixed, V_TAINT, V_LOCAL, txt, walk

log = logging.getLogger(__name__)

try:
    from tree_sitter import Language, Parser
    import tree_sitter_swift as _tss
    _PARSER = Parser(Language(_tss.language()))
    AVAILABLE = True
except Exception as _exc:                           # pragma: no cover
    AVAILABLE = False
    log.warning(
        "Swift AST analysis is disabled: tree-sitter or tree-sitter-swift could not be loaded (%s: %s). "
        "Only pattern-based rules will run for .swift files. Install the missing packages with: "
        "pip install tree-sitter tree-sitter-swift", type(_exc).__name__, _exc)

SUPPORTED = (".swift",)
MAX_PROJECT_BYTES = C.MAX_PROJECT_BYTES

RULES = {
    "AST-SW-001": ("Command execution with untrusted data", "CRITICAL", "HIGH",
                   "{sink} executes a command that is partly built from external input.",
                   "Pass arguments as a separate list to Process and validate the input against an allowlist.", "CWE-78"),
    "AST-SW-002": ("SQL injection", "CRITICAL", "HIGH",
                   "{sink} receives a query built from externally supplied data.",
                   "Use parameterized queries (sqlite3_bind_*, ? / separate arguments); never string interpolation.", "CWE-89"),
    "AST-SW-003": ("Weak cryptographic algorithm", "MEDIUM", "MEDIUM",
                   "{sink} uses an algorithm or mode that is considered weak.",
                   "Use SHA-256 or stronger and AES-GCM (CryptoKit); for passwords use PBKDF2 or argon2.", "CWE-327"),
    "AST-SW-004": ("Certificate verification disabled", "HIGH", "HIGH",
                   "{sink}: the connection accepts any certificate.",
                   "Always evaluate server trust (SecTrustEvaluateWithError) or use pinning.", "CWE-295"),
    "AST-SW-005": ("Sensitive data stored without protection", "MEDIUM", "MEDIUM",
                   "{sink}: a value that looks confidential (password, token, key) ends up in an unprotected location.",
                   "Store secrets in the Keychain with kSecAttrAccessibleWhenUnlocked, not in UserDefaults.", "CWE-311"),
    "AST-SW-006": ("Unsanitized content loaded into the WebView (XSS)", "HIGH", "MEDIUM",
                   "{sink} loads externally supplied data into the WebView.",
                   "Load trusted content only and encode all external data before inserting it into the page.", "CWE-79"),
    "AST-SW-007": ("Externally controlled file path (path traversal)", "HIGH", "MEDIUM",
                   "{sink} uses a path supplied by external input.",
                   "Normalize the path (standardizedFileURL) and verify it stays inside the permitted directory.", "CWE-22"),
    "AST-SW-008": ("Request to, or opening of, an externally controlled address", "HIGH", "MEDIUM",
                   "{sink} uses an address supplied by external input (SSRF or redirect).",
                   "Accept only hosts/schemes from an allowlist.", "CWE-918"),
    "AST-SW-009": ("Insecure deserialization", "HIGH", "HIGH",
                   "{sink} rebuilds objects without restricting the allowed classes.",
                   "Use NSSecureCoding with unarchivedObject(ofClass:from:) or data formats (Codable).", "CWE-502"),
    "AST-SW-010": ("Sensitive data in logs", "MEDIUM", "MEDIUM",
                   "{sink} writes a value that looks confidential to the logs.",
                   "Never write passwords, tokens or keys to logs.", "CWE-532"),
    "AST-SW-011": ("Insecure random numbers", "MEDIUM", "MEDIUM",
                   "{sink} is predictable and must not be used for secrets, tokens or keys.",
                   "Use SecRandomCopyBytes or SystemRandomNumberGenerator.", "CWE-338"),
    "AST-SW-012": ("Cleartext connection (http)", "MEDIUM", "LOW",
                   "{what}",
                   "Use https:// (App Transport Security).", "CWE-319"),
    "AST-SW-013": ("Hardcoded encryption key", "HIGH", "MEDIUM",
                   "{sink} uses a key or initialization vector written directly in the code.",
                   "Generate the key with a secure generator and store it in the Keychain.", "CWE-321"),
    "AST-SW-016": ("Biometric authentication enforced only in logic", "LOW", "LOW",
                   "{sink} returns only true or false: anyone who tampers with the running app can force it to always return true.",
                   "Bind access to a biometry-protected Keychain item (kSecAccessControlBiometryCurrentSet) instead of trusting the boolean.", "CWE-287"),
    "AST-SW-014": ("Risky WebView configuration", "MEDIUM", "MEDIUM",
                   "{sink}: the WebView grants JavaScript or local files more access than needed.",
                   "Disable JavaScript, window opening and file access when they are not needed.", "CWE-749"),
}

SENS = re.compile(r"(?i)(passw|pwd|passphrase|secret|token|api_?key|credit|card|ssn|\bpin\b|private|otp|bearer)")
SENS_NAME = re.compile(r"(?i)(token|secret|passw|pwd|nonce|salt|session|csrf|otp|apikey|api_key|\bkey\b|_key|key_|\biv\b|cookie|auth)")
SQL_RE = re.compile(r"(?i)\b(select|insert\s+into|update\s+\w+\s+set|delete\s+from|drop\s+(table|database)|create\s+table|alter\s+table|where\s+\w+|order\s+by|union\s+select)\b")
PARAM_TYPE = re.compile(r"(Request|URLComponents|URL\b|UITextField|NSItemProvider|UserActivity)")
WEAK_CONST = re.compile(r"(kCCAlgorithmDES|kCCAlgorithm3DES|kCCAlgorithmRC4|kCCAlgorithmRC2|kCCAlgorithmCAST|kCCAlgorithmBlowfish|kCCOptionECBMode)")


class SwiftLang(C.LangBase):
    ENGINE = "swift_ast"
    EXTS = SUPPORTED
    RULES = RULES
    AVAILABLE = AVAILABLE
    CALL_TYPES = {"call_expression"}
    FUNC_TYPES = {"function_declaration", "init_declaration", "deinit_declaration"}
    STMT_TYPES = {"property_declaration", "assignment", "for_statement"}
    TEST_RE = re.compile(r"(^|/)_?(Tests?|UITests?|Examples?|docs?|Samples?)(/|$)|(Tests?|Spec)\.swift$")
    TEST_QUIET = frozenset({"AST-SW-004", "AST-SW-008", "AST-SW-010", "AST-SW-012", "AST-SW-014"})
    CLEAN_RE = re.compile(r"(addingPercentEncoding|escapeHTML|htmlEscaped|sanitize|Sanitize|standardizedFileURL|lastPathComponent|\.hash)")
    NUM_RE = re.compile(r"(^|\.)(Int|Int64|Int32|Double|Float|UInt|UInt8|UInt16|UInt32|UInt64|UUID|Bool)$|\.(count|isEmpty)$")
    VALIDATE_RE = re.compile(r"(hasPrefix|hasSuffix|contains|matches|isValid|validate|isSafe|isAllowed|allowed|whitelist|allowlist|range\(of)")
    LEN_RE = re.compile(r"(\.count|min)$")
    SOURCE_CALLS = [
        (re.compile(r"^(readLine|readLn)$"), V_LOCAL),
        (re.compile(r"(ProcessInfo\.processInfo\.environment|getenv)"), V_LOCAL),
        (re.compile(r"(\.text|\.stringValue|\.string)$"), V_TAINT),
        (re.compile(r"\.(queryItems|query|parameters|content|decode|body|data|headers|cookies)$"), V_TAINT),
    ]
    SOURCE_MEMBERS = [
        (re.compile(r"^CommandLine\.arguments"), V_LOCAL),
        (re.compile(r"^ProcessInfo\.processInfo\.(environment|arguments)"), V_LOCAL),
        (re.compile(r"^(UIPasteboard|NSPasteboard)\.general\.string"), V_TAINT),
        (re.compile(r"\.(queryItems|text|stringValue)$"), V_TAINT),
        (re.compile(r"\.(parameters|query|headers|cookies|body)$"), V_TAINT),
    ]
    SINKS = [
        Sink("AST-SW-001", r"^(system|popen|posix_spawn|execv|execve|execvp)$"),
        Sink("AST-SW-001", r"(^|\.)Process\.run$", (0, 1)),
        Sink("AST-SW-002", r"^(sqlite3_exec|sqlite3_prepare|sqlite3_prepare_v2|sqlite3_prepare_v3)$", (1,)),
        Sink("AST-SW-002", r"\.(execute|executeQuery|executeUpdate|prepare|run|scalar|fetchAll|fetchOne|fetchCursor|fetchSet|query|raw)$", (0,)),
        Sink("AST-SW-006", r"\.(evaluateJavaScript|loadHTMLString)$", (0,)),
        Sink("AST-SW-007", r"(^|\.)(contents|createFile|removeItem|contentsOfDirectory|fileExists|createDirectory|copyItem|moveItem|attributesOfItem|isReadableFile|isWritableFile)$", (0,), skip_local=True),
        Sink("AST-SW-007", r"^(URL|NSURL)$", (0,), skip_local=True),
        Sink("AST-SW-007", r"^(FileHandle|InputStream|OutputStream)$", (0,), skip_local=True),
        Sink("AST-SW-008", r"^(URLRequest|NSURLRequest)$", (0,)),
        Sink("AST-SW-008", r"\.(dataTask|downloadTask|uploadTask|open|openURL)$", (0,)),
        Sink("AST-SW-008", r"^(WKWebView|WebView)\.load$", (0,)),
    ]
    PROPAGATE = [
        (re.compile(r"\.(append|insert|appendingFormat|appending|appendingPathComponent|replacingOccurrences)$"), "args", ("recv",)),
    ]

    def parse(self, rel, text):
        return _PARSER.parse(text.encode("utf-8", "ignore"))

    def top_level(self, root, rel):
        return {"name": "<file>", "params": [], "body": root, "receiver": None, "text": "", "top": True}

    # ---- functions -------------------------------------------------------------------------------------
    def functions(self, root):
        for n in walk(root):
            if n.type not in ("function_declaration", "init_declaration"):
                continue
            body = next((c for c in n.children if c.type == "function_body"), None)
            if body is None:
                continue
            name = next((txt(c) for c in n.children if c.type == "simple_identifier"), "init")
            params = []
            for c in n.children:
                if c.type == "parameter":
                    ids = [txt(x) for x in c.children if x.type == "simple_identifier"]
                    ty = " ".join(txt(x) for x in c.children if x.type in ("user_type", "optional_type", "array_type", "function_type", "tuple_type"))
                    if ids:
                        params.append((ids[-1], ty, ""))
            yield {"name": name, "params": params, "body": body, "receiver": None, "text": txt(body)}

    # ---- expressions -----------------------------------------------------------------------------------
    def qual_of(self, n):
        if n is None:
            return ""
        t = n.type
        if t in ("simple_identifier", "type_identifier", "identifier"):
            return txt(n)
        if t == "navigation_expression":
            tgt = n.child_by_field_name("target") or (n.named_children[0] if n.named_children else None)
            suf = n.child_by_field_name("suffix") or (n.named_children[-1] if n.named_children else None)
            nm = txt(suf).lstrip(".?!") if suf is not None else ""
            return self.qual_of(tgt) + "." + nm
        if t == "call_expression":
            return self.qual_of(n.children[0]) + "()" if n.children else ""
        if t in ("user_type", "optional_type") and n.named_children:
            return txt(n)
        if t in ("tuple_expression", "parenthesized_expression", "postfix_expression", "try_expression", "as_expression") and n.named_children:
            return self.qual_of(n.named_children[0])
        return re.sub(r"\s+", "", txt(n))[:40]

    def _is_subscript(self, n):
        for c in n.children:
            if c.type == "call_suffix":
                va = next((x for x in c.children if x.type == "value_arguments"), None)
                if va is not None and va.children and va.children[0].type == "[":
                    return True
        return False

    def _args(self, n):
        out = []
        for c in n.children:
            if c.type == "call_suffix":
                for va in c.children:
                    if va.type == "value_arguments":
                        for a in va.named_children:
                            if a.type == "value_argument":
                                v = a.child_by_field_name("value") or (a.named_children[-1] if a.named_children else None)
                                if v is not None and v.type != "value_argument_label":
                                    out.append(v)
                            else:
                                out.append(a)
        return out

    def expr(self, n):
        t = n.type
        if t in ("line_string_literal", "multi_line_string_literal", "raw_string_literal"):
            nodes = [c.child_by_field_name("value") or (c.named_children[0] if c.named_children else None)
                     for c in walk(n) if c.type == "interpolated_expression"]
            nodes = [x for x in nodes if x is not None]
            return ("tmpl2", [], nodes) if nodes else ("const",)
        if t in ("integer_literal", "real_literal", "boolean_literal", "hex_literal", "bin_literal", "oct_literal", "nil", "true", "false",
                 "regex_literal", "lambda_literal", "key_path_expression", "self_expression", "special_literal", "diagnostic"):
            return ("const",)
        if t == "simple_identifier":
            return ("name", txt(n))
        if t == "navigation_expression":
            tgt = n.child_by_field_name("target") or (n.named_children[0] if n.named_children else None)
            suf = n.child_by_field_name("suffix") or (n.named_children[-1] if n.named_children else None)
            return ("member", tgt, txt(suf).lstrip(".?!") if suf is not None else "", self.qual_of(n))
        if t in ("tuple_expression", "parenthesized_expression", "postfix_expression", "prefix_expression", "try_expression",
                 "await_expression", "as_expression", "check_expression", "directly_assignable_expression") and n.named_children:
            return ("wrap", n.named_children[0])
        if t in ("comparison_expression", "equality_expression", "conjunction_expression", "disjunction_expression", "range_expression"):
            return ("cmp",)
        if t in ("additive_expression", "multiplicative_expression", "nil_coalescing_expression", "infix_expression", "bitwise_operation"):
            return ("bin", list(n.named_children), "+")
        if t == "ternary_expression":
            kids = [c for c in n.named_children]
            return ("cond", (kids[0] if kids else None, kids[1] if len(kids) > 1 else None, kids[2] if len(kids) > 2 else None))
        if t in ("array_literal", "dictionary_literal"):
            return ("list", list(n.named_children))
        if t == "call_expression":
            callee = n.children[0] if n.children else None
            if callee is None:
                return ("other",)
            if self._is_subscript(n):
                return ("index", callee, None)
            args = self._args(n)
            if callee.type == "navigation_expression":
                tgt = callee.child_by_field_name("target") or (callee.named_children[0] if callee.named_children else None)
                suf = callee.child_by_field_name("suffix") or (callee.named_children[-1] if callee.named_children else None)
                return ("call", self.qual_of(callee), tgt, args, txt(suf).lstrip(".?!") if suf is not None else "")
            q = self.qual_of(callee)
            return ("call", q, None, args, q)
        return ("other",)

    def stmt(self, n):
        t = n.type
        if t == "property_declaration":
            nm = n.child_by_field_name("name")
            val = n.child_by_field_name("value")
            if nm is None:
                return None
            names = [txt(x) for x in walk(nm) if x.type == "simple_identifier"][:1]
            return ("decl", names, [val] if val is not None else None)
        if t == "assignment":
            tg, res = n.child_by_field_name("target"), n.child_by_field_name("result")
            op = txt(n.child_by_field_name("operator")) or "="
            if tg is not None and res is not None:
                return ("assign", [tg], [res], op)
        if t == "for_statement":
            it = n.child_by_field_name("collection")
            item = n.child_by_field_name("item")
            if it is not None and item is not None:
                return ("for", [item], it)
        return None

    def lkey(self, n):
        if n is None:
            return None
        t = n.type
        if t == "simple_identifier":
            return txt(n)
        if t == "directly_assignable_expression" and n.named_children:
            return self.lkey(n.named_children[0])
        if t == "navigation_expression":
            return self.qual_of(n)
        if t == "pattern":
            return next((txt(x) for x in walk(n) if x.type == "simple_identifier"), None)
        if t == "call_expression" and self._is_subscript(n):
            return self.lkey(n.children[0])
        return None

    def is_simple_target(self, n):
        return True

    def is_deep(self, n):
        return n.type in ("if_statement", "guard_statement", "for_statement", "while_statement", "repeat_while_statement", "switch_statement",
                          "switch_entry", "do_statement", "catch_block", "lambda_literal")

    def cond_of(self, n):
        if n.type in ("if_statement", "guard_statement", "while_statement", "repeat_while_statement"):
            for c in n.children:
                if c.type in ("statements", "{", "else", "control_transfer_statement"):
                    break
                if c.is_named and c.type not in ("if", "guard", "while", "let", "var", "value_binding_pattern", "comment"):
                    return c
        return None

    def is_relational(self, x):
        return x.type == "comparison_expression"

    def is_equality(self, x):
        return x.type == "equality_expression"

    def is_name_node(self, x):
        return x.type == "simple_identifier"

    def literal(self, n):
        if n is None:
            return None
        if n.type in ("line_string_literal", "multi_line_string_literal"):
            if any(c.type == "interpolated_expression" for c in walk(n)):
                return None
            raw = txt(n)
            return raw[3:-3] if raw.startswith('"""') else raw[1:-1]
        if n.type in ("integer_literal", "boolean_literal", "true", "false"):
            return txt(n)
        return None

    def sink_label(self, n):
        c = n.children[0] if n.children else n
        return self.qual_of(c)[:60]

    def param_taint(self, fname, pname, ptype, pann):
        if fname == "application" and re.search(r"\bURL\b", ptype or "") and pname == "url":
            return V_TAINT              # URL scheme / universal link: the address is decided by another app or a website
        return V_TAINT if re.search(r"\b(Vapor\.)?Request\b", ptype or "") else None

    def source_member(self, key):
        for rx, v in self.SOURCE_MEMBERS:
            if rx.search(key):
                return v
        return None

    def source_call(self, qual, simple):
        for rx, v in self.SOURCE_CALLS:
            if rx.search(qual):
                return v
        return None

    # ---- audit and hooks --------------------------------------------------------------------------------
    def sql_built(self, eng, n):
        if n is None:
            return False
        sv = getattr(eng, "_sqlvars", None)
        if sv is None:
            sv = eng._sqlvars = set()
        if n.type == "simple_identifier":
            return txt(n) in sv
        if n.type not in ("line_string_literal", "multi_line_string_literal", "additive_expression", "call_expression"):
            return False
        if n.type == "call_expression":
            e = self.expr(n)
            if not (e[1] in ("String", "NSString") or e[4] in ("appendingFormat", "replacingOccurrences", "appending")):
                return False
        pieces = [txt(x) for x in walk(n) if x.type in ("line_str_text", "multi_line_str_text")]
        has_sql = any(SQL_RE.search(p) for p in pieces) or any(txt(x) in sv for x in walk(n) if x.type == "simple_identifier")
        if not has_sql:
            return False
        v = eng.ev(n)
        return v[0] >= C.OTHER or bool(v[1])

    def track_sql(self, eng, n):
        st = self.stmt(n)
        if st is None:
            return
        sv = getattr(eng, "_sqlvars", None)
        if sv is None:
            sv = eng._sqlvars = set()
        if st[0] == "decl" and st[2]:
            for nm, v in zip(st[1], st[2]):
                if self.sql_built(eng, v):
                    sv.add(nm)
        elif st[0] == "assign":
            key = self.lkey(st[1][0])
            if key and st[2] and self.sql_built(eng, st[2][0]):
                sv.add(key)

    def call_effects(self, eng, qual, simple, recv, args, vals, node):
        line = C.line_of(node)
        rel = eng.rel
        atxt = " ".join(txt(a) for a in args)
        # --- Built SQL (audit)
        if re.search(r"^(sqlite3_exec|sqlite3_prepare\w*)$|\.(execute|executeQuery|executeUpdate|prepare|run|scalar|fetchAll|fetchOne|query|raw)$", qual):
            for a in args[:3]:
                if self.sql_built(eng, a):
                    v = eng.ev(a)
                    if v[0] == C.TAINT and v[2]:
                        continue
                    eng.p.add(rel, "AST-SW-002", "confirmed" if v[0] == C.TAINT else "unknown", line, sink=qual)
                    for pi in v[1]:
                        eng.p.summary.setdefault(eng.key, []).append((frozenset([pi]), "AST-SW-002", rel, line, {"sink": qual}, "str", False))
        # --- weak cryptography
        if re.match(r"^(CC_MD5|CC_SHA1|CC_MD2|CC_MD4|CC_MD5_Init|CC_SHA1_Init)$", qual) or re.search(r"Insecure\.(MD5|SHA1)", qual):
            eng.p.add(rel, "AST-SW-003", "fixed", line, sink=qual)
        if qual in ("CCCrypt", "CCCryptorCreate", "CCCryptorCreateWithMode") and WEAK_CONST.search(atxt):
            eng.p.add(rel, "AST-SW-003", "fixed", line, sink=qual)
        # --- hardcoded keys
        if re.match(r"^(AES|Blowfish|ChaCha20|Rabbit|HMAC|SymmetricKey|CryptoSwift\.\w+)$", qual):
            for a in args:
                e = self.expr(a)
                lit_inside = a.type in ("line_string_literal",) or (a.type == "call_expression" and self.expr(a)[2] is not None and self.expr(a)[2].type == "line_string_literal")
                if lit_inside and self.literal(a if a.type == "line_string_literal" else a.children[0].named_children[0]) not in (None, ""):
                    eng.p.add(rel, "AST-SW-013", "fixed", line, sink=qual)
                    break
        # --- UserDefaults / logs with sensitive data
        if simple in ("set", "setValue", "setObject") and recv is not None and re.search(r"(?i)(UserDefaults|defaults|prefs|standard)", txt(recv)):
            lab = " ".join(txt(x) for x in node.children if x.type == "call_suffix")
            if SENS.search(lab):
                eng.p.add(rel, "AST-SW-005", "fixed", line, sink=f"{qual} with a sensitive key")
            elif any(SENS.search(txt(a)) for a in args[:1]):
                eng.p.add(rel, "AST-SW-005", "fixed", line, sink=qual)
        if qual in ("print", "NSLog", "debugPrint", "os_log", "Logger.log", "logger.info", "logger.debug", "logger.error", "logger.notice") or re.match(r"^logger\.\w+$", qual):
            if any(SENS.search(txt(a)) for a in args):
                eng.p.add(rel, "AST-SW-010", "fixed", line, sink=qual)
        # --- deserialization
        if re.search(r"NSKeyedUnarchiver\.(unarchiveObject|unarchiveTopLevelObjectWithData)$", qual):
            eng.p.add(rel, "AST-SW-009", "fixed", line, sink=qual)
        if simple == "evaluatePolicy" and recv is not None:
            eng.p.add(rel, "AST-SW-016", "unknown", line, sink=qual)
        # --- UIWebView (deprecated and lacking isolation)
        if qual == "UIWebView":
            eng.p.add(rel, "AST-SW-014", "fixed", line, sink="UIWebView")
        # --- weak random numbers
        if re.match(r"^(rand|random|srand|srandom|srand48|drand48|lrand48|mrand48)$", qual):
            eng.p.add(rel, "AST-SW-011", "fixed", line, sink=qual)
        elif re.search(r"(^|\.)(arc4random\w*|random)$", qual) and not qual.startswith("Secure"):
            p = node.parent
            while p is not None and p.type not in ("property_declaration", "assignment", "statements", "function_body"):
                p = p.parent
            tgt = ""
            if p is not None and p.type == "property_declaration":
                nm = p.child_by_field_name("name")
                tgt = txt(nm) if nm is not None else ""
            elif p is not None and p.type == "assignment":
                tgt = txt(p.child_by_field_name("target"))
            if SENS_NAME.search(tgt) or SENS_NAME.search(eng.name):
                eng.p.add(rel, "AST-SW-011", "unknown", line, sink=qual)

    def on_node(self, eng, n):
        rel = eng.rel
        line = C.line_of(n)
        t = n.type
        if t in self.STMT_TYPES:
            self.track_sql(eng, n)
        if t == "assignment":
            tg, res = txt(n.child_by_field_name("target")), n.child_by_field_name("result")
            rv = txt(res)
            if re.search(r"(?i)(allowsInvalidSSLCertificate|allowInvalidCertificates)$", tg) and rv == "true":
                eng.p.add(rel, "AST-SW-004", "fixed", line, sink=tg + " = true")
            if re.search(r"(?i)validatesDomainName$", tg) and rv == "false":
                eng.p.add(rel, "AST-SW-004", "fixed", line, sink=tg + " = false")
            if re.search(r"(?i)(javaScriptCanOpenWindowsAutomatically|allowFileAccessFromFileURLs|allowUniversalAccessFromFileURLs|javaScriptEnabled)$", tg) and rv == "true":
                eng.p.add(rel, "AST-SW-014", "fixed", line, sink=tg + " = true")
            if re.search(r"(?i)(launchPath|executableURL|arguments)$", tg) and res is not None:
                v = eng.ev(res)
                if v[0] == C.TAINT and not v[2]:
                    eng.p.add(rel, "AST-SW-001", "confirmed", line, sink=tg)
                elif v[0] >= C.OTHER and self.expr(res)[0] != "const" and re.search(r"(?i)(launchPath|executableURL)$", tg):
                    eng.p.add(rel, "AST-SW-001", "unknown", line, sink=tg)
        if t in ("user_type", "type_identifier") and txt(n) == "UIWebView":
            eng.p.add(rel, "AST-SW-014", "fixed", line, sink="UIWebView (deprecata)")
        if t == "simple_identifier" and txt(n) in ("kSecAttrAccessibleAlways", "kSecAttrAccessibleAlwaysThisDeviceOnly", "NSFileProtectionNone"):
            eng.p.add(rel, "AST-SW-005", "fixed", line, sink=txt(n))
        if t == "line_string_literal":
            raw = txt(n)
            m = re.match(r'^"http://([^/"\\]+)', raw)
            if m and not re.match(r"(localhost|127\.|0\.0\.0\.0|www\.w3\.org|schemas\.|example\.|xmlns)", m.group(1)):
                eng.p.add(rel, "AST-SW-012", "unknown", line, what=f"The address http://{m.group(1)} uses an unencrypted connection.")
        if t == "call_expression":
            q = self.qual_of(n.children[0]) if n.children else ""
            if re.search(r"(useCredential)", txt(n)) and re.search(r"URLCredential\(trust", txt(n)):
                body = eng.fdef.get("text", "")
                if not re.search(r"SecTrustEvaluate|\.evaluate\(|SecTrustEvaluateWithError|isValid", body):
                    eng.p.add(rel, "AST-SW-004", "fixed", line, sink="URLCredential(trust:) accepted without evaluation")


LANG = SwiftLang()


def analyze_swift_project(sources):
    return C.analyze(LANG, sources)


def analyze_swift_source(rel_path, text):
    return C.analyze_source(LANG, rel_path, text)
