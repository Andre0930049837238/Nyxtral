# -*- coding: utf-8 -*-
"""
kotlin_engine.py
=================
Security engine for Kotlin (.kt .kts: Spring/Ktor servers and Android apps) built on a real parser (tree-sitter-kotlin) and
data-flow analysis on top of the shared core in lang_core.py.

Vulnerability classes covered: command injection, SQL injection (JDBC, Room/SQLite, JPA), WebView (XSS, JavaScript and file
access), weak cryptography (MD5, SHA-1, DES, AES/ECB, short RSA keys, NullCipher), disabled TLS/host verification, cleartext
sockets and http URLs, weak random numbers for sensitive data, path traversal, SSRF, deserialization, XXE, cookies without
Secure/HttpOnly, sensitive data in logs and SharedPreferences, untrusted intents.

Known limitations: no type checker; methods are recognized by name. The code under analysis is never executed.
"""

import logging
import re

import lang_core as C
from lang_core import Sink, Fixed, V_TAINT, V_LOCAL, txt, walk

log = logging.getLogger(__name__)

try:
    from tree_sitter import Language, Parser
    import tree_sitter_kotlin as _tsk
    _PARSER = Parser(Language(_tsk.language()))
    AVAILABLE = True
except Exception as _exc:                           # pragma: no cover
    AVAILABLE = False
    log.warning(
        "Kotlin AST analysis is disabled: tree-sitter or tree-sitter-kotlin could not be loaded (%s: %s). "
        "Only pattern-based rules will run for .kt/.kts files. Install the missing packages with: "
        "pip install tree-sitter tree-sitter-kotlin", type(_exc).__name__, _exc)

SUPPORTED = (".kt", ".kts")
MAX_PROJECT_BYTES = C.MAX_PROJECT_BYTES

RULES = {
    "AST-KT-001": ("Command execution with untrusted data", "CRITICAL", "HIGH",
                   "{sink} executes a command that is partly built from external input or assembled at runtime.",
                   "Pass arguments as a separate list to ProcessBuilder and validate the input against an allowlist.", "CWE-78"),
    "AST-KT-002": ("SQL injection", "CRITICAL", "HIGH",
                   "{sink} receives a query built from externally supplied data.",
                   "Use parameterized queries (PreparedStatement, ? with bindArgs, Room parameters); never concatenation or string templates.", "CWE-89"),
    "AST-KT-003": ("Unsanitized content loaded into the WebView (XSS)", "HIGH", "MEDIUM",
                   "{sink} loads externally supplied data into the WebView.",
                   "Load trusted content only; sanitize and encode all external data before inserting it into the page.", "CWE-79"),
    "AST-KT-004": ("Risky WebView configuration", "MEDIUM", "MEDIUM",
                   "{sink}: the WebView exposes JavaScript or local files to pages that may not be trusted.",
                   "Disable JavaScript and file access when not needed, and restrict addJavascriptInterface to your own content.", "CWE-749"),
    "AST-KT-005": ("Weak cryptographic algorithm", "MEDIUM", "MEDIUM",
                   "{sink} uses an algorithm, mode or key that is considered weak.",
                   "Use SHA-256 or stronger, AES-GCM and RSA keys of at least 2048 bits; for passwords use argon2, bcrypt or PBKDF2.", "CWE-327"),
    "AST-KT-006": ("Certificate or hostname verification disabled", "HIGH", "HIGH",
                   "{sink}: the connection no longer verifies the identity of the remote peer.",
                   "Keep the default verification enabled; for special certificates use pinning rather than accepting everything.", "CWE-295"),
    "AST-KT-007": ("Insecure random numbers for sensitive data", "MEDIUM", "MEDIUM",
                   "{sink} is predictable, yet here it generates a value that looks like a secret ('{name}').",
                   "Use java.security.SecureRandom.", "CWE-338"),
    "AST-KT-008": ("Externally controlled file path (path traversal)", "HIGH", "MEDIUM",
                   "{sink} uses a path supplied by external input.",
                   "Normalize the path (canonicalPath), verify it stays inside the permitted directory, and reject '..'.", "CWE-22"),
    "AST-KT-009": ("Request to an externally controlled address (SSRF)", "HIGH", "MEDIUM",
                   "{sink} contacts an address supplied by external input.",
                   "Accept only hosts from an allowlist and block internal addresses.", "CWE-918"),
    "AST-KT-010": ("Sensitive data in logs or stored in cleartext on the device", "MEDIUM", "MEDIUM",
                   "{sink} logs or stores in cleartext a value that looks confidential.",
                   "Never write passwords, tokens or keys to logs or SharedPreferences: use EncryptedSharedPreferences or the Keystore.", "CWE-532"),
    "AST-KT-011": ("Overly broad file or preference permissions", "MEDIUM", "MEDIUM",
                   "{sink}: the file or preferences are readable/writable by other apps.",
                   "Use MODE_PRIVATE.", "CWE-276"),
    "AST-KT-012": ("Deserialization of untrusted data", "HIGH", "MEDIUM",
                   "{sink} rebuilds objects from externally supplied data.",
                   "Avoid Java serialization on external data: use data formats (JSON) with a schema.", "CWE-502"),
    "AST-KT-013": ("XML parser without external entity protection (XXE)", "MEDIUM", "MEDIUM",
                   "{sink} creates an XML parser without disabling DOCTYPE/external entities.",
                   "Set disallow-doctype-decl (or FEATURE_SECURE_PROCESSING) on the parser.", "CWE-611"),
    "AST-KT-014": ("Cleartext connection (no TLS)", "MEDIUM", "LOW",
                   "{what}",
                   "Use https:// and TLS sockets (SSLSocket).", "CWE-319"),
    "AST-KT-015": ("Cookie without protection flags", "MEDIUM", "MEDIUM",
                   "{what}",
                   "Set Secure and HttpOnly (and SameSite) on session cookies.", "CWE-614"),
    "AST-KT-016": ("Untrusted intent launched without checks", "MEDIUM", "LOW",
                   "{sink} launches a component chosen by externally supplied data.",
                   "Verify the target component and do not forward received intents.", "CWE-927"),
}

SENSITIVE = re.compile(r"(token|secret|passw|pwd|nonce|salt|session|csrf|otp|apikey|api_key|\bkey\b|_key|key_|\biv\b|cookie|auth|pin\b)", re.I)
SENS_LOG = re.compile(r"(?i)(passw|pwd|secret|token|api_?key|credit|card|ssn|pin\b|private)")
SQL_RE = re.compile(r"(?i)\b(select|insert\s+into|update\s+\w+\s+set|delete\s+from|drop\s+(table|database)|create\s+table|alter\s+table|where\s+\w+|order\s+by|union\s+select)\b")
HOST_FIXED = re.compile(r"^https?://[A-Za-z0-9.\-]+(:\d+)?(/|\?|$)")
ANN_TAINT = re.compile(r"(RequestParam|PathVariable|RequestBody|QueryParam|FormParam|PathParam|RequestHeader|CookieValue|ModelAttribute|RequestPart|HeaderParam|MatrixParam|BeanParam)")
TYPE_TAINT = re.compile(r"(HttpServletRequest|ServerHttpRequest|ServerRequest|ApplicationCall|RoutingContext|HttpRequest|Intent|WebRequest|MultipartFile)")
SPLIT = re.compile(r"\$([A-Za-z_][A-Za-z0-9_]*)")


def _fixed_host(eng, n):
    e = LANG.expr(n)
    if n.type == "string_literal" and e[0] == "const":
        return True
    if n.type == "string_literal":
        raw = txt(n)[1:-1]
        return bool(HOST_FIXED.match(raw))
    if n.type == "binary_expression":
        x = n
        while x.type == "binary_expression" and x.named_children:
            x = x.named_children[0]
        return x.type == "string_literal" and bool(HOST_FIXED.match(txt(x)[1:-1]))
    return False


class KotlinLang(C.LangBase):
    ENGINE = "kotlin_ast"
    EXTS = SUPPORTED
    RULES = RULES
    AVAILABLE = AVAILABLE
    CALL_TYPES = {"call_expression"}
    FUNC_TYPES = {"function_declaration"}
    STMT_TYPES = {"property_declaration", "assignment", "for_statement"}
    TEST_RE = re.compile(r"(^|/)_?(tests?|androidTest|testFixtures|examples?|docs?|samples?)(/|$)|(Test|Tests|Spec)\.kts?$")
    TEST_QUIET = frozenset({"AST-KT-006", "AST-KT-008", "AST-KT-009", "AST-KT-010", "AST-KT-013", "AST-KT-014", "AST-KT-015", "AST-KT-016"})
    CLEAN_RE = re.compile(r"(escapeHtml|escapeXml|encodeURIComponent|URLEncoder\.encode|Html\.escapeHtml|htmlEscape|HtmlUtils\.htmlEscape|"
                          r"sanitize|Sanitize|\.canonicalPath$|getCanonicalPath|FilenameUtils\.getName|\.name$|Paths\.get\(\)\.fileName)")
    NUM_RE = re.compile(r"(toInt|toLong|toDouble|toFloat|toShort|toByte|toIntOrNull|toLongOrNull|toBoolean|parseInt|parseLong|Integer\.parseInt|"
                        r"Long\.parseLong|UUID\.fromString|valueOf|\.length$|\.size$)")
    VALIDATE_RE = re.compile(r"(startsWith|contains|matches|isValid|validate|isSafe|isAllowed|allowed|whitelist|allowlist|isNumeric|isDigit)")
    LEN_RE = re.compile(r"(\.length|\.size|min|coerceAtMost|coerceIn)$")
    SOURCE_CALLS = [
        (re.compile(r"(^|\.)(readLine|readln|readLn|readlnOrNull)$"), V_LOCAL),
        (re.compile(r"(^|\.)(System\.getenv|getenv)$"), V_LOCAL),
        (re.compile(r"\.(getParameter|getParameterValues|getParameterMap|getHeader|getHeaders|getQueryString|getCookies|getRequestURI|getRequestURL|"
                    r"getPathInfo|getInputStream|getReader|getStringExtra|getStringArrayExtra|getParcelableExtra|getQueryParameter|getQueryParameters|"
                    r"getDataString|getData|getExtras|receive|receiveText|receiveParameters|receiveOrNull|param|queryParam|pathParam|formParam|body|"
                    r"bodyAsText|bodyToMono|bodyToFlux|formParams)$"), V_TAINT),
        (re.compile(r"(^|\.)(call\.receive|call\.receiveText|call\.receiveParameters)$"), V_TAINT),
    ]
    SOURCE_MEMBERS = [
        (re.compile(r"^(call\.(parameters|request|receive)|request\.(queryString|parameterMap|headers|cookies|pathInfo|requestURI|inputStream|reader))"), V_TAINT),
        (re.compile(r"^(intent|getIntent\(\))(\.|$)"), V_TAINT),
        (re.compile(r"\.(queryParameters|queryParams|parameters|formParameters|pathParameters|headers|cookies)$"), V_TAINT),
    ]
    SINKS = [
        Sink("AST-KT-001", r"(^|\.)Runtime\.getRuntime\(\)\.exec$"),
        Sink("AST-KT-001", r"^ProcessBuilder$"),
        Sink("AST-KT-001", r"\.command$"),
        Sink("AST-KT-001", r"\.exec$", (0,)),
        Sink("AST-KT-002", r"\.(rawQuery|execSQL|compileStatement|rawQueryWithFactory|executeQuery|executeUpdate|executeLargeUpdate|execute|prepareStatement|prepareCall|"
                            r"createQuery|createNativeQuery|queryForObject|queryForList|queryForMap|queryForRowSet|query|update|batchUpdate|addBatch)$", (0,)),
        Sink("AST-KT-003", r"\.(loadUrl|evaluateJavascript|loadData)$", (0,)),
        Sink("AST-KT-003", r"\.loadDataWithBaseURL$", (1,)),
        Sink("AST-KT-008", r"^(File|FileInputStream|FileOutputStream|FileReader|FileWriter|RandomAccessFile|PrintWriter|Scanner|BufferedReader)$", None, skip_local=True),
        Sink("AST-KT-008", r"^(Paths\.get|Path\.of|Files\.(readAllBytes|readAllLines|readString|newInputStream|newOutputStream|write|writeString|copy|move|delete|deleteIfExists|lines|walk|list))$", None, skip_local=True),
        Sink("AST-KT-008", r"\.(openFileOutput|openFileInput|getFileStreamPath)$", (0,), skip_local=True),
        Sink("AST-KT-009", r"^(URL|URI)$", (0,), exempt=_fixed_host),
        Sink("AST-KT-009", r"\.url$", (0,), exempt=_fixed_host),
        Sink("AST-KT-009", r"\.(openConnection|openStream|readText)$", (), ),
        Sink("AST-KT-012", r"^ObjectInputStream$", (0,)),
        Sink("AST-KT-016", r"(^|\.)(startActivity|startActivityForResult|startService|sendBroadcast|startForegroundService)$", (0,)),
    ]
    FIXED = [
        Fixed("AST-KT-005", r"(^|\.)MessageDigest\.getInstance$", (0, r"(?i)^(md2|md4|md5|sha-?1)$")),
        Fixed("AST-KT-005", r"(^|\.)Cipher\.getInstance$", (0, r"(?i)^(des|desede|3des|rc2|rc4|arcfour|blowfish|aes|rsa|.*/ecb/.*|rsa/ecb/pkcs1padding|.*pkcs1padding)$")),
        Fixed("AST-KT-005", r"^NullCipher$"),
        Fixed("AST-KT-005", r"(^|\.)KeyPairGenerator\.getInstance\(\)\.initialize$", (0, r"^(512|768|1024)$")),
        Fixed("AST-KT-005", r"\.initialize$", (0, r"^(512|768|1024)$")),
        Fixed("AST-KT-005", r"^DefaultHttpClient$"),
        Fixed("AST-KT-005", r"(^|\.)SecretKeySpec$", (1, r"(?i)^(des|desede|rc4|rc2|blowfish)$")),
        Fixed("AST-KT-006", r"\.(setHostnameVerifier|setDefaultHostnameVerifier)$", None, any_lit=r"ALLOW_ALL|AllowAll"),
        Fixed("AST-KT-006", r"(^|\.)SSLContext\.getInstance$", (0, r"(?i)^(ssl|sslv3|sslv2|tls|tlsv1|tlsv1\.0|tlsv1\.1)$")),
        Fixed("AST-KT-004", r"\.setJavaScriptEnabled$", (0, r"^true$")),
        Fixed("AST-KT-004", r"\.(setAllowFileAccess|setAllowFileAccessFromFileURLs|setAllowUniversalAccessFromFileURLs|setAllowContentAccess)$", (0, r"^true$")),
        Fixed("AST-KT-004", r"\.addJavascriptInterface$"),
        Fixed("AST-KT-005", r"(^|\.)DigestUtils\.(getMd5Digest|md5|md5Hex|getMd2Digest|md2Hex|getSha1Digest|sha1|sha1Hex|getShaDigest|sha|shaHex)$"),
        Fixed("AST-KT-015", r"\.(setSecure|setHttpOnly)$", (0, r"^false$")),
        Fixed("AST-KT-014", r"\.(setDefaultUseCaches)$", (0, r"^never$")),
    ]
    PROPAGATE = [
        (re.compile(r"\.(readText|readBytes|readLine|readLines|read|useLines|bufferedReader|reader)$"), "recv", ("recv",)),
        (re.compile(r"\.(append|appendLine|plus|add|addAll|put|set)$"), "args", ("recv",)),
        (re.compile(r"(Json|Gson|ObjectMapper|Moshi|Yaml)[\w.()]*\.(fromJson|readValue|decodeFromString|parse|load)$"), "args", ()),
    ]

    # ---- parsing and functions ---------------------------------------------------------------------------
    def parse(self, rel, text):
        return _PARSER.parse(text.encode("utf-8", "ignore"))

    def top_level(self, root, rel):
        return {"name": "<file>", "params": [], "body": root, "receiver": None, "text": "", "top": True}

    def _first_ident(self, n):
        for c in n.children:
            if c.type in ("identifier", "simple_identifier"):
                return txt(c)
        return ""

    def functions(self, root):
        for n in walk(root):
            if n.type != "function_declaration":
                continue
            body = None
            for c in n.children:
                if c.type in ("function_body", "block"):
                    body = c
            if body is None:
                continue
            params = []
            for c in n.children:
                if c.type == "function_value_parameters":
                    ann = ""
                    for p in c.children:
                        if p.type == "parameter_modifiers":
                            ann = txt(p)
                        elif p.type == "parameter":
                            nm = self._first_ident(p)
                            ty = " ".join(txt(x) for x in p.children if x.type in ("user_type", "nullable_type", "function_type"))
                            params.append((nm, ty, ann))
                            ann = ""
            yield {"name": self._first_ident(n), "params": params, "body": body, "receiver": None, "text": txt(body)}

    # ---- expression classification -------------------------------------------------------------------
    def qual_of(self, n):
        if n is None:
            return ""
        t = n.type
        if t in ("identifier", "simple_identifier", "type_identifier"):
            return txt(n)
        if t == "navigation_expression":
            kids = [c for c in n.children if c.type not in (".", "?.", "::", "comment")]
            if len(kids) >= 2:
                return self.qual_of(kids[0]) + "." + txt(kids[-1])
        if t == "call_expression":
            return self.qual_of(n.children[0]) + "()" if n.children else ""
        if t in ("parenthesized_expression", "postfix_expression", "as_expression") and n.named_children:
            return self.qual_of(n.named_children[0])
        if t in ("indexing_expression", "index_expression") and n.named_children:
            return self.qual_of(n.named_children[0]) + "[]"
        return re.sub(r"\s+", "", txt(n))[:40]

    def _template_names(self, n):
        raw = txt(n)
        names = SPLIT.findall(raw)
        nodes = [c.named_children[0] for c in walk(n) if c.type == "interpolation" and c.named_children]
        return names, nodes

    def _call_parts(self, n):
        callee = n.children[0] if n.children else None
        args = []
        for c in n.children:
            if c.type == "value_arguments":
                for a in c.named_children:
                    if a.type == "value_argument" and a.named_children:
                        args.append(a.named_children[-1])
                    elif a.type not in ("comment",):
                        args.append(a)
        return callee, args

    def expr(self, n):
        t = n.type
        if t in ("string_literal", "multiline_string_literal"):
            names, nodes = self._template_names(n)
            return ("tmpl2", names, nodes) if (names or nodes) else ("const",)
        if t.endswith("_literal") or t in ("null", "true", "false", "this", "super", "lambda_literal", "anonymous_function", "object_literal"):
            return ("const",)
        if t in ("identifier", "simple_identifier"):
            return ("name", txt(n))
        if t == "navigation_expression":
            kids = [c for c in n.children if c.type not in (".", "?.", "::", "comment")]
            if len(kids) >= 2:
                return ("member", kids[0], txt(kids[-1]), self.qual_of(n))
            return ("other",)
        if t in ("indexing_expression", "index_expression") and n.named_children:
            return ("index", n.named_children[0], None)
        if t in ("parenthesized_expression", "postfix_expression", "prefix_expression", "as_expression", "check_expression",
                 "spread_expression", "await_expression", "jump_expression") and n.named_children:
            return ("wrap", n.named_children[0] if t != "as_expression" else n.named_children[0])
        if t in ("comparison_expression", "equality_expression", "conjunction_expression", "disjunction_expression", "range_expression"):
            return ("cmp",)
        if t in ("binary_expression", "additive_expression", "multiplicative_expression", "elvis_expression", "infix_expression"):
            return ("bin", [c for c in n.named_children], "+")
        if t == "call_expression":
            callee, args = self._call_parts(n)
            if callee is None:
                return ("other",)
            if callee.type == "navigation_expression":
                kids = [c for c in callee.children if c.type not in (".", "?.", "::", "comment")]
                recv = kids[0] if len(kids) >= 2 else None
                return ("call", self.qual_of(callee), recv, args, txt(kids[-1]) if kids else "")
            q = self.qual_of(callee)
            return ("call", q, None, args, q)
        if t == "if_expression":
            parts = [c for c in n.named_children if c.type in ("block", "control_structure_body", "statements")]
            return ("list", parts) if parts else ("other",)
        return ("other",)

    def stmt(self, n):
        t = n.type
        if t == "property_declaration":
            names, val = [], None
            seen_eq = False
            for c in n.children:
                if c.type == "variable_declaration":
                    names.append(self._first_ident(c))
                elif c.type == "multi_variable_declaration":
                    names += [self._first_ident(x) for x in c.named_children if x.type == "variable_declaration"]
                elif c.type == "=":
                    seen_eq = True
                elif seen_eq and c.type not in ("comment",):
                    val = c
                    break
            return ("decl", [x for x in names if x], [val] if val is not None else None)
        if t == "assignment":
            kids = n.children
            if len(kids) >= 3:
                return ("assign", [kids[0]], [kids[-1]], txt(kids[1]))
            return None
        if t == "for_statement":
            var = next((c for c in n.children if c.type in ("variable_declaration", "multi_variable_declaration")), None)
            it = None
            seen_in = False
            for c in n.children:
                if c.type == "in":
                    seen_in = True
                elif seen_in and it is None and c.type not in ("(", ")"):
                    it = c
            if var is not None and it is not None:
                return ("for", [var.named_children[0]] if var.named_children else [], it)
        return None

    def lkey(self, n):
        if n is None:
            return None
        t = n.type
        if t in ("identifier", "simple_identifier"):
            return txt(n)
        if t == "navigation_expression":
            return self.qual_of(n)
        if t in ("indexing_expression", "index_expression") and n.named_children:
            return self.lkey(n.named_children[0])
        return None

    def is_simple_target(self, n):
        return n.type in ("identifier", "simple_identifier", "navigation_expression")

    def is_deep(self, n):
        return n.type in ("if_expression", "when_expression", "for_statement", "while_statement", "do_while_statement",
                          "try_expression", "catch_block", "when_entry", "lambda_literal", "finally_block")

    def cond_of(self, n):
        if n.type in ("if_expression", "while_statement", "do_while_statement"):
            for c in n.children:
                if c.type not in ("if", "while", "do", "(", ")", "comment", "control_structure_body", "block", "else") and c.is_named:
                    return c
        return None

    def is_relational(self, x):
        return x.type == "comparison_expression"

    def is_equality(self, x):
        return x.type == "equality_expression"

    def is_name_node(self, x):
        return x.type in ("identifier", "simple_identifier")

    def literal(self, n):
        if n is None:
            return None
        if n.type in ("string_literal", "multiline_string_literal"):
            if self._template_names(n) != ([], []):
                return None
            raw = txt(n)
            return raw[3:-3] if raw.startswith('"""') else raw[1:-1]
        if n.type == "number_literal" or n.type.endswith("integer_literal") or n.type in ("true", "false", "boolean_literal"):
            return txt(n)
        if n.type == "identifier" and txt(n) in ("true", "false"):
            return txt(n)
        return None

    def sink_label(self, n):
        c = n.children[0] if n.children else n
        return self.qual_of(c)[:60]

    def param_taint(self, fname, pname, ptype, pann):
        if ANN_TAINT.search(pann or "") or TYPE_TAINT.search(ptype or ""):
            return V_TAINT
        if fname == "main" and pname in ("args", "argv"):
            return V_LOCAL
        return None

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

    # ---- audit and specific hooks -----------------------------------------------------------------------
    def sql_built(self, eng, n):
        if n is None:
            return False
        sv = getattr(eng, "_sqlvars", None)
        if sv is None:
            sv = eng._sqlvars = set()
        if n.type in ("identifier", "simple_identifier"):
            return txt(n) in sv
        if n.type not in ("string_literal", "multiline_string_literal", "binary_expression", "additive_expression", "call_expression"):
            return False
        if n.type == "call_expression":
            e = self.expr(n)
            if not (e[1] in ("String.format", "format", "StringBuilder().append", "java.lang.String.format") or e[4] in ("format", "plus", "toString", "joinToString", "replace")):
                return False
        pieces = []
        for x in walk(n):
            if x.type == "string_content":
                pieces.append(txt(x))
        has_sql = any(SQL_RE.search(p) for p in pieces) or any(txt(x) in sv for x in walk(n) if x.type in ("identifier", "simple_identifier"))
        if not has_sql:
            return False
        v = eng.ev(n)
        return v[0] >= C.OTHER or bool(v[1])

    def call_effects(self, eng, qual, simple, recv, args, vals, node):
        line = C.line_of(node)
        rel = eng.rel
        body_txt = eng.fdef.get("text", "")
        # --- Built SQL (audit): queries with SQL and non-constant fragments
        if re.search(r"\.(rawQuery|execSQL|compileStatement|executeQuery|executeUpdate|execute|prepareStatement|prepareCall|createQuery|createNativeQuery|"
                     r"queryForObject|queryForList|queryForMap|query|update|batchUpdate|addBatch)$", qual):
            for a in args[:2]:
                if self.sql_built(eng, a):
                    v = eng.ev(a)
                    if v[0] == C.TAINT and v[2]:
                        continue
                    if v[0] == C.TAINT:
                        eng.p.add(rel, "AST-KT-002", "confirmed", line, sink=qual)
                    else:
                        eng.p.add(rel, "AST-KT-002", "unknown", line, sink=qual)
                    for pi in v[1]:
                        eng.p.summary.setdefault(eng.key, []).append((frozenset([pi]), "AST-KT-002", rel, line, {"sink": qual}, "str", False))
        # --- cleartext socket (ephemeral port 0 is harmless)
        if qual in ("Socket", "ServerSocket", "java.net.Socket", "java.net.ServerSocket"):
            if not (args and (self.literal(args[0]) or "").strip() == "0"):
                eng.p.add(rel, "AST-KT-014", "fixed", line, what=f"{qual} opens an unencrypted connection (no TLS).")
        # --- cookie added to the response without Secure / HttpOnly
        if simple == "addCookie" and args:
            miss = [w for w in ("HttpOnly", "Secure") if not re.search(w + r"\(true\)|is" + w + r"\s*=\s*true|" + w.lower() + r"\s*=\s*true", body_txt)]
            if miss:
                eng.p.add(rel, "AST-KT-015", "fixed", line, what="Cookie added to the response without " + " and ".join(miss) + ".")
        # --- command / library loaded with text built at runtime (audit)
        if re.search(r"\.(exec|loadLibrary|load)$", qual) and args and not qual.endswith("Runtime.getRuntime().exec"):
            a = args[0]
            if self.expr(a)[0] != "const":
                v = eng.ev(a)
                if (v[0] >= C.OTHER or v[1]) and v[0] != C.TAINT:
                    if a.type in ("binary_expression", "additive_expression", "call_expression", "string_literal"):
                        eng.p.add(rel, "AST-KT-001", "unknown", line, sink=qual)
        # --- command built at runtime (audit)
        if qual.endswith("Runtime.getRuntime().exec") and args:
            a = args[0]
            if self.expr(a)[0] != "const" and (a.type in ("string_literal", "binary_expression", "additive_expression", "call_expression") or True):
                v = eng.ev(a)
                if v[0] >= C.OTHER and not (v[0] == C.TAINT):
                    eng.p.add(rel, "AST-KT-001", "unknown", line, sink=qual)
        # --- XXE
        if re.search(r"(DocumentBuilderFactory|SAXParserFactory|XMLInputFactory|TransformerFactory|SchemaFactory|XMLReaderFactory)\.(newInstance|createXMLReader)$", qual):
            if not re.search(r"disallow-doctype-decl|FEATURE_SECURE_PROCESSING|IS_SUPPORTING_EXTERNAL_ENTITIES|ACCESS_EXTERNAL|setExpandEntityReferences|external-general-entities", body_txt):
                eng.p.add(rel, "AST-KT-013", "unknown", line, sink=qual)
        # --- cookies
        if qual == "Cookie" or qual.endswith(".Cookie"):
            miss = [w for w in ("HttpOnly", "Secure") if not re.search(w, body_txt)]
            if miss:
                eng.p.add(rel, "AST-KT-015", "fixed", line, what="Cookie created without " + " and ".join(miss) + ".")
        # --- logs and storage containing sensitive data
        if re.match(r"^(Log\.[divwe]|println|print|Timber\.[divwe]|logger\.\w+|Logger\.\w+)$", qual) or qual in ("Log.wtf",):
            if any(SENS_LOG.search(txt(a)) and a.type != "string_literal" or (a.type == "string_literal" and False) for a in args[1:] or args):
                eng.p.add(rel, "AST-KT-010", "fixed", line, sink=qual)
        if simple in ("putString", "putInt", "putLong") and args:
            lit = self.literal(args[0]) or ""
            if SENS_LOG.search(lit) and re.search(r"(?i)(shared|pref|editor|edit\(\))", qual):
                eng.p.add(rel, "AST-KT-010", "fixed", line, sink=qual)
        # --- weak Random for sensitive data
        if re.search(r"(^|\.)(Random(\(\))?\.next\w+|Math\.random|nextInt|nextLong|nextBytes)$", qual) and "SecureRandom" not in qual:
            tgt = eng.name
            if SENSITIVE.search(tgt):
                eng.p.add(rel, "AST-KT-007", "fixed", line, sink=qual, name=tgt)
            else:
                p = node.parent
                while p is not None and p.type not in ("property_declaration", "assignment", "block", "statements", "function_body"):
                    p = p.parent
                if p is not None and p.type in ("property_declaration", "assignment"):
                    nm = self._first_ident(p.named_children[0]) if p.type == "property_declaration" and p.named_children else txt(p.children[0])
                    if SENSITIVE.search(nm or "") and not re.search(r"SecureRandom", body_txt):
                        eng.p.add(rel, "AST-KT-007", "fixed", line, sink=qual, name=nm)

    def on_node(self, eng, n):
        rel = eng.rel
        line = C.line_of(n)
        t = n.type
        if t in ("property_declaration", "assignment"):
            self.track_sql(eng, n)
        if t in ("navigation_expression", "identifier") and re.fullmatch(r"(\w+\.)*MODE_WORLD_(READABLE|WRITEABLE)", txt(n)):
            eng.p.add(rel, "AST-KT-011", "fixed", line, sink=txt(n))
        if t == "string_literal":
            raw = txt(n)
            m = re.match(r'^"http://([^/"$]+)', raw)
            if m and not re.match(r"(localhost|127\.|10\.0\.2\.2|0\.0\.0\.0|\[::1\]|www\.w3\.org|schemas\.|xmlns|java\.sun\.com|xml\.apache\.org|maven\.apache|www\.springframework|example\.)", m.group(1)):
                eng.p.add(rel, "AST-KT-014", "unknown", line, what=f"The address http://{m.group(1)} uses an unencrypted connection.")
        if t == "function_declaration" and self._first_ident(n) == "checkServerTrusted":
            body = next((c for c in n.children if c.type in ("function_body", "block")), None)
            if body is not None and re.fullmatch(r"\{\s*\}", txt(body).strip()) or (body is not None and re.fullmatch(r"\{\s*(//[^\n]*\s*)*\}", txt(body).strip())):
                eng.p.add(rel, "AST-KT-006", "fixed", line, sink="TrustManager that accepts every certificate")
        if t == "lambda_literal" and re.search(r"->\s*true\s*\}?$", re.sub(r"\s+", " ", txt(n)).strip()):
            p = n.parent
            hops = 0
            while p is not None and hops < 4 and p.type != "call_expression":
                p = p.parent; hops += 1
            if p is not None and re.search(r"(hostnameVerifier|HostnameVerifier|setHostnameVerifier|setDefaultHostnameVerifier)", txt(p)[:120]):
                eng.p.add(rel, "AST-KT-006", "fixed", line, sink="HostnameVerifier that accepts every host")
        if t == "assignment":
            kids = n.children
            if len(kids) >= 3:
                key = txt(kids[0])
                val = txt(kids[-1])
                if re.search(r"(javaScriptEnabled|allowFileAccess|allowFileAccessFromFileURLs|allowUniversalAccessFromFileURLs|allowContentAccess)$", key) and val == "true":
                    eng.p.add(rel, "AST-KT-004", "fixed", line, sink=key + " = true")
                if re.search(r"(isHttpOnly|httpOnly|isSecure|secure)$", key) and val == "false":
                    eng.p.add(rel, "AST-KT-015", "fixed", line, what=f"{key} = false disables the cookie protection.")

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
            _, targets, values, op = st
            key = self.lkey(targets[0])
            if key and values and self.sql_built(eng, values[0]):
                sv.add(key)
            elif key and op == "+=" and any(SQL_RE.search(txt(x)) for x in [values[0]]) is False and key in sv:
                pass


LANG = KotlinLang()


def analyze_kotlin_project(sources):
    return C.analyze(LANG, sources)


def analyze_kotlin_source(rel_path, text):
    return C.analyze_source(LANG, rel_path, text)
