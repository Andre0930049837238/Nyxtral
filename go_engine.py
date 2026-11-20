# -*- coding: utf-8 -*-
"""
go_engine.py
=============
Security engine for Go (.go) built on a real parser (tree-sitter-go) and data-flow analysis on top of the shared core
in lang_core.py.

Vulnerability classes covered: command injection, SQL injection, path traversal (incl. zip-slip), SSRF, XSS, open redirect,
template injection, weak cryptography, disabled TLS/SSH verification, weak random numbers for sensitive data,
overly permissive file permissions, cookies without Secure/HttpOnly, servers without timeouts / listening on all interfaces,
predictable temporary files, decompression bombs, use of unsafe.

Known limitations: there is no type checker (methods on unknown types stay opaque: dangerous call sites are recognized
by name), and web handlers are recognized from the parameter type (http.Request, gin.Context, echo.Context, fiber.Ctx...).
"""

import logging
import re

import lang_core as C
from lang_core import Sink, Fixed, V_TAINT, V_LOCAL, txt, walk

log = logging.getLogger(__name__)

try:
    from tree_sitter import Language, Parser
    import tree_sitter_go as _tsg
    _LANG = Language(_tsg.language())
    _PARSER = Parser(_LANG)
    AVAILABLE = True
except Exception as _exc:                           # pragma: no cover
    AVAILABLE = False
    log.warning(
        "Go AST analysis is disabled: could not load tree-sitter or tree-sitter-go (%s: %s). "
        "Only the generic pattern rules will run on .go files. "
        "Install the missing packages with: pip install tree-sitter tree-sitter-go",
        type(_exc).__name__, _exc,
    )

SUPPORTED = (".go",)
MAX_PROJECT_BYTES = C.MAX_PROJECT_BYTES

RULES = {
    "AST-GO-001": ("Command execution with untrusted data", "CRITICAL", "HIGH",
                   "{sink} runs a command that is partly built from external input.",
                   "Pass the data as separate arguments to exec.Command (never through 'sh -c') and validate the input against an allowlist of permitted values.", "CWE-78"),
    "AST-GO-002": ("SQL injection", "CRITICAL", "HIGH",
                   "{sink} receives a query built from externally supplied data.",
                   "Use parameterized queries: db.Query(\"... WHERE id = $1\", id), never string concatenation or fmt.Sprintf.", "CWE-89"),
    "AST-GO-003": ("File path chosen by external input (path traversal)", "HIGH", "MEDIUM",
                   "{sink} uses a path that comes from external input.",
                   "Apply filepath.Base to the file name, or use filepath.Clean + strings.HasPrefix to verify that the path stays inside the permitted directory.", "CWE-22"),
    "AST-GO-004": ("Request to an address chosen by external input (SSRF)", "HIGH", "MEDIUM",
                   "{sink} contacts an address that comes from external input: internal services could be reached.",
                   "Accept only hosts from an allowlist and block internal addresses.", "CWE-918"),
    "AST-GO-005": ("Unsanitized content sent to the browser (XSS)", "HIGH", "MEDIUM",
                   "{sink} writes a value coming from external input to the response or template without sanitizing it.",
                   "Use html/template (which escapes automatically) or html.EscapeString; do not use template.HTML on external data.", "CWE-79"),
    "AST-GO-006": ("Redirect to an address chosen by external input", "MEDIUM", "LOW",
                   "{sink} redirects the user to an address decided by external input.",
                   "Redirect only to internal paths or to hosts on an allowlist.", "CWE-601"),
    "AST-GO-007": ("Weak cryptographic algorithm", "MEDIUM", "MEDIUM",
                   "{sink} uses an algorithm or key size that is considered weak.",
                   "Use SHA-256/SHA-3, AES-GCM, and RSA keys of at least 2048 bits; for passwords use argon2/bcrypt/scrypt.", "CWE-327"),
    "AST-GO-008": ("Certificate or host verification disabled", "HIGH", "HIGH",
                   "{sink}: the connection no longer verifies the identity of the remote party.",
                   "Keep verification enabled (InsecureSkipVerify: false) and enforce a minimum TLS version of 1.2.", "CWE-295"),
    "AST-GO-009": ("Insecure random numbers for sensitive data", "MEDIUM", "MEDIUM",
                   "{sink} (math/rand) is predictable, yet it generates a value that looks like a secret ('{name}').",
                   "Use crypto/rand instead of math/rand.", "CWE-338"),
    "AST-GO-010": ("Overly permissive file permissions", "MEDIUM", "MEDIUM",
                   "{sink} sets permissions that allow anyone to write.",
                   "Use the minimum permissions required, for example 0600 for files and 0750 for directories.", "CWE-732"),
    "AST-GO-011": ("Use of the unsafe package", "LOW", "LOW",
                   "{sink} bypasses Go's memory-safety checks.",
                   "Avoid unsafe unless it is strictly necessary and well isolated.", "CWE-242"),
    "AST-GO-012": ("Cookie without protection flags", "MEDIUM", "MEDIUM",
                   "{what}",
                   "Set Secure: true and HttpOnly: true (and SameSite) on session cookies.", "CWE-614"),
    "AST-GO-013": ("Server without timeouts or listening on all interfaces", "LOW", "LOW",
                   "{what}",
                   "Use an http.Server with ReadHeaderTimeout/ReadTimeout and listen only on the interface that is needed.", "CWE-400"),
    "AST-GO-014": ("Temporary file in a predictable location", "MEDIUM", "MEDIUM",
                   "{sink} uses a fixed path under /tmp: another user can create it first.",
                   "Use os.CreateTemp / os.MkdirTemp, which pick a random name.", "CWE-377"),
    "AST-GO-015": ("Unbounded decompression (decompression bomb)", "MEDIUM", "MEDIUM",
                   "{sink} reads the entire decompressed content: a small file can expand until memory is exhausted.",
                   "Limit the read with io.LimitReader or http.MaxBytesReader.", "CWE-409"),
    "AST-GO-016": ("Zip-slip: archive entry name used as a file path", "HIGH", "MEDIUM",
                   "{sink} builds a path from the name of a file inside an archive without verifying that it stays within the destination directory.",
                   "After Join, verify that the path starts with the destination directory (strings.HasPrefix) and reject '..'.", "CWE-22"),
    "AST-GO-018": ("Service listening on all network interfaces", "LOW", "LOW",
                   "{what}",
                   "Listen only on the interface that is needed (for example 127.0.0.1) and restrict access.", "CWE-1327"),
    "AST-GO-019": ("HTTP server without TLS", "LOW", "LOW",
                   "{what}",
                   "Use ListenAndServeTLS (or put the service behind a proxy that terminates HTTPS).", "CWE-319"),
    "AST-GO-020": ("Unsigned JWT token", "HIGH", "HIGH",
                   "{sink} allows unsigned tokens: anyone can forge a valid token.",
                   "Accept only strong signing algorithms (e.g. HS256/RS256) and reject 'none'.", "CWE-347"),
    "AST-GO-017": ("Template built from untrusted data", "HIGH", "MEDIUM",
                   "{sink} parses text coming from external input as a template.",
                   "Do not build the template from external input: pass the input as data instead.", "CWE-94"),
}

SENSITIVE = re.compile(r"(token|secret|passw|pwd|nonce|salt|session|csrf|otp|apikey|api_key|\bkey\b|_key|key_|\biv\b|cookie|auth)", re.I)
HANDLER_TYPE = re.compile(r"(events\.\w+(Request|Event)|http\.Request|gin\.Context|echo\.Context|fiber\.Ctx|iris\.Context|fasthttp\.RequestCtx|buffalo\.Context|restful\.Request|chi\.|mux\.|beego\.|web\.Context)")
RW_TYPE = re.compile(r"(http\.ResponseWriter)")


SQL_RE = re.compile(r"(?i)\b(select|insert\s+into|update\s+\w+\s+set|delete\s+from|drop\s+(table|database)|create\s+(table|database)|alter\s+table|truncate|union\s+select|where\s+\w+|order\s+by|exec(ute)?\s+\w+)\b")
HOST_FIXED = re.compile(r"^https?://[A-Za-z0-9.\-]+(:\d+)?(/|\?|$)")


def _fixed_host(eng, n):
    """URL with scheme and host hardcoded in the source: only the path is dynamic, so this is not SSRF."""
    t = n
    while t is not None and t.type == "parenthesized_expression" and t.named_children:
        t = t.named_children[0]
    if t is None:
        return False
    lead = None
    if t.type == "call_expression":
        e = LANG.expr(t)
        if e[1] in ("fmt.Sprintf", "fmt.Sprint") and e[3]:
            lead = LANG.literal(e[3][0])
    elif t.type == "binary_expression":
        x = t
        while x.type == "binary_expression" and x.child_by_field_name("left") is not None:
            x = x.child_by_field_name("left")
        lead = LANG.literal(x)
    elif t.type in ("interpreted_string_literal", "raw_string_literal"):
        return True
    return bool(lead and HOST_FIXED.match(lead))


class GoLang(C.LangBase):
    ENGINE = "go_ast"
    EXTS = SUPPORTED
    RULES = RULES
    AVAILABLE = AVAILABLE
    CALL_TYPES = {"call_expression"}
    FUNC_TYPES = {"function_declaration", "method_declaration"}
    STMT_TYPES = {"short_var_declaration", "assignment_statement", "var_spec", "const_spec", "range_clause"}
    TEST_RE = re.compile(r"(^|/)_?(testdata|tests?|examples?|docs?|vendor)(/|$)|_test\.go$")
    TEST_QUIET = frozenset({"AST-GO-004", "AST-GO-005", "AST-GO-006", "AST-GO-008", "AST-GO-009", "AST-GO-010", "AST-GO-012", "AST-GO-013",
                            "AST-GO-014", "AST-GO-015", "AST-GO-016", "AST-GO-018", "AST-GO-019"})
    CLEAN_RE = re.compile(r"(filepath\.Base|path\.Base|html\.EscapeString|template\.(HTML|JS|URL)?EscapeString|url\.(Query|Path)Escape|"
                          r"strconv\.Quote|regexp\.QuoteMeta|shellescape\.Quote|[Ss]anitize|bluemonday|\.Sanitize$|\.Escape$|EscapeString)")
    NUM_RE = re.compile(r"(strconv\.(Atoi|ParseInt|ParseUint|ParseFloat|ParseBool|Itoa)$|(^|\.)len$|uuid\.Parse|net\.ParseIP)")
    VALIDATE_RE = re.compile(r"(HasPrefix|HasSuffix|Contains|MatchString|\.Match$|IsAbs|[Ii]sValid|[Vv]alidate|[Ii]sSafe|[Ii]sAllowed|[Aa]llowed|[Ww]hitelist|[Aa]llowlist)")
    LEN_RE = re.compile(r"(^|\.)len$")
    SOURCE_CALLS = [(re.compile(r"^os\.(Getenv|LookupEnv|Environ)$"), V_LOCAL),
                    (re.compile(r"^flag\.(String|Arg|Args|Parse)"), V_LOCAL)]
    SOURCE_MEMBERS = [(re.compile(r"^os\.(Args|Stdin)\b"), V_LOCAL)]

    SINKS = [
        Sink("AST-GO-001", r"(^|\.)exec\.(Command|CommandContext)$"),
        Sink("AST-GO-001", r"^(syscall\.(Exec|ForkExec)|os\.StartProcess)$"),
        Sink("AST-GO-002", r"\.(Query|QueryRow|Exec|Prepare|Queryx|QueryRowx|MustExec|NamedExec|NamedQuery)$", (0,)),
        Sink("AST-GO-002", r"\.(QueryContext|QueryRowContext|ExecContext|PrepareContext|MustExecContext|NamedExecContext|QueryxContext)$", (1,)),
        Sink("AST-GO-002", r"\.(Select|Get|SelectContext|GetContext)$", (1, 2)),
        Sink("AST-GO-002", r"\.(Raw|Having|Joins|Order|Group)$", (0,)),
        Sink("AST-GO-002", r"\.Where$", (0,)),
        Sink("AST-GO-003", r"^(os\.(Open|OpenFile|Create|ReadFile|WriteFile|Remove|RemoveAll|Mkdir|MkdirAll|Stat|Lstat|ReadDir|Chmod|Chown|Truncate|Chdir|DirFS)|"
                            r"ioutil\.(ReadFile|WriteFile|ReadDir)|filepath\.(Walk|WalkDir|Glob)|zip\.OpenReader|http\.Dir)$", (0,), skip_local=True),
        Sink("AST-GO-003", r"^os\.(Rename|Symlink|Link)$", (0, 1), skip_local=True),
        Sink("AST-GO-003", r"^http\.ServeFile$", (2,), skip_local=True),
        Sink("AST-GO-004", r"^http\.(Get|Post|Head|PostForm)$", (0,), exempt=_fixed_host),
        Sink("AST-GO-004", r"^http\.NewRequest$", (1,), exempt=_fixed_host),
        Sink("AST-GO-004", r"^http\.NewRequestWithContext$", (2,), exempt=_fixed_host),
        Sink("AST-GO-004", r"([Cc]lient|resty|req)\.(Get|Post|Head|PostForm)$", (0,), exempt=_fixed_host),
        Sink("AST-GO-004", r"^net\.(Dial|DialTimeout)$", (1,)),
        Sink("AST-GO-005", r"^template\.(HTML|JS|JSStr|URL|CSS|HTMLAttr|Srcset)$"),
        Sink("AST-GO-006", r"^http\.Redirect$", (2,)),
        Sink("AST-GO-006", r"(?<!http)\.Redirect$", (0, 1)),
        Sink("AST-GO-017", r"template\.New\([^)]*\)\.Parse$", (0,)),
        Sink("AST-GO-017", r"^template\.Must$", (0,), template_only=False),
    ]
    FIXED = [
        Fixed("AST-GO-007", r"^(md5|sha1)\.(New|Sum)$"),
        Fixed("AST-GO-007", r"^(des|rc4)\.(NewCipher|NewTripleDESCipher)$"),
        Fixed("AST-GO-007", r"^(sha256|sha3)\.(New224|Sum224)$"),
        Fixed("AST-GO-007", r"^cgi\.(Serve|Handler)$"),
        Fixed("AST-GO-020", r"(jwt\.SigningMethodNone|jwt\.UnsafeAllowNoneSignatureType)$"),
        Fixed("AST-GO-007", r"^rsa\.GenerateKey$", (1, r"^(512|768|1024)$")),
        Fixed("AST-GO-008", r"^ssh\.InsecureIgnoreHostKey$"),
        Fixed("AST-GO-010", r"^os\.(Chmod|Mkdir|MkdirAll)$", (1, r"^0[oO]?[0-7]*[2367]$")),
        Fixed("AST-GO-010", r"^(os|ioutil)\.WriteFile$", (2, r"^0[oO]?[0-7]*[2367]$")),
        Fixed("AST-GO-010", r"^os\.OpenFile$", (2, r"^0[oO]?[0-7]*[2367]$")),
        Fixed("AST-GO-011", r"^unsafe\.Pointer$"),
        Fixed("AST-GO-014", r"^(os\.(Create|Open|OpenFile|WriteFile|Mkdir|MkdirAll)|ioutil\.WriteFile)$", (0, r"^/(var/)?tmp/")),
    ]
    PROPAGATE = [
        (re.compile(r"\.Decode$"), "recv", (0,)),
        (re.compile(r"(json|xml|yaml|toml|gob|proto)\.Unmarshal$"), "args", (1,)),
        (re.compile(r"(\.Read|\.ReadFrom|\.Scan|\.ScanLines)$"), "recv", (0,)),
        (re.compile(r"^fmt\.(Sscanf|Sscan|Fscan|Fscanf|Fscanln)$"), "args", (2, 3, 4)),
        (re.compile(r"^io\.Copy$"), "args", (0,)),
        (re.compile(r"\.(WriteString|Write|WriteByte|WriteRune)$"), "args", ("recv",)),
        (re.compile(r"^fmt\.Fprint(f|ln)?$"), "args", (0,)),
    ]

    def __init__(self):
        self.imports = {}                    # file path -> {alias: package}

    def top_level(self, root, rel):
        return {"name": "<package>", "params": [], "body": root, "receiver": None, "text": "", "top": True}

    # ---- parsing ---------------------------------------------------------------------------------
    def parse(self, rel, text):
        tree = _PARSER.parse(text.encode("utf-8", "ignore"))
        imps = {}
        for n in walk(tree.root_node):
            if n.type == "import_spec":
                p = n.child_by_field_name("path")
                nm = n.child_by_field_name("name")
                path = txt(p).strip('"`')
                alias = txt(nm) if nm is not None else path.split("/")[-1]
                imps[alias] = path
        self.imports[rel] = imps
        return tree

    def has_import(self, rel, path_prefix):
        return any(p.startswith(path_prefix) for p in self.imports.get(rel, {}).values())

    def functions(self, root):
        for n in walk(root):
            if n.type in ("function_declaration", "method_declaration"):
                name = txt(n.child_by_field_name("name"))
                body = n.child_by_field_name("body")
                if body is None:
                    continue
                params = []
                pl = n.child_by_field_name("parameters")
                params = self._params(pl)
                rcv = None
                r = n.child_by_field_name("receiver")
                if r is not None:
                    rp = self._params(r)
                    rcv = (rp[0][0], rp[0][1]) if rp else None
                yield {"name": name, "params": params, "body": body, "receiver": rcv,
                       "text": txt(body)}

    def _params(self, pl):
        out = []
        if pl is None:
            return out
        for p in pl.named_children:
            if p.type in ("parameter_declaration", "variadic_parameter_declaration"):
                ty = txt(p.child_by_field_name("type"))
                names = [txt(c) for c in p.children if c.type == "identifier"]
                if not names:
                    out.append((None, ty, ""))
                for nm in names:
                    out.append((nm, ty, ""))
        return out

    # ---- classification ---------------------------------------------------------------------------
    def qual_of(self, n):
        if n is None:
            return ""
        t = n.type
        if t == "identifier" or t == "field_identifier" or t == "package_identifier":
            return txt(n)
        if t == "selector_expression":
            return self.qual_of(n.child_by_field_name("operand")) + "." + txt(n.child_by_field_name("field"))
        if t == "call_expression":
            return self.qual_of(n.child_by_field_name("function")) + "()"
        if t == "parenthesized_expression" and n.named_children:
            return self.qual_of(n.named_children[0])
        if t == "index_expression":
            return self.qual_of(n.child_by_field_name("operand")) + "[]"
        return re.sub(r"\s+", "", txt(n))[:40]

    def expr(self, n):
        t = n.type
        if t in ("interpreted_string_literal", "raw_string_literal", "int_literal", "float_literal", "rune_literal", "true",
                 "false", "nil", "iota", "imaginary_literal", "func_literal"):
            return ("const",)
        if t == "identifier":
            return ("name", txt(n))
        if t == "selector_expression":
            return ("member", n.child_by_field_name("operand"), txt(n.child_by_field_name("field")), self.qual_of(n))
        if t == "index_expression":
            return ("index", n.child_by_field_name("operand"), n.child_by_field_name("index"))
        if t in ("slice_expression", "type_assertion_expression"):
            return ("wrap", n.child_by_field_name("operand"))
        if t == "type_conversion_expression":
            return ("wrap", n.child_by_field_name("operand"))
        if t == "parenthesized_expression":
            return ("wrap", n.named_children[0] if n.named_children else None)
        if t == "unary_expression":
            return ("wrap", n.child_by_field_name("operand"))
        if t == "binary_expression":
            op = txt(n.child_by_field_name("operator"))
            if op in ("==", "!=", "<", ">", "<=", ">=", "&&", "||"):
                return ("cmp",)
            return ("bin", [n.child_by_field_name("left"), n.child_by_field_name("right")], op)
        if t == "call_expression":
            fn = n.child_by_field_name("function")
            args = [a for a in n.child_by_field_name("arguments").named_children if a.type != "comment"] \
                if n.child_by_field_name("arguments") is not None else []
            if fn is not None and fn.type == "selector_expression":
                return ("call", self.qual_of(fn), fn.child_by_field_name("operand"), args, txt(fn.child_by_field_name("field")))
            q = self.qual_of(fn)
            return ("call", q, None, args, q)
        if t == "composite_literal":
            body = n.child_by_field_name("body")
            vals = []
            if body is not None:
                for el in body.named_children:
                    c = el.named_children[-1] if el.named_children else None
                    if c is not None and c.type == "literal_element" and c.named_children:
                        c = c.named_children[0]
                    vals.append(c)
            return ("list", [v for v in vals if v is not None])
        if t in ("expression_list", "argument_list"):
            return ("list", list(n.named_children))
        if t == "keyed_element" and n.named_children:
            return ("wrap", n.named_children[-1])
        if t == "literal_element" and n.named_children:
            return ("wrap", n.named_children[0])
        return ("other",)

    def stmt(self, n):
        t = n.type
        if t == "short_var_declaration" or t == "assignment_statement":
            l, r = n.child_by_field_name("left"), n.child_by_field_name("right")
            op = ":=" if t == "short_var_declaration" else txt(n.child_by_field_name("operator"))
            if l is None or r is None:
                return None
            return ("assign", list(l.named_children), list(r.named_children), op)
        if t in ("var_spec", "const_spec"):
            names = [txt(c) for c in n.children_by_field_name("name")]
            v = n.child_by_field_name("value")
            return ("decl", names, list(v.named_children) if v is not None else None)
        if t == "range_clause":
            l, r = n.child_by_field_name("left"), n.child_by_field_name("right")
            if l is None or r is None:
                return None
            return ("for", list(l.named_children), r)
        return None

    def lkey(self, n):
        if n is None:
            return None
        t = n.type
        if t == "identifier":
            return None if txt(n) == "_" else txt(n)
        if t == "selector_expression":
            return self.qual_of(n)
        if t in ("index_expression", "slice_expression"):
            return self.lkey(n.child_by_field_name("operand"))
        if t in ("unary_expression", "parenthesized_expression"):
            return self.lkey(n.child_by_field_name("operand") or (n.named_children[0] if n.named_children else None))
        return None

    def is_simple_target(self, n):
        return n.type in ("identifier", "selector_expression")

    def is_deep(self, n):
        return n.type in ("if_statement", "for_statement", "expression_switch_statement", "type_switch_statement",
                          "select_statement", "func_literal", "expression_case", "default_case", "communication_case")

    def cond_of(self, n):
        if n.type == "if_statement":
            return n.child_by_field_name("condition")
        if n.type == "for_statement":
            for c in n.children:
                if c.type == "for_clause":
                    return c.child_by_field_name("condition")
                if c.type == "binary_expression":
                    return c
        return None

    def is_relational(self, x):
        return x.type == "binary_expression" and txt(x.child_by_field_name("operator")) in ("<", ">", "<=", ">=")

    def is_equality(self, x):
        return x.type == "binary_expression" and txt(x.child_by_field_name("operator")) in ("==", "!=")

    def literal(self, n):
        if n is None:
            return None
        if n.type in ("interpreted_string_literal", "raw_string_literal"):
            return txt(n)[1:-1]
        if n.type == "int_literal":
            return txt(n)
        return None

    def sink_label(self, n):
        return self.qual_of(n.child_by_field_name("function"))[:60]

    def param_taint(self, fname, pname, ptype, pann):
        return V_TAINT if HANDLER_TYPE.search(ptype or "") else None

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

    # ---- engine-specific hooks ---------------------------------------------------------------------------
    def on_enter(self, eng, n):
        if n.type == "func_literal":           # anonymous handlers: http.HandleFunc("/x", func(w, r) {...})
            pl = n.child_by_field_name("parameters")
            for pn, pt, _ in self._params(pl):
                if pn and HANDLER_TYPE.search(pt or ""):
                    eng.env[pn] = V_TAINT
                    if RW_TYPE.search(pt or ""):
                        pass
        if n.type == "function_declaration" or n.type == "method_declaration":
            pass

    def rw_names(self, eng):
        names = getattr(eng, "_rw", None)
        if names is None:
            names = {pn for pn, pt, _ in eng.fdef["params"] if pn and RW_TYPE.search(pt or "")}
            # also include the parameters of func_literals inside the function
            for x in walk(eng.fdef["body"]):
                if x.type == "func_literal":
                    names |= {pn for pn, pt, _ in self._params(x.child_by_field_name("parameters")) if pn and RW_TYPE.search(pt or "")}
            eng._rw = names
        return names

    # ---- SQL built via concatenation / Sprintf: also fires without a confirmed external source ("audit") -----------
    SQL_METHODS = re.compile(r"\.(Query|QueryRow|Exec|Prepare|Queryx|QueryRowx|MustExec|NamedExec|NamedQuery|QueryContext|QueryRowContext|"
                             r"ExecContext|PrepareContext|Select|Get|SelectContext|GetContext|Raw|Where|Having|Joins|Order|Group|Model|"
                             r"ExecOne|QueryOne|Exec_|WhereOr|Table)$")

    def sql_built(self, eng, n):
        if n is None:
            return False
        sv = getattr(eng, "_sqlvars", None)
        if sv is None:
            sv = eng._sqlvars = set()
        t = n.type
        while t == "parenthesized_expression" and n.named_children:
            n = n.named_children[0]; t = n.type
        if t == "identifier":
            return txt(n) in sv
        if t == "binary_expression" and txt(n.child_by_field_name("operator")) == "+":
            pass
        elif t == "call_expression":
            e = self.expr(n)
            if not (e[1] in ("fmt.Sprintf", "fmt.Sprint", "fmt.Sprintln", "strings.Join", "strings.Replace", "strings.ReplaceAll") or e[4] == "String"):
                return False
            if e[4] == "String" and e[2] is not None:       # builder.String()
                return txt(e[2]) in sv
        else:
            return False
        pieces = [self.literal(x) or "" for x in walk(n) if x.type in ("interpreted_string_literal", "raw_string_literal")]
        has_sql = any(SQL_RE.search(p) for p in pieces) or any(txt(x) in sv for x in walk(n) if x.type == "identifier")
        return has_sql and eng.ev(n)[0] >= C.OTHER or (has_sql and eng.ev(n)[1] != frozenset())

    def track_sql(self, eng, n):
        st = self.stmt(n)
        if st is None:
            return
        sv = getattr(eng, "_sqlvars", None)
        if sv is None:
            sv = eng._sqlvars = set()
        if st[0] == "assign":
            _, targets, values, op = st
            vals = values if isinstance(values, list) else [values]
            for i, t in enumerate(targets):
                key = self.lkey(t)
                if not key:
                    continue
                v = vals[i] if i < len(vals) else (vals[0] if vals else None)
                if v is None:
                    continue
                lit = self.literal(v)
                if lit is not None and SQL_RE.search(lit):
                    sv.add(key) if op == "+=" and False else eng.__dict__.setdefault("_sqllit", set()).add(key)
                elif op == "+=" and key in getattr(eng, "_sqllit", set()) and eng.ev(v)[0] >= C.OTHER:
                    sv.add(key)
                elif self.sql_built(eng, v):
                    sv.add(key)
        elif st[0] == "decl" and st[2]:
            for nm, v in zip(st[1], st[2]):
                lit = self.literal(v)
                if lit is not None and SQL_RE.search(lit):
                    eng.__dict__.setdefault("_sqllit", set()).add(nm)
                elif self.sql_built(eng, v):
                    sv.add(nm)

    SHELLS = re.compile(r"(^|/)(sh|bash|zsh|dash|ksh|cmd(\.exe)?|powershell(\.exe)?|pwsh)$")

    def call_effects(self, eng, qual, simple, recv, args, vals, node):
        line = C.line_of(node)
        rel = eng.rel
        body_txt = eng.fdef.get("text", "")

        # --- Built SQL (audit): query containing SQL keywords and non-constant pieces
        if self.SQL_METHODS.search(qual):
            for a in args[:4]:
                if self.sql_built(eng, a):
                    v = eng.ev(a)
                    if v[0] == C.TAINT and v[2]:
                        continue                      # numeric-only: cannot change the structure of the query
                    if v[0] == C.TAINT:
                        eng.p.add(rel, "AST-GO-002", "confirmed", line, sink=qual)
                    elif v[0] >= C.OTHER or v[1]:
                        eng.p.add(rel, "AST-GO-002", "unknown", line, sink=qual)
                    for pi in v[1]:
                        eng.p.summary.setdefault(eng.key, []).append((frozenset([pi]), "AST-GO-002", rel, line, {"sink": qual}, "str", False))

        # --- commands: non-constant program name, or a shell with non-constant arguments (audit)
        if re.search(r"(^|\.)exec\.(Command|CommandContext)$", qual) or qual in ("syscall.Exec", "syscall.ForkExec", "os.StartProcess"):
            off = 1 if qual.endswith("CommandContext") else 0
            if len(args) > off:
                nm = args[off]
                if self.expr(nm)[0] != "const":
                    eng.p.add(rel, "AST-GO-001", "unknown", line, sink=qual)
                else:
                    lit = self.literal(nm) or ""
                    if self.SHELLS.search(lit) and any(self.expr(x)[0] != "const" for x in args[off + 1:]):
                        eng.p.add(rel, "AST-GO-001", "unknown", line, sink=qual)

        # --- template.HTML & co. with non-constant values (audit)
        if re.search(r"^template\.(HTML|JS|JSStr|URL|CSS|HTMLAttr|Srcset)$", qual) and args and self.expr(args[0])[0] != "const":
            eng.p.add(rel, "AST-GO-005", "unknown", line, sink=qual)

        # --- XSS: direct write to the HTTP response
        rw = self.rw_names(eng)
        quiet = re.search(r"application/json|text/plain|application/xml|octet-stream", body_txt) is not None
        target = None
        if simple in ("Write", "WriteString") and recv is not None and txt(recv) in rw and args:
            target = args[:1]
        elif qual in ("io.WriteString",) and args and txt(args[0]) in rw:
            target = args[1:2]
        elif qual in ("fmt.Fprintf", "fmt.Fprint", "fmt.Fprintln") and args and txt(args[0]) in rw:
            target = args[1:] if qual != "fmt.Fprintf" else args[2:]
            if qual == "fmt.Fprintf" and len(args) >= 2 and self.expr(args[1])[0] != "const":
                target = args[1:]
        if target and not quiet:
            for a in target:
                v = eng.ev(a)
                names = eng.names(a)
                if v[0] == C.TAINT and not v[2]:
                    if not (names & eng.validated):
                        eng.p.add(rel, "AST-GO-005", "confirmed", line, sink=qual or simple)
                elif v[1]:
                    for pi in v[1]:
                        eng.p.summary.setdefault(eng.key, []).append((frozenset([pi]), "AST-GO-005", rel, line, {"sink": qual or simple}, "str", False))
                elif v[0] >= C.OTHER and self.expr(a)[0] != "const" and not (names & eng.validated):
                    eng.p.add(rel, "AST-GO-005", "unknown", line, sink=qual or simple)

        # --- MD5/SHA1 used as a password hash
        if re.search(r"[Pp]ass(wd|word)?|[Pp]wd", simple) and args:
            atxt = " ".join(txt(a) for a in args)
            if re.search(r"(md5|sha1)\.", atxt) or (re.search(r"\.Sum\(", atxt) and re.search(r"(md5|sha1)\.New", eng.fdef.get("text", ""))):
                eng.p.add(rel, "AST-GO-007", "fixed", line, sink=f"{simple} (weak hash)")

        # --- zip-slip
        if qual in ("filepath.Join", "path.Join") and (self.has_import(rel, "archive/zip") or self.has_import(rel, "archive/tar")):
            if any(a.type == "selector_expression" and txt(a.child_by_field_name("field")) == "Name" for a in args):
                if not re.search(r"HasPrefix|\"\.\.\"|filepath\.Rel|IsLocal", body_txt):
                    eng.p.add(rel, "AST-GO-016", "unknown", line, sink=qual)
        if qual in ("zip.OpenReader", "zip.NewReader", "tar.NewReader") and not re.search(r"HasPrefix|\"\.\.\"|filepath\.Rel|IsLocal", body_txt):
            eng.p.add(rel, "AST-GO-016", "unknown", line, sink=qual)

        # --- decompression bomb
        bombs = getattr(eng, "_bombs", set())
        if qual in ("io.Copy", "io.CopyBuffer", "io.ReadAll", "ioutil.ReadAll") and args:
            for a in args:
                if txt(a) in bombs or re.search(r"(gzip|zlib|flate|bzip2|zstd|lz4)\.NewReader", self.qual_of(a)):
                    if not re.search(r"LimitReader|MaxBytesReader|CopyN", body_txt):
                        eng.p.add(rel, "AST-GO-015", "fixed", line, sink=qual)
                    break

        # --- network: server without timeouts, missing TLS, listening on all interfaces
        if qual in ("http.ListenAndServe", "http.ListenAndServeTLS"):
            eng.p.add(rel, "AST-GO-013", "fixed", line, what=f"{qual} starts a server without timeouts (exposed to slowloris-style attacks).")
        if qual == "http.ListenAndServe":
            eng.p.add(rel, "AST-GO-019", "fixed", line, what="http.ListenAndServe serves plain HTTP: traffic is not encrypted.")
        if qual in ("net.Listen", "http.ListenAndServe", "http.ListenAndServeTLS"):
            ai = 1 if qual == "net.Listen" else 0
            lit = self.literal(args[ai]) if len(args) > ai else None
            if lit is not None and re.match(r"^(0\.0\.0\.0)?:\d+$", lit):
                eng.p.add(rel, "AST-GO-018", "fixed", line, what=f"{qual} makes the service listen on all network interfaces.")

        # --- weak random numbers (math/rand) inside sensitive functions or variables
        imps = self.imports.get(rel, {})
        head = qual.split(".")[0]
        if imps.get(head, "").startswith("math/rand") and re.search(r"\.(Int|Intn|Int31|Int31n|Int63|Int63n|Uint32|Uint64|Read|Float64|Perm)$", qual):
            sens = SENSITIVE.search(eng.name)
            if not sens:
                p = node.parent
                while p is not None and p.type not in ("short_var_declaration", "assignment_statement", "var_spec", "statement_list", "block"):
                    p = p.parent
                if p is not None and p.type in ("short_var_declaration", "assignment_statement", "var_spec"):
                    tgt = p.child_by_field_name("left") or p.child_by_field_name("name")
                    sens = SENSITIVE.search(txt(tgt) if tgt is not None else "")
                    if sens:
                        eng.p.add(rel, "AST-GO-009", "fixed", line, sink=qual, name=txt(tgt)[:30])
            else:
                eng.p.add(rel, "AST-GO-009", "fixed", line, sink=qual, name=eng.name)

    def on_node(self, eng, n):
        rel = eng.rel
        line = C.line_of(n)
        t = n.type
        if t in self.STMT_TYPES:
            self.track_sql(eng, n)
        if t == "import_spec":
            path = txt(n.child_by_field_name("path")).strip('"`')
            if re.match(r"^math/rand(/v\d+)?$", path):
                eng.p.add(rel, "AST-GO-009", "unknown", line, sink=path, name="")
            if path == "text/template":
                eng.p.add(rel, "AST-GO-005", "unknown", line, sink="import text/template")
        if t == "keyed_element" and len(n.named_children) >= 2:
            key, val = txt(n.named_children[0]), txt(n.named_children[-1])
            if key == "InsecureSkipVerify" and val == "true":
                eng.p.add(rel, "AST-GO-008", "fixed", line, sink="InsecureSkipVerify: true")
            if key == "MinVersion" and re.search(r"VersionSSL30|VersionTLS10|VersionTLS11", val):
                eng.p.add(rel, "AST-GO-008", "fixed", line, sink=f"MinVersion: {val}")
            if key == "CipherSuites" and re.search(r"RC4|3DES|_NULL_|_EXPORT_|DES_CBC|TLS_RSA_WITH_AES_\d+_CBC_SHA(256)?\b", val):
                eng.p.add(rel, "AST-GO-008", "fixed", line, sink="CipherSuites with weak algorithms")
        if t == "composite_literal":
            ty = txt(n.child_by_field_name("type"))
            body = n.child_by_field_name("body")
            keys = {}
            if body is not None:
                for el in body.named_children:
                    if el.type == "keyed_element" and len(el.named_children) >= 2:
                        keys[txt(el.named_children[0])] = txt(el.named_children[-1])
            if re.search(r"(http\.Cookie|sessions\.Options)$", ty):
                miss = []
                if keys.get("Secure", "false") == "false":
                    miss.append("Secure")
                if keys.get("HttpOnly", "false") == "false":
                    miss.append("HttpOnly")
                if re.search(r"SameSiteNone", keys.get("SameSite", "")):
                    miss.append("SameSite")
                if miss:
                    eng.p.add(rel, "AST-GO-012", "fixed", line, what="Cookie created without " + " and ".join(miss) + ".")
            if re.search(r"http\.Server$", ty):
                if not any(k in keys for k in ("ReadHeaderTimeout", "ReadTimeout")):
                    eng.p.add(rel, "AST-GO-013", "fixed", line, what="http.Server created without ReadHeaderTimeout/ReadTimeout (exposed to slowloris).")
            if re.search(r"tls\.Config$", ty) and "MinVersion" not in keys:
                eng.p.add(rel, "AST-GO-008", "unknown", line, sink="tls.Config without MinVersion")
        if t in ("short_var_declaration", "assignment_statement"):
            r = n.child_by_field_name("right")
            l = n.child_by_field_name("left")
            if r is not None and l is not None and r.named_children and r.named_children[0].type == "call_expression" \
                    and re.search(r"(gzip|zlib|flate|bzip2|zstd|lz4)\.NewReader", self.qual_of(r.named_children[0].child_by_field_name("function"))):
                bombs = getattr(eng, "_bombs", None)
                if bombs is None:
                    bombs = eng._bombs = set()
                bombs.update(txt(x) for x in l.named_children)


LANG = GoLang()


def analyze_go_project(sources):
    return C.analyze(LANG, sources)


def analyze_go_source(rel_path, text):
    return C.analyze_source(LANG, rel_path, text)
