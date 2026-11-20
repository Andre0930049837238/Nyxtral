# -*- coding: utf-8 -*-
"""
c_engine.py
============
Security engine for C and C++ (.c .h .cpp .hpp .cc .cxx .hh .hxx) built on a real parser (tree-sitter-c and
tree-sitter-cpp) with data-flow analysis, in the same style as ast_engine.py (Python), js_engine.py
(JS/TS) and rust_engine.py (Rust).

What it does:
  - follows untrusted data (argv, getenv, stdin, cin, sockets, read/recv) inside functions, through
    assignments, std::string concatenations, casts, struct fields and buffer copies;
  - summarizes, for every function in the project, which parameters reach a dangerous sink, so that a call
    in another file (run(argv[1]) -> system(c)) is recognized as well;
  - recognizes the most common validity checks (size comparisons, strlen/sizeof in a condition, min());
  - separates "Confirmed" (the data comes from an external source), "Detected with certainty" (inherently
    unsafe usage, e.g. gets) and "Potential" (cannot be determined: needs manual review).

Vulnerability classes covered: command injection, format string, unbounded copies (strcpy/strcat/sprintf), gets, scanf %s
without a width, externally controlled copy size, allocation with an untrusted size, path traversal,
weak cryptography, disabled TLS verification, insecure temporary files, weak random numbers for sensitive data,
use-after-free and double free (within the same block), overly permissive file permissions.

Known limitations: there is no preprocessor (macros are not expanded: an all-uppercase name is treated as a
constant), no type checker (methods on unknown types stay opaque), no pointer-aliasing analysis and no
cross-branch data-flow beyond an approximation, and use-after-free is detected only within the same block.
It does not execute the code. If tree-sitter-c/cpp are missing, only the generic checks (secrets, sensitive files) stay active.
"""

import logging
import re

log = logging.getLogger(__name__)

CONST, PARAM, OTHER, TAINT = 0, 1, 2, 3

try:
    from tree_sitter import Language, Parser
except Exception as _exc:                           # pragma: no cover
    Language = Parser = None
    log.warning(
        "C/C++ AST analysis is disabled: the 'tree_sitter' package could not be imported (%s: %s). "
        "Only the generic pattern rules will run on C/C++ files. Install it with: pip install tree-sitter",
        type(_exc).__name__, _exc,
    )

_LANGS = {}
try:
    import tree_sitter_cpp as _tscpp
    _LANGS["cpp"] = Language(_tscpp.language())
except Exception as _exc:
    log.warning(
        "Could not load the tree-sitter C++ grammar (%s: %s). C++ files will be parsed with the C grammar if available, "
        "otherwise AST analysis is skipped. Install it with: pip install tree-sitter-cpp",
        type(_exc).__name__, _exc,
    )
try:
    import tree_sitter_c as _tsc
    _LANGS["c"] = Language(_tsc.language())
except Exception as _exc:
    log.warning(
        "Could not load the tree-sitter C grammar (%s: %s). C files will be parsed with the C++ grammar if available, "
        "otherwise AST analysis is skipped. Install it with: pip install tree-sitter-c",
        type(_exc).__name__, _exc,
    )
AVAILABLE = bool(_LANGS) and Parser is not None
if not AVAILABLE:
    log.warning("C/C++ AST analysis is unavailable: no usable tree-sitter grammar was loaded. "
                "Taint tracking and memory-safety checks for C/C++ will not run.")

SUPPORTED = (".c", ".h", ".cpp", ".hpp", ".cc", ".cxx", ".hh", ".hxx")
MAX_PROJECT_BYTES = 20 * 1024 * 1024
MAX_PROJECT_FILES = 3000
_PARSERS = {}

CONF_LABEL = {
    "confirmed": "Confirmed: the tracked data comes from an external source",
    "unknown": "Potential: the origin of the data cannot be determined automatically; verify manually",
    "fixed": "Detected with certainty in the code: inherently unsafe usage",
}
SEV_DOWN = {"CRITICAL": "HIGH", "HIGH": "MEDIUM", "MEDIUM": "LOW", "LOW": "LOW", "INFO": "INFO"}
TEST_PATH_RE = re.compile(r"(^|/)(tests?|testing|fixtures?|examples?|docs?|samples?|demos?|benchmarks?)(/|$)|"
                          r"(^|/)(test_[^/]*|[^/]*_test)\.(c|cc|cpp|cxx)$", re.I)


def _parse(rel_path, text):
    lang = "c" if rel_path.lower().endswith(".c") and "c" in _LANGS else "cpp"
    if lang not in _LANGS:
        lang = next(iter(_LANGS))
    if lang not in _PARSERS:
        _PARSERS[lang] = Parser(_LANGS[lang])
    return _PARSERS[lang].parse(text.encode("utf-8", "ignore"))


# ---------------------------------------------------------------------------
# Rules: id -> (name, severity if confirmed/certain, severity if potential, description, recommendation, CWE)
# ---------------------------------------------------------------------------
RULES = {
    "AST-C-001": ("Command execution with untrusted data", "CRITICAL", "HIGH",
                  "A system command ({sink}) receives a value that comes from external input.",
                  "Avoid system()/popen(): use execv with separate arguments and validate the input against an allowlist of permitted values.", "CWE-78"),
    "AST-C-002": ("Externally controlled format string", "HIGH", "MEDIUM",
                  "{sink}() receives a non-constant value as its format string: whoever controls it can read or write memory.",
                  "Always use a constant format string: printf(\"%s\", text) instead of printf(text).", "CWE-134"),
    "AST-C-003": ("Unbounded string copy (buffer overflow)", "HIGH", "MEDIUM",
                  "{sink}() copies without checking the size of the destination.",
                  "Use snprintf/strlcpy (or std::string) and check the length before copying.", "CWE-120"),
    "AST-C-004": ("gets() is unsafe", "CRITICAL", "CRITICAL",
                  "gets() cannot limit how many characters it reads: it is always a potential buffer overflow (removed from the C11 standard).",
                  "Replace it with fgets(buf, sizeof buf, stdin).", "CWE-242"),
    "AST-C-005": ("scanf with %s and no width", "HIGH", "HIGH",
                  "{sink}() reads a string with no length limit in the format.",
                  "Specify a width (e.g. \"%63s\" for a 64-byte buffer) or use fgets.", "CWE-120"),
    "AST-C-006": ("Externally controlled copy size", "HIGH", "MEDIUM",
                  "{sink}() uses a value coming from external input as its size and it does not appear to be compared with the buffer capacity.",
                  "Compare the size with that of the destination buffer before copying or reading.", "CWE-787"),
    "AST-C-007": ("Allocation with an externally controlled size", "MEDIUM", "LOW",
                  "{sink}() allocates memory based on a value coming from external input, without an upper bound.",
                  "Set a reasonable maximum and check for overflow in size additions and multiplications.", "CWE-789"),
    "AST-C-008": ("File path chosen by external input (path traversal)", "HIGH", "MEDIUM",
                  "{sink} opens or modifies a file whose path comes from external input.",
                  "Normalize the path (realpath) and verify that it stays inside the permitted directory; reject '..' and absolute paths.", "CWE-22"),
    "AST-C-009": ("Weak cryptographic algorithm", "MEDIUM", "MEDIUM",
                  "{sink} uses an algorithm that is considered broken or too weak.",
                  "Use SHA-256/SHA-3 for hashing and AES-GCM for encryption; for passwords use argon2, bcrypt or scrypt.", "CWE-327"),
    "AST-C-010": ("TLS certificate verification disabled", "HIGH", "HIGH",
                  "{sink}: the connection no longer verifies the identity of the remote party.",
                  "Keep certificate and hostname verification enabled.", "CWE-295"),
    "AST-C-011": ("Insecure temporary file", "MEDIUM", "MEDIUM",
                  "{sink}() generates a predictable name: another user can create the file first and have data written to it.",
                  "Use mkstemp() (or std::filesystem with a random name).", "CWE-377"),
    "AST-C-012": ("Insecure random numbers for sensitive data", "MEDIUM", "MEDIUM",
                  "A value that looks like a secret ('{name}') is generated with {sink}(), which is predictable.",
                  "Use getrandom(), RAND_bytes() or std::random_device.", "CWE-338"),
    "AST-C-013": ("Use of already-freed memory", "HIGH", "HIGH",
                  "{what}",
                  "After free()/delete, set the pointer to NULL and do not use it again.", "CWE-416"),
    "AST-C-016": ("Non-reentrant function (strtok)", "LOW", "LOW",
                  "{sink}() uses shared internal state: it is not thread-safe and it modifies the string it receives.",
                  "Use strtok_r (or strsep) instead of strtok.", "CWE-676"),
    "AST-C-015": ("Copy into a buffer whose size is externally controlled", "HIGH", "MEDIUM",
                  "{sink}() copies a fixed number of bytes into a buffer created with a size that comes from external input "
                  "and that does not appear to be compared with the amount copied: if it is smaller, the copy writes past the end of the buffer.",
                  "Before copying, verify that the buffer size is at least the amount copied (and that the size computation cannot overflow).", "CWE-122"),
    "AST-C-014": ("Overly permissive file permissions", "MEDIUM", "MEDIUM",
                  "{sink}() sets permissions that allow anyone to write ({mode}).",
                  "Use the minimum permissions required, for example 0600 or 0644.", "CWE-732"),
}

# --- sources, sinks, special functions ----------------------------------------------------------------
NUM_FUNCS = {"atoi", "atol", "atoll", "atof", "strtol", "strtoul", "strtoll", "strtoull", "strtod", "strtof",
             "stoi", "stol", "stoul", "stoll", "stoull", "stod", "stof", "to_string"}
BOUND_FUNCS = {"min", "MIN", "clamp", "std::min", "strnlen_s"}
CONST_FUNCS = {"_", "gettext", "N_", "tr", "QT_TR_NOOP", "L", "TEXT", "_T", "dgettext"}
TAINT_RET = {"getenv", "secure_getenv", "getpass", "readline", "gets", "getlogin"}
STDIN_FUNCS = {"fgets", "fread", "fgetc", "getc", "fscanf"}
FD_READ = {"read": 1, "recv": 1, "recvfrom": 1, "pread": 1, "recvmsg": 1}
CMD_FUNCS = {"system": [0], "popen": [0], "_popen": [0], "WinExec": [0], "ShellExecuteA": [2, 3], "ShellExecuteW": [2, 3],
             "execl": None, "execlp": None, "execle": None, "execv": None, "execvp": None, "execve": None, "execvpe": None}
FMT_FUNCS = {"printf": 0, "fprintf": 1, "sprintf": 1, "snprintf": 2, "dprintf": 1, "syslog": 1, "vprintf": 0, "vfprintf": 1,
             "vsprintf": 1, "vsnprintf": 2, "wprintf": 0, "fwprintf": 1, "err": 1, "errx": 1, "warn": 0, "warnx": 0}
COPY_FUNCS = {"strcpy": 1, "strcat": 1, "wcscpy": 1, "wcscat": 1, "stpcpy": 1, "lstrcpy": 1, "lstrcpyA": 1, "lstrcat": 1}
SIZE_SINKS = {"memcpy": 2, "memmove": 2, "strncpy": 2, "strncat": 2, "memset": 2, "bcopy": 2, "read": 2, "recv": 2,
              "recvfrom": 2, "pread": 3, "wmemcpy": 2, "CopyMemory": 2}
ALLOC_FUNCS = {"malloc": 0, "realloc": 1, "alloca": 0, "aligned_alloc": 1, "valloc": 0, "_alloca": 0}
PATH_FUNCS = {"fopen": 0, "open": 0, "freopen": 0, "creat": 0, "access": 0, "stat": 0, "lstat": 0, "unlink": 0, "remove": 0,
              "rename": 0, "chdir": 0, "mkdir": 0, "rmdir": 0, "opendir": 0, "readlink": 0, "truncate": 0, "symlink": 1,
              "fopen_s": 1, "_wfopen": 0, "CreateFileA": 0, "CreateFileW": 0, "chown": 0, "realpath_": 0}
WEAK_CRYPTO = re.compile(r"^(MD2|MD4|MD5|MD5_Init|MD5_Update|MD5_Final|SHA1|SHA1_Init|SHA1_Update|SHA1_Final|DES_\w+|RC2_\w+|RC4|RC4_set_key|"
                         r"BF_\w+|EVP_md2|EVP_md4|EVP_md5|EVP_sha1|EVP_des_\w+|EVP_rc4\w*|EVP_rc2\w*|EVP_bf_\w+|CC_MD5\w*|CC_SHA1\w*|"
                         r"mbedtls_md5\w*|mbedtls_sha1\w*|mbedtls_des\w*|crypt)$")
TMP_FUNCS = {"tmpnam", "tempnam", "mktemp", "tmpnam_r"}
RAND_FUNCS = {"rand", "random", "rand_r", "lrand48", "drand48", "mrand48"}
SENSITIVE_NAME = re.compile(r"(token|secret|passw|pwd|nonce|salt|session|csrf|otp|apikey|api_key|\bkey\b|_key|key_|\biv\b|_iv)", re.I)
SCAN_SPEC = re.compile(r"%(\*)?(\d+)?(?:hh|h|ll|l|L|z|j|t)?([sS\[])")
NUMERIC_CASTS = {"int", "long", "short", "size_t", "unsigned", "ssize_t", "uint32_t", "uint64_t", "int32_t", "int64_t", "uint8_t", "uint16_t"}

# value: (level, parameters, numeric, local)
#   numeric:  the data went through atoi/strtol...: it is no longer a dangerous string, but it is still an attacker-controllable size;
#   local:    comes only from argv / environment variables / keyboard, i.e. from whoever already runs the program (for file paths and
#             allocation sizes of a command-line tool this is intended behavior, not a flaw).
V_CONST = (CONST, frozenset(), True, False)
V_OTHER = (OTHER, frozenset(), False, False)
V_TAINT = (TAINT, frozenset(), False, False)        # network, file descriptors: genuinely external data
V_LOCAL = (TAINT, frozenset(), False, True)         # argv, getenv, stdin, cin


def _join(vals):
    vals = [v for v in vals if v is not None]
    if not vals:
        return V_CONST
    lvl = max(v[0] for v in vals)
    params = frozenset().union(*[v[1] for v in vals])
    live = [v for v in vals if v[0] >= OTHER or v[1]]
    num = all(v[2] for v in live) if live else True
    tainted = [v for v in vals if v[0] == TAINT]
    return (lvl, params, num, bool(tainted) and all(v[3] for v in tainted))


def _t(n):
    return n.text.decode("utf-8", "ignore") if n is not None else ""


def _line(n):
    return n.start_point[0] + 1


def _base_name(n):
    """Name of the 'root' variable of an expression (buf[i], a.b, *p, &x, (T)x...)."""
    while n is not None:
        t = n.type
        if t in ("identifier", "field_identifier"):
            return _t(n)
        if t in ("subscript_expression", "field_expression", "pointer_expression", "parenthesized_expression",
                 "unary_expression", "cast_expression", "update_expression", "reference_expression"):
            n = n.child_by_field_name("argument") or n.child_by_field_name("value") or (n.named_children[-1] if n.named_children else None)
            continue
        if t == "qualified_identifier":
            return _t(n.child_by_field_name("name"))
        if t == "binary_expression":              # buf + 1, p - n: the base is the left operand
            n = n.child_by_field_name("left")
            continue
        if t == "call_expression":                # getshrstr(ts), c_str(): the base is the first argument
            a = n.child_by_field_name("arguments")
            n = a.named_children[0] if a is not None and a.named_children else None
            continue
        return None
    return None


def _lkey(n):
    """Field-sensitive assignment key: 'a.b' for a->b, otherwise the root variable."""
    while n is not None and n.type in ("subscript_expression", "parenthesized_expression", "cast_expression"):
        n = n.child_by_field_name("argument") or n.child_by_field_name("value") or (n.named_children[-1] if n.named_children else None)
    if n is not None and n.type == "field_expression":
        return re.sub(r"\s+", "", _t(n)).replace("->", ".")
    return _base_name(n)


def _decl_name(d):
    while d is not None and d.type not in ("identifier", "field_identifier"):
        nxt = d.child_by_field_name("declarator")
        if nxt is None:
            nxt = d.named_children[0] if d.named_children else None
        d = nxt
    return _t(d) if d is not None else None


def _callee(call):
    """(normalized name, is_method, object) of a call_expression."""
    fn = call.child_by_field_name("function")
    if fn is None:
        return "", False, None
    t = fn.type
    if t == "identifier":
        return _t(fn), False, None
    if t == "qualified_identifier":
        return _t(fn.child_by_field_name("name")).split("::")[-1], False, None
    if t == "field_expression":
        return _t(fn.child_by_field_name("field")), True, fn.child_by_field_name("argument")
    if t == "template_function":
        nm = fn.child_by_field_name("name")
        return _t(nm).split("::")[-1], False, None
    return _t(fn), False, None


def _args(call):
    a = call.child_by_field_name("arguments")
    return [c for c in a.named_children if c.type != "comment"] if a is not None else []


def _literal_text(n):
    if n is None:
        return None
    if n.type == "string_literal":
        return _t(n)[1:-1] if _t(n).startswith('"') else _t(n)
    if n.type == "concatenated_string":
        parts = [_literal_text(c) for c in n.named_children if c.type == "string_literal"]
        return "".join(p or "" for p in parts)
    if n.type == "parenthesized_expression" and n.named_children:
        return _literal_text(n.named_children[0])
    return None


def _octal_mode(n):
    t = _t(n)
    if n.type == "number_literal" and re.fullmatch(r"0[0-7]{3,4}", t):
        return t
    return None


def _walk(n):
    stack = [n]
    while stack:
        x = stack.pop()
        yield x
        stack.extend(reversed(x.children))


class Project:
    """State shared across files: known functions, summaries and collected findings."""

    def __init__(self):
        self.funcs = {}          # function name -> key (rel, name) of its first definition
        self.defs = {}           # function name -> set of files that define it
        self.summary = {}        # key -> list of (parameters, sid, rel, line, sink)
        self.calls = []          # (caller_key, callee_name, [values], line)
        self.findings = {}       # rel -> list
        self.seen = {}           # (rel, sid, line) -> finding
        self.lines = {}          # rel -> source lines
        self.is_test = {}

    def resolve(self, name, rel):
        """Key of the called function, only if unambiguous (same file, or a single definition in the project)."""
        files = self.defs.get(name)
        if not files:
            return None
        if rel in files:
            return (rel, name)
        return (next(iter(files)), name) if len(files) == 1 else None

    def add(self, rel, sid, conf, line, name_ctx=None, via=None, **fmt):
        key = (rel, sid, line)
        name, sev_c, sev_u, desc, rec, cwe = RULES[sid]
        sev = sev_c if conf in ("confirmed", "fixed") else sev_u
        prev = self.seen.get(key)
        if prev is not None:
            if conf == "confirmed" and prev["confidence"] != "confirmed":
                prev.update({"severity": sev_c, "confidence": "confirmed", "confidence_label": CONF_LABEL["confirmed"]})
            return
        desc = desc.format(**{"sink": fmt.get("sink", "the function"), "name": fmt.get("name", ""),
                              "mode": fmt.get("mode", ""), "what": fmt.get("what", "")})
        if via:
            desc += f" (the data flows through the function '{via}')"
        if self.is_test.get(rel):
            sev = SEV_DOWN.get(sev, sev)
            desc += " [Test code: severity reduced.]"
        lines = self.lines.get(rel, [])
        snip = lines[line - 1].strip() if 0 < line <= len(lines) else ""
        f = {"id": sid, "name": name, "severity": sev, "confidence": "confirmed" if conf == "fixed" else conf,
             "confidence_label": CONF_LABEL[conf], "file": rel, "line": line,
             "snippet": snip[:160] + (" …" if len(snip) > 160 else ""), "description": desc,
             "recommendation": rec, "engine": "c_ast", "cwe": cwe}
        self.seen[key] = f
        self.findings.setdefault(rel, []).append(f)


class FuncAnalyzer:
    def __init__(self, proj, rel, fnode, name, params, key):
        self.p, self.rel, self.fnode, self.name, self.key = proj, rel, fnode, name, key
        self.env = {}
        self.checked = set()
        self.arrsize = {}
        self.alloc = {}          # pointer -> names used to size it (malloc(n+1), ensure(buf, n))
        self.allocval = {}       # pointer -> value (data flow) of the size it was created with
        self.depth = 0
        for i, pn in enumerate(params):
            if pn:
                self.env[pn] = V_LOCAL if (name in ("main", "wmain", "_tmain") and i == 1) else (PARAM, frozenset([i]), False, False)

    # ---- expression evaluation -------------------------------------------------------------
    def ev(self, n):
        if n is None:
            return V_CONST
        t = n.type
        if t in ("number_literal", "string_literal", "char_literal", "concatenated_string", "true", "false", "null",
                 "nullptr", "sizeof_expression", "raw_string_literal", "alignof_expression"):
            return V_CONST
        if t == "identifier":
            v = self.env.get(_t(n))
            if v is not None:
                return v
            return V_CONST if _t(n).isupper() or _t(n) in ("NULL", "stdin", "stdout", "stderr") else V_OTHER
        if t in ("parenthesized_expression", "unary_expression", "update_expression", "pointer_expression", "reference_expression"):
            return self.ev(n.child_by_field_name("argument")) if n.child_by_field_name("argument") is not None else \
                _join([self.ev(c) for c in n.named_children])
        if t == "cast_expression":
            return self.ev(n.child_by_field_name("value"))
        if t == "field_expression":
            key = re.sub(r"\s+", "", _t(n)).replace("->", ".")
            if key in self.env:
                return self.env[key]
            v = self.ev(n.child_by_field_name("argument"))
            # a field of a pointer parameter (state->len) is not the parameter itself: the caller controls the
            # pointer, not necessarily the contents of its fields
            return V_OTHER if v[0] == PARAM else v
        if t == "subscript_expression":
            return self.ev(n.child_by_field_name("argument"))
        if t == "binary_expression":
            op = _t(n.child_by_field_name("operator"))
            if op in ("==", "!=", "<", ">", "<=", ">=", "&&", "||"):
                return V_CONST
            return _join([self.ev(n.child_by_field_name("left")), self.ev(n.child_by_field_name("right"))])
        if t == "conditional_expression":
            cond = n.child_by_field_name("condition")
            br = [n.child_by_field_name("consequence"), n.child_by_field_name("alternative")]
            if cond is not None and any(x.type == "binary_expression" and _t(x.child_by_field_name("operator")) in ("<", ">", "<=", ">=")
                                        for x in _walk(cond)):
                cn = {_t(x) for x in _walk(cond) if x.type in ("identifier", "field_expression")}
                bn = {_t(x) for b in br if b is not None for x in _walk(b) if x.type in ("identifier", "field_expression")}
                if cn & bn:
                    return V_CONST                      # a > b ? b : a  (a min/max): the size is bounded
            return _join([self.ev(b) for b in br])
        if t in ("initializer_list", "argument_list"):
            return _join([self.ev(c) for c in n.named_children])
        if t == "comma_expression":
            return self.ev(n.child_by_field_name("right"))
        if t == "call_expression":
            return self.ev_call(n)
        if t == "assignment_expression":
            return self.ev(n.child_by_field_name("right"))
        if t in ("qualified_identifier", "template_function"):
            return V_OTHER
        return V_OTHER

    def ev_call(self, n):
        name, is_method, obj = _callee(n)
        args = _args(n)
        if name in CONST_FUNCS:
            return V_CONST
        if name in TAINT_RET and not is_method:
            return V_LOCAL
        if name in BOUND_FUNCS:
            return V_CONST
        vals = [self.ev(a) for a in args]
        if is_method:
            vals.append(self.ev(obj))
        if name in NUM_FUNCS:
            j = _join(vals)
            return (j[0], j[1], True, j[3]) if j[0] >= OTHER or j[1] else V_CONST
        if any(v[0] == TAINT for v in vals) or any(v[1] for v in vals):
            return _join(vals)
        return V_OTHER if (is_method or name not in self.p.funcs) else V_OTHER

    # ---- environment updates --------------------------------------------------------------
    def setv(self, name, v, overwrite):
        if not name:
            return
        if overwrite and self.depth == 0:
            self.env[name] = v
        else:
            old = self.env.get(name)
            self.env[name] = _join([old, v]) if old is not None else v

    # ---- traversal ---------------------------------------------------------------------------------
    def visit(self, n):
        t = n.type
        if t == "compound_statement":
            self.check_free_sequence(n)
        deep = t in ("if_statement", "for_statement", "while_statement", "do_statement", "switch_statement",
                     "for_range_loop", "try_statement", "case_statement")
        if t in ("if_statement", "while_statement", "do_statement", "for_statement", "switch_statement"):
            self.collect_checks(n.child_by_field_name("condition") or n)
        if deep:
            self.depth += 1
        for c in n.children:
            self.visit(c)
        if deep:
            self.depth -= 1
        if t == "call_expression":
            self.on_call(n)
        elif t == "declaration":
            self.on_declaration(n)
        elif t == "assignment_expression":
            self.on_assign(n)
        elif t == "binary_expression" and _t(n.child_by_field_name("operator")) == ">>":
            self.on_stream_in(n)
        elif t == "new_expression":
            self.on_new(n)

    def collect_checks(self, cond):
        if cond is None:
            return
        for x in _walk(cond):
            if x.type == "binary_expression" and _t(x.child_by_field_name("operator")) in ("<", ">", "<=", ">="):
                for y in _walk(x):
                    if y.type == "identifier":
                        self.checked.add(_t(y))
            elif x.type == "call_expression":
                nm, _, _ = _callee(x)
                if nm in ("strlen", "strnlen", "size", "length", "min", "MIN"):
                    for y in _walk(x):
                        if y.type == "identifier":
                            self.checked.add(_t(y))
            elif x.type == "sizeof_expression":
                for y in _walk(x):
                    if y.type == "identifier":
                        self.checked.add(_t(y))

    def note_alloc(self, name, value):
        v = value
        while v is not None and v.type in ("cast_expression", "parenthesized_expression"):
            v = v.child_by_field_name("value") or (v.named_children[-1] if v.named_children else None)
        if name and v is not None and v.type in ("call_expression", "new_expression"):
            self.alloc[name] = {_t(x) for x in _walk(v) if x.type == "identifier"}
            if v.type == "call_expression":
                cn, m, _ = _callee(v)
                if cn in ("malloc", "calloc", "realloc", "alloca", "g_malloc", "xmalloc", "OPENSSL_malloc") and not m:
                    self.allocval[name] = _join([self.ev(a) for a in _args(v)])

    def on_declaration(self, n):
        ty = _t(n.child_by_field_name("type"))
        for d in n.children_by_field_name("declarator"):
            if d.type == "init_declarator":
                nm = _decl_name(d.child_by_field_name("declarator"))
                val = d.child_by_field_name("value")
                if val is not None and val.type == "argument_list":     # std::string s(x);  std::ifstream f(path);
                    a = [c for c in val.named_children]
                    if re.search(r"(i|o)?fstream", ty) and a:
                        self.hit_path(self.ev(a[0]), n, "std::" + re.search(r"(i|o)?fstream", ty).group(0))
                    self.setv(nm, _join([self.ev(c) for c in a]), True)
                else:
                    v = self.ev(val)
                    self.setv(nm, v, True)
                    self.note_alloc(nm, val)
                    self.check_rand_decl(nm, val, n)
                if d.child_by_field_name("declarator") is not None and d.child_by_field_name("declarator").type == "array_declarator":
                    self.note_array(d.child_by_field_name("declarator"))
            elif d.type == "function_declarator" and self.looks_like_ctor(d):
                # "std::ifstream f(p);" / "std::string s(x);" : the grammar parses this as a function declaration
                nm = _decl_name(d.child_by_field_name("declarator"))
                pl = d.child_by_field_name("parameters")
                vals = []
                for p in pl.named_children:
                    leaf = p.named_children[0] if p.named_children else None
                    vals.append(self.ev(leaf) if leaf is not None and leaf.type == "type_identifier" and False else
                                self.env.get(_t(leaf), V_CONST if _t(leaf).isupper() else V_OTHER) if leaf is not None else V_CONST)
                m = re.search(r"(i|o)?fstream", ty)
                if m and vals:
                    self.hit_path(vals[0], n, "std::" + m.group(0))
                self.setv(nm, _join(vals), True)
            else:
                nm = _decl_name(d)
                if d.type == "array_declarator":
                    self.note_array(d)
                if nm:
                    self.env[nm] = V_OTHER if nm not in self.env or self.depth == 0 else self.env[nm]

    def looks_like_ctor(self, d):
        pl = d.child_by_field_name("parameters")
        if pl is None or not pl.named_children:
            return False
        return all(p.type == "parameter_declaration" and p.child_by_field_name("declarator") is None
                   and len(p.named_children) == 1 and p.named_children[0].type == "type_identifier" for p in pl.named_children)

    def note_array(self, d):
        sz = d.child_by_field_name("size")
        nm = _decl_name(d)
        if nm and sz is not None and sz.type == "number_literal":
            try:
                self.arrsize[nm] = int(_t(sz).rstrip("uUlL"), 0)
            except ValueError:
                pass

    def on_assign(self, n):
        left, right = n.child_by_field_name("left"), n.child_by_field_name("right")
        op = _t(n.child_by_field_name("operator"))
        nm = _lkey(left)
        v = self.ev(right)
        if op != "=":
            v = _join([self.ev(left), v])
            self.setv(nm, v, False)
        else:
            self.setv(nm, v, left is not None and left.type in ("identifier", "field_expression"))
        if left is not None and left.type == "identifier":
            self.check_rand_decl(nm, right, n)
            if op == "=":
                self.note_alloc(nm, right)

    def on_stream_in(self, n):
        leaf = n
        while leaf.type == "binary_expression" and leaf.child_by_field_name("left") is not None:
            leaf = leaf.child_by_field_name("left")
        if re.search(r"(^|::)cin$", _t(leaf)) or _t(leaf) in ("cin", "std::cin"):
            self.setv(_base_name(n.child_by_field_name("right")), V_LOCAL, False)

    def on_new(self, n):
        d = n.child_by_field_name("declarator")
        if d is not None and d.type == "new_declarator":
            for x in d.named_children:
                if x.type != "type_identifier" and x.type != "primitive_type":
                    self.hit_alloc(self.ev(x), n, "new[]")

    # ---- sink checkpoints ----------------------------------------------------------------
    def string_hit(self, v, sid, node, **kw):
        """'String' sink: purely numeric values are not dangerous."""
        if v[0] == TAINT and not v[2]:
            self.p.add(self.rel, sid, "confirmed", _line(node), **kw)
            return True
        if v[1]:
            for pi in v[1]:
                self.p.summary.setdefault(self.key, []).append((frozenset([pi]), sid, self.rel, _line(node), kw))
        return False

    def size_hit(self, v, expr, sid, node, dest=None, **kw):
        names = {_t(x) for x in _walk(expr) if x.type == "identifier"} if expr is not None else set()
        if names & self.checked:
            return
        if dest and names & self.alloc.get(dest, set()):
            return                      # the buffer was created with this very size
        if v[0] == TAINT:
            self.p.add(self.rel, sid, "confirmed", _line(node), **kw)
        elif v[1]:
            for pi in v[1]:
                self.p.summary.setdefault(self.key, []).append((frozenset([pi]), sid, self.rel, _line(node), kw))

    def hit_path(self, v, node, sink):
        if v[0] == TAINT and v[3]:
            return                      # path chosen by whoever launches the program: intended behavior
        self.string_hit(v, "AST-C-008", node, sink=sink)

    def hit_alloc(self, v, node, sink):
        if v[0] == TAINT and not v[3]:
            names = {_t(x) for x in _walk(node) if x.type == "identifier"}
            if not (names & self.checked):
                self.p.add(self.rel, "AST-C-007", "confirmed", _line(node), sink=sink)

    def check_rand_decl(self, name, value, node):
        if not name or value is None or not SENSITIVE_NAME.search(name):
            return
        for x in _walk(value):
            if x.type == "call_expression":
                nm, m, _ = _callee(x)
                if nm in RAND_FUNCS and not m:
                    self.p.add(self.rel, "AST-C-012", "fixed", _line(node), sink=nm, name=name)
                    return

    def on_call(self, n):
        name, is_method, obj = _callee(n)
        args = _args(n)
        line = _line(n)
        rel = self.rel
        vals = [self.ev(a) for a in args]

        # call to a project function: used for cross-function/cross-file summaries
        if not is_method and name in self.p.funcs:
            ck = self.p.resolve(name, self.rel)
            if ck is not None:
                self.p.calls.append((self.key, ck, vals, line))

        # --- sources that write into a buffer
        if not is_method:
            if name == "fgets" and len(args) >= 3:
                self.setv(_base_name(args[0]), V_LOCAL if _t(args[2]) == "stdin" else V_TAINT, False)
            elif name == "gets" and args:
                self.setv(_base_name(args[0]), V_LOCAL, False)
            elif name in FD_READ and len(args) >= 2:
                is_stdin = name == "read" and _t(args[0]).strip() == "0"
                self.setv(_base_name(args[1]), V_LOCAL if is_stdin else V_TAINT, False)
            elif name == "fread" and args:
                self.setv(_base_name(args[0]), V_LOCAL if (len(args) >= 4 and _t(args[3]) == "stdin") else V_TAINT, False)
            elif name == "getline" and len(args) >= 3:
                self.setv(_base_name(args[0]), V_LOCAL if _t(args[2]) == "stdin" else V_TAINT, False)
            elif name == "getline" and len(args) == 2 and "cin" in _t(args[0]):
                self.setv(_base_name(args[1]), V_TAINT, False)
            elif name in ("scanf", "vscanf") and len(args) >= 2:
                for a in args[1:]:
                    self.setv(_base_name(a), V_TAINT, False)
            elif name == "fscanf" and len(args) >= 3 and _t(args[0]) == "stdin":
                for a in args[2:]:
                    self.setv(_base_name(a), V_TAINT, False)
            elif name == "sscanf" and len(args) >= 3 and vals[0][0] == TAINT:
                for a in args[2:]:
                    self.setv(_base_name(a), V_TAINT, False)
            # propagation through copies / formatting
            elif name in ("strcpy", "strncpy", "strcat", "strncat", "memcpy", "memmove", "stpcpy", "wcscpy") and len(args) >= 2:
                self.setv(_lkey(args[0]), vals[1], name in ("strcpy", "strncpy", "memcpy", "memmove", "stpcpy") and args[0].type != "field_expression")
            elif name in ("sprintf", "snprintf") and len(args) >= 3:
                start = 2 if name == "sprintf" else 3
                self.setv(_base_name(args[0]), _join(vals[start - 1:]) if len(vals) >= start else V_OTHER, True)

        if is_method:
            # std::string::append / push_back / assign propagate the data into the object
            if name in ("append", "assign", "push_back", "insert", "replace", "operator+=") and obj is not None:
                self.setv(_base_name(obj), _join(vals), False)
            return

        # --- AST-C-016 strtok
        if name == "strtok":
            self.p.add(rel, "AST-C-016", "fixed", line, sink=name)
        # --- AST-C-004 gets
        if name == "gets":
            self.p.add(rel, "AST-C-004", "fixed", line, sink="gets")

        # --- AST-C-001 command injection
        if name in CMD_FUNCS:
            idxs = CMD_FUNCS[name] if CMD_FUNCS[name] is not None else range(len(args))
            for i in idxs:
                if i < len(vals):
                    self.string_hit(vals[i], "AST-C-001", n, sink=name + "()")

        # --- AST-C-002 format string
        if name in FMT_FUNCS:
            i = FMT_FUNCS[name]
            if i < len(args):
                fv, fa = vals[i], args[i]
                if _literal_text(fa) is None and fv[0] >= OTHER and fa.type != "string_literal":
                    if fv[0] == TAINT and not fv[2]:
                        self.p.add(rel, "AST-C-002", "confirmed", line, sink=name)
                    elif fv[1]:
                        for pi in fv[1]:
                            self.p.summary.setdefault(self.key, []).append((frozenset([pi]), "AST-C-002", rel, line, {"sink": name}))
                    elif fa.type in ("identifier", "call_expression", "field_expression", "subscript_expression"):
                        self.p.add(rel, "AST-C-002", "unknown", line, sink=name)

        # --- AST-C-003 / AST-C-005 unbounded copies and scanf %s
        if name in COPY_FUNCS and len(args) >= 2:
            self.on_unbounded_copy(n, name, args, vals)
        if name in ("sprintf", "vsprintf") and len(args) >= 2:
            self.on_sprintf(n, name, args, vals)
        if name in ("scanf", "fscanf", "sscanf", "vscanf"):
            fi = 0 if name in ("scanf", "vscanf") else 1
            if fi < len(args):
                lit = _literal_text(args[fi])
                if lit is not None:
                    for m in SCAN_SPEC.finditer(lit):
                        if not m.group(1) and not m.group(2):
                            self.p.add(rel, "AST-C-005", "fixed", line, sink=name)
                            break

        # --- AST-C-006 externally controlled size
        if name in SIZE_SINKS and SIZE_SINKS[name] < len(args):
            i = SIZE_SINKS[name]
            self.size_hit(vals[i], args[i], "AST-C-006", n, dest=_base_name(args[0]), sink=name + "()")
        # --- AST-C-015 fixed-size copy into a buffer with an externally chosen size
        if name in ("memcpy", "memmove", "memset", "bcopy", "strncpy") and len(args) >= 3:
            dest = _base_name(args[0])
            av = self.allocval.get(dest)
            if av and av[0] == TAINT and not av[3] and vals[2][0] == CONST and not (self.alloc.get(dest, set()) & self.checked):
                self.p.add(rel, "AST-C-015", "confirmed", line, sink=name + "()")
        # --- AST-C-007 allocation
        if name in ALLOC_FUNCS and ALLOC_FUNCS[name] < len(args):
            self.hit_alloc(vals[ALLOC_FUNCS[name]], n, name + "()")
        if name == "calloc" and len(args) >= 2:
            self.hit_alloc(_join(vals[:2]), n, "calloc()")
        # --- AST-C-008 paths
        if name in PATH_FUNCS and PATH_FUNCS[name] < len(args):
            self.hit_path(vals[PATH_FUNCS[name]], n, name + "()")
        # --- AST-C-009 weak cryptography
        if WEAK_CRYPTO.match(name):
            self.p.add(rel, "AST-C-009", "fixed", line, sink=name + "()")
        # --- AST-C-010 TLS
        if name in ("SSL_CTX_set_verify", "SSL_set_verify") and len(args) >= 2 and "SSL_VERIFY_NONE" in _t(args[1]):
            self.p.add(rel, "AST-C-010", "fixed", line, sink=name + "(…, SSL_VERIFY_NONE)")
        if name == "curl_easy_setopt" and len(args) >= 3 and _t(args[1]) in ("CURLOPT_SSL_VERIFYPEER", "CURLOPT_SSL_VERIFYHOST") \
                and re.fullmatch(r"0[lL]?|false|FALSE", _t(args[2]).strip()):
            self.p.add(rel, "AST-C-010", "fixed", line, sink=f"curl_easy_setopt({_t(args[1])}, 0)")
        # --- AST-C-011 temporary files
        if name in TMP_FUNCS:
            self.p.add(rel, "AST-C-011", "fixed", line, sink=name)
        # --- AST-C-014 permissions
        if name in ("chmod", "fchmod") and len(args) >= 2:
            self.perm(n, name, args[1])
        if name == "umask" and args and _octal_mode(args[0]) in ("000", "0000"):
            self.p.add(rel, "AST-C-014", "fixed", line, sink="umask", mode="umask 0")

    def perm(self, n, name, arg):
        m = _octal_mode(arg)
        if m and int(m[-1]) & 2:
            self.p.add(self.rel, "AST-C-014", "fixed", _line(n), sink=name, mode=m)

    def on_unbounded_copy(self, n, name, args, vals):
        si = COPY_FUNCS[name]
        src, sv = args[si], vals[si]
        lit = _literal_text(src)
        dest = _base_name(args[0])
        if lit is not None:
            size = self.arrsize.get(dest)
            if size is not None and len(lit.replace("\\", "")) + (0 if name in ("strcat", "wcscat", "lstrcat") else 1) > size and name in ("strcpy", "wcscpy", "lstrcpy", "stpcpy"):
                self.p.add(self.rel, "AST-C-003", "fixed", _line(n), sink=name)
            return
        sname = _base_name(src)
        if sname and sname in self.checked:
            return
        if sv[0] == TAINT and not sv[2]:
            self.p.add(self.rel, "AST-C-003", "confirmed", _line(n), sink=name)
        elif sv[1]:
            for pi in sv[1]:
                self.p.summary.setdefault(self.key, []).append((frozenset([pi]), "AST-C-003", self.rel, _line(n), {"sink": name}))
            self.p.add(self.rel, "AST-C-003", "unknown", _line(n), sink=name)
        elif sv[0] >= OTHER:
            self.p.add(self.rel, "AST-C-003", "unknown", _line(n), sink=name)

    def on_sprintf(self, n, name, args, vals):
        fi = 1
        if fi >= len(args):
            return
        lit = _literal_text(args[fi])
        rest = vals[fi + 1:]
        if lit is not None and not re.search(r"%(?:[\d.*-]*)(?:hh|h|ll|l|L|z|j|t)?[sS\[]", lit):
            return                                    # numeric formats only: predictable length
        if any(v[0] == TAINT and not v[2] for v in rest):
            self.p.add(self.rel, "AST-C-003", "confirmed", _line(n), sink=name)
        elif lit is None or any(v[0] >= OTHER or v[1] for v in rest):
            sname = _base_name(args[fi + 1]) if len(args) > fi + 1 else None
            if not (sname and sname in self.checked):
                self.p.add(self.rel, "AST-C-003", "unknown", _line(n), sink=name)

    # ---- use-after-free / double free (same block) ----------------------------------------------
    def check_free_sequence(self, block):
        stmts = [c for c in block.named_children if c.type != "comment"]
        for i, st in enumerate(stmts):
            var = self.freed_var(st)
            if not var:
                continue
            for later in stmts[i + 1:]:
                use = self.first_use(later, var)
                if use == "reset":
                    break
                if use:
                    if use == "free":
                        self.p.add(self.rel, "AST-C-013", "confirmed", _line(later), what=f"'{var}' is freed twice (line {_line(st)} and line {_line(later)}).")
                    else:
                        self.p.add(self.rel, "AST-C-013", "confirmed", _line(later), what=f"'{var}' is used after being freed at line {_line(st)}.")
                    # keep going: each later use is another finding, until the variable is reassigned
                if later.type in ("return_statement", "break_statement", "continue_statement", "goto_statement"):
                    break

    @staticmethod
    def _norm(n):
        return re.sub(r"\s+", "", _t(n)).replace("->", ".")

    def freed_var(self, st):
        if st.type != "expression_statement" or not st.named_children:
            return None
        e = st.named_children[0]
        if e.type == "call_expression":
            nm, m, _ = _callee(e)
            a = _args(e)
            if nm in ("free", "kfree", "g_free", "OPENSSL_free", "xfree") and not m and len(a) == 1 and a[0].type in ("identifier", "field_expression"):
                return self._norm(a[0])
        if e.type == "delete_expression":
            c = [x for x in e.named_children if x.type in ("identifier", "field_expression")]
            if len(c) == 1:
                return self._norm(c[0])
        return None

    def first_use(self, st, var):
        for x in _walk(st):
            if x.type == "assignment_expression":
                l = x.child_by_field_name("left")
                if l is not None and self._norm(l) == var:
                    return "reset"
            if x.type == "pointer_expression" and _t(x).startswith("&") and self._norm(x.child_by_field_name("argument")) == var:
                return "reset"
        if self.freed_var(st) == var:
            return "free"
        for x in _walk(st):
            if x.type == "expression_statement" and self.freed_var(x) == var:
                return "free"
        for x in _walk(st):
            if x.type in ("identifier", "field_expression"):
                key = self._norm(x)
                inside = x.parent is not None and x.parent.type == "field_expression" and x.parent.child_by_field_name("argument") is not None and x.parent.child_by_field_name("argument").id == x.id
                if inside and x.type == "identifier":
                    continue            # the name is part of a longer chain, which is evaluated as a chain
                if key == var or key.startswith(var + ".") or key.startswith(var + "["):
                    par = x.parent
                    if par is not None and (
                            (par.type == "binary_expression" and _t(par.child_by_field_name("operator")) in ("==", "!=")) or
                            (par.type == "unary_expression" and _t(par).startswith("!")) or
                            par.type in ("sizeof_expression", "condition_clause") or
                            (par.type == "parenthesized_expression" and par.parent is not None and par.parent.type in ("if_statement", "while_statement"))):
                        continue
                    return "use"
        return None


# ---------------------------------------------------------------------------
# Function discovery and orchestration
# ---------------------------------------------------------------------------
def _function_info(fd):
    decl = fd.child_by_field_name("declarator")
    while decl is not None and decl.type != "function_declarator":
        nxt = decl.child_by_field_name("declarator")
        if nxt is None:
            return None
        decl = nxt
    if decl is None:
        return None
    nm = decl.child_by_field_name("declarator")
    if nm is None:
        return None
    name = _t(nm).split("::")[-1].strip()
    params = []
    pl = decl.child_by_field_name("parameters")
    if pl is not None:
        for p in pl.named_children:
            if p.type in ("parameter_declaration", "optional_parameter_declaration"):
                params.append(_decl_name(p.child_by_field_name("declarator")))
            else:
                params.append(None)
    return name, params


def _collect_functions(root):
    out = []
    for n in _walk(root):
        if n.type == "function_definition":
            info = _function_info(n)
            body = n.child_by_field_name("body")
            if info and body is not None:
                out.append((info[0], info[1], body))
    return out


def _resolve_calls(proj):
    """Propagate summaries: when a caller passes tainted data (or one of its own parameters) to a dangerous parameter."""
    done = set()
    for _ in range(4):
        changed = False
        for caller, ckey, vals, line in proj.calls:
            callee_name = ckey[1]
            for entry in list(proj.summary.get(ckey, [])):
                params, sid, rel, sline, kw = entry
                for pi in params:
                    if pi >= len(vals):
                        continue
                    v = vals[pi]
                    string_kind = sid in ("AST-C-001", "AST-C-002", "AST-C-003", "AST-C-008")
                    if v[0] == TAINT and v[3] and sid in ("AST-C-007", "AST-C-008"):
                        continue
                    if v[0] == TAINT and (not string_kind or not v[2]):
                        key = (rel, sid, sline)
                        if key not in done:
                            done.add(key)
                            proj.add(rel, sid, "confirmed", sline, via=callee_name, **kw)
                            changed = True
                    elif v[1]:
                        new = (v[1], sid, rel, sline, kw)
                        lst = proj.summary.setdefault(caller, [])
                        if not any(e[1:] == new[1:] and e[0] == new[0] for e in lst):
                            lst.append(new)
                            changed = True
        if not changed:
            break


def analyze_c_project(sources):
    """sources: {relative_path: text}. Returns {path: [findings]}, following the data across files as well."""
    if not AVAILABLE:
        return {}
    if len(sources) > MAX_PROJECT_FILES or sum(len(t) for t in sources.values()) > MAX_PROJECT_BYTES:
        log.warning("C/C++ project is too large for cross-file analysis (%d files, %d bytes; limits: %d files, %d bytes). "
                    "Falling back to per-file analysis: data flowing between files will not be tracked.",
                    len(sources), sum(len(t) for t in sources.values()), MAX_PROJECT_FILES, MAX_PROJECT_BYTES)
        return {p: _run({p: t}).get(p, []) for p, t in sources.items()}   # too large: analyze file by file
    return _run(sources)


def _run(sources):
    proj = Project()
    parsed = {}
    for rel, text in sources.items():
        try:
            tree = _parse(rel, text)
        except Exception as exc:
            log.error("Could not parse C/C++ file '%s' (%s: %s). The file was skipped by the AST engine; "
                      "check that it is valid source text and that the tree-sitter grammars are installed correctly.",
                      rel, type(exc).__name__, exc)
            continue
        proj.lines[rel] = text.splitlines()
        proj.is_test[rel] = bool(TEST_PATH_RE.search(rel.replace("\\", "/")))
        funcs = _collect_functions(tree.root_node)
        parsed[rel] = (tree, funcs)
        for name, _, _ in funcs:
            proj.funcs.setdefault(name, (rel, name))
            proj.defs.setdefault(name, set()).add(rel)
    for rel, (tree, funcs) in parsed.items():
        for name, params, body in funcs:
            fa = FuncAnalyzer(proj, rel, body, name, params, (rel, name))
            try:
                fa.visit(body)
            except RecursionError:
                log.warning("Function '%s' in '%s' is too deeply nested for the C/C++ analyzer (recursion limit reached); "
                            "analysis of this function was aborted and its findings may be incomplete.", name, rel)
            except Exception as exc:
                log.error("Unexpected error while analyzing function '%s' in '%s' (%s: %s). "
                          "Analysis of this function was aborted; findings for it may be incomplete. "
                          "Please report this together with the offending source file.",
                          name, rel, type(exc).__name__, exc)
    try:
        _resolve_calls(proj)
    except Exception as exc:
        log.error("Cross-function summary propagation failed (%s: %s). "
                  "Findings that depend on data flowing between functions or files may be missing.",
                  type(exc).__name__, exc)
    out = {rel: proj.findings.get(rel, []) for rel in sources}
    for fl in out.values():
        fl.sort(key=lambda f: f["line"])
    return out


def analyze_c_source(rel_path, text):
    if not AVAILABLE or not rel_path.lower().endswith(SUPPORTED):
        return []
    return _run({rel_path: text}).get(rel_path, [])
