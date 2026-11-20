# -*- coding: utf-8 -*-
"""
rust_engine.py
===============
Security engine for Rust (.rs) built on a real parser (tree-sitter-rust) with data-flow analysis
across the functions and files of the project (like ast_engine.py for Python and js_engine.py for JS/TS), covering the
specifics of Rust:

  - macros: format!/println!/vec!/write!... are re-analyzed as expressions (including inline
    "{name}" arguments); sqlx::query!(...) is checked at compile time and therefore considered safe;
  - types: a typed extractor parameter (Path<u32>, Query<Struct{id: u32}>) with only numeric /
    boolean / enum fields is not dangerous; a String field is (the project's structs are read);
  - builder chains: Command::new("sh").arg("-c").arg(x), Cookie::build(..).secure(false);
  - "sensitive" data (passwords, tokens, keys...) and "constant" values that reach cryptographic
    functions or logs, in addition to untrusted data (args, env, stdin, HTTP, web extractors);
  - per-function summaries shared across modules (use crate::..., super::, self::).

Vulnerability classes covered: command injection, SQL injection, path traversal, SSRF and non-https URLs, XSS, open
redirect, regex injection, log injection, uncontrolled allocation (DoS), disabled TLS, weak ciphers and hashes
(also on sensitive data), hardcoded keys/IVs/salts, cookies without flags, plaintext logging and database storage of
sensitive data, use of unsafe APIs with untrusted sizes/indexes.

Known limitations: there is no type checker (methods on unknown types stay opaque), no call graph of the
frameworks (they are recognized by name/attribute), no memory analysis (use-after-free/lifetimes), and
it does not execute the code. If tree-sitter-rust is missing, only the quality/pattern engine stays active.
"""

import logging
import os
import re

from ast_engine import CONF_LABEL, CONST, OTHER, PARAM, SEV_DOWN, TAINT, TEST_PATH_RE

log = logging.getLogger(__name__)

try:
    import tree_sitter_rust as _tsr
    from tree_sitter import Language, Parser
    _LANG = Language(_tsr.language())
    AVAILABLE = True
except Exception as _exc:
    AVAILABLE = False
    _LANG = None
    log.warning(
        "Rust AST analysis is disabled: could not load tree-sitter or tree-sitter-rust (%s: %s). "
        "Only the generic pattern rules and the quality engine will run on .rs files. "
        "Install the missing packages with: pip install tree-sitter tree-sitter-rust",
        type(_exc).__name__, _exc,
    )

SUPPORTED = (".rs",)
_PARSER = []


def _parse(text):
    if not _PARSER:
        _PARSER.append(Parser(_LANG))
    return _PARSER[0].parse(text.encode("utf-8", "ignore"))


# ---------------------------------------------------------------------------
# Values: (level, safe_for, parameters, flags)
# ---------------------------------------------------------------------------
NOP, NOF = frozenset(), frozenset()
KINDS = frozenset(("cmd", "sql", "path", "ssrf", "redirect", "xss", "regex", "log", "tpl", "mem", "alloc", "clog", "cstore",
                   "pwhash", "ctrans"))
INJ_SAFE = frozenset(("cmd", "sql", "path", "ssrf", "redirect", "xss", "regex", "log", "tpl", "mem"))   # numbers: everything except alloc
V_CONST = (CONST, KINDS, NOP, NOF)
V_OTHER = (OTHER, NOP, NOP, NOF)
V_TAINT = (TAINT, NOP, NOP, frozenset({("remote",)}))
V_LOCAL = (TAINT, NOP, NOP, frozenset({("local",)}))
V_NUM = (TAINT, INJ_SAFE, NOP, NOF)
V_SENS = (CONST, KINDS, NOP, frozenset({"sens"}))


def join(vals):
    lvl, safe, params, flags = CONST, None, NOP, NOF
    for l, s, p, f in vals:
        if p:
            params = params | p
        if f:
            flags = flags | f
        if l > lvl:
            lvl = l
        if l > CONST:
            safe = s if safe is None else (safe & s)
    return (lvl, KINDS if safe is None else safe, params, flags)


def _t(n):
    return n.text.decode("utf-8", "ignore")


def _line(n):
    return n.start_point[0] + 1


def _f(n, name):
    return n.child_by_field_name(name)


def _named(n):
    return [c for c in n.named_children if c.type not in ("line_comment", "block_comment")]


TRANSPARENT = ("parenthesized_expression", "reference_expression", "try_expression", "await_expression", "type_cast_expression",
               "unsafe_block_expr")
NUM_TYPES = {"i8", "i16", "i32", "i64", "i128", "isize", "u8", "u16", "u32", "u64", "u128", "usize", "f32", "f64", "bool", "char",
             "Uuid", "IpAddr", "Ipv4Addr", "Ipv6Addr", "NaiveDate", "DateTime", "Duration", "SocketAddr"}
SENS_RE = re.compile(r"password|passwd|passphrase|secret|api_?key|access_?key|private_?key|token|credential|credit_?card|card_?number|"
                     r"cvv|ssn|social_?security|bank_?account|account_?number|\bpin\b|auth_?key|phone_?(number)?|e_?mail|date_?of_?birth|\bdob\b|passport|iban|medical|health_?", re.I)
SENS_BAD_PREFIX = re.compile(r"^(is|has|check|validate|verify|len|hash|hashed|harmless)_", re.I)
LOG_MACROS = {"todo", "unimplemented", "debug", "info", "warn", "error", "trace", "log", "println", "print", "eprintln", "eprint", "dbg", "panic", "assert",
              "assert_eq", "assert_ne", "debug_assert", "debug_assert_eq", "debug_assert_ne", "write", "writeln", "unreachable",
              "todo", "unimplemented"}
FMT_MACROS = {"format", "println", "print", "eprintln", "eprint", "write", "writeln", "panic", "format_args"} | LOG_MACROS
PRIVATE_HOST = re.compile(r"^(localhost|127\.|10\.|192\.168\.|172\.(1[6-9]|2\d|3[01])\.|\[?::1\]?|0\.0\.0\.0)", re.I)


def _is_num_type(txt):
    txt = re.sub(r"\b(std|core)::\w+::", "", txt)
    parts = re.findall(r"[A-Za-z_]\w*", txt)
    parts = [p for p in parts if p not in ("Option", "Vec", "Some", "Ok", "Result", "Box", "Rc", "Arc", "mut", "dyn", "web", "Path", "Query",
                                            "Json", "Form", "axum", "extract")]
    return bool(parts) and all(p in NUM_TYPES for p in parts)


# ---------------------------------------------------------------------------
# Sink tables  (last two path segments -> specification)
# ---------------------------------------------------------------------------
INFO = {   # class -> (sid, title, severity, potential, cwe, explanation, remedy, impact)
    "cmd": ("AST-RS-001", "System command built from untrusted data", "CRITICAL", None, "CWE-78",
            "the program to launch or its arguments depend on external input.",
            "Use a fixed program and pass the arguments as a list, validating them against an allowlist; avoid 'sh -c'.",
            "Whoever controls the data can run commands or alter what the launched program does."),
    "sql": ("AST-RS-002", "SQL query built from untrusted data", "CRITICAL", "HIGH", "CWE-89",
            "the query is composed by concatenating or interpolating (format!) non-constant data.",
            "Use parameterized queries (sqlx::query(\"... $1\").bind(x), rusqlite params!) or the compile-time checked macros (query!).",
            "A crafted value alters the query: it reads, modifies or deletes data it should not touch."),
    "path": ("AST-RS-003", "User-controlled file path (path traversal)", "HIGH", None, "CWE-22",
             "a file path depends on external input ('../' allows escaping the intended directory).",
             "Use Path::file_name(), or canonicalize and verify with starts_with(base) before opening the file.",
             "Whoever controls the path can read or overwrite files they should not touch (keys, configuration)."),
    "ssrf": ("AST-RS-004", "Request to a user-chosen address (SSRF)", "HIGH", None, "CWE-918",
             "the URL (or its host) of a request depends on external input.",
             "Allow only hosts from an allowlist or build the URL from fixed parts.",
             "The server becomes a bridge to internal services (databases, admin panels, cloud metadata)."),
    "redirect": ("AST-RS-005", "Redirect to a user-chosen address", "MEDIUM", None, "CWE-601",
                 "the redirect destination depends on external input (open redirect).",
                 "Redirect only to internal paths or to domains on an allowlist.",
                 "A link that looks like it belongs to your site takes the victim to a fake site (phishing)."),
    "xss": ("AST-RS-006", "Unsanitized content in the HTML response (XSS)", "HIGH", None, "CWE-79",
            "external input ends up in an HTML response without being sanitized.",
            "Use a template engine with automatic escaping (askama, maud, tera) or html_escape::encode_text.",
            "A user can inject a script that runs in visitors' browsers and steals sessions or data."),
    "regex": ("AST-RS-007", "Regular expression built from untrusted data", "MEDIUM", None, "CWE-20",
              "the regular expression pattern depends on external input.",
              "Use regex::escape(x) on the value before inserting it into the pattern.",
              "The user alters the meaning of the search (e.g. matches everything) or makes compilation fail."),
    "log": ("AST-RS-008", "Untrusted data written to logs (log injection)", "LOW", None, "CWE-117",
            "a user-chosen value is written to the logs as is, possibly containing newlines.",
            "Remove or escape control characters (replace('\\n', \"\"), {:?} formatting) before logging it.",
            "A user can forge log entries and hide their tracks."),
    "alloc": ("AST-RS-009", "User-controlled allocation size", "MEDIUM", None, "CWE-770",
              "a size chosen by external input is used to allocate memory without an upper bound.",
              "Limit the size (min/clamp with a maximum) or reject values that are too large before allocating.",
              "A huge value exhausts the server's memory (denial of service)."),
    "tpl": ("AST-RS-010", "Template built from user data (SSTI)", "CRITICAL", None, "CWE-1336",
            "the template text depends on external input.",
            "Use fixed templates and pass the data as context variables.",
            "The user writes template-engine instructions that can read data or execute code."),
    "mem": ("AST-RS-011", "Unsafe API with an untrusted size/index", "HIGH", None, "CWE-787",
            "an externally chosen size or index reaches an unsafe function that does not check bounds.",
            "Check bounds first (get(i), safe slices) and avoid the *_unchecked / from_raw_parts variants with external values.",
            "Out-of-bounds memory write or read: crash or code execution."),
    "clog": ("AST-RS-012", "Sensitive data written to logs in plaintext", "MEDIUM", None, "CWE-312",
             "a password, token or other sensitive value is logged.",
             "Never log secrets: remove or mask them (e.g. \"***\").",
             "Anyone who reads the logs (or receives them through a monitoring service) obtains valid credentials."),
    "cstore": ("AST-RS-013", "Sensitive data stored in plaintext in the database", "MEDIUM", None, "CWE-312",
               "sensitive data is written to the database without being encrypted or hashed.",
               "Encrypt the data (AES-GCM) or, for passwords, store only a hash made with argon2/bcrypt.",
               "Anyone who accesses the database (or a backup) obtains the data in plaintext."),
    "pwhash": ("AST-RS-014", "Sensitive data protected with an unsuitable hash", "HIGH", None, "CWE-327",
               "a password or secret is hashed with MD5/SHA-1/SHA-2/SHA-3, which are fast hashes unsuitable for passwords.",
               "For passwords use argon2, bcrypt or scrypt.",
               "With a GPU, billions of guesses per second can be tried: passwords are recovered quickly."),
    "ctrans": ("AST-RS-015", "Sensitive data sent without encryption", "MEDIUM", None, "CWE-319",
               "sensitive data is transmitted over a plaintext channel (http://, TCP socket).",
               "Use https/TLS for every transmission of sensitive data.",
               "Anyone who intercepts the network can read the credentials."),
}
PLAIN = {
    "cert": ("AST-RS-016", "TLS certificate verification disabled", "HIGH", "CWE-295",
             "danger_accept_invalid_* / verification disabled: the connection accepts any certificate.",
             "Remove the option and use the default verification (add your own CA if needed).",
             "A network attacker impersonates the server and reads or alters the data (man-in-the-middle)."),
    "nohttps": ("AST-RS-017", "Unencrypted URL (http://)", "MEDIUM", "CWE-319",
                "the request uses http instead of https: traffic can be read and modified on the network.",
                "Use https:// (except on local development networks).", "Anyone on the same network can read or alter the communication."),
    "algo": ("AST-RS-018", "Weak or broken encryption algorithm", "HIGH", "CWE-327",
             "DES, 3DES, RC2/RC4/RC5, Blowfish or ECB mode do not adequately protect the data.",
             "Use AES-256-GCM or ChaCha20-Poly1305.", "Encrypted data can be decrypted or analyzed with common tools."),
    "hc": ("AST-RS-019", "Hardcoded cryptographic key, IV or salt", "HIGH", "CWE-798",
           "a constant value is used as the key, IV, nonce or salt of a cryptographic operation.",
           "Generate keys and nonces with a secure generator (OsRng) and keep keys out of the code (environment variables, vault).",
           "Anyone who reads the code (or the binary) knows the key: the encryption no longer protects anything."),
    "cookie": ("AST-RS-020", "Cookie without the Secure flag", "MEDIUM", "CWE-614",
               "the cookie may also travel over unencrypted connections (.secure(true) is missing).",
               "Set .secure(true) (and .http_only(true), same_site).", "A session cookie can be intercepted on the network."),
}

CMD_ARG = ("cmd", 0)
SIG_SINKS = {   # last two path segments
    "Command::new": ("cmd", 0),
    **{f"fs::{n}": ("path", 0) for n in ("read_to_string", "read", "write", "remove_file", "remove_dir", "remove_dir_all", "create_dir",
                                           "create_dir_all", "read_dir", "metadata", "symlink_metadata", "canonicalize", "read_link",
                                           "set_permissions", "exists", "try_exists")},
    "fs::copy": ("path", "any"), "fs::rename": ("path", "any"), "fs::hard_link": ("path", "any"),
    "File::open": ("path", 0), "File::create": ("path", 0), "File::create_new": ("path", 0), "OpenOptions::open": ("path", 0),
    **{f"{m}::{n}": ("ssrf", 0) for m in ("reqwest", "blocking", "ureq", "surf", "isahc", "attohttpc")
       for n in ("get", "post", "put", "delete", "head", "patch")},
    "TcpStream::connect": ("ssrf", 0), "Redirect::to": ("redirect", 0), "Redirect::temporary": ("redirect", 0),
    "Redirect::permanent": ("redirect", 0), "Redirect::see_other": ("redirect", 0),
    "Html": ("xss", 0), "Html::new": ("xss", 0), "reply::html": ("xss", 0), "RawHtml": ("xss", 0), "PreEscaped": ("xss", 0), "HttpResponse::body": None,
    "Regex::new": ("regex", 0), "RegexBuilder::new": ("regex", 0), "RegexSet::new": ("regex", 0),
    "sqlx::query": ("sql", 0), "sqlx::query_as": ("sql", 0), "sqlx::query_scalar": ("sql", 0), "sqlx::raw_sql": ("sql", 0),
    "diesel::sql_query": ("sql", 0), "Statement::from_string": ("sql", 1), "Statement::from_sql_and_values": ("sql", 1),
    "Vec::with_capacity": ("alloc", 0), "Vec::try_with_capacity": ("alloc", 0), "Vec::with_capacity_in": ("alloc", 0),
    "String::with_capacity": ("alloc", 0), "HashMap::with_capacity": ("alloc", 0), "VecDeque::with_capacity": ("alloc", 0),
    "libc::malloc": ("alloc", 0), "libc::calloc": ("alloc", "any"), "libc::realloc": ("alloc", 1), "alloc::alloc": ("alloc", 0),
    "alloc::alloc_zeroed": ("alloc", 0), "alloc::realloc": ("alloc", "any"), "Layout::from_size_align_unchecked": None,
    "slice::from_raw_parts": ("mem", 1), "slice::from_raw_parts_mut": ("mem", 1), "ptr::copy_nonoverlapping": ("mem", 2),
    "ptr::copy": ("mem", 2), "ptr::write_bytes": ("mem", 2), "Tera::one_off": ("tpl", 0), "Environment::render_str": ("tpl", 0),
    "Handlebars::render_template": ("tpl", 0),
}
SIG_SINKS = {k: v for k, v in SIG_SINKS.items() if v}
METHOD_SINKS = {   # method name -> (class, argument)
    "reserve": ("alloc", 0), "reserve_exact": ("alloc", 0), "try_reserve": ("alloc", 0), "try_reserve_exact": ("alloc", 0),
    "set_len": ("alloc", 0), "resize": ("alloc", 0), "get_unchecked": ("mem", 0), "get_unchecked_mut": ("mem", 0),
    "render_str": ("tpl", 0), "render_template": ("tpl", 0), "add_raw_template": ("tpl", 1),
    "alloc": ("alloc", 0), "alloc_zeroed": ("alloc", 0), "allocate": ("alloc", 0), "allocate_zeroed": ("alloc", 0), "grow_zeroed": ("alloc", "any"),
    "realloc": ("alloc", "any"), "grow": ("alloc", "any"), "shrink": ("alloc", "any"),
    "render_template_string": ("tpl", 0),
}
SQL_METHODS = {"prep", "query_stream", "exec_iter", "prepare_cached", "execute", "query", "query_one", "query_row", "query_map", "query_opt", "query_first", "query_drop", "query_iter",
               "query_fold", "prepare", "execute_batch", "batch_execute", "simple_query", "exec", "exec_drop", "query_raw", "fetch",
               "fetch_one", "fetch_all", "fetch_optional", "query_scalar"}
SQL_RE = re.compile(r"\b(select|insert\s+into|update|delete\s+from|drop|create\s+table|alter\s+table|where|values|union)\b", re.I)
HTML_RE = re.compile(r"<[a-zA-Z/!]")
REQ_METHODS = {"get", "post", "put", "delete", "head", "patch", "request"}
HASH_TYPES = re.compile(r"(?i)(md5|md4|sha-?1|sha224|sha256|sha384|sha512|sha3|sha2|blake2|blake3|ripemd)")
STRONG_PW = re.compile(r"argon2|bcrypt|scrypt|pbkdf2|password_hash", re.I)
WEAK_CIPHERS = re.compile(r"(?i)des(ede)?\w*(Encryptor|Decryptor|Cipher)|\b(Rc4|RC4|Des|DesEde\w*|TdesEee\w*|TdesEde\w*|Rc2|RC2|Rc5|RC5\w*|Blowfish|Bf\w*|Cast5|Idea|Arc4|Arcfour)\b")
KEY_METHODS = {   # method/function -> indexes of the arguments that are key/IV/nonce/salt
    "from_slice": (0,), "new_from_slice": (0,), "new_from_slices": (0, 1), "from_seed": (0,), "seed_from_u64": (0,),
    "set_salt": (0,), "set_salt_u64": (0,), "set_key": (0,), "set_iv": (0,), "set_nonce": (0,), "set_password": (0,),
    "hash_password_into": (1,), "pbkdf2_hmac": (1,), "from_b64": (0,), "encode_b64": (0,),
}
KEY_SIGS = {"Crypter::new": (2, 3), "symm::encrypt": (1, 2), "symm::decrypt": (1, 2), "ChaCha20::new": (0, 1), "ChaCha20Poly1305::new": (0,),
            "Aes128::new": (0,), "Aes256::new": (0,), "Aes128Gcm::new": (0,), "Aes256Gcm::new": (0,), "Hmac::new_from_slice": (0,),
            "SaltString::new": (0,), "Salt::new": (0,), "Cipher::new": (0,), "KeyIvInit::new": (0, 1), "Mac::new_from_slice": (0,)}
COOKIE_CTORS = {"ResponseCookie::new", "ResponseCookie::from", "ResponseCookie::build", "ResponseCookie::named", "SetCookie::new", "Cookie::new", "Cookie::build", "Cookie::parse", "Cookie::parse_encoded", "Cookie::from", "CookieBuilder::new",
                "CookieConfig::new", "CookieConfig::default", "Cookie::named"}
COOKIE_SINK_METHODS = {"add", "add_original", "insert", "append", "cookie", "add_cookie"}
COOKIE_PRESERVING = {"clone", "path", "domain", "expires", "max_age", "permanent", "make_permanent", "http_only", "same_site", "unset_domain",
                     "set_path", "set_domain", "set_http_only", "set_same_site", "set_max_age", "set_expires", "build", "finish",
                     "unwrap", "expect", "to_owned", "into_owned", "name", "value", "named", "with_name", "set_name", "set_value", "build_cookie",
                     "unset_path", "unset_max_age", "unset_expires", "secure_if", "set_permanent", "into", "to_string", "removal", "expires_in", "with_secure_false"}
SAN_CALLS = {   # path (last segments) -> neutralized classes ("*" = all except alloc)
    "html_escape::encode_text": {"xss"}, "html_escape::encode_double_quoted_attribute": {"xss"}, "ammonia::clean": {"xss"},
    "askama_escape::escape": {"xss"}, "regex::escape": {"regex"}, "urlencoding::encode": {"ssrf", "redirect", "xss"},
    "sanitize_filename::sanitize": {"path"}, "shell_escape::escape": {"cmd"}, "shlex::quote": {"cmd"}, "shlex::try_quote": {"cmd"},
}
SAN_METHODS = {"file_name": {"path"}, "escape_debug": {"log", "xss"}, "escape_default": {"log", "xss", "cmd"}, "len": "NUM", "count": "NUM",
               "is_empty": "NUM", "is_some": "NUM", "is_ok": "NUM", "is_none": "NUM", "is_err": "NUM", "contains": "NUM",
               "starts_with": "NUM", "ends_with": "NUM", "eq": "NUM", "to_lowercase_ne": "NUM"}
PURE_METHODS = {"to_string", "to_owned", "clone", "as_str", "as_bytes", "into_bytes", "to_vec", "into", "as_ref", "unwrap", "expect", "unwrap_or",
                "unwrap_or_default", "unwrap_or_else", "trim", "trim_start", "trim_end", "to_lowercase", "to_uppercase", "replace", "replacen",
                "join", "push_str", "push", "concat", "borrow", "deref", "as_mut", "iter", "into_iter", "collect", "nth", "next", "first",
                "last", "get", "cloned", "copied", "chars", "bytes", "lines", "split", "split_whitespace", "map", "ok", "ok_or", "ok_or_else",
                "and_then", "map_err", "text", "bytes_stream", "json", "body", "send", "await", "lock", "read", "write", "as_slice", "to_str",
                "to_string_lossy", "display", "format", "repeat", "chain", "strip_prefix", "strip_suffix", "split_once", "rsplit", "parse"}


class Project:
    def __init__(self):
        self.modules, self.summaries, self.structs, self.enums, self.analyzers = {}, {}, {}, set(), {}

    def add_module(self, crate, modpath, key):
        self.modules[(crate, modpath)] = key


def module_info(rel_path):
    """(crate, module path) of a file: relative to the nearest src directory."""
    p = rel_path.replace("\\", "/")
    parts = p.split("/")
    if "src" in parts:
        i = len(parts) - 1 - parts[::-1].index("src")
        crate, rest = "/".join(parts[:i]), parts[i + 1:]
    else:
        crate, rest = "", parts
    if rest:
        last = rest[-1][:-3] if rest[-1].endswith(".rs") else rest[-1]
        rest = rest[:-1] + ([] if last in ("mod", "lib", "main") else [last])
    return crate, tuple(rest)


class RustAnalyzer:
    def __init__(self, rel_path, tree, project=None):
        self.rel_path, self.tree, self.root, self.project = rel_path, tree, tree.root_node, project
        self.crate, self.modpath = module_info(rel_path)
        self.mod = rel_path
        self.is_test = bool(TEST_PATH_RE.search(rel_path.replace("\\", "/").lower())) or "/tests/" in rel_path.replace("\\", "/")
        self.findings, self.seen = [], {}
        self.aliases, self.globs = {}, []
        self.registry, self.summaries, self.sigs = {}, {}, {}
        self.structs, self.module_env = {}, {}
        self.cur, self.cur_class, self.report, self.loop_depth = None, None, True, 0
        self.macro_cache = {}
        self.in_test = 0
        self.src = tree.root_node.text.split(b"\n")

    # ----------------------------------------------------------- preparation
    def _use_paths(self, n, prefix=""):
        t = n.type
        if t == "scoped_use_list":
            p = _f(n, "path")
            base = (prefix + "::" if prefix else "") + (_t(p) if p is not None else "")
            for c in _named(_f(n, "list")):
                yield from self._use_paths(c, base)
        elif t == "use_list":
            for c in _named(n):
                yield from self._use_paths(c, prefix)
        elif t == "use_as_clause":
            p, a = _f(n, "path"), _f(n, "alias")
            yield ((prefix + "::" if prefix else "") + _t(p), _t(a))
        elif t == "use_wildcard":
            k = _named(n)
            yield ((prefix + "::" if prefix else "") + (_t(k[0]) if k else ""), "*")
        elif t == "self":
            yield (prefix, prefix.split("::")[-1])
        else:
            full = (prefix + "::" if prefix else "") + _t(n)
            yield (full, full.split("::")[-1])

    def prepare(self):
        stack = [self.root]
        while stack:
            n = stack.pop()
            t = n.type
            if t == "use_declaration":
                arg = _f(n, "argument")
                if arg is not None:
                    for full, alias in self._use_paths(arg):
                        if alias == "*":
                            self.globs.append(full)
                        else:
                            self.aliases[alias] = full
            elif t == "struct_item":
                nm, body = _f(n, "name"), _f(n, "body")
                if nm is not None and body is not None:
                    fields = {}
                    for fd in _named(body):
                        if fd.type == "field_declaration":
                            fields[_t(_f(fd, "name"))] = _t(_f(fd, "type"))
                    self.structs[_t(nm)] = fields
                    if self.project is not None:
                        self.project.structs[_t(nm)] = fields
            elif t == "enum_item":
                nm = _f(n, "name")
                if nm is not None and self.project is not None:
                    self.project.enums.add(_t(nm))
            if t in ("function_item",):
                nm = _f(n, "name")
                par = n.parent
                if nm is not None and par is not None and par.type in ("source_file", "mod_item", "declaration_list") and \
                        (par.type != "declaration_list" or (par.parent is not None and par.parent.type == "mod_item")):
                    self.registry[_t(nm)] = (n, None)
            elif t == "impl_item":
                ty, body = _f(n, "type"), _f(n, "body")
                if ty is not None and body is not None:
                    tn = re.sub(r"<.*", "", _t(ty))
                    for m in _named(body):
                        if m.type == "function_item":
                            self.registry[f"{tn}.{_t(_f(m, 'name'))}"] = (m, tn)
            stack.extend(n.children)

    def update_summaries(self):
        changed = False
        for key, (node, cls) in self.registry.items():
            s = self._run_function(node, key, cls, False)
            sig = (tuple(sorted((i, tuple(sorted(m))) for i, m in s["hits"].items())),
                   (s["ret"][0], tuple(sorted(s["ret"][1])), tuple(sorted(s["ret"][2]))), tuple(sorted(map(str, s["ret"][3]))))
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

    # ----------------------------------------------------------- names
    def dotted(self, n):
        if n is None:
            return None
        t = n.type
        if t in ("identifier", "self", "type_identifier", "field_identifier", "crate", "super", "metavariable"):
            return _t(n)
        if t == "scoped_identifier" or t == "scoped_type_identifier":
            p, nm = _f(n, "path"), _f(n, "name")
            ps = self.dotted(p) if p is not None else ""
            return f"{ps}::{_t(nm)}" if ps else _t(nm)
        if t == "generic_function":
            return self.dotted(_f(n, "function"))
        if t == "generic_type":
            return self.dotted(_f(n, "type"))
        if t == "field_expression":
            v, f = self.dotted(_f(n, "value")), _f(n, "field")
            return f"{v}.{_t(f)}" if v and f is not None else None
        if t in ("parenthesized_expression", "reference_expression"):
            k = _named(n)
            return self.dotted(k[-1]) if k else None
        return None

    def resolve(self, name):
        if not name:
            return None
        parts = name.split("::")
        head = parts[0]
        full = self.aliases.get(head)
        if full is not None:
            return "::".join([full] + parts[1:])
        if len(parts) == 1:
            for g in self.globs:
                if head[:1].isupper() or True:
                    return g + "::" + head if len(self.globs) == 1 and not head.islower() else name
        return name

    @staticmethod
    def sig2(rn):
        parts = (rn or "").split("::")
        return "::".join(parts[-2:])

    def _local_key(self, fn, rn):
        if fn is None:
            return None, 0
        if fn.type == "identifier" and _t(fn) in self.registry:
            return _t(fn), 0
        if fn.type == "field_expression":
            v, f = _f(fn, "value"), _f(fn, "field")
            if v is not None and v.type == "self" and self.cur_class:
                k = f"{self.cur_class}.{_t(f)}"
                if k in self.registry:
                    return k, 1
        if rn and "::" in rn:
            parts = rn.split("::")
            if parts[0] in ("Self", "self") and self.cur_class and len(parts) == 2:
                k = f"{self.cur_class}.{parts[1]}"
                if k in self.registry:
                    return k, 0
            if len(parts) == 2:
                k = f"{parts[0]}.{parts[1]}"
                if k in self.registry:
                    return k, 0
        return None, 0

    def _global_key(self, rn):
        if not rn or self.project is None or "::" not in rn:
            return None
        parts = rn.split("::")
        mp = list(self.modpath)
        if parts[0] == "crate":
            parts = parts[1:]
            mp = []
        elif parts[0] == "self":
            parts = parts[1:]
        elif parts[0] == "super":
            while parts and parts[0] == "super":
                parts = parts[1:]
                mp = mp[:-1]
        else:
            return None   # external crate
        for cut in (1, 2):
            if len(parts) <= cut - 1:
                continue
            fnname = ".".join(parts[-cut:]) if cut == 2 else parts[-1]
            modp = tuple(mp + parts[:-cut])
            key_mod = self.project.modules.get((self.crate, modp))
            if key_mod is not None and (key_mod, fnname) in self.project.summaries:
                return (key_mod, fnname)
        return None

    # ----------------------------------------------------------- findings
    def _snippet(self, line):
        try:
            t = self.src[line - 1].decode("utf-8", "ignore").strip()
        except Exception as exc:
            log.debug("Could not extract the source snippet for %s:%s (%s: %s)", self.rel_path, line, type(exc).__name__, exc)
            return ""
        return t[:160] + (" …" if len(t) > 160 else "")

    def _add(self, sid, name, sev, conf, line, desc, rec, cwe, impact=None, via=None):
        key = (sid, line)
        prev = self.seen.get(key)
        if prev is not None:
            if conf == "confirmed" and prev["confidence"] == "unknown":
                prev.update({"severity": sev, "confidence": "confirmed", "confidence_label": CONF_LABEL["confirmed"]})
                if via:
                    prev["description"] += f" (the data flows through the function '{via}')"
            return
        if via:
            desc += f" (the data flows through the function '{via}')"
        if self.is_test or self.in_test:
            sev = SEV_DOWN.get(sev, sev)
            desc += " [Test code: severity reduced.]"
        f = {"id": sid, "name": name, "severity": sev, "confidence": "confirmed" if conf == "fixed" else conf,
             "confidence_label": CONF_LABEL[conf], "file": self.rel_path, "line": line, "snippet": self._snippet(line),
             "description": desc, "recommendation": rec, "engine": "rust_ast", "cwe": cwe}
        if impact:
            f["impact"] = impact
        self.seen[key] = f
        self.findings.append(f)

    def _hit(self, kind, label, val, at, via=None, only_confirmed=False, record_only=False, need="taint"):
        self._hit_loc(kind, label, val, self.mod, _line(at), via, only_confirmed, record_only, need)

    def _hit_loc(self, kind, label, val, mod, line, via=None, only_confirmed=False, record_only=False, need="taint"):
        """need: 'taint' = untrusted data; 'sens' = sensitive data. The alert is always reported on the sink line (even in another file)."""
        if need == "sens":
            lvl = TAINT if "sens" in val[3] else CONST
        else:
            lvl = CONST if kind in val[1] else val[0]
        if lvl == CONST:
            return
        if val[2] and self.cur is not None and need == "taint":
            for p in val[2]:
                self.cur["hits"].setdefault(p, {})[f"{kind}|{label}|{mod}|{line}"] = (kind, label, need, mod, line)
        if not self.report or record_only:
            return
        an = self if mod == self.mod else (self.project.analyzers.get(mod) if self.project is not None else None)
        if an is None:
            return
        sid, name, sev, pot, cwe, what, rec, impact = INFO[kind]
        if lvl == TAINT:
            note = ""
            if need == "taint" and any(x == ("local",) for x in val[3]) and not any(x == ("remote",) for x in val[3]) and not val[2]:
                sev, note = SEV_DOWN.get(sev, sev), " [local origin (arguments/environment): lower risk than network input.]"
            an._add(sid, name, sev, "confirmed", line, f"{label}: {what}{note}", rec, cwe, impact, via)
        elif pot and not only_confirmed:
            an._add(sid, name, pot, "unknown", line, f"{label}: {what}", rec, cwe, impact, via)

    def _plain(self, key, at, conf="fixed", extra=""):
        if self.report:
            sid, name, sev, cwe, what, rec, impact = PLAIN[key]
            self._add(sid, name, sev, conf, _line(at), what + extra, rec, cwe, impact)

    # ----------------------------------------------------------- functions
    def _attrs_of(self, fn_node):
        out, p = [], fn_node.prev_sibling
        while p is not None and p.type in ("attribute_item", "line_comment", "block_comment"):
            if p.type == "attribute_item":
                out.append(_t(p))
            p = p.prev_sibling
        return out

    def _bind_pattern(self, pat, val, env, typ=None):
        if pat is None:
            return
        t = pat.type
        if t == "identifier":
            nm = _t(pat)
            env[nm] = self._sens_wrap(nm, val)
            if typ:
                env[("type", nm)] = typ
        elif t in ("mut_pattern", "ref_pattern", "reference_pattern", "captured_pattern", "or_pattern", "slice_pattern", "range_pattern"):
            for c in _named(pat):
                self._bind_pattern(c, val, env, typ)
        elif t in ("tuple_struct_pattern", "tuple_pattern", "struct_pattern"):
            tn = _f(pat, "type") if t != "tuple_pattern" else None
            tname = re.sub(r"<.*", "", _t(tn)).split("::")[-1] if tn is not None else ""
            inner_typ = typ
            if tname in ("Path", "Query", "Json", "Form") and typ:
                inner_typ = typ
            for c in _named(pat):
                if c is tn:
                    continue
                if c.type == "field_pattern":
                    nm = _f(c, "name")
                    p2 = _f(c, "pattern")
                    self._bind_pattern(p2 if p2 is not None else nm, val, env)
                else:
                    self._bind_pattern(c, val, env, inner_typ)
        elif t == "field_pattern":
            self._bind_pattern(_f(pat, "pattern") or _f(pat, "name"), val, env)
        elif t == "shorthand_field_initializer":
            pass
        else:
            for c in _named(pat):
                self._bind_pattern(c, val, env, typ)

    def _sens_wrap(self, name, val):
        if SENS_RE.search(name) and not SENS_BAD_PREFIX.match(name) and "sens" not in val[3]:
            return (val[0], val[1], val[2], val[3] | {"sens"})
        return val

    def _param_value(self, ptype, handler, route_attr):
        """Value of an extractor parameter, based on its type."""
        tt = ptype or ""
        extractor = re.search(r"\b(Path|Query|Json|Form|TypedHeader|Data<Vec|ContentLengthLimit)\s*<|"
                              r"\b(HttpRequest|Bytes|Multipart|Payload|Host|HeaderMap|CookieJar|RawBody|ConnectInfo)\b", tt)
        if not (extractor or route_attr):
            return None
        if re.search(r"\b(State|Data|Extension|PgPool|Pool|SqlitePool|Arc<|AppState|web::Data|Session|Config)\b", tt) and not extractor:
            return None
        if _is_num_type(re.sub(r"^&?\s*", "", tt)):
            return V_NUM
        # Query<Struct> with numeric fields
        m = re.search(r"<\s*([A-Z]\w*)\s*>", tt)
        if m and extractor:
            st = (self.project.structs if self.project else self.structs).get(m.group(1))
            if st is not None and all(_is_num_type(ft) or ft in (self.project.enums if self.project else set()) for ft in st.values()):
                return V_NUM
        return V_TAINT

    def _run_function(self, node, name, cls, report, base_env=None, closure_val=None):
        saved = (self.cur, self.report, self.cur_class, self.loop_depth)
        self.report, self.loop_depth = report, 0
        if cls:
            self.cur_class = cls
        attrs = self._attrs_of(node) if node.type == "function_item" else []
        is_test_fn = any(re.search(r"#\[\s*(\w+::)*(test|rstest|bench)\b|cfg\(test\)", a) for a in attrs)
        if is_test_fn:
            self.in_test += 1
        route = any(re.search(r"#\[\s*(\w+::)*(get|post|put|delete|patch|head|options|route|handler|rpc|tool|command)\b", a) for a in attrs)
        ps = _f(node, "parameters")
        plist = _named(ps) if ps is not None else []
        if node.type == "closure_expression":
            plist = [c for c in _named(ps)] if ps is not None else []
        env = dict(base_env) if base_env is not None else {k: v for k, v in self.module_env.items() if not isinstance(k, tuple) and v[0] == CONST}
        pnames, idx = [], 0
        for p in plist:
            if p.type == "self_parameter":
                env["self"] = V_OTHER
                pnames.append("self")
                idx += 1
                continue
            pat = _f(p, "pattern") if p.type == "parameter" else p
            ptype = _t(_f(p, "type")) if p.type == "parameter" and _f(p, "type") is not None else None
            pn = _t(pat) if pat is not None and pat.type == "identifier" else None
            pnames.append(pn)
            val = None
            if closure_val is not None:
                val = closure_val
            else:
                val = self._param_value(ptype, True, route)
            if val is None:
                val = (PARAM, NOP, frozenset({idx}), NOF)
            else:
                val = (val[0], val[1], frozenset({idx}), val[3])
            if pat is not None:
                self._bind_pattern(pat, val, env, ptype)
            idx += 1
        ctx = {"hits": {}, "rets": [], "route": route}
        self.cur = ctx
        body = _f(node, "body")
        if body is not None:
            v = self._block(body, env) if body.type == "block" else self.eval(body, env)
            ctx["rets"].append(v)
        ret = join(ctx["rets"]) if ctx["rets"] else V_CONST
        self.cur, self.report, self.cur_class, self.loop_depth = saved
        if is_test_fn:
            self.in_test -= 1
        return {"hits": ctx["hits"], "ret": ret, "params": pnames}

    def _apply_summary(self, s, key, offset, node, vals):
        argmap = {j + offset: v for j, v in enumerate(vals)}
        for idx, metas in s["hits"].items():
            v = argmap.get(idx)
            if v is not None:
                for kind, label, need, mod, line in metas.values():
                    self._hit_loc(kind, label, v, mod, line, via=key.split(".")[-1], only_confirmed=True, need=need)
        ret = s["ret"]
        parts = []
        if ret[0] >= OTHER or ret[3]:
            parts.append((ret[0], ret[1], NOP, ret[3]))
        parts += [(argmap[p][0], argmap[p][1] | ret[1], argmap[p][2], argmap[p][3] | ret[3]) for p in ret[2] if p in argmap]
        return join(parts) if parts else V_CONST

    # ----------------------------------------------------------- expressions
    def eval(self, n, env):
        if n is None:
            return V_CONST
        t = n.type
        if t == "boolean_literal":
            return (CONST, KINDS, NOP, frozenset({("T",)}) if _t(n) == "true" else NOF)
        if t in ("string_literal", "raw_string_literal", "char_literal", "float_literal"):
            txt = _t(n)
            flags = frozenset({("hc", _line(n))}) if t in ("string_literal", "raw_string_literal") else NOF
            mh = re.match(r'^r?#*"http://([^/"]+)', txt, re.I) if t in ("string_literal", "raw_string_literal") else None
            if mh and not PRIVATE_HOST.match(mh.group(1)) and "{" not in mh.group(1):
                flags = flags | {("http", _line(n))}
            return (CONST, KINDS, NOP, flags)
        if t == "integer_literal":
            return (CONST, KINDS, NOP, frozenset({("hc", _line(n))}))
        if t == "identifier":
            nm = _t(n)
            if nm in env:
                return env[nm]
            return self._sens_wrap(nm, V_CONST if nm in self.aliases or nm[:1].isupper() else V_OTHER)
        if t in ("self", "crate", "super"):
            return env.get("self", V_OTHER)
        if t in TRANSPARENT:
            k = _named(n)
            v = self.eval(k[0], env) if k else V_OTHER
            if t == "type_cast_expression":
                ty = _f(n, "type")
                if ty is not None and _is_num_type(_t(ty)):
                    return (v[0], v[1] | INJ_SAFE, v[2], v[3]) if v[0] else v
            return v
        if t == "unary_expression":
            k = _named(n)
            v = self.eval(k[-1], env) if k else V_OTHER
            if _t(n).lstrip().startswith("!"):
                return (v[0], v[1], v[2], frozenset(x for x in v[3] if x != ("T",)))
            return v
        if t == "field_expression":
            return self._field(n, env)
        if t == "index_expression":
            k = _named(n)
            vs = [self.eval(c, env) for c in k]
            return vs[0] if vs and vs[0][0] == CONST else join(vs)
        if t == "call_expression":
            return self._call(n, env)
        if t == "macro_invocation":
            return self._macro(n, env)
        if t == "binary_expression":
            op = _t(_f(n, "operator"))
            lv, rv = self.eval(_f(n, "left"), env), self.eval(_f(n, "right"), env)
            if op in ("==", "!=", "<", ">", "<=", ">=", "&&", "||"):
                return V_CONST
            return join([lv, rv])
        if t in ("array_expression", "tuple_expression"):
            vals = []
            ln = _f(n, "length")
            for c in _named(n):
                v = self.eval(c, env)
                if ln is not None and c.start_byte == ln.start_byte and c.end_byte == ln.end_byte:
                    self._hit("alloc", "[x; n]", v, c)
                else:
                    vals.append(v)
            return join(vals) if vals else V_CONST
        if t == "struct_expression":
            vals = []
            body = _f(n, "body")
            for c in _named(body) if body is not None else []:
                if c.type == "field_initializer":
                    fnm = _t(_f(c, "field"))
                    v = self.eval(_f(c, "value"), env)
                    vals.append(self._sens_wrap(fnm, v))
                elif c.type == "shorthand_field_initializer":
                    nm = _t(_named(c)[0])
                    vals.append(env.get(nm, self._sens_wrap(nm, V_OTHER)))
                elif c.type == "base_field_initializer":
                    vals.append(self.eval(_named(c)[0], env))
            return join(vals) if vals else V_CONST
        if t in ("block", "unsafe_block", "async_block", "const_block"):
            return self._block(n, env)
        if t == "if_expression":
            return self._if(n, env)
        if t == "match_expression":
            return self._match(n, env)
        if t in ("for_expression", "while_expression", "loop_expression"):
            return self._loop(n, env)
        if t == "closure_expression":
            self._run_function(n, None, None, self.report, env)
            return V_CONST
        if t == "return_expression":
            k = _named(n)
            v = self.eval(k[0], env) if k else V_CONST
            if self.cur is not None:
                self.cur["rets"].append(v)
            return V_CONST
        if t in ("range_expression",):
            vs = [self.eval(c, env) for c in _named(n)]
            return join(vs) if vs else V_CONST
        if t in ("scoped_identifier", "generic_function"):
            rn = self.resolve(self.dotted(n))
            return V_CONST
        if t == "assignment_expression" or t == "compound_assignment_expr":
            left, right = _f(n, "left"), _f(n, "right")
            v = self.eval(right, env)
            self._assign(left, v, env, compound=(t != "assignment_expression"))
            return V_CONST
        if t in ("let_condition",):
            v = self.eval(_f(n, "value"), env)
            self._bind_pattern(_f(n, "pattern"), v, env)
            return V_CONST
        if t == "let_chain":
            for c in _named(n):
                self.eval(c, env)
            return V_CONST
        if t in ("break_expression", "continue_expression"):
            for c in _named(n):
                self.eval(c, env)
            return V_CONST
        out = [self.eval(c, env) for c in _named(n) if c.type.endswith("expression") or c.type.endswith("literal")]
        return join(out) if out else V_OTHER

    def _assign(self, left, v, env, compound=False):
        if left is None:
            return
        if left.type == "identifier":
            nm = _t(left)
            if compound:
                v = join([env.get(nm, V_OTHER), v])
            env[nm] = self._sens_wrap(nm, v)
        elif left.type == "field_expression":
            dn = self.dotted(left)
            if dn:
                env[dn] = v
        elif left.type == "index_expression":
            k = _named(left)
            if k and k[0].type == "identifier":
                nm = _t(k[0])
                env[nm] = join([env.get(nm, V_CONST), v])

    def _field(self, n, env):
        v, f = _f(n, "value"), _f(n, "field")
        fname = _t(f) if f is not None else ""
        dn = self.dotted(n)
        if dn and dn in env:
            return env[dn]
        base = self.eval(v, env)
        # typed field of a project struct (Query<Params>, Json<Body>)
        vd = self.dotted(v) if v is not None else None
        root = (vd or "").split(".")[0]
        ty = env.get(("type", root))
        structs = self.project.structs if self.project else self.structs
        if ty:
            m = re.search(r"<\s*([A-Z]\w*)\s*>", ty)
            sname = m.group(1) if m else re.sub(r"[&\s]|mut", "", ty)
            st = structs.get(sname)
            if st is not None and fname in st:
                ft = st[fname]
                if _is_num_type(ft) or ft in (self.project.enums if self.project else set()):
                    return (base[0], base[1] | INJ_SAFE, base[2], base[3]) if base[0] else base
        return self._sens_wrap(fname, base)

    # ----------------------------------------------------------- blocks and control flow
    def _block(self, n, env):
        last = V_CONST
        for c in _named(n):
            last = self._stmt(c, env)
        return last

    def _walk(self, stmts, env):
        for s in stmts:
            self._stmt(s, env)

    def _stmt(self, s, env):
        t = s.type
        if t == "expression_statement":
            k = _named(s)
            return self.eval(k[0], env) if k else V_CONST
        if t == "let_declaration":
            val, pat, ty = _f(s, "value"), _f(s, "pattern"), _f(s, "type")
            v = self.eval(val, env) if val is not None else V_OTHER
            tt = _t(ty) if ty is not None else None
            if tt and _is_num_type(tt) and v[0]:
                v = (v[0], v[1] | INJ_SAFE, v[2], v[3])
            if val is not None and self._is_command_chain(val, env):
                env[("cmd", _t(pat))] = True
            if val is not None and (v[0] > CONST or "sens" in v[3]):
                skq = self._skeleton(val)
                if skq and SQL_RE.search(skq):
                    v = (v[0], v[1], v[2], v[3] | {("built", _line(val))})
            if val is not None and pat is not None and pat.type in ("identifier", "mut_pattern"):
                nm = _t(pat if pat.type == "identifier" else _named(pat)[0]) if pat.type == "identifier" or _named(pat) else ""
                skh = self._skeleton(val)
                if re.match(r'^http://[^\x00{]', skh, re.I) and not PRIVATE_HOST.match(re.sub(r"^http://", "", skh, flags=re.I)):
                    v = (v[0], v[1], v[2], v[3] | {("http", _line(val))})
                alt = _f(s, "alternative")
                if alt is not None:
                    self.eval(alt, env)
            self._bind_pattern(pat, v, env, tt)
            return V_CONST
        if t in ("function_item",):
            nm = _f(s, "name")
            self._run_function(s, _t(nm) if nm is not None else None, None, self.report, env if self.cur is not None else None)
            return V_CONST
        if t == "impl_item":
            ty, body = _f(s, "type"), _f(s, "body")
            tn = re.sub(r"<.*", "", _t(ty)) if ty is not None else None
            prev = self.cur_class
            self.cur_class = tn
            for m in (_named(body) if body is not None else []):
                if m.type == "function_item":
                    self._run_function(m, f"{tn}.{_t(_f(m, 'name'))}", tn, self.report, env if self.cur is not None else None)
            self.cur_class = prev
            return V_CONST
        if t == "mod_item":
            body = _f(s, "body")
            test_mod = any("cfg(test)" in a for a in self._attrs_of(s))
            if test_mod:
                self.in_test += 1
            if body is not None:
                self._walk(_named(body), env)
            if test_mod:
                self.in_test -= 1
            return V_CONST
        if t in ("const_item", "static_item"):
            val, nm = _f(s, "value"), _f(s, "name")
            if val is not None and nm is not None:
                env[_t(nm)] = self._sens_wrap(_t(nm), self.eval(val, env))
            return V_CONST
        if t in ("block", "unsafe_block", "async_block", "const_block"):
            return self._block(s, env)
        if t.endswith("expression") or t in ("macro_invocation",):
            return self.eval(s, env)
        return V_CONST

    @staticmethod
    def _terminates(n):
        if n is None:
            return False
        kids = _named(n)
        if not kids:
            return False
        last = kids[-1]
        if last.type == "expression_statement":
            k = _named(last)
            last = k[0] if k else last
        if last.type in ("return_expression", "break_expression", "continue_expression"):
            return True
        if last.type == "macro_invocation":
            mn = last.child_by_field_name("macro")
            return mn is not None and _t(mn).split("::")[-1] in ("panic", "unreachable", "todo", "unimplemented")
        if last.type == "call_expression":
            fn = _f(last, "function")
            return fn is not None and _t(fn) in ("std::process::exit", "process::exit", "exit")
        return False

    def _merge(self, a, b, pre):
        out = {}
        for k in set(a) | set(b):
            if isinstance(k, tuple):
                out[k] = a.get(k, b.get(k))
            else:
                out[k] = join([a.get(k, pre.get(k, V_OTHER)), b.get(k, pre.get(k, V_OTHER))])
        return out

    def _guards(self, c, env=None):
        """(names made safe if the test is true, if it is false): name -> neutralized classes."""
        if c is None:
            return {}, {}
        t = c.type
        if t == "parenthesized_expression":
            k = _named(c)
            return self._guards(k[0], env) if k else ({}, {})
        if t == "unary_expression" and _t(c).startswith("!"):
            k = _named(c)
            a, b = self._guards(k[-1], env) if k else ({}, {})
            return b, a
        if t == "binary_expression":
            op = _t(_f(c, "operator"))
            l, r = _f(c, "left"), _f(c, "right")
            if op in ("&&", "||"):
                pa, pb = self._guards(l, env), self._guards(r, env)
                side = 0 if op == "&&" else 1
                out = {}
                for p in (pa, pb):
                    for k, v in p[side].items():
                        out[k] = out.get(k, NOP) | v
                return (out, {}) if side == 0 else ({}, out)
            if op in ("<", "<=", ">", ">=") and l is not None and r is not None:
                li, ri = l.type == "identifier", r.type == "identifier"
                lit = lambda x: x.type in ("integer_literal",) or (x.type == "identifier" and _t(x).isupper())
                if li and lit(r):
                    return ({_t(l): frozenset({"alloc"})}, {}) if op in ("<", "<=") else ({}, {_t(l): frozenset({"alloc"})})
                if ri and lit(l):
                    return ({_t(r): frozenset({"alloc"})}, {}) if op in (">", ">=") else ({}, {_t(r): frozenset({"alloc"})})
            if op in ("==", "!=") and l is not None and l.type == "identifier" and r is not None and r.type in ("string_literal", "integer_literal", "boolean_literal"):
                return ({_t(l): KINDS}, {}) if op == "==" else ({}, {_t(l): KINDS})
        if t == "call_expression":
            fn = _f(c, "function")
            args = _named(_f(c, "arguments")) if _f(c, "arguments") is not None else []
            if fn is not None and fn.type in ("identifier", "scoped_identifier") and args:
                fname = _t(fn).split("::")[-1]
                a0 = args[0].children[-1] if args[0].type == "reference_expression" and args[0].children else args[0]
                if re.search(r"(?i)(^is_(valid|safe|allowed|clean)|valid(ate)?_|_valid\b|is_safe|safe_path|path_is_valid|sanitiz|allowed|whitelist|allowlist)", fname) and a0.type == "identifier":
                    return {_t(a0): KINDS}, {}
            if fn is not None and fn.type == "field_expression":
                recv, m = _f(fn, "value"), _t(_f(fn, "field"))
                rname = self._gname(recv)
                a0 = args[0] if args else None
                a0name = self._gname(a0)
                if m in ("starts_with",) and rname and args:
                    return {rname: frozenset({"redirect", "ssrf", "path?"})}, {}
                if m == "contains" and rname and args and args[0].type == "string_literal" and re.search(r"[./\\]", _t(args[0])):
                    return {}, {rname: frozenset({"path"})}   # contains("..") / contains("/") ... : if false, the name contains no separators
                if m == "contains" and a0name and recv is not None and (
                        recv.type in ("array_expression", "reference_expression") or (rname and "." not in rname and (rname.isupper() or (
                            env is not None and rname in env and env[rname][0] == CONST)))):
                    return {a0name: KINDS}, {}
                if m in ("is_match",) and a0name:
                    return {a0name: KINDS}, {}
                if m in ("is_alphanumeric", "is_ascii_alphanumeric", "is_numeric", "is_ascii_digit", "is_alphabetic") and rname:
                    return {rname: KINDS}, {}
                if m == "all" and recv is not None:
                    chain = _t(recv)
                    root = re.match(r"\s*&?\s*([A-Za-z_]\w*)", chain)
                    if root and re.search(r"(alphanumeric|is_numeric|is_ascii|is_alphabetic|is_digit)", _t(c)):
                        return {root.group(1): KINDS}, {}
        if t == "macro_invocation":
            mn = _f(c, "macro")
            if mn is not None and _t(mn) == "matches":
                m = re.match(r"\(\s*&?(\w+)\s*,", _t(c[-1]) if False else _t(_named(c)[-1]) if _named(c) else "")
                if m:
                    return {m.group(1): KINDS}, {}
        return {}, {}

    def _gname(self, n):
        """Name (including fields) of the variable at the core of an expression: &x, x.as_str(), q.name.clone() ..."""
        for _ in range(6):
            if n is None:
                return None
            if n.type in ("reference_expression", "parenthesized_expression"):
                k = _named(n)
                n = k[-1] if k else None
            elif n.type == "identifier":
                return _t(n)
            elif n.type == "field_expression":
                return self.dotted(n)
            elif n.type == "call_expression":
                fn = _f(n, "function")
                if fn is not None and fn.type == "field_expression" and _t(_f(fn, "field")) in PURE_METHODS | {"as_str", "as_ref", "to_string", "as_bytes"}:
                    n = _f(fn, "value")
                else:
                    return None
            else:
                return None
        return None

    @staticmethod
    def _apply_clean(env, mapping):
        for k, kinds in mapping.items():
            cur = env.get(k, V_OTHER)
            kinds = frozenset(kinds)
            if "path?" in kinds:
                kinds = (kinds - {"path?"}) | ({"path"} if ("canon",) in cur[3] or "canon" in cur[3] else set())
            env[k] = (CONST, KINDS, NOP, cur[3]) if kinds == KINDS else (cur[0], cur[1] | kinds, cur[2], cur[3])

    def _if(self, n, env):
        cond = _f(n, "condition")
        self.eval(cond, env)
        e1, e2 = dict(env), dict(env)
        if cond is not None and cond.type == "let_condition":
            self._bind_pattern(_f(cond, "pattern"), self.eval(_f(cond, "value"), env), e1)
        tclean, fclean = self._guards(cond, env)
        self._apply_clean(e1, tclean)
        self._apply_clean(e2, fclean)
        cons, alt = _f(n, "consequence"), _f(n, "alternative")
        v1 = self._block(cons, e1) if cons is not None else V_CONST
        v2 = V_CONST
        if alt is not None:
            k = _named(alt)
            v2 = self._block(k[0], e2) if k and k[0].type == "block" else (self.eval(k[0], e2) if k else V_CONST)
        t1, t2 = self._terminates(cons), alt is not None and self._terminates(_named(alt)[0] if _named(alt) else None)
        new = e2 if (t1 and not t2) else e1 if (t2 and not t1) else self._merge(e1, e2, env)
        env.clear()
        env.update(new)
        return join([v1, v2])

    def _match(self, n, env):
        sv = self.eval(_f(n, "value"), env)
        body = _f(n, "body")
        outs, vals, pre = [], [], dict(env)
        for arm in (_named(body) if body is not None else []):
            if arm.type != "match_arm":
                continue
            e = dict(env)
            pat = _f(arm, "pattern")
            self._bind_pattern(pat, sv, e)
            guard = None
            if pat is not None and pat.type == "match_pattern":
                for c in _named(pat):
                    if c.type == "condition":
                        pass
            v = self.eval(_f(arm, "value"), e)
            vals.append(v)
            outs.append(e)
        for o in outs:
            env.update(self._merge(env, o, pre))
        return join(vals) if vals else V_CONST

    def _loop(self, n, env):
        t = n.type
        itv = V_OTHER
        if t == "for_expression":
            itv = self.eval(_f(n, "value"), env)
        elif t == "while_expression":
            cond = _f(n, "condition")
            if cond is not None:
                self.eval(cond, env)
        passes = 2 if self.loop_depth < 2 else 1
        self.loop_depth += 1
        cur = dict(env)
        for _ in range(passes):
            e = dict(cur)
            if t == "for_expression":
                self._bind_pattern(_f(n, "pattern"), itv, e)
            elif t == "while_expression" and _f(n, "condition") is not None and _f(n, "condition").type == "let_condition":
                self._bind_pattern(_f(_f(n, "condition"), "pattern"), self.eval(_f(_f(n, "condition"), "value"), e), e)
            body = _f(n, "body")
            if body is not None:
                self._block(body, e)
            cur = self._merge(cur, e, env)
        self.loop_depth -= 1
        env.clear()
        env.update(cur)
        return V_OTHER

    # ----------------------------------------------------------- macros
    def _macro_args(self, n):
        """Re-analyze the arguments of a macro as call arguments; returns (arguments_node, offset)."""
        key = (n.start_byte, n.end_byte)
        if key in self.macro_cache:
            return self.macro_cache[key]
        tt = None
        for c in n.children:
            if c.type == "token_tree":
                tt = c
        res = (None, None)
        if tt is not None:
            inner = tt.text.decode("utf-8", "ignore")[1:-1]
            prefix = "\n" * tt.start_point[0]
            src = f"{prefix}fn __m() {{ __macro({inner}); }}"
            try:
                tr = _parse(src)
                fnb = _f(tr.root_node.children[0], "body")
                call = _named(_named(fnb)[0])[0] if fnb is not None and _named(fnb) else None
                if call is not None and call.type == "call_expression":
                    res = (_f(call, "arguments"), tr)
            except Exception as exc:
                log.debug("Could not re-parse macro arguments in %s (%s: %s); the macro will be skipped.",
                          self.rel_path, type(exc).__name__, exc)
                res = (None, None)
        self.macro_cache[key] = res
        return res

    def _macro(self, n, env):
        mn = _f(n, "macro")
        name = _t(mn) if mn is not None else ""
        short = name.split("::")[-1]
        rn = self.resolve(name) if "::" not in name else name
        argn, _tree = self._macro_args(n)
        args = _named(argn) if argn is not None else []
        if short in ("query", "query_as", "query_scalar", "query_file", "query_unchecked") and "sqlx" in (rn or name):
            for a in args[1:] if short == "query_as" else args[1:]:
                self.eval(a, env)
            return V_CONST   # checked at compile time
        if short == "vec" and argn is not None:
            vals = [self.eval(a, env) for a in args]
            return join(vals) if vals else V_CONST
        vals = []
        fmt = None
        for a in args:
            if fmt is None and a.type in ("string_literal", "raw_string_literal"):
                fmt = a
            if a.type == "assignment_expression":
                v = self.eval(_f(a, "right"), env)
                nm = _t(_f(a, "left"))
                env[nm] = v
                vals.append(v)
            else:
                vals.append(self.eval(a, env))
        if fmt is not None:   # inline arguments {name} / {name:?}
            ftxt = _t(fmt)
            for m in re.finditer(r"\{([A-Za-z_]\w*(?:\.\w+)*)(?::[^}]*)?\}", ftxt):
                root = m.group(1)
                v = env.get(root)
                if v is None:
                    v = self._sens_wrap(root.split(".")[-1], V_OTHER)
                vals.append(self._sens_wrap(root.split(".")[-1], v))
        v = join(vals) if vals else V_CONST
        if short in FMT_MACROS or short in LOG_MACROS:
            if short != "format":
                self._log_sink(n, short, vals, v, fmt, args, env)
        if short in ("format", "format_args"):
            sk = self._skeleton(n)
            if re.match(r"http://[^\x00{]", sk, re.I) and not PRIVATE_HOST.match(re.sub(r"^http://", "", sk, flags=re.I)):
                v = (v[0], v[1], v[2], v[3] | {("http", _line(n))})
            if v[0] == TAINT and "xss" not in v[1] and "\x00" in sk and HTML_RE.search(sk):
                self._hit("xss", "HTML built from user data", v, n, only_confirmed=True)
            if short == "format" and SQL_RE.search(sk) and (v[0] > CONST or "sens" in v[3]):
                v = (v[0], v[1], v[2], v[3] | {("built", _line(n))})
        return v

    def _log_sink(self, n, short, vals, v, fmt, args, env):
        ftxt = _t(fmt) if fmt is not None else ""
        if short in ("write", "writeln") and args:
            dest = _t(args[0])
            if not re.search(r"stdout|stderr|log|file|writer|\bout\b|handle|stream|\bw\b", dest, re.I) or re.match(r"^\s*(&mut\s+)?(f|fmt|formatter)\s*$", dest):
                return   # write to a Formatter (Display/Debug) or a buffer: not a log
            vals = vals[1:]
            v = join(vals) if vals else V_CONST
        debug_fmt = ":?" in ftxt or ":#?" in ftxt or bool(re.search(r"=\s*\?", _t(n)))
        if v[0] == TAINT and short not in ("assert", "assert_eq", "assert_ne", "debug_assert", "debug_assert_eq", "debug_assert_ne", "panic", "dbg", "unreachable", "todo", "unimplemented"):
            vv = (v[0], v[1] | ({"log"} if debug_fmt else set()), v[2], v[3])
            self._hit("log", short + "!", vv, n)
        if "sens" in v[3]:
            self._hit("clog", short + "!", v, n, need="sens")

    def _skeleton(self, n):
        n = n
        if n.type == "macro_invocation":
            argn, _t2 = self._macro_args(n)
            for a in (_named(argn) if argn is not None else []):
                if a.type in ("string_literal", "raw_string_literal"):
                    return re.sub(r"\{[^}]*\}", "\x00", _t(a)[1:-1])
            return ""
        if n.type == "string_literal":
            return _t(n)[1:-1]
        if n.type == "reference_expression":
            k = _named(n)
            return self._skeleton(k[-1]) if k else ""
        if n.type == "call_expression":
            fn = _f(n, "function")
            if fn is not None and fn.type == "field_expression":
                return self._skeleton(_f(fn, "value"))
            args = _named(_f(n, "arguments")) if _f(n, "arguments") is not None else []
            if fn is not None and args and args[0].type == "string_literal" and _t(fn).endswith(("String::from", "::from", "to_string")):
                return _t(args[0])[1:-1]
            return ""
        if n.type == "binary_expression" and _t(_f(n, "operator")) == "+":
            return self._skeleton(_f(n, "left")) + (self._skeleton(_f(n, "right")) or "\x00")
        return ""

    # ----------------------------------------------------------- calls
    def _is_command_chain(self, n, env):
        """True if the expression is a chain that starts from Command::new(...) (or from a Command variable)."""
        while n is not None:
            if n.type == "identifier":
                return bool(env.get(("cmd", _t(n))))
            if n.type == "call_expression":
                fn = _f(n, "function")
                if fn is None:
                    return False
                if fn.type == "field_expression":
                    n = _f(fn, "value")
                    continue
                rn = self.resolve(self.dotted(fn))
                return self.sig2(rn) == "Command::new"
            if n.type in ("reference_expression", "parenthesized_expression", "try_expression", "await_expression"):
                k = _named(n)
                n = k[-1] if k else None
                continue
            if n.type == "field_expression":
                n = _f(n, "value")
                continue
            return False
        return False

    def _chain_has(self, n, pattern):
        txt = _t(n)
        return bool(re.search(pattern, txt))

    def _shell_command(self, n):
        """Is the chain 'sh -c' / 'cmd /C'?"""
        txt = _t(n)
        return bool(re.search(r'Command::new\(\s*"(?:/bin/)?(?:sh|bash|zsh|cmd(?:\.exe)?|powershell|pwsh)"\s*\)', txt) and
                    re.search(r'"(-c|/[cC]|-Command)"', txt))

    def _call(self, n, env):
        fn = _f(n, "function")
        argn = _f(n, "arguments")
        args = _named(argn) if argn is not None else []
        fnu = fn
        if fn is not None and fn.type == "generic_function":
            fnu = _f(fn, "function")
        attr, recv_n, recv = None, None, None
        pn = self.dotted(fnu) if fnu is not None else None
        rn = self.resolve(pn) if pn and fnu.type != "field_expression" else None
        if fnu is not None and fnu.type == "field_expression":
            recv_n = _f(fnu, "value")
            attr = _t(_f(fnu, "field"))
            recv = self.eval(recv_n, env)
        elif fnu is not None and fnu.type not in ("identifier", "scoped_identifier"):
            recv = self.eval(fnu, env)
        # closure as argument: the parameters receive the value of the receiver
        vals = []
        for a in args:
            if a.type == "closure_expression":
                cv = recv if recv is not None else V_OTHER
                if attr in ("map", "and_then", "then", "and") and recv_n is not None and re.search(r"warp::(path::param|query|body|header|cookie)|path!\(", _t(recv_n)):
                    cv = V_TAINT
                self._run_function(a, None, None, self.report, env, closure_val=cv)
                vals.append(V_CONST)
            else:
                vals.append(self.eval(a, env))
        self._sinks(n, fnu, rn, attr, recv_n, recv, args, vals, env)
        allv = vals
        # --- sources
        sg = self.sig2(rn)
        last = (rn or attr or "").split("::")[-1]
        if rn and rn.endswith(("env::args", "env::args_os", "env::var", "env::var_os", "env::vars", "io::stdin", "io::read_to_string", "stdin")):
            return V_LOCAL
        if rn and sg in ("reqwest::get", "blocking::get", "ureq::get", "ureq::post", "surf::get", "isahc::get", "attohttpc::get"):
            return V_TAINT
        if attr in ("read_line", "read_to_string", "read_to_end", "recv", "recv_from", "read_exact") and recv is not None:
            if recv[0] >= OTHER or attr in ("read_line",):
                return V_LOCAL if attr in ("read_line", "read_to_string") and not re.search(r"(?i)stream|socket|tcp|conn|client|body", _t(recv_n or fn)) else V_TAINT
        if attr in ("text", "bytes", "json", "send", "body", "chunk") and recv is not None and recv[0] == TAINT:
            return V_TAINT
        if attr in ("send", "text", "bytes", "json") and recv_n is not None and re.search(r"\b(reqwest|Client|ureq|surf|isahc|attohttpc)\b", _t(recv_n)) \
                and re.search(r"\.(get|post|put|delete|patch|head|request)\(", _t(recv_n)):
            return V_TAINT
        # --- sanitizers
        san = SAN_CALLS.get(sg)
        if san:
            base = join(allv)
            return (base[0], base[1] | frozenset(san), base[2], base[3]) if base[0] else V_CONST
        if attr in SAN_METHODS:
            sm = SAN_METHODS[attr]
            if sm == "NUM":
                return V_CONST
            base = join(([recv] if recv else []) + allv)
            return (base[0], base[1] | frozenset(sm), base[2], base[3]) if base[0] else base
        if attr == "parse" and fnu is not None:
            gt = fn.type == "generic_function"
            targ = _t(_f(fn, "type_arguments")) if gt else ""
            base = recv if recv is not None else V_OTHER
            if gt and _is_num_type(targ.strip("<>")):
                return (base[0], base[1] | INJ_SAFE, base[2], base[3] - {"sens"}) if base[0] else base
            if base[0] and not gt:
                pass
        if attr in ("min", "clamp") and recv is not None and any(a.type in ("integer_literal",) or (a.type == "identifier" and _t(a).isupper()) for a in args):
            return (recv[0], recv[1] | frozenset({"alloc"}), recv[2], recv[3])
        if rn and rn.endswith(("cmp::min", "cmp::max")) and any(a.type == "integer_literal" or (a.type == "identifier" and _t(a).isupper()) for a in args):
            base = join(allv)
            return (base[0], base[1] | frozenset({"alloc"}), base[2], base[3])
        if attr == "canonicalize" or sg in ("fs::canonicalize",):
            base = join(([recv] if recv else []) + allv)
            return (base[0], base[1], base[2], base[3] | {"canon"})
        if attr in ("replace", "replacen") and args and args[0].type in ("string_literal", "char_literal") and re.search(r"\\n|\\r", _t(args[0])):
            base = join(([recv] if recv else []) + allv)
            return (base[0], base[1] | frozenset({"log"}), base[2], base[3]) if base[0] else base
        if (attr in ("fill", "fill_bytes", "try_fill", "try_fill_bytes") or sg in ("getrandom::fill", "getrandom::getrandom", "rand::fill")) and args:
            for a in args:
                tgt = a
                if tgt.type == "reference_expression":
                    kk = _named(tgt)
                    tgt = kk[-1] if kk else tgt
                if tgt.type == "identifier":
                    env[_t(tgt)] = V_OTHER   # filled with random bytes: no longer a fixed value
        if rn and rn.endswith(("mem::zeroed",)):
            return (CONST, KINDS, NOP, frozenset({("hc", _line(n))}))
        # --- cookies, hashes, builders
        if rn and self.sig2(rn) in COOKIE_CTORS:
            return (CONST, KINDS, NOP, frozenset({("insec", _line(n))}) | join(allv)[3])
        if attr == "secure" and recv is not None and args:
            if ("T",) in vals[0][3]:
                return (recv[0], recv[1], recv[2], frozenset(x for x in recv[3] if not (isinstance(x, tuple) and x[0] == "insec")))
            return recv
        if attr in ("build", "finish") and recv is not None and any(isinstance(x, tuple) and x[0] == "insec" for x in recv[3]):
            return (recv[0], recv[1], recv[2], frozenset(x for x in recv[3] if not (isinstance(x, tuple) and x[0] == "insec")))
        if attr in COOKIE_PRESERVING and recv is not None and any(isinstance(x, tuple) and x[0] == "insec" for x in recv[3]):
            return recv
        if attr == "set_secure" and recv_n is not None and recv_n.type == "identifier" and args:
            nm = _t(recv_n)
            cur = env.get(nm)
            if cur is not None:
                keep = frozenset(x for x in cur[3] if not (isinstance(x, tuple) and x[0] == "insec"))
                env[nm] = (cur[0], cur[1], cur[2], keep if ("T",) in vals[0][3] else keep | {("insec", _line(n))})
            return V_CONST
        # --- local / global functions
        key, off = self._local_key(fnu, rn)
        if key in self.summaries:
            return self._sens_wrap(key.split(".")[-1], self._apply_summary(self.summaries[key], key, off, n, vals))
        gk = self._global_key(rn)
        if gk:
            return self._apply_summary(self.project.summaries[gk], gk[1], 0, n, vals)
        # --- default
        if attr in ("expect", "wrap_err", "context", "with_context", "map_err", "ok_or", "ok_or_else", "expect_err", "unwrap_or_else", "wrap_err_with") and recv is not None:
            return recv
        if attr in ("send", "text", "json", "bytes", "status", "headers", "chunk") and recv is not None:
            return (recv[0], recv[1], recv[2], frozenset(x for x in recv[3] if x != "sens" and not (isinstance(x, tuple) and x[0] in ("hc", "insec"))))
        if attr in ("render", "render_once", "render_to_string", "render_with", "render_sync"):
            base = join(([recv] if recv else []) + allv)
            return (base[0], base[1] | frozenset({"xss"}), base[2], base[3]) if base[0] else base
        if attr is not None:
            if attr in PURE_METHODS or attr in ("push", "extend"):
                res = join(([recv] if recv else []) + allv)
                return res
            res = join(([recv] if recv else []) + allv)
            return V_OTHER if res[0] == CONST and not res[3] else res
        res = join(allv)
        nm = (rn or "").split("::")[-1]
        if nm not in ("from", "try_from", "new", "from_slice", "from_static", "from_utf8", "default") and \
                sg.split("::")[-1] not in ("from", "try_from", "new", "from_slice", "from_static", "from_utf8", "default", "Some", "Ok", "Err", "from_str"):
            res = (res[0], res[1], res[2], frozenset(x for x in res[3] if not (isinstance(x, tuple) and x[0] == "hc")))
        if nm in ("String::from", "from", "new", "default", "to_string", "from_utf8", "from_utf8_lossy", "Some", "Ok", "Err", "Box::new", "Arc::new",
                  "Rc::new", "Path::new", "PathBuf::from", "format", "from_str") or sg in ("String::from", "PathBuf::from", "Path::new", "OsString::from",
                                                                                         "String::from_utf8", "String::from_utf8_lossy", "Some", "Ok", "Box::new"):
            return res
        if res[0] == CONST and not res[3] and len(args) == 0:
            return self._sens_wrap(nm, V_OTHER)
        return self._sens_wrap(nm, res) if res[0] != CONST or res[3] else self._sens_wrap(nm, V_OTHER)

    # ----------------------------------------------------------- sinks
    def _arg(self, spec, vals):
        if spec == "any":
            return join(vals) if vals else None
        return vals[spec] if len(vals) > spec else None

    def _sinks(self, n, fn, rn, attr, recv_n, recv, args, vals, env):
        at_m = _f(fn, "field") if fn is not None and fn.type == "field_expression" else n
        sg = self.sig2(rn)
        # --- by path
        spec = SIG_SINKS.get(sg) or (SIG_SINKS.get(rn.split("::")[-1]) if rn and "::" not in rn else None)
        if spec:
            kind, a = spec
            v = self._arg(a, vals)
            at = args[a] if isinstance(a, int) and len(args) > a else n
            if v is not None:
                if kind == "ssrf":
                    sk = self._skeleton(args[0]) if args else ""
                    host_fixed = bool(re.match(r"https?://[^/\x00]+/", sk)) or (args and args[0].type == "identifier" and env.get(("hostfixed", _t(args[0]))))
                    if not host_fixed:
                        self._hit("ssrf", rn, v, at)
                    self._nohttps(v, n, args)
                    self._ctrans(v, n, args[:1])
                elif kind == "xss":
                    self._hit("xss", rn or "Html", v, at)
                else:
                    self._hit(kind, rn, v, at)
                if kind == "sql" and "sens" in v[3] and any(isinstance(x, tuple) and x[0] == "built" for x in v[3]):
                    self._hit("cstore", rn, v, at, need="sens")
        # --- Command: arguments
        if attr in ("arg", "args") and recv_n is not None and self._is_command_chain(recv_n, env):
            v = join(vals) if vals else None
            if v is not None:
                self._hit("cmd", "Command." + attr, v, args[0] if args else n)
        if attr in ("arg", "args", "env", "envs", "current_dir") and False:
            pass
        # --- SQL and DB
        if attr in SQL_METHODS and args:
            v = vals[0]
            sk = self._skeleton(args[0])
            built = any(isinstance(x, tuple) and x[0] == "built" for x in v[3]) or self._is_building(args[0], env) or "\x00" in sk
            sqlish = bool(SQL_RE.search(sk)) or any(isinstance(x, tuple) and x[0] == "built" for x in v[3])
            lvl = CONST if "sql" in v[1] else v[0]
            tgt = args[0]
            dbrecv = bool(recv_n is not None and re.search(r"(?i)conn|connection|\bdb\b|pool|client|stmt|\btx\b|transaction|sqlx|postgres|rusqlite|mysql|sqlite|database|session", _t(recv_n)))
            if lvl == TAINT and (sqlish or built or (dbrecv and attr in ("query", "execute", "prepare", "query_one", "query_row", "fetch", "fetch_one", "fetch_all", "batch_execute", "execute_batch", "simple_query", "query_drop", "query_iter", "query_first", "query_opt", "query_fold", "exec", "query_map", "fetch_optional", "query_scalar"))):
                self._hit("sql", f".{attr}", v, tgt)
            elif lvl > CONST and built and sqlish:
                self._hit("sql", f".{attr}", v, tgt)
            elif lvl > CONST:
                self._hit("sql", f".{attr}", v, tgt, record_only=True)
            if "sens" in v[3] and (sqlish or attr in ("execute", "query", "execute_batch")) and \
                    re.search(r"(?i)insert|update|replace|values", sk):
                self._hit("cstore", f".{attr}", v, tgt, need="sens")
        if attr == "bind" and recv_n is not None and re.search(r"\bsqlx::query|query_as|query_scalar|\.bind\(", _t(recv_n)) and args:
            if "sens" in vals[0][3]:
                self._hit("cstore", ".bind", vals[0], args[0], need="sens")
        # --- HTTP client requests
        if attr in REQ_METHODS and recv_n is not None and args and re.search(r"\b(reqwest|Client|client|ureq|isahc|surf|attohttpc)\b", _t(recv_n)) and \
                not (recv is not None and False):
            idx = 1 if attr == "request" else 0
            if len(args) > idx:
                v = vals[idx]
                sk = self._skeleton(args[idx])
                if not (re.match(r"https?://[^/\x00]+/", sk) or (args[idx].type == "identifier" and env.get(("hostfixed", _t(args[idx]))))):
                    self._hit("ssrf", f".{attr}", v, args[idx])
                self._nohttps(v, n, args[idx:idx + 1])
                self._ctrans(v, n, args[idx:idx + 1])
        if attr in ("body", "json", "form", "text", "multipart") and recv_n is not None and args and re.search(r"\b(reqwest|Client|client|ureq|http)\b", _t(recv_n)):
            v = vals[0]
            if "sens" in v[3]:
                u = re.search(r'"(http://[^"]+)"', _t(recv_n))
                if u and not PRIVATE_HOST.match(re.sub(r"^https?://", "", u.group(1))):
                    self._hit("ctrans", f".{attr}", v, args[0], need="sens")
        # --- miscellaneous methods
        ms = METHOD_SINKS.get(attr) if attr else None
        if ms and args:
            kind, a = ms
            v = self._arg(a, vals)
            if v is not None and not (kind == "alloc" and attr in ("alloc", "alloc_zeroed", "allocate", "allocate_zeroed", "realloc", "grow", "shrink") and
                                      not re.search(r"System|Global|alloc|Allocator", _t(recv_n) if recv_n is not None else "")):
                self._hit(kind, f".{attr}", v, args[a] if isinstance(a, int) and len(args) > a else n)
        if attr in ("header", "append_header", "insert_header", "set_header") and args and len(args) >= 1:
            txt = _t(args[0])
            if re.search(r"(?i)location", txt):
                v = join(vals)
                self._hit("redirect", ".header(Location)", v, args[0])
        if attr == "body" and recv_n is not None and args and re.search(r"(?i)content_type\(\s*\"text/html|ContentType::html|mime::TEXT_HTML", _t(recv_n)):
            self._hit("xss", ".body (text/html)", vals[0], args[0])
        if attr in ("log_expect", "log_unwrap", "log_err", "log_ok", "log_warn", "log_error", "log_info", "log_debug"):
            vv = join(([recv] if recv else []) + list(vals))
            if "sens" in vv[3]:
                self._hit("clog", "." + attr, vv, at_m, need="sens")
        # --- cookie
        if attr in ("build", "finish") and recv is not None and any(isinstance(x, tuple) and x[0] == "insec" for x in recv[3]):
            self._plain("cookie", at_m)
        if attr in COOKIE_SINK_METHODS and args and any(isinstance(x, tuple) and x[0] == "insec" for x in vals[0][3]) and \
                not (attr in ("insert", "append", "add") and recv_n is not None and re.search(r"\b(HashMap|HashSet|Vec|map|set|vec)\b", _t(recv_n)) and False):
            self._plain("cookie", at_m)
        if sg in ("ServerSession::new", "CookieSession::new") and args and any(isinstance(x, tuple) and x[0] == "insec" for x in vals[0][3]):
            self._plain("cookie", n)
        # --- TLS
        if attr in ("danger_accept_invalid_certs", "danger_accept_invalid_hostnames", "danger_accept_invalid_cert", "danger_accept_invalid_host") and args:
            if not (args[0].type == "boolean_literal" and _t(args[0]) == "false"):
                self._plain("cert", at_m)
        if attr == "set_verify" and args and re.search(r"SslVerifyMode::NONE|VerifyMode::NONE", _t(args[0])):
            self._plain("cert", at_m)
        if attr == "dangerous" and recv_n is not None and re.search(r"(?i)rustls|ClientConfig|builder", _t(recv_n)):
            self._plain("cert", at_m)
        # --- cryptography
        self._crypto(n, rn, sg, attr, recv_n, recv, args, vals, at_m)

    def _is_building(self, node, env):
        node = node
        if node.type in ("reference_expression", "parenthesized_expression"):
            k = _named(node)
            node = k[-1] if k else node
        if node.type == "macro_invocation":
            mn = _f(node, "macro")
            return mn is not None and _t(mn).split("::")[-1] == "format"
        if node.type == "call_expression":
            fn = _f(node, "function")
            if fn is not None and fn.type == "field_expression":
                return self._is_building(_f(fn, "value"), env) or _t(_f(fn, "field")) in ("replace",) and False
            return False
        if node.type == "binary_expression" and _t(_f(node, "operator")) == "+":
            return True
        if node.type == "identifier":
            return bool(env.get(("built", _t(node))))
        return False

    def _nohttps(self, v, n, args):
        for fl in v[3]:
            if isinstance(fl, tuple) and fl[0] == "http" and self.report:
                self._plain("nohttps", n if not args else args[0], "unknown")
                break
        if args:
            sk = self._skeleton(args[0])
            if re.match(r"http://[^\x00{]", sk, re.I) and not PRIVATE_HOST.match(re.sub(r"^http://", "", sk, flags=re.I)):
                self._plain("nohttps", args[0], "unknown")

    def _ctrans(self, v, n, args):
        if "sens" in v[3]:
            self._hit("ctrans", "HTTP request", v, args[0] if args else n, need="sens")

    def _crypto(self, n, rn, sg, attr, recv_n, recv, args, vals, at_m):
        full = rn or ""
        txt_recv = _t(recv_n) if recv_n is not None else ""
        # weak encryption algorithms
        base = full.split("::")
        ftxt = _t(n.child_by_field_name("function")) if n.type == "call_expression" and n.child_by_field_name("function") is not None else ""
        if sg.endswith(("::new", "::new_from_slice", "::new_from_slices", "::from_key", "::new_with_eff_key_len", "::new_with_key_len")) or \
                attr in ("new_from_slice", "new_from_slices"):
            if WEAK_CIPHERS.search(full) or WEAK_CIPHERS.search(ftxt) or (attr in ("new_from_slice", "new_from_slices") and WEAK_CIPHERS.search(txt_recv)):
                self._plain("algo", n)
        gen_txt = _t(n)
        if attr in ("new_from_slices", "new_from_slice", "new") and WEAK_CIPHERS.search(txt_recv + " " + full) is None and \
                re.search(r"::<\s*(des::)?(Des|TdesEee3|TdesEde3|TdesEee2|TdesEde2|Rc2|Rc4|Blowfish)\b", gen_txt):
            self._plain("algo", n)
        if re.search(r"Cipher::(des_\w+|rc4|bf_\w+|aes_\d+_ecb|rc2_\w+|cast5_\w+|idea_\w+|seed_\w+)", full) or \
                re.search(r"\b\w*Ecb\w*(Encryptor|Decryptor)\b|ecb::(Encryptor|Decryptor)", full) or \
                (sg.startswith("Ecb") or "::ecb::" in full.lower() and sg.endswith("::new")):
            self._plain("algo", n)
        # hashes of sensitive data
        is_hash_call = sg.split("::")[-1] in ("digest", "compute", "hash", "chain_update", "update", "chain", "new_with_prefix", "digest_str") or \
            attr in ("update", "chain_update", "chain", "digest", "input", "new_with_prefix")
        if is_hash_call:
            hashy = HASH_TYPES.search(full) or HASH_TYPES.search(txt_recv) or (attr in ("update", "chain_update", "chain", "input") and recv_n is not None and False)
            if hashy and not STRONG_PW.search(full + txt_recv):
                for v, a in zip(vals, args):
                    if "sens" in v[3]:
                        self._hit("pwhash", rn or ("." + (attr or "")), v, a, need="sens")
                        break
        # cipher / MAC / KDF constructors: every constant argument is a key, IV or nonce
        if sg.split("::")[-1] in ("new", "from_slice", "from", "new_from_slice", "new_from_slices", "from_key_nonce", "init") and \
                re.search(r"(?i)(Encryptor|Decryptor|Cipher|Aes\d*|Rabbit|ChaCha|Salsa|Hmac|Cmac|Gcm|Cbc|Ctr|Cfb|Ofb|Ecb|Xts|Camellia|Aria|Sm4|Twofish|Poly1305|"
                          r"Aead|Key(?!Value)|Nonce|Iv\b|Kdf|Pbkdf|Hkdf|Rc4|Des\b|Blowfish)", full):
            for v, a in zip(vals, args):
                self._hc(v, a)
        # hardcoded keys, IVs, salts
        idxs = KEY_SIGS.get(sg) or (KEY_METHODS.get(attr) if attr else None) or (KEY_METHODS.get(sg.split("::")[-1]) if sg.split("::")[-1] in KEY_METHODS else None)
        if sg.split("::")[-1] == "from_slice" and "::" in (rn or "") and not re.search(r"(Key|Nonce|GenericArray|Iv|Salt)", rn or ""):
            idxs = None
        if idxs:
            for i in idxs:
                if i < len(vals):
                    self._hc(vals[i], args[i])
        if attr in ("encrypt", "decrypt", "encrypt_in_place", "decrypt_in_place", "seal", "open") and args:
            if re.search(r"(?i)aes|chacha|cipher|aead|gcm|crypt", txt_recv) or True:
                v0 = vals[0]
                if attr in ("encrypt", "decrypt") and len(vals) >= 2 and re.search(r"(?i)\b(nonce|iv)\b|Nonce::from", _t(args[0])):
                    self._hc(v0, args[0])
                elif re.search(r"(?i)encrypt|decrypt", attr) and len(args) >= 2 and re.search(r"(?i)\bkey\b|&\[", _t(args[1])) and False:
                    self._hc(vals[1], args[1])

    def _hc(self, v, at):
        """Constant value used as a key/IV/nonce/salt: reported where the value was written."""
        if not self.report:
            return
        for fl in sorted([x for x in v[3] if isinstance(x, tuple) and x[0] == "hc"], key=lambda x: x[1]):
            sid, name, sev, cwe, what, rec, impact = PLAIN["hc"]
            self._add(sid, name, sev, "fixed", fl[1], what, rec, cwe, impact)


# ---------------------------------------------------------------------------
# Public API
# ---------------------------------------------------------------------------
def analyze_rust_source(rel_path, text):
    if not AVAILABLE or not rel_path.endswith(".rs"):
        return []
    a = None
    try:
        a = RustAnalyzer(rel_path, _parse(text))
        return a.run()
    except RecursionError:
        log.warning("Rust file '%s' is too deeply nested for the analyzer (recursion limit reached); "
                    "returning the partial findings collected so far.", rel_path)
        return a.findings if a else []
    except Exception as exc:
        log.error("Unexpected error while analyzing Rust file '%s' (%s: %s). Returning the partial findings "
                  "collected so far; the file may be malformed or use syntax the analyzer does not support. "
                  "Please report this together with the offending source file.",
                  rel_path, type(exc).__name__, exc)
        return a.findings if a else []


MAX_PROJECT_BYTES = 20 * 1024 * 1024
MAX_PROJECT_FILES = 2000


def analyze_rust_project(sources):
    """sources: {relative_path: text}. Returns {path: [findings]}, following the data across modules as well."""
    if not AVAILABLE:
        return {}
    if len(sources) > MAX_PROJECT_FILES or sum(len(t) for t in sources.values()) > MAX_PROJECT_BYTES:
        log.warning("Rust project is too large for cross-module analysis (%d files, %d bytes; limits: %d files, %d bytes). "
                    "Falling back to per-file analysis: data flowing between modules will not be tracked.",
                    len(sources), sum(len(t) for t in sources.values()), MAX_PROJECT_FILES, MAX_PROJECT_BYTES)
        return {p: analyze_rust_source(p, t) for p, t in sources.items()}
    proj, analyzers, out = Project(), {}, {}
    for rel, text in sources.items():
        try:
            a = RustAnalyzer(rel, _parse(text), proj)
        except Exception as exc:
            log.error("Could not parse Rust file '%s' (%s: %s). The file was skipped by the AST engine; "
                      "check that it is valid Rust source and that tree-sitter-rust is installed correctly.",
                      rel, type(exc).__name__, exc)
            out[rel] = []
            continue
        proj.add_module(a.crate, a.modpath, a.mod)
        proj.analyzers[a.mod] = a
        analyzers[rel] = a
    try:
        for a in analyzers.values():
            a.prepare()
        for _ in range(3):
            if not any([a.update_summaries() for a in analyzers.values()]):
                break
        for rel, a in analyzers.items():
            out[rel] = a.finish()
            a.tree = a.root = None
    except Exception as exc:
        log.error("Cross-module analysis of the Rust project failed (%s: %s). Falling back to the partial findings "
                  "collected so far; results that depend on data flowing between modules may be missing.",
                  type(exc).__name__, exc)
        for rel, a in analyzers.items():
            out.setdefault(rel, a.findings)
    return out
