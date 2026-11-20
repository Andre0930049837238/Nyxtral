# -*- coding: utf-8 -*-
"""
php_engine.py
==============
Security engine for PHP (.php: classic applications, Laravel, Symfony, WordPress) built on a real parser (tree-sitter-php)
and data-flow analysis on top of the shared core in lang_core.py.

Vulnerability classes covered: command injection (exec, system, backticks...), code execution (eval, assert, create_function,
variable functions, call_user_func), SQL injection (mysqli, PDO, WordPress wpdb, Laravel DB/whereRaw, Doctrine), file inclusion
and path traversal, XSS (echo, print, printf), SSRF, open redirect, deserialization (unserialize), XXE (LIBXML_NOENT), weak
cryptography (md5, sha1, mcrypt, ECB, static IV), disabled TLS verification (cURL), weak random numbers for sensitive data,
permissive cookies and CORS, debug mode left on, phpinfo, cleartext FTP, extract/parse_str on input.

Known limitations: no type checker (methods are recognized by name), no support for Blade/Twig templates or .env files.
The code under analysis is never executed.
"""

import logging
import re

import lang_core as C
from lang_core import Sink, Fixed, V_TAINT, V_LOCAL, txt, walk

log = logging.getLogger(__name__)

try:
    from tree_sitter import Language, Parser
    import tree_sitter_php as _tsp
    _PARSER = Parser(Language(_tsp.language_php()))
    AVAILABLE = True
except Exception as _exc:                           # pragma: no cover
    AVAILABLE = False
    log.warning(
        "PHP AST analysis is disabled: tree-sitter or tree-sitter-php could not be loaded (%s: %s). "
        "Only pattern-based rules will run for .php files. Install the missing packages with: "
        "pip install tree-sitter tree-sitter-php", type(_exc).__name__, _exc)

SUPPORTED = (".php", ".phtml", ".inc")
MAX_PROJECT_BYTES = C.MAX_PROJECT_BYTES

RULES = {
    "AST-PHP-001": ("Command execution with untrusted data", "CRITICAL", "HIGH",
                    "{sink} executes a command that is partly built from external input or assembled at runtime.",
                    "Avoid the shell; if unavoidable, use escapeshellarg() on every argument and an allowlist of commands.", "CWE-78"),
    "AST-PHP-002": ("Code execution with untrusted data", "CRITICAL", "HIGH",
                    "{sink} executes as PHP code a text that comes from external input or is built at runtime.",
                    "Do not use eval/assert/create_function: use fixed functions and allowlists.", "CWE-95"),
    "AST-PHP-003": ("SQL injection", "CRITICAL", "HIGH",
                    "{sink} receives a query built from externally supplied data.",
                    "Use prepared statements (PDO::prepare, mysqli_prepare, \\$wpdb->prepare, Laravel bindings); never concatenation.", "CWE-89"),
    "AST-PHP-004": ("Inclusion or opening of externally chosen files", "CRITICAL", "HIGH",
                    "{sink} uses a path supplied by external input: any file (even a remote one) can be included or read.",
                    "Use an allowlist of files; never pass input to include/require; use basename() and realpath().", "CWE-98"),
    "AST-PHP-005": ("Unsanitized content written to the page (XSS)", "HIGH", "MEDIUM",
                    "{sink} writes externally supplied data to the page without sanitizing it.",
                    "Use htmlspecialchars($x, ENT_QUOTES, 'UTF-8') (or a template engine with automatic escaping).", "CWE-79"),
    "AST-PHP-006": ("Request to an externally controlled address (SSRF)", "HIGH", "MEDIUM",
                    "{sink} contacts an address supplied by external input, which may allow access to internal services.",
                    "Accept only hosts from an allowlist and block internal addresses.", "CWE-918"),
    "AST-PHP-007": ("Redirect to an externally controlled address", "MEDIUM", "LOW",
                    "{sink} redirects the user to an address chosen by external input.",
                    "Redirect only to internal paths or to hosts on an allowlist.", "CWE-601"),
    "AST-PHP-008": ("Insecure deserialization or XML parser with external entities", "HIGH", "MEDIUM",
                    "{sink} rebuilds objects or parses XML in a way that crafted input could execute code or read files.",
                    "Use json_decode instead of unserialize and do not pass LIBXML_NOENT; with unserialize, set allowed_classes => false.", "CWE-502"),
    "AST-PHP-009": ("Weak cryptographic algorithm", "MEDIUM", "MEDIUM",
                    "{sink} uses an algorithm, mode or initialization vector that is weak or fixed.",
                    "Use password_hash() for passwords, hash('sha256') or stronger, and openssl with AES-GCM and a random IV (random_bytes).", "CWE-327"),
    "AST-PHP-010": ("Certificate verification disabled", "HIGH", "HIGH",
                    "{sink}: the connection no longer verifies the identity of the remote peer.",
                    "Keep CURLOPT_SSL_VERIFYPEER = true and CURLOPT_SSL_VERIFYHOST = 2.", "CWE-295"),
    "AST-PHP-011": ("Insecure random numbers for sensitive data", "MEDIUM", "MEDIUM",
                    "{sink} is predictable, yet here it generates a value that looks like a secret ('{name}').",
                    "Use random_int() and random_bytes().", "CWE-330"),
    "AST-PHP-012": ("Insecure configuration (cookies, CORS, debug)", "MEDIUM", "MEDIUM",
                    "{what}",
                    "Set Secure/HttpOnly/SameSite on cookies, restrict CORS origins and disable debug mode in production.", "CWE-1004"),
    "AST-PHP-013": ("Dangerous or information-leaking function left enabled", "MEDIUM", "LOW",
                    "{sink} is a function that exposes information or uses insecure protocols.",
                    "Remove phpinfo() from production code and replace FTP with SFTP.", "CWE-200"),
    "AST-PHP-014": ("Variables created from external input", "HIGH", "MEDIUM",
                    "{sink} creates variables with names and values chosen by the user, which can overwrite internal variables.",
                    "Read only the expected fields, one by one.", "CWE-621"),
    "AST-PHP-015": ("Weak hash comparison", "MEDIUM", "MEDIUM",
                    "{what}",
                    "Compare hashes with hash_equals() and === (the '==' comparison treats '0e123' as a number).", "CWE-697"),
    "AST-PHP-016": ("Mass assignment: model created with every request field", "MEDIUM", "LOW",
                    "{sink} populates the model with every submitted field, so a user can set fields they should not.",
                    "Use \\$request->only([...]) or validated() with only the permitted fields.", "CWE-915"),
    "AST-PHP-018": ("Base conversion with loss of precision", "LOW", "LOW",
                    "{sink} loses precision with large numbers: values may come out wrong and become a security issue.",
                    "Use GMP (gmp_strval) or BCMath for large numbers.", "CWE-190"),
    "AST-PHP-017": ("LDAP without a password", "HIGH", "HIGH",
                    "{sink} connects to LDAP without a password (anonymous access).",
                    "Always pass valid credentials to ldap_bind.", "CWE-521"),
}

SENSITIVE = re.compile(r"(token|secret|passw|pwd|nonce|salt|session|csrf|otp|apikey|api_key|\bkey\b|_key|key_|\biv\b|cookie|auth)", re.I)
SQL_RE = re.compile(r"(?i)\b(select|insert\s+into|update\s+\w+\s+set|delete\s+from|drop\s+(table|database)|create\s+table|alter\s+table|truncate|where\s+\w+|order\s+by|union\s+select|from\s+\w+)\b")
HOST_FIXED = re.compile(r"^https?://[A-Za-z0-9.\-]+(:\d+)?(/|\?|$)")
SUPERGLOBALS = re.compile(r"^\$_(GET|POST|REQUEST|COOKIE|FILES|SERVER|SESSION)$")


def _fixed_host(eng, n):
    t = n
    while t is not None and t.type == "parenthesized_expression" and t.named_children:
        t = t.named_children[0]
    if t is None:
        return False
    if t.type in ("string", "encapsed_string") and LANG.expr(t)[0] == "const":
        return True
    x = t
    while x is not None and x.type == "binary_expression" and x.child_by_field_name("left") is not None:
        x = x.child_by_field_name("left")
    return x is not None and x.type in ("string", "encapsed_string") and bool(HOST_FIXED.match(LANG.literal(x) or ""))


class PhpLang(C.LangBase):
    ENGINE = "php_ast"
    EXTS = SUPPORTED
    RULES = RULES
    AVAILABLE = AVAILABLE
    CALL_TYPES = {"function_call_expression", "member_call_expression", "scoped_call_expression", "object_creation_expression",
                  "nullsafe_member_call_expression", "include_expression", "include_once_expression", "require_expression", "require_once_expression",
                  "shell_command_expression"}
    FUNC_TYPES = {"function_definition", "method_declaration"}
    STMT_TYPES = {"assignment_expression", "augmented_assignment_expression", "foreach_statement"}
    TEST_RE = re.compile(r"(^|/)_?(tests?|testdata|examples?|docs?|samples?)(/|$)|(Test|Tests)\.php$")
    TEST_QUIET = frozenset({"AST-PHP-010", "AST-PHP-011", "AST-PHP-012", "AST-PHP-013", "AST-PHP-015"})
    CLEAN_RE = re.compile(r"(htmlspecialchars|htmlentities|esc_html|esc_attr|esc_url|esc_js|wp_kses|strip_tags|escapeshellarg|escapeshellcmd|addslashes_NO|"
                          r"mysqli_real_escape_string|real_escape_string|pg_escape_string|esc_sql|quote|basename|realpath|filter_var|intval|floatval|absint|"
                          r"urlencode|rawurlencode|json_encode|sanitize_\w+|\be\b|e|isset|empty|is_\w+|ctype_\w+|in_array|array_key_exists)$")
    NUM_RE = re.compile(r"^(intval|floatval|doubleval|absint|round|floor|ceil|abs|strlen|count|sizeof|boolval|is_numeric|ctype_digit|\(int\)|\(float\))$")
    VALIDATE_RE = re.compile(r"(in_array|preg_match|ctype_\w+|is_numeric|filter_var|is_int|validate|isValid|startsWith|str_starts_with|strpos|file_exists_NO|array_key_exists|isset)")
    LEN_RE = re.compile(r"(strlen|count|min)$")
    SOURCE_CALLS = [
        (re.compile(r"^(getenv|filter_input|filter_input_array|getallheaders|apache_request_headers|file_get_contents\(php://input\))$"), V_TAINT),
        (re.compile(r"^(readline|fgets_stdin|stream_get_contents_NO)$"), V_LOCAL),
        (re.compile(r"\$(request|req)->(input|get|post|query|all|only|except|header|cookie|route|json|file|file_get_contents|getContent|getQueryString|"
                    r"getPathInfo|getRequestUri|get_param|get_params|get_json_params)$"), V_TAINT),
    ]
    SOURCE_MEMBERS = [(re.compile(r"^\$(argv)$"), V_LOCAL), (re.compile(r"^\$_(GET|POST|REQUEST|COOKIE|FILES)$"), V_TAINT),
                      (re.compile(r"^\$_SERVER$"), V_TAINT), (re.compile(r"^\$(request|req)->(query|request|headers|cookies|attributes|files|server|content)$"), V_TAINT)]
    SINKS = [
        Sink("AST-PHP-001", r"^(exec|system|passthru|shell_exec|popen|proc_open|pcntl_exec|mail_NO|expect_popen|ssh2_exec)$", None, audit="any"),
        Sink("AST-PHP-002", r"^(eval|assert|create_function|preg_replace_callback_NO|call_user_func|call_user_func_array|forward_static_call|"
                            r"array_map_NO|mb_ereg_replace_NO|assert_options_NO|register_shutdown_function_NO|ob_start_NO)$", (0,), audit="any"),
        Sink("AST-PHP-003", r"^(mysql_query|mysql_unbuffered_query|mysql_db_query|pg_query|pg_send_query|pg_prepare_NO|sqlite_query|sqlite_exec|sqlsrv_query_NO|"
                            r"mssql_query|oci_parse_NO|odbc_exec|odbc_prepare_NO|ibase_query|maxdb_query)$", None, audit=True),
        Sink("AST-PHP-003", r"^(mysqli_query|mysqli_real_query|mysqli_multi_query|mysqli_prepare|pg_query_NO|sqlsrv_query|oci_parse|mysqli_send_query)$", (1,), audit=True),
        Sink("AST-PHP-003", r"(->|::)(query|exec|multi_query|real_query|prepare|execute_NO|get_results|get_var|get_row|get_col|"
                            r"executeQuery|executeStatement|executeUpdate|createQuery|createNativeQuery|fetchAll|fetchOne|fetchAssociative|fetchAllAssociative|fetchRow|"
                            r"whereRaw|orderByRaw|selectRaw|havingRaw|groupByRaw|fromRaw|joinRaw|statement|unprepared|raw|select|insert|update|delete)$", (0,), audit=True),
        Sink("AST-PHP-004", r"^(include|include_once|require|require_once)$", (0,), audit="any"),
        Sink("AST-PHP-004", r"^(fopen|file_get_contents|file_put_contents|readfile|unlink|file|fread_NO|copy|rename|mkdir|rmdir|move_uploaded_file|opendir|scandir|"
                            r"highlight_file|show_source|parse_ini_file|touch|chmod_NO|glob|is_file|is_dir|file_exists|filesize|symlink|readlink|rmdir|fpassthru_NO|"
                            r"finfo_file|getimagesize|imagecreatefrom\w+|simplexml_load_file|DOMDocument::load|SplFileObject)$", (0,), skip_local=True),
        Sink("AST-PHP-005", r"^(printf|vprintf|print_r|var_dump_NO|die|exit|echo|print)$", (0,)),
        Sink("AST-PHP-006", r"^(curl_init|get_headers|fsockopen|pfsockopen|stream_socket_client|ftp_connect|gethostbyname_NO)$", (0,), exempt=_fixed_host),
        Sink("AST-PHP-006", r"^(SoapClient|SimpleXMLElement_NO)$", (0,), exempt=_fixed_host),
        Sink("AST-PHP-006", r"^(file_get_contents|fopen|readfile|copy|file|simplexml_load_file|get_meta_tags|imagecreatefromjpeg|imagecreatefrompng|imagecreatefromgif)$", (0,), exempt=_fixed_host),
        Sink("AST-PHP-006", r"(->|::)(get|post|put|delete|request|send|head|patch)$", (0, 1), exempt=_fixed_host),
        Sink("AST-PHP-006", r"^(wp_remote_get|wp_remote_post|wp_remote_request|wp_safe_remote_get|wp_safe_remote_post|wp_safe_remote_request|wp_safe_remote_head|wp_remote_head)$", (0,), exempt=_fixed_host, audit="any"),
        Sink("AST-PHP-003", r"(->|::)(where|orWhere|whereNot_NO|pluck|orderBy|orderByDesc|max|min|avg|sum|count|select|groupBy|having|value|distinct|whereColumn|latest|oldest)$", (0,)),
        Sink("AST-PHP-007", r"^(wp_redirect|redirect|wp_safe_redirect_NO)$", (0,)),
        Sink("AST-PHP-007", r"^(RedirectResponse|Redirect::to|Redirect::away|Redirect::route_NO)$", (0,)),
        Sink("AST-PHP-007", r"(->|::)(redirect|redirectToRoute_NO|redirectTo|away|to)$", (0,)),
        Sink("AST-PHP-008", r"^(unserialize|maybe_unserialize|yaml_parse|yaml_parse_file_NO|msgpack_unpack_NO)$", (0,), audit="any"),
        Sink("AST-PHP-004", r"^unlink$", (0,), audit="any"),
        Sink("AST-PHP-014", r"^(extract|parse_str|import_request_variables|mb_parse_str)$", (0,), audit="any"),
    ]
    FIXED = [
        Fixed("AST-PHP-009", r"^(md5|sha1|crc32|md5_file|sha1_file|md2|md4)$"),
        Fixed("AST-PHP-009", r"^hash$", (0, r"(?i)^(md2|md4|md5|sha1|crc32\w*|sha(3-|512/)?224|adler32|fnv\w*|joaat)$")),
        Fixed("AST-PHP-009", r"^(mcrypt_\w+|mdecrypt_generic|crypt_NO)$"),
        Fixed("AST-PHP-009", r"^(openssl_encrypt|openssl_decrypt)$", (1, r"(?i)^(des\S*|rc2\S*|rc4\S*|bf\S*|.*-ecb|aes-\d+-ecb|des-ede\S*|cast5\S*)$")),
        Fixed("AST-PHP-009", r"^(openssl_public_encrypt|openssl_private_decrypt)$", None, any_lit=r"OPENSSL_PKCS1_PADDING"),
        Fixed("AST-PHP-009", r"^(sha256_NO)$"),
        Fixed("AST-PHP-013", r"^(phpinfo)$"),

    ]
    PROPAGATE = [
        (re.compile(r"(->|::)(append|add|set|put|push|with|where_NO)$"), "args", ("recv",)),
    ]

    def parse(self, rel, text):
        return _PARSER.parse(text.encode("utf-8", "ignore"))

    def top_level(self, root, rel):
        return {"name": "<file>", "params": [], "body": root, "receiver": None, "text": "", "top": True}

    # ---- functions -------------------------------------------------------------------------------------
    def functions(self, root):
        for n in walk(root):
            if n.type not in ("function_definition", "method_declaration"):
                continue
            body = n.child_by_field_name("body")
            if body is None:
                continue
            params = []
            pl = n.child_by_field_name("parameters")
            if pl is not None:
                for q in pl.named_children:
                    if q.type in ("simple_parameter", "variadic_parameter", "property_promotion_parameter"):
                        nm = q.child_by_field_name("name")
                        ty = txt(q.child_by_field_name("type")) if q.child_by_field_name("type") is not None else ""
                        params.append((txt(nm) if nm is not None else None, ty, ""))
            yield {"name": txt(n.child_by_field_name("name")), "params": params, "body": body, "receiver": None, "text": txt(body)}

    # ---- expressions --------------------------------------------------------------------------------------
    def qual_of(self, n):
        if n is None:
            return ""
        t = n.type
        if t in ("name", "variable_name", "qualified_name", "relative_name"):
            return re.sub(r"\s+", "", txt(n)).lstrip("\\")
        if t == "member_access_expression" or t == "nullsafe_member_access_expression":
            return self.qual_of(n.child_by_field_name("object")) + "->" + txt(n.child_by_field_name("name"))
        if t == "member_call_expression" or t == "nullsafe_member_call_expression":
            return self.qual_of(n.child_by_field_name("object")) + "->" + txt(n.child_by_field_name("name"))
        if t == "scoped_call_expression":
            return self.qual_of(n.child_by_field_name("scope")) + "::" + txt(n.child_by_field_name("name"))
        if t == "scoped_property_access_expression":
            return self.qual_of(n.child_by_field_name("scope")) + "::" + txt(n.child_by_field_name("name"))
        if t == "function_call_expression":
            return self.qual_of(n.child_by_field_name("function")) + "()"
        if t == "subscript_expression" and n.named_children:
            return self.qual_of(n.named_children[0]) + "[]"
        if t == "parenthesized_expression" and n.named_children:
            return self.qual_of(n.named_children[0])
        return re.sub(r"\s+", "", txt(n))[:40]

    def _args(self, n):
        a = n.child_by_field_name("arguments")
        out = []
        if a is not None:
            for c in a.named_children:
                if c.type == "argument":
                    e = c.named_children[-1] if c.named_children else None
                    if e is not None and e.type != "name" or (e is not None and len(c.named_children) == 1):
                        out.append(e)
                    elif e is not None:
                        out.append(e)
                elif c.type != "comment":
                    out.append(c)
        return out

    def expr(self, n):
        t = n.type
        if t in ("string", "heredoc_NO", "integer", "float", "boolean", "null", "nowdoc", "text", "true", "false", "class_constant_access_expression",
                 "anonymous_function", "arrow_function", "isset_expression_NO", "empty_intrinsic", "isset_intrinsic"):
            return ("const",)
        if t in ("encapsed_string", "heredoc", "shell_command_expression"):
            names = [txt(c) for c in walk(n) if c.type == "variable_name"]
            exprs = [c for c in walk(n) if c.type in ("member_access_expression", "subscript_expression", "function_call_expression")]
            if names:
                return ("tmpl2", [], [c for c in walk(n) if c.type == "variable_name"])
            return ("const",) if t != "shell_command_expression" else ("const",)
        if t == "variable_name":
            return ("name", txt(n))
        if t == "name" or t == "qualified_name":
            return ("const",) if txt(n).upper() in ("TRUE", "FALSE", "NULL") or txt(n).isupper() else ("name", txt(n))
        if t in ("member_access_expression", "nullsafe_member_access_expression"):
            return ("member", n.child_by_field_name("object"), txt(n.child_by_field_name("name")), self.qual_of(n))
        if t == "scoped_property_access_expression":
            return ("other",)
        if t == "subscript_expression":
            return ("index", n.named_children[0] if n.named_children else None, None)
        if t in ("parenthesized_expression", "unary_op_expression", "cast_expression", "reference_assignment_expression_NO", "error_suppression_expression",
                 "clone_expression", "print_intrinsic_NO") and n.named_children:
            return ("wrap", n.named_children[-1])
        if t == "binary_expression":
            op = txt(n.child_by_field_name("operator"))
            if op in ("==", "!=", "===", "!==", "<", ">", "<=", ">=", "&&", "||", "and", "or", "xor", "<>", "<=>", "instanceof"):
                return ("cmp",)
            return ("bin", [n.child_by_field_name("left"), n.child_by_field_name("right")], op)
        if t == "conditional_expression":
            return ("cond", (n.child_by_field_name("condition"), n.child_by_field_name("body"), n.child_by_field_name("alternative")))
        if t == "array_creation_expression":
            return ("list", [c.named_children[-1] for c in n.named_children if c.type == "array_element_initializer" and c.named_children])
        if t == "assignment_expression":
            return ("wrap", n.child_by_field_name("right"))
        if t == "function_call_expression":
            fn = n.child_by_field_name("function")
            q = self.qual_of(fn)
            if fn is not None and fn.type in ("name", "qualified_name"):
                q = q.lower()
            return ("call", q, None, self._args(n), q)
        if t in ("member_call_expression", "nullsafe_member_call_expression"):
            obj = n.child_by_field_name("object")
            return ("call", self.qual_of(n), obj, self._args(n), txt(n.child_by_field_name("name")))
        if t == "scoped_call_expression":
            return ("call", self.qual_of(n), None, self._args(n), txt(n.child_by_field_name("name")))
        if t == "object_creation_expression":
            cls = [c for c in n.named_children if c.type in ("name", "qualified_name")]
            nm = txt(cls[0]) if cls else ""
            return ("call", nm.lstrip("\\"), None, self._args(n), nm.lstrip("\\"))
        if t in ("include_expression", "include_once_expression", "require_expression", "require_once_expression"):
            kw = t.replace("_expression", "")
            return ("call", kw, None, [n.named_children[-1]] if n.named_children else [], kw)
        return ("other",)

    def stmt(self, n):
        t = n.type
        if t == "assignment_expression":
            return ("assign", [n.child_by_field_name("left")], [n.child_by_field_name("right")], "=")
        if t == "augmented_assignment_expression":
            return ("assign", [n.child_by_field_name("left")], [n.child_by_field_name("right")], txt(n.child_by_field_name("operator")))
        if t == "foreach_statement":
            kids = n.named_children
            if len(kids) >= 2:
                targets = [c for c in kids[1:] if c.type in ("variable_name", "pair")]
                return ("for", [targets[-1]] if targets else [], kids[0])
        return None

    def lkey(self, n):
        if n is None:
            return None
        t = n.type
        if t == "variable_name":
            return txt(n)
        if t in ("member_access_expression", "nullsafe_member_access_expression"):
            return self.qual_of(n)
        if t == "subscript_expression" and n.named_children:
            return self.lkey(n.named_children[0])
        if t == "pair" and n.named_children:
            return self.lkey(n.named_children[-1])
        return None

    def is_simple_target(self, n):
        return n.type in ("variable_name", "member_access_expression")

    def is_deep(self, n):
        return n.type in ("if_statement", "else_clause", "else_if_clause", "for_statement", "foreach_statement", "while_statement", "do_statement",
                          "switch_statement", "try_statement", "catch_clause", "anonymous_function", "arrow_function", "conditional_expression", "case_statement")

    def cond_of(self, n):
        if n.type in ("if_statement", "else_if_clause", "while_statement", "do_statement"):
            return n.child_by_field_name("condition")
        return None

    def is_relational(self, x):
        return x.type == "binary_expression" and txt(x.child_by_field_name("operator")) in ("<", ">", "<=", ">=")

    def is_equality(self, x):
        return x.type == "binary_expression" and txt(x.child_by_field_name("operator")) in ("==", "!=", "===", "!==")

    def is_name_node(self, x):
        return x.type == "variable_name"

    def literal(self, n):
        if n is None:
            return None
        if n.type == "string":
            return "".join(txt(c) for c in n.children if c.type in ("string_content", "string_value", "escape_sequence")) or txt(n)[1:-1]
        if n.type == "encapsed_string":
            if any(c.type == "variable_name" for c in walk(n)):
                return None
            return "".join(txt(c) for c in n.children if c.type == "string_content")
        if n.type in ("integer", "boolean", "float"):
            return txt(n)
        if n.type == "name" and txt(n).lower() in ("true", "false", "null"):
            return txt(n).lower()
        return None

    def sink_label(self, n):
        e = self.expr(n)
        return (e[1] if e[0] == "call" else txt(n))[:60]

    def param_taint(self, fname, pname, ptype, pann):
        if re.search(r"Request", ptype or "") or pname in ("$request", "$req"):
            return V_TAINT
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

    # ---- audit and hooks --------------------------------------------------------------------------------------
    def sql_built(self, eng, n):
        if n is None:
            return False
        sv = getattr(eng, "_sqlvars", None)
        if sv is None:
            sv = eng._sqlvars = set()
        sl = getattr(eng, "_sqllit", set())
        t = n.type
        if t == "variable_name":
            return txt(n) in sv
        if t == "binary_expression":
            if txt(n.child_by_field_name("operator")) != ".":
                return False
        elif t == "encapsed_string":
            if not any(c.type == "variable_name" for c in walk(n)):
                return False
        elif t == "function_call_expression":
            e = self.expr(n)
            if e[1] not in ("sprintf", "vsprintf", "str_replace", "implode", "join", "concat"):
                return False
        else:
            return False
        pieces = [self.literal(x) or "" for x in walk(n) if x.type in ("string",)] + [txt(x) for x in walk(n) if x.type == "string_content"]
        has_sql = any(SQL_RE.search(p) for p in pieces) or any(txt(x) in sv or txt(x) in sl for x in walk(n) if x.type == "variable_name")
        if not has_sql:
            return False
        v = eng.ev(n)
        return v[0] >= C.OTHER or bool(v[1])

    def track_sql(self, eng, n):
        st = self.stmt(n)
        if st is None or st[0] != "assign":
            return
        sv = getattr(eng, "_sqlvars", None)
        if sv is None:
            sv = eng._sqlvars = set()
        sl = getattr(eng, "_sqllit", None)
        if sl is None:
            sl = eng._sqllit = set()
        key = self.lkey(st[1][0])
        v = st[2][0]
        if key and v is not None:
            lit = self.literal(v)
            if lit and SQL_RE.search(lit):
                sl.add(key)
            elif self.sql_built(eng, v) or (st[3] == ".=" and key in sl and eng.ev(v)[0] >= C.OTHER):
                sv.add(key)

    def call_effects(self, eng, qual, simple, recv, args, vals, node):
        line = C.line_of(node)
        rel = eng.rel
        # --- Built SQL (audit)
        if re.search(r"^(mysql_query|mysqli_query|mysqli_real_query|mysqli_multi_query|mysqli_prepare|pg_query|sqlite_query|odbc_exec)$|"
                     r"(->|::)(query|exec|multi_query|real_query|prepare|get_results|get_var|get_row|get_col|executeQuery|executeStatement|createQuery|createNativeQuery|"
                     r"whereRaw|orderByRaw|selectRaw|havingRaw|groupByRaw|fromRaw|statement|unprepared|raw|select)$", qual):
            for a in args[:2]:
                if self.sql_built(eng, a):
                    v = eng.ev(a)
                    if v[0] == C.TAINT and v[2]:
                        continue
                    eng.p.add(rel, "AST-PHP-003", "confirmed" if v[0] == C.TAINT else "unknown", line, sink=qual)
                    for pi in v[1]:
                        eng.p.summary.setdefault(eng.key, []).append((frozenset([pi]), "AST-PHP-003", rel, line, {"sink": qual}, "str", False))
        # --- curl: TLS verification disabled
        if qual == "curl_setopt" and len(args) >= 3:
            opt, val = txt(args[1]), txt(args[2]).strip().lower()
            if opt == "CURLOPT_SSL_VERIFYPEER" and val in ("false", "0"):
                eng.p.add(rel, "AST-PHP-010", "fixed", line, sink="CURLOPT_SSL_VERIFYPEER = false")
            if opt == "CURLOPT_SSL_VERIFYHOST" and val in ("false", "0", "1"):
                eng.p.add(rel, "AST-PHP-010", "fixed", line, sink=f"CURLOPT_SSL_VERIFYHOST = {val}")
            if opt == "CURLOPT_URL":
                v = eng.ev(args[2])
                if v[0] == C.TAINT and not v[2] and not _fixed_host(eng, args[2]):
                    eng.p.add(rel, "AST-PHP-006", "confirmed", line, sink="CURLOPT_URL")
        if qual == "curl_setopt_array" and len(args) >= 2 and re.search(r"CURLOPT_SSL_VERIFYPEER\s*=>\s*(false|0)", txt(args[1])):
            eng.p.add(rel, "AST-PHP-010", "fixed", line, sink="CURLOPT_SSL_VERIFYPEER => false")
        if qual == "stream_context_create" and args and re.search(r"verify_peer(_name)?['\"]\s*=>\s*(false|0)|allow_self_signed['\"]\s*=>\s*(true|1)", txt(args[0])):
            eng.p.add(rel, "AST-PHP-010", "fixed", line, sink="verify_peer => false")
        # --- XXE / XML
        if simple in ("simplexml_load_string", "loadXML", "load", "simplexml_load_file", "xml_parse") or qual.endswith("->loadXML") or qual.endswith("->load"):
            if any(re.search(r"LIBXML_NOENT|LIBXML_DTDLOAD", txt(a)) for a in args):
                eng.p.add(rel, "AST-PHP-008", "fixed", line, sink=f"{qual} with LIBXML_NOENT")
        if qual.startswith("ftp_") and qual in ("ftp_connect", "ftp_login", "ftp_put", "ftp_get", "ftp_exec", "ftp_fput", "ftp_fget", "ftp_nb_get", "ftp_nb_put"):
            eng.p.add(rel, "AST-PHP-013", "fixed", line, sink=qual + " (cleartext FTP)", cwe="CWE-319")
        if qual in ("openssl_encrypt", "openssl_decrypt") and len(args) >= 5:
            iv = args[4]
            meth = (self.literal(args[1]) or "").lower()
            if (not meth or "cbc" in meth or "ctr" in meth) and eng.ev(iv)[0] == C.CONST and (self.literal(iv) != ""):
                eng.p.add(rel, "AST-PHP-009", "fixed", line, sink=qual + " with a fixed IV", cwe="CWE-329")
        if qual == "putenv" and args and re.search(r"APP_DEBUG\s*=\s*['\"]?true", txt(args[0]), re.I):
            eng.p.add(rel, "AST-PHP-012", "fixed", line, what="APP_DEBUG=true exposes internal error details in production.", cwe="CWE-489")
        if qual == "config" and args and re.search(r"['\"]app\.debug['\"]\s*=>\s*['\"]?true", txt(args[0]), re.I):
            eng.p.add(rel, "AST-PHP-012", "fixed", line, what="app.debug enabled exposes internal error details in production.", cwe="CWE-489")
        if qual == "base_convert" and args and re.search(r"\b(md5|sha1|sha256|sha512|hash|hash_hmac|bin2hex|random_bytes|openssl_random_pseudo_bytes|uniqid|crc32)\s*\(", txt(args[0])):
            eng.p.add(rel, "AST-PHP-018", "fixed", line, sink=qual)
        if qual in ("ldap_bind", "ldap_sasl_bind_NO"):
            lit = (self.literal(args[2]) or "").lower() if len(args) > 2 else None
            if len(args) < 3 or lit in ("", "null"):
                eng.p.add(rel, "AST-PHP-017", "fixed", line, sink=qual)
        # --- others
        if qual == "unserialize" and len(args) >= 2 and re.search(r"allowed_classes['\"]\s*=>\s*false", txt(args[1])):
            pass
        if simple == "header" or qual == "header":
            if args:
                lit = txt(args[0])
                if re.search(r"(?i)access-control-allow-origin\s*:\s*\*", lit):
                    eng.p.add(rel, "AST-PHP-012", "fixed", line, what="Access-Control-Allow-Origin: * header accepts requests from any origin.", cwe="CWE-942")
                m = re.match(r"(?is)^[\"']\s*location\s*:", lit)
                if m or re.search(r"(?i)^[\"']?\s*location\s*:", lit):
                    v = eng.ev(args[0])
                    if v[0] == C.TAINT and not v[2]:
                        eng.p.add(rel, "AST-PHP-007", "confirmed", line, sink="header(Location)")
                    elif v[0] == C.PARAM or (v[0] >= C.OTHER and self.expr(args[0])[0] in ("bin", "tmpl2")):
                        eng.p.add(rel, "AST-PHP-007", "unknown", line, sink="header(Location)")
        if qual in ("session_set_cookie_params", "setcookie", "setrawcookie") and args:
            atxt = " ".join(txt(a) for a in args)
            if qual == "setcookie" and len(args) < 7 and not re.search(r"httponly|secure", atxt, re.I):
                eng.p.add(rel, "AST-PHP-012", "fixed", line, what="setcookie without the Secure and HttpOnly options.")
            if re.search(r"['\"]?(secure|httponly)['\"]?\s*=>\s*(false|0)", atxt, re.I):
                eng.p.add(rel, "AST-PHP-012", "fixed", line, what="Cookie with Secure or HttpOnly disabled.")
        if qual in ("md5", "sha1") and args:
            pass
        if qual in ("mt_rand", "rand", "uniqid", "lcg_value", "mt_srand", "srand", "random_NO", "shuffle", "str_shuffle", "array_rand"):
            nm = eng.name
            hit = SENSITIVE.search(nm)
            if not hit:
                p = node.parent
                while p is not None and p.type not in ("assignment_expression", "expression_statement", "compound_statement"):
                    p = p.parent
                if p is not None and p.type == "assignment_expression":
                    lhs = txt(p.child_by_field_name("left"))
                    nm = lhs
                    hit = SENSITIVE.search(lhs)
            if hit:
                eng.p.add(rel, "AST-PHP-011", "fixed", line, sink=qual, name=nm)
        # --- Laravel mass assignment
        if re.search(r"(::|->)(create|fill|forceFill|update|firstOrCreate|updateOrCreate|insert)$", qual) and args:
            if re.search(r"\$(request|req)->(all|input|post)\(\)|\$_(POST|GET|REQUEST)\b", txt(args[0])):
                eng.p.add(rel, "AST-PHP-016", "fixed" if False else "unknown", line, sink=qual)
        # --- md5 loose equality: md5($a) == md5($b) is handled in on_node
        # --- eval/assert as a language construct
        if qual in ("eval", "assert") and args:
            v = eng.ev(args[0])
            if self.expr(args[0])[0] != "const" and (v[0] >= C.OTHER or v[1]):
                eng.p.add(rel, "AST-PHP-002", "confirmed" if v[0] == C.TAINT and not v[2] else "unknown", line, sink=qual)
        # --- variable function: $f($x) with a non-constant $f
        if node.type == "function_call_expression":
            fn = node.child_by_field_name("function")
            if fn is not None and fn.type == "variable_name":
                v = eng.ev(fn)
                if v[0] == C.TAINT and not v[2]:
                    eng.p.add(rel, "AST-PHP-002", "confirmed", line, sink=f"{txt(fn)}()")
                elif v[0] == C.PARAM:
                    eng.p.add(rel, "AST-PHP-002", "unknown", line, sink=f"{txt(fn)}()")

    def on_node(self, eng, n):
        rel = eng.rel
        line = C.line_of(n)
        t = n.type
        if t in self.STMT_TYPES:
            self.track_sql(eng, n)
        if t == "echo_statement" or t == "print_intrinsic":
            for c in n.named_children:
                if c.type in ("echo", "print", "comment"):
                    continue
                v = eng.ev(c)
                names = eng.names(c)
                if v[0] == C.TAINT and not v[2] and not (names & eng.validated):
                    eng.p.add(rel, "AST-PHP-005", "confirmed", line, sink="echo" if t == "echo_statement" else "print")
                elif v[1]:
                    for pi in v[1]:
                        eng.p.summary.setdefault(eng.key, []).append((frozenset([pi]), "AST-PHP-005", rel, line, {"sink": "echo"}, "str", False))
        if t == "assignment_expression":
            l, r = n.child_by_field_name("left"), n.child_by_field_name("right")
            if l is not None and re.search(r"APP_DEBUG", txt(l)) and re.fullmatch(r"['\"]?true['\"]?", txt(r).strip().lower()):
                eng.p.add(rel, "AST-PHP-012", "fixed", line, what="APP_DEBUG=true exposes internal error details in production.", cwe="CWE-489")
            if r is not None:
                head = None
                if r.type == "binary_expression":
                    x = r
                    while x.type == "binary_expression" and x.child_by_field_name("left") is not None:
                        x = x.child_by_field_name("left")
                    head = self.literal(x) if x.type == "string" else None
                    rest_ok = bool(head and re.fullmatch(r"https?://", head))
                elif r.type == "encapsed_string":
                    m = re.match(r'^"https?://\{?\$', txt(r))
                    rest_ok = bool(m)
                else:
                    rest_ok = False
                if rest_ok:
                    v = eng.ev(r)
                    if v[0] == C.TAINT and not v[2]:
                        eng.p.add(rel, "AST-PHP-006", "confirmed", line, sink="URL with a host chosen by external input")
        if t == "shell_command_expression":
            v = eng.ev(n)
            if v[0] == C.TAINT and not v[2]:
                eng.p.add(rel, "AST-PHP-001", "confirmed", line, sink="backtick")
            elif v[0] >= C.OTHER or v[1]:
                eng.p.add(rel, "AST-PHP-001", "unknown", line, sink="backtick")
        if t == "binary_expression" and txt(n.child_by_field_name("operator")) in ("==", "!="):
            l, r = txt(n.child_by_field_name("left")), txt(n.child_by_field_name("right"))
            if re.search(r"\b(md5|sha1|crc32)\s*\(", l) or re.search(r"\b(md5|sha1|crc32)\s*\(", r):
                eng.p.add(rel, "AST-PHP-015", "fixed", line, what="'==' comparison between hashes: values such as '0e123' are treated as the number 0.")
        if t == "variable_name" and txt(n).startswith("$$"):
            pass
        if t == "array_element_initializer" and len(n.named_children) >= 2:
            key, val = txt(n.named_children[0]).strip("'\""), txt(n.named_children[-1]).strip().lower()
            if key in ("http_only", "secure") and val in ("false", "0"):
                eng.p.add(rel, "AST-PHP-012", "fixed", line, what=f"Setting '{key}' => false: the session cookie is not protected.")
            if key in ("same_site",) and val in ("null", "'none'", "\"none\""):
                eng.p.add(rel, "AST-PHP-012", "fixed", line, what="Cookie without a restrictive SameSite.")
            if key == "debug" and val == "true":
                eng.p.add(rel, "AST-PHP-012", "fixed", line, what="'debug' => true exposes internal error details in production.")
            if key in ("csrf_protection",) and val in ("false", "0"):
                eng.p.add(rel, "AST-PHP-012", "fixed", line, what="csrf_protection disabled.", cwe="CWE-352")
            if key.lower() == "access-control-allow-origin" and val in ("'*'", '"*"'):
                eng.p.add(rel, "AST-PHP-012", "fixed", line, what="Access-Control-Allow-Origin: * accepts requests from any origin.", cwe="CWE-942")


LANG = PhpLang()


def analyze_php_project(sources):
    return C.analyze(LANG, sources)


def analyze_php_source(rel_path, text):
    return C.analyze_source(LANG, rel_path, text)
