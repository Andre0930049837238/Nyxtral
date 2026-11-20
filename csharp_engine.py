# -*- coding: utf-8 -*-
"""
csharp_engine.py
=================
Security engine for C# (.cs: ASP.NET MVC / Core, services, desktop apps) built on a real parser (tree-sitter-c-sharp) and
data-flow analysis on top of the shared core in lang_core.py.

Vulnerability classes covered: command injection, SQL injection (ADO.NET, Entity Framework, Dapper), XSS (Response.Write, Html.Raw,
HtmlString), path traversal, SSRF (HttpClient, WebClient, WebRequest), open redirect, insecure deserialization (BinaryFormatter,
SoapFormatter, NetDataContractSerializer, LosFormatter, JavaScriptSerializer, Json.NET TypeNameHandling, FastJson,
DataContractSerializer), XXE, weak cryptography (MD5, SHA-1, DES, RC2, ECB, short RSA keys / PKCS#1), disabled TLS validation,
unprotected cookies, LDAP/XPath injection, ReDoS, JWT without validation, exposed stack traces, binding to all interfaces,
POST actions without anti-CSRF protection.

Known limitations: no type checker (methods are recognized by name), no support for Razor (.cshtml) or web.config files.
The code under analysis is never executed.
"""

import logging
import re

import lang_core as C
from lang_core import Sink, Fixed, V_TAINT, V_LOCAL, txt, walk

log = logging.getLogger(__name__)

try:
    from tree_sitter import Language, Parser
    import tree_sitter_c_sharp as _tscs
    _PARSER = Parser(Language(_tscs.language()))
    AVAILABLE = True
except Exception as _exc:                           # pragma: no cover
    AVAILABLE = False
    log.warning(
        "C# AST analysis is disabled: tree-sitter or tree-sitter-c-sharp could not be loaded (%s: %s). "
        "Only pattern-based rules will run for .cs files. Install the missing packages with: "
        "pip install tree-sitter tree-sitter-c-sharp", type(_exc).__name__, _exc)

SUPPORTED = (".cs",)
MAX_PROJECT_BYTES = C.MAX_PROJECT_BYTES

RULES = {
    "AST-CS-001": ("Command execution with untrusted data", "CRITICAL", "HIGH",
                   "{sink} executes a command that is partly built from external input or assembled at runtime.",
                   "Pass arguments as a list (ArgumentList) without a shell, and validate the input against an allowlist.", "CWE-78"),
    "AST-CS-002": ("SQL injection", "CRITICAL", "HIGH",
                   "{sink} receives a query built from externally supplied data.",
                   "Use parameterized queries (SqlParameter, Dapper parameters, FromSqlInterpolated); never string concatenation or string.Format.", "CWE-89"),
    "AST-CS-003": ("Unsanitized content written to the response (XSS)", "HIGH", "MEDIUM",
                   "{sink} writes externally supplied data to the page without encoding it.",
                   "Rely on Razor automatic encoding, HtmlEncoder.Default.Encode or AntiXSS; avoid Html.Raw and HtmlString on external data.", "CWE-79"),
    "AST-CS-004": ("Externally controlled file path (path traversal)", "HIGH", "MEDIUM",
                   "{sink} uses a path supplied by external input.",
                   "Apply Path.GetFileName to the name, or use Path.GetFullPath and verify the result stays inside the permitted directory.", "CWE-22"),
    "AST-CS-005": ("Request to an externally controlled address (SSRF)", "HIGH", "MEDIUM",
                   "{sink} contacts an address supplied by external input, which may allow access to internal services.",
                   "Accept only hosts from an allowlist and block internal addresses.", "CWE-918"),
    "AST-CS-006": ("Redirect to an externally controlled address", "MEDIUM", "LOW",
                   "{sink} redirects the user to an address chosen by external input.",
                   "Use LocalRedirect or Url.IsLocalUrl before redirecting.", "CWE-601"),
    "AST-CS-007": ("Insecure deserialization", "HIGH", "HIGH",
                   "{sink} rebuilds objects without restricting the allowed types, which can lead to code execution.",
                   "Avoid BinaryFormatter and similar (deprecated) formatters: use System.Text.Json or Json.NET with TypeNameHandling.None.", "CWE-502"),
    "AST-CS-008": ("XML parser with external entities enabled (XXE)", "HIGH", "MEDIUM",
                   "{sink}: the XML parser can read server files or contact internal addresses.",
                   "Set DtdProcessing.Prohibit and XmlResolver = null.", "CWE-611"),
    "AST-CS-009": ("Weak cryptographic algorithm", "MEDIUM", "MEDIUM",
                   "{sink} uses an algorithm, mode or padding scheme that is considered weak.",
                   "Use SHA-256 or stronger, AES-GCM, and RSA-OAEP with at least 2048-bit keys; for passwords use PBKDF2 or Argon2.", "CWE-327"),
    "AST-CS-010": ("Certificate validation disabled or weak protocol", "HIGH", "MEDIUM",
                   "{sink}: the connection accepts any certificate or uses an obsolete protocol.",
                   "Keep the default validation and use TLS 1.2 or later.", "CWE-295"),
    "AST-CS-011": ("Cookie without protection flags", "MEDIUM", "MEDIUM",
                   "{what}",
                   "Set Secure, HttpOnly and SameSite on session cookies.", "CWE-614"),
    "AST-CS-012": ("LDAP or XPath injection", "HIGH", "MEDIUM",
                   "{sink} builds a query from externally supplied data.",
                   "Encode the values (LDAP/XPath encoders) or use parameterized queries.", "CWE-90"),
    "AST-CS-013": ("Regular expression without a time limit (ReDoS)", "MEDIUM", "LOW",
                   "{sink} uses a regular expression built from external data or without a timeout, which can hang the service.",
                   "Pass a matchTimeout to Regex and never compile external input as a pattern.", "CWE-1333"),
    "AST-CS-014": ("JWT token without full validation", "HIGH", "MEDIUM",
                   "{what}",
                   "Enable ValidateLifetime, ValidateIssuer, ValidateAudience and ValidateIssuerSigningKey.", "CWE-613"),
    "AST-CS-015": ("Internal information exposed", "LOW", "LOW",
                   "{sink} displays or writes the full stack trace, which can reveal paths and internal structure.",
                   "Log the details with a logger and show only a generic message to the user.", "CWE-209"),
    "AST-CS-016": ("Service listening on all interfaces", "LOW", "LOW",
                   "{what}",
                   "Listen only on the required address (localhost or an internal network).", "CWE-1327"),
    "AST-CS-017": ("State-changing action without anti-CSRF protection", "MEDIUM", "LOW",
                   "{what}",
                   "Add [ValidateAntiForgeryToken] (or enable AutoValidateAntiforgeryToken globally).", "CWE-352"),
    "AST-CS-019": ("Unmanaged code or bypassed memory bounds", "MEDIUM", "MEDIUM",
                   "{sink} creates a view over memory without checks: a length error reads or writes out of bounds.",
                   "Use Span<T> with validated lengths and avoid MemoryMarshal on external data.", "CWE-125"),
    "AST-CS-020": ("Missing HSTS security header", "LOW", "LOW",
                   "{what}",
                   "Add app.UseHsts() to the production pipeline.", "CWE-319"),
    "AST-CS-018": ("Mass assignment: the model object is populated with every submitted field", "MEDIUM", "LOW",
                   "{what}",
                   "Use a dedicated model or [Bind(Include=...)] limited to the permitted fields.", "CWE-915"),
}

SENSITIVE = re.compile(r"(token|secret|passw|pwd|nonce|salt|session|csrf|otp|apikey|api_key|\bkey\b|_key|key_|\biv\b|cookie|auth)", re.I)
SQL_RE = re.compile(r"(?i)\b(select|insert\s+into|update\s+\w+\s+set|delete\s+from|drop\s+(table|database)|create\s+table|alter\s+table|truncate|where\s+\w+|order\s+by|union\s+select|from\s+\w+|exec(ute)?\s+\w+)\b")
HOST_FIXED = re.compile(r"^https?://[A-Za-z0-9.\-]+(:\d+)?(/|\?|$)")
ATTR_TAINT = re.compile(r"(FromQuery|FromBody|FromForm|FromRoute|FromHeader|FromServices_NO|ModelBinder)")
TYPE_TAINT = re.compile(r"(HttpRequest|HttpRequestBase|HttpRequestMessage|HttpListenerRequest|IFormFile|IFormCollection|HttpPostedFile)")


def _fixed_host(eng, n):
    t = n
    while t is not None and t.type == "parenthesized_expression" and t.named_children:
        t = t.named_children[0]
    if t is None:
        return False
    if t.type in ("string_literal", "verbatim_string_literal"):
        return True
    if t.type == "interpolated_string_expression":
        raw = txt(t)
        m = re.match(r'^\$@?"(.*)', raw)
        return bool(m and HOST_FIXED.match(m.group(1)))
    if t.type == "binary_expression":
        x = t
        while x.type == "binary_expression" and x.child_by_field_name("left") is not None:
            x = x.child_by_field_name("left")
        return x.type in ("string_literal", "verbatim_string_literal") and bool(HOST_FIXED.match(LANG.literal(x) or ""))
    return False


class CSharpLang(C.LangBase):
    ENGINE = "csharp_ast"
    EXTS = SUPPORTED
    RULES = RULES
    AVAILABLE = AVAILABLE
    CALL_TYPES = {"invocation_expression", "object_creation_expression"}
    FUNC_TYPES = {"method_declaration", "constructor_declaration", "local_function_statement"}
    STMT_TYPES = {"variable_declarator", "assignment_expression", "foreach_statement"}
    TEST_RE = re.compile(r"(^|/)_?(tests?|testdata|examples?|docs?|samples?)(/|$)|(Tests?|Spec)\.cs$")
    TEST_QUIET = frozenset({"AST-CS-010", "AST-CS-011", "AST-CS-013", "AST-CS-015", "AST-CS-016", "AST-CS-017", "AST-CS-018"})
    CLEAN_RE = re.compile(r"(HtmlEncode|UrlEncode|HtmlEncoder|UrlEncoder|JavaScriptEncoder|AntiXss|Sanitize|Sanitizer|Path\.GetFileName|GetFileNameWithoutExtension|"
                          r"Path\.GetFullPath|Uri\.EscapeDataString|SecurityElement\.Escape|IsLocalUrl|EscapeDataString|XmlConvert)")
    NUM_RE = re.compile(r"((int|long|double|decimal|float|short|byte|bool|Guid|Int32|Int64|Double|Decimal|Boolean)\.(Parse|TryParse)|Convert\.To(Int|Double|Decimal|Boolean|Single|Byte)\w*|"
                        r"\.Length$|\.Count$|Guid\.Parse|\.GetHashCode$)")
    VALIDATE_RE = re.compile(r"(StartsWith|EndsWith|Contains|Equals|IsMatch|IsValid|Validate|IsSafe|IsAllowed|Allowed|Whitelist|Allowlist|IsNullOrEmpty_NO|IsLocalUrl|IsNumeric|IsDigit)")
    LEN_RE = re.compile(r"(\.Length|\.Count|Math\.Min)$")
    SOURCE_CALLS = [
        (re.compile(r"(^|\.)(Console\.ReadLine|Environment\.GetEnvironmentVariable|Environment\.GetCommandLineArgs)$"), V_LOCAL),
        (re.compile(r"\.(GetQueryString|GetQueryNameValuePairs|ReadAsStringAsync|ReadAsStream|ReadFromJsonAsync|ReadBodyAsync_NO|GetFormValue|GetHeader|GetCookie|"
                    r"QueryString|Form|Headers|Cookies)$"), V_TAINT),
    ]
    SOURCE_MEMBERS = [
        (re.compile(r"(^|\.)(Request|HttpContext\.Request|context\.Request|ctx\.Request)\.(QueryString|Query|Form|Headers|Cookies|Params|Path|RawUrl|Url|UserAgent|"
                    r"Body|InputStream|Files|ServerVariables|PathInfo|QueryString\[|Content)"), V_TAINT),
        (re.compile(r"^Request\.(QueryString|Query|Form|Headers|Cookies|Params|Path|RawUrl|Url|Body|InputStream|PathInfo|Content)$"), V_TAINT),
        (re.compile(r"^(Environment\.CommandLine)$"), V_LOCAL),
    ]
    SINKS = [
        Sink("AST-CS-001", r"(^|\.)Process\.Start$", None, audit=True),
        Sink("AST-CS-001", r"^(ProcessStartInfo|System\.Diagnostics\.ProcessStartInfo)$", None, audit=True),
        Sink("AST-CS-002", r"^(SqlCommand|OleDbCommand|OdbcCommand|NpgsqlCommand|MySqlCommand|SqliteCommand|SQLiteCommand|OracleCommand|SqlDataAdapter|"
                            r"OleDbDataAdapter|OdbcDataAdapter|MySqlDataAdapter|NpgsqlDataAdapter|SqlCeCommand|FbCommand|DB2Command)$", (0,), audit=True),
        Sink("AST-CS-002", r"\.(ExecuteSqlRaw|ExecuteSqlCommand|ExecuteSqlRawAsync|ExecuteSqlCommandAsync|FromSqlRaw|FromSql|SqlQuery|SqlQueryRaw|"
                            r"Query|QueryAsync|QueryFirst|QueryFirstOrDefault|QuerySingle|QuerySingleOrDefault|QueryMultiple|Execute|ExecuteAsync|ExecuteScalar|"
                            r"ExecuteScalarAsync|ExecuteReader|ExecuteReaderAsync|CreateSQLQuery|CreateQuery|ExecuteNonQuery_NO)$", (0,), audit=True),
        Sink("AST-CS-003", r"(^|\.)(Response\.Write|Response\.Output\.Write|HttpContext\.Response\.Write|Html\.Raw|Raw|new HtmlString|HtmlString|MvcHtmlString\.Create|"
                            r"Response\.WriteAsync|Response\.BinaryWrite_NO)$", (0,)),
        Sink("AST-CS-004", r"^((System\.IO\.)?(File|Directory)\.\w+|FileStream|StreamReader|StreamWriter|FileInfo|DirectoryInfo|BinaryReader|BinaryWriter|"
                            r"XmlTextReader|XmlTextWriter|ZipFile\.\w+|Path\.Combine_NO|PhysicalFileProvider|Server\.MapPath|PhysicalFile|FileSystemWatcher)$", None, skip_local=True),
        Sink("AST-CS-004", r"\.(MapPath|ReadAllText|ReadAllBytes|WriteAllText|ReadAllLines|SaveAs|Open|OpenRead|OpenWrite|CopyTo|MoveTo)$", (0,), skip_local=True),
        Sink("AST-CS-005", r"^(Uri|System\.Uri)$", (0,), exempt=_fixed_host),
        Sink("AST-CS-005", r"\.(GetAsync|GetStringAsync|GetStreamAsync|GetByteArrayAsync|PostAsync|PutAsync|DeleteAsync|PatchAsync|SendAsync_NO|"
                            r"DownloadString|DownloadStringAsync|DownloadStringTaskAsync|DownloadData|DownloadDataAsync|DownloadFile|DownloadFileAsync|"
                            r"DownloadFileTaskAsync|UploadString|UploadData|UploadFile|OpenRead|OpenReadAsync|Get|Post|Put|Delete|Execute|ExecuteAsync|ExecuteGetAsync|ExecutePostAsync)$", (0,), exempt=_fixed_host, audit=True),
        Sink("AST-CS-005", r"^(WebRequest\.Create|WebRequest\.CreateHttp|HttpWebRequest\.Create|FtpWebRequest\.Create|RestClient|RestRequest)$", (0,), exempt=_fixed_host, audit=True),
        Sink("AST-CS-005", r"^HttpRequestMessage$", (1,), exempt=_fixed_host, audit=True),
        Sink("AST-CS-005", r"^(Uri|System\.Uri)$", (0,), exempt=_fixed_host, audit=False),
        Sink("AST-CS-006", r"(^|\.)(Response\.Redirect|Redirect|RedirectPermanent|RedirectToRoute_NO|HttpResponse\.Redirect|Response\.RedirectPermanent|RedirectResult|new RedirectResult)$", (0,), audit=True),
        Sink("AST-CS-006", r"^RedirectResult$", (0,)),
        Sink("AST-CS-007", r"(^|\.)(Activator\.CreateInstance|Type\.GetType|Assembly\.Load|Assembly\.LoadFrom|Assembly\.LoadFile)$", (0,), audit=False),
        Sink("AST-CS-012", r"^(DirectorySearcher|DirectoryEntry)$", (0, 1), audit=True),
        Sink("AST-CS-012", r"\.(SelectNodes|SelectSingleNode|Evaluate|Compile|Select)$", (0,), audit=False),
        Sink("AST-CS-013", r"^(Regex|System\.Text\.RegularExpressions\.Regex)$", (0,), audit=True),
        Sink("AST-CS-013", r"^Regex\.(IsMatch|Match|Matches|Replace|Split)$", (1,), audit=True),
    ]
    FIXED = [
        Fixed("AST-CS-007", r"^(BinaryFormatter|SoapFormatter|NetDataContractSerializer|LosFormatter|ObjectStateFormatter|FastJSON|JSON\.ToObject_NO|"
                            r"System\.Runtime\.Serialization\.Formatters\.Binary\.BinaryFormatter|System\.Runtime\.Serialization\.Formatters\.Soap\.SoapFormatter)$"),
        Fixed("AST-CS-007", r"(^|\.)(FsPickler\.Create\w+Serializer|Pickler\.\w+|JSON\.ToObject|JSON\.Parse_NO|fastJSON\.JSON\.\w+_NO)$"),
        Fixed("AST-CS-007", r"^JavaScriptSerializer$", None, any_lit=r"SimpleTypeResolver"),
        Fixed("AST-CS-007", r"^(DataContractSerializer|DataContractJsonSerializer)$", None, any_lit=r"DataContractResolver"),
        Fixed("AST-CS-009", r"(^|\.)(MD5|SHA1|DES|RC2|TripleDES|SHA1Managed|MD5CryptoServiceProvider|SHA1CryptoServiceProvider|DESCryptoServiceProvider|"
                            r"RC2CryptoServiceProvider|TripleDESCryptoServiceProvider|RIPEMD160|HMACMD5|HMACSHA1_NO)\.Create$"),
        Fixed("AST-CS-009", r"^(MD5CryptoServiceProvider|SHA1CryptoServiceProvider|SHA1Managed|SHA1Cng|MD5Cng|DESCryptoServiceProvider|RC2CryptoServiceProvider|"
                            r"TripleDESCryptoServiceProvider|TripleDESCng|HMACMD5|PasswordDeriveBytes|MD5Managed_NO)$"),
        Fixed("AST-CS-009", r"(^|\.)(HashAlgorithm|SymmetricAlgorithm|AsymmetricAlgorithm|CryptoConfig)\.(Create|CreateFromName)$", (0, r"(?i)^(md5|sha1|sha-1|des|rc2|3des|tripledes|rijndael_NO)$")),
        Fixed("AST-CS-009", r"^RSACryptoServiceProvider$", (0, r"^(512|768|1024)$")),
        Fixed("AST-CS-009", r"\.(Encrypt|Decrypt)$", (1, r"^false$")),
        Fixed("AST-CS-010", r"\.(set_ServerCertificateValidationCallback)$"),
        Fixed("AST-CS-010", r"^(HttpClientHandler\.DangerousAcceptAnyServerCertificateValidator)$"),
        Fixed("AST-CS-019", r"^MemoryMarshal\.(CreateSpan|CreateReadOnlySpan)$"),
        Fixed("AST-CS-014", r"^SecurityTokenHandler_NO$"),
    ]
    PROPAGATE = [
        (re.compile(r"\.(Append|AppendFormat|Insert|Add|Write|Concat)$"), "args", ("recv",)),
        (re.compile(r"\.(ReadToEnd|ReadLine|ReadAllText|ReadAllLines|ReadAllBytes|ToString|Trim|Substring|Replace|Split|ToLower|ToUpper|Format|Join|GetString|GetBytes)$"), "recv", ()),
    ]

    def parse(self, rel, text):
        return _PARSER.parse(text.encode("utf-8", "ignore"))

    def top_level(self, root, rel):
        return {"name": "<class>", "params": [], "body": root, "receiver": None, "text": "", "top": True}

    # ---- functions and parameters --------------------------------------------------------------------------
    def functions(self, root):
        for n in walk(root):
            if n.type not in ("method_declaration", "constructor_declaration", "local_function_statement"):
                continue
            body = n.child_by_field_name("body")
            if body is None:
                continue
            nm = txt(n.child_by_field_name("name"))
            mods = " ".join(txt(c) for c in n.children if c.type in ("modifier", "attribute_list"))
            ctrl = False
            p = n.parent
            while p is not None:
                if p.type in ("class_declaration", "record_declaration"):
                    head = txt(p)[:300].split("{")[0]
                    ctrl = bool(re.search(r"(Controller|ControllerBase|PageModel|ApiController|Hub|Page)\b", head))
                    break
                p = p.parent
            public = "public" in mods
            params = []
            pl = n.child_by_field_name("parameters")
            if pl is not None:
                for q in pl.named_children:
                    if q.type != "parameter":
                        continue
                    pn = q.child_by_field_name("name")
                    ty = txt(q.child_by_field_name("type")) if q.child_by_field_name("type") is not None else ""
                    attrs = " ".join(txt(c) for c in q.children if c.type == "attribute_list")
                    if ctrl and public and not ATTR_TAINT.search(attrs) and re.match(r"(string|String|int|long|Guid|object|IFormFile|var)\b|[A-Z]\w*(Model|Dto|Request|Input|Command|Params)$", ty or ""):
                        attrs += " FromQuery"
                    params.append((txt(pn) if pn is not None else None, ty, attrs))
            yield {"name": nm, "params": params, "body": body, "receiver": None, "text": txt(body), "mods": mods}

    # ---- expressions --------------------------------------------------------------------------------------
    def qual_of(self, n):
        if n is None:
            return ""
        t = n.type
        if t in ("identifier", "predefined_type", "this_expression", "this", "base_expression"):
            return txt(n)
        if t == "member_access_expression":
            return self.qual_of(n.child_by_field_name("expression")) + "." + txt(n.child_by_field_name("name"))
        if t == "invocation_expression":
            return self.qual_of(n.child_by_field_name("function")) + "()"
        if t == "object_creation_expression":
            return re.sub(r"<.*>", "", txt(n.child_by_field_name("type"))) + "()"
        if t in ("parenthesized_expression", "cast_expression", "await_expression") and n.named_children:
            return self.qual_of(n.named_children[-1])
        if t == "element_access_expression":
            return self.qual_of(n.child_by_field_name("expression")) + "[]"
        if t == "generic_name":
            return txt(n.named_children[0]) if n.named_children else txt(n)
        if t == "qualified_name":
            return re.sub(r"\s+", "", txt(n))
        return re.sub(r"\s+", "", txt(n))[:40]

    def _args(self, n):
        a = n.child_by_field_name("arguments")
        out = []
        if a is not None:
            for c in a.named_children:
                if c.type == "argument":
                    e = c.named_children[-1] if c.named_children else None
                    if e is not None:
                        out.append(e)
                elif c.type != "comment":
                    out.append(c)
        return out

    def expr(self, n):
        t = n.type
        if t in ("string_literal", "verbatim_string_literal", "raw_string_literal", "character_literal", "integer_literal", "real_literal", "boolean_literal",
                 "null_literal", "this_expression", "this", "lambda_expression", "anonymous_method_expression", "typeof_expression", "default_expression",
                 "sizeof_expression", "nameof_expression_NO", "is_expression", "is_pattern_expression"):
            return ("const",) if t not in ("is_expression", "is_pattern_expression") else ("cmp",)
        if t == "interpolated_string_expression":
            skip = ("interpolation_brace", "interpolation_format_clause", "interpolation_alignment_clause")
            nodes = [next((x for x in c.named_children if x.type not in skip), None) for c in walk(n) if c.type == "interpolation"]
            nodes = [x for x in nodes if x is not None]
            return ("tmpl2", [], nodes) if nodes else ("const",)
        if t == "identifier":
            return ("name", txt(n))
        if t == "member_access_expression":
            return ("member", n.child_by_field_name("expression"), txt(n.child_by_field_name("name")), self.qual_of(n))
        if t == "element_access_expression":
            return ("index", n.child_by_field_name("expression"), None)
        if t in ("parenthesized_expression", "prefix_unary_expression", "postfix_unary_expression", "await_expression", "as_expression",
                 "conditional_access_expression", "checked_expression", "ref_expression") and n.named_children:
            return ("wrap", n.named_children[0] if t not in ("as_expression",) else n.named_children[0])
        if t == "cast_expression":
            return ("wrap", n.child_by_field_name("value") or (n.named_children[-1] if n.named_children else None))
        if t == "binary_expression":
            op = txt(n.child_by_field_name("operator"))
            if op in ("==", "!=", "<", ">", "<=", ">=", "&&", "||", "is", "as"):
                return ("cmp",) if op != "as" else ("wrap", n.child_by_field_name("left"))
            return ("bin", [n.child_by_field_name("left"), n.child_by_field_name("right")], op)
        if t == "conditional_expression":
            return ("cond", (n.child_by_field_name("condition"), n.child_by_field_name("consequence"), n.child_by_field_name("alternative")))
        if t in ("initializer_expression", "array_creation_expression", "implicit_array_creation_expression", "collection_expression"):
            return ("list", list(n.named_children))
        if t == "assignment_expression":
            return ("wrap", n.child_by_field_name("right"))
        if t == "invocation_expression":
            fn = n.child_by_field_name("function")
            args = self._args(n)
            if fn is not None and fn.type == "member_access_expression":
                return ("call", self.qual_of(fn), fn.child_by_field_name("expression"), args, txt(fn.child_by_field_name("name")))
            if fn is not None and fn.type == "generic_name":
                nm = txt(fn.named_children[0]) if fn.named_children else txt(fn)
                return ("call", nm, None, args, nm)
            q = self.qual_of(fn)
            return ("call", q, None, args, q)
        if t == "object_creation_expression":
            ty = n.child_by_field_name("type")
            nm = re.sub(r"<.*>", "", txt(ty)).split(".")[-1]
            return ("call", re.sub(r"<.*>", "", re.sub(r"\s+", "", txt(ty))), None, self._args(n), nm)
        return ("other",)

    def stmt(self, n):
        t = n.type
        if t == "variable_declarator":
            nm = n.child_by_field_name("name")
            val = None
            for c in n.named_children:
                if c is not nm and c.type not in ("bracketed_argument_list",):
                    val = c if val is None else val
            if val is not None and val.type == "equals_value_clause" and val.named_children:
                val = val.named_children[-1]
            return ("decl", [txt(nm)], [val] if val is not None and val.id != nm.id else None)
        if t == "assignment_expression":
            return ("assign", [n.child_by_field_name("left")], [n.child_by_field_name("right")], txt(n.child_by_field_name("operator")))
        if t == "foreach_statement":
            l, r = n.child_by_field_name("left"), n.child_by_field_name("right")
            if l is not None and r is not None:
                return ("for", [l], r)
        return None

    def lkey(self, n):
        if n is None:
            return None
        t = n.type
        if t == "identifier":
            return txt(n)
        if t == "member_access_expression":
            return self.qual_of(n)
        if t == "element_access_expression":
            return self.lkey(n.child_by_field_name("expression"))
        return None

    def is_simple_target(self, n):
        return n.type in ("identifier", "member_access_expression")

    def is_deep(self, n):
        return n.type in ("if_statement", "for_statement", "foreach_statement", "while_statement", "do_statement", "switch_statement", "switch_expression",
                          "try_statement", "catch_clause", "lambda_expression", "conditional_expression", "switch_section")

    def cond_of(self, n):
        if n.type in ("if_statement", "while_statement", "do_statement"):
            return n.child_by_field_name("condition")
        return None

    def is_relational(self, x):
        return x.type == "binary_expression" and txt(x.child_by_field_name("operator")) in ("<", ">", "<=", ">=")

    def is_equality(self, x):
        return x.type == "binary_expression" and txt(x.child_by_field_name("operator")) in ("==", "!=")

    def literal(self, n):
        if n is None:
            return None
        if n.type in ("string_literal", "verbatim_string_literal", "raw_string_literal"):
            raw = txt(n)
            if raw.startswith('@"'):
                return raw[2:-1]
            if raw.startswith('"""'):
                return raw[3:-3]
            return raw[1:-1]
        if n.type in ("integer_literal", "boolean_literal"):
            return txt(n)
        return None

    def sink_label(self, n):
        e = self.expr(n)
        return (e[1] if e[0] == "call" else txt(n))[:60]

    def param_taint(self, fname, pname, ptype, pann):
        if ATTR_TAINT.search(pann or "") or TYPE_TAINT.search(ptype or ""):
            return V_TAINT
        if fname == "Main" and pname in ("args", "argv"):
            return V_LOCAL
        return None

    def source_member(self, key):
        for rx, v in self.SOURCE_MEMBERS:
            if rx.search(key):
                return v
        return None

    def source_call(self, qual, simple):
        for rx, v in self.SOURCE_CALLS:
            if rx.search(qual) and not re.match(r"^(Query|Form|Headers|Cookies|Execute\w*|Get)$", qual):
                return v
        return None

    # ---- audit and hooks -----------------------------------------------------------------------------------
    def sql_built(self, eng, n):
        if n is None:
            return False
        sv = getattr(eng, "_sqlvars", None)
        if sv is None:
            sv = eng._sqlvars = set()
        sl = getattr(eng, "_sqllit", set())
        t = n.type
        while t == "parenthesized_expression" and n.named_children:
            n = n.named_children[0]; t = n.type
        if t == "identifier":
            return txt(n) in sv
        if t == "binary_expression":
            if txt(n.child_by_field_name("operator")) != "+":
                return False
        elif t == "interpolated_string_expression":
            pass
        elif t == "invocation_expression":
            e = self.expr(n)
            if e[4] == "ToString" and e[2] is not None and e[2].type == "identifier":
                return txt(e[2]) in sv
            if not (e[1] in ("string.Format", "String.Format") or e[4] in ("Format", "Concat", "Replace", "Join")):
                return False
        else:
            return False
        pieces = [self.literal(x) or "" for x in walk(n) if x.type in ("string_literal", "verbatim_string_literal")]
        pieces += [txt(x) for x in walk(n) if x.type in ("string_content", "interpolated_string_text", "interpolated_verbatim_string_text")]
        has_sql = any(SQL_RE.search(p) for p in pieces) or any(txt(x) in sv or txt(x) in sl for x in walk(n) if x.type == "identifier")
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
        sl = getattr(eng, "_sqllit", None)
        if sl is None:
            sl = eng._sqllit = set()
        if st[0] == "decl" and st[2]:
            for nm, v in zip(st[1], st[2]):
                if v is None:
                    continue
                lit = self.literal(v)
                if lit is not None and SQL_RE.search(lit):
                    sl.add(nm)
                elif self.sql_built(eng, v):
                    sv.add(nm)
        elif st[0] == "assign":
            key = self.lkey(st[1][0])
            v = st[2][0]
            if key and v is not None:
                if (self.literal(v) or "") and SQL_RE.search(self.literal(v) or ""):
                    sl.add(key)
                elif self.sql_built(eng, v) or (st[3] == "+=" and key in sl and eng.ev(v)[0] >= C.OTHER):
                    sv.add(key)

    def call_effects(self, eng, qual, simple, recv, args, vals, node):
        line = C.line_of(node)
        rel = eng.rel
        body_txt = eng.fdef.get("text", "")
        # --- StringBuilder used to build SQL
        if simple in ("Append", "AppendLine", "AppendFormat") and recv is not None and recv.type == "identifier" and args:
            nm = txt(recv)
            sl = getattr(eng, "_sqllit", None)
            if sl is None:
                sl = eng._sqllit = set()
            sv = getattr(eng, "_sqlvars", None)
            if sv is None:
                sv = eng._sqlvars = set()
            if SQL_RE.search(self.literal(args[0]) or "") or nm in sl:
                sl.add(nm)
            if nm in sl and any(self.literal(a) is None and (eng.ev(a)[0] >= C.OTHER or eng.ev(a)[1]) for a in args):
                sv.add(nm)
        # --- XmlTextReader: with default settings it processes external entities
        xtr = getattr(eng, "_xtr", set())
        if xtr and recv is not None and txt(recv) in xtr and simple in ("Read", "ReadElementContentAsString", "ReadString", "ReadInnerXml", "ReadOuterXml", "MoveToContent"):
            eng.p.add(rel, "AST-CS-008", "unknown", line, sink=f"{txt(recv)}.{simple} (XmlTextReader with default settings)")
        # --- RSA with PKCS#1 v1.5 padding, JavaScriptSerializer with a resolver, keys from a weak generator
        if simple in ("CreateKeyExchange", "DecryptKeyExchange") and re.search(r"RSAPKCS1KeyExchange", body_txt):
            eng.p.add(rel, "AST-CS-009", "fixed", line, sink=qual + " (PKCS#1 v1.5 padding)")
        if qual in ("JavaScriptSerializer",) and any(re.search(r"[Rr]esolver", txt(a)) for a in args):
            eng.p.add(rel, "AST-CS-007", "fixed", line, sink="JavaScriptSerializer with TypeResolver")
        if simple == "NextBytes" and args and recv is not None and re.search(r"(?i)rand|rng", txt(recv)) and "Crypto" not in txt(recv):
            eng.__dict__.setdefault("_weakkey", set()).add(txt(args[0]))
        wk = getattr(eng, "_weakkey", set())
        if wk and re.match(r"^(AesGcm|AesCcm|Aes|AesCng|AesManaged|ChaCha20Poly1305|HMACSHA256|HMACSHA512|SymmetricAlgorithm)$", qual.split(".")[-1]) and any(txt(a) in wk for a in args):
            eng.p.add(rel, "AST-CS-009", "fixed", line, sink=f"{qual} with a key generated by Random")
        # --- certificate validation by subject name / trust sent in the handshake
        if simple == "Equals" and re.search(r"(SubjectName\.Name|\.Subject\b|SubjectName)", " ".join(txt(a) for a in args) + " " + (txt(recv) if recv is not None else "")):
            eng.p.add(rel, "AST-CS-010", "fixed", line, sink="comparison on the certificate subject name")
        if re.search(r"SslCertificateTrust\.(CreateForX509Collection|CreateForX509Store)$", qual) and any(re.search(r"\btrue\b", txt(a)) for a in args):
            eng.p.add(rel, "AST-CS-010", "fixed", line, sink=qual + " sending the certificate chain in the handshake")
        if qual.endswith("UseDeveloperExceptionPage"):
            eng.p.add(rel, "AST-CS-015", "unknown", line, sink=qual)
        # --- Built SQL (audit)
        if re.search(r"^(SqlCommand|OleDbCommand|OdbcCommand|NpgsqlCommand|MySqlCommand|SqliteCommand|SQLiteCommand|OracleCommand|SqlDataAdapter)$|"
                     r"\.(ExecuteSqlRaw|ExecuteSqlCommand|FromSqlRaw|FromSql|SqlQuery|Query|QueryAsync|QueryFirst|QueryFirstOrDefault|QuerySingle|Execute|ExecuteAsync|ExecuteScalar|ExecuteReader)$", qual):
            for a in args[:1]:
                if self.sql_built(eng, a):
                    v = eng.ev(a)
                    if v[0] == C.TAINT and v[2]:
                        continue
                    eng.p.add(rel, "AST-CS-002", "confirmed" if v[0] == C.TAINT else "unknown", line, sink=qual)
                    for pi in v[1]:
                        eng.p.summary.setdefault(eng.key, []).append((frozenset([pi]), "AST-CS-002", rel, line, {"sink": qual}, "str", False))
        # --- process assembled at runtime
        if re.search(r"(^|\.)Process\.Start$", qual) and args:
            for a in args:
                v = eng.ev(a)
                if self.expr(a)[0] != "const" and (v[0] >= C.OTHER or v[1]) and v[0] != C.TAINT:
                    eng.p.add(rel, "AST-CS-001", "unknown", line, sink=qual)
                    break
        # --- XSS in MVC: Content(..., "text/html"), HtmlString
        # --- stack trace
        if simple in ("ToString", "StackTrace") and recv is not None and re.search(r"(?i)\b(ex|e|exception|err)\b", txt(recv)) and re.search(r"Response\.Write|Content\(|return\s", body_txt) and False:
            pass
        # --- Weak Random in sensitive contexts
        if re.search(r"(^|\.)(Random\.Next|Random\.NextBytes|Next|NextBytes|NextDouble)$", qual) and "RNGCryptoServiceProvider" not in body_txt and "RandomNumberGenerator" not in body_txt:
            nm = eng.name
            hit = SENSITIVE.search(nm)
            if not hit:
                p = node.parent
                while p is not None and p.type not in ("variable_declarator", "assignment_expression", "block", "expression_statement"):
                    p = p.parent
                if p is not None and p.type in ("variable_declarator", "assignment_expression"):
                    lhs = p.child_by_field_name("name") or p.child_by_field_name("left")
                    nm = txt(lhs) if lhs is not None else ""
                    hit = SENSITIVE.search(nm)
            if hit and ("new Random" in body_txt or simple in ("Next", "NextBytes")):
                eng.p.add(rel, "AST-CS-009", "fixed", line, sink=f"{qual} (non-cryptographic generator)")
        # --- ReDoS: Regex without a timeout
        if qual in ("Regex.IsMatch", "Regex.Match", "Regex.Matches", "Regex.Replace", "Regex.Split") and args:
            if len(args) < (3 if simple in ("IsMatch", "Match", "Matches") else 4) and self.expr(args[1] if len(args) > 1 else args[0])[0] != "const":
                v = eng.ev(args[1]) if len(args) > 1 else eng.ev(args[0])
                if v[0] >= C.OTHER or v[1]:
                    eng.p.add(rel, "AST-CS-013", "unknown", line, sink=qual)
        if qual == "Regex" and args:
            if any(re.search(r"InfiniteMatchTimeout", txt(a)) for a in args):
                eng.p.add(rel, "AST-CS-013", "fixed", line, sink="Regex with infinite timeout")
        if re.search(r"Regex\.(IsMatch|Match|Matches|Replace)$", qual) and any(re.search(r"InfiniteMatchTimeout", txt(a)) for a in args):
            eng.p.add(rel, "AST-CS-013", "fixed", line, sink=qual + " with infinite timeout")
        # --- ASP.NET: cookies
        if qual in ("HttpCookie", "CookieOptions", "System.Web.HttpCookie") or simple in ("Append",) and re.search(r"Cookies", qual):
            miss = [w for w in ("HttpOnly", "Secure") if not re.search(w + r"\s*=\s*true", body_txt)]
            if miss and qual in ("HttpCookie", "CookieOptions", "System.Web.HttpCookie"):
                eng.p.add(rel, "AST-CS-011", "fixed", line, what="Cookie created without " + " and ".join(miss) + ".")
        # --- HttpListener on all interfaces
        if simple == "Add" and recv is not None and re.search(r"Prefixes", txt(recv)) and args:
            lit = self.literal(args[0]) or ""
            if re.search(r"://(\*|\+)[:/]", lit):
                eng.p.add(rel, "AST-CS-016", "fixed", line, what="HttpListener listening on all interfaces (address with * or +).")
        # --- use of variables configured insecurely
        unsafe = getattr(eng, "_xmlunsafe", set())
        if unsafe and (qual in ("XmlReader.Create",) or simple in ("Load", "LoadXml", "LoadFrom")):
            names = {txt(a) for a in args} | ({txt(recv)} if recv is not None else set())
            if names & unsafe:
                eng.p.add(rel, "AST-CS-008", "fixed", line, sink=qual)
        psi = getattr(eng, "_psi", {})
        if psi and simple == "Start" and recv is not None and txt(recv) in psi:
            eng.p.add(rel, "AST-CS-001", "confirmed" if psi[txt(recv)] == "confirmed" else "unknown", line, sink=qual)
        if qual == "XmlTextReader" and not re.search(r"DtdProcessing\.(Prohibit|Ignore)|ProhibitDtd\s*=\s*true|XmlResolver\s*=\s*null", body_txt):
            eng.p.add(rel, "AST-CS-008", "unknown", line, sink="new XmlTextReader (default settings)")
            p = node.parent
            while p is not None and p.type not in ("variable_declarator", "assignment_expression", "block", "expression_statement", "using_statement"):
                p = p.parent
            if p is not None and p.type == "variable_declarator":
                eng.__dict__.setdefault("_xtr", set()).add(txt(p.child_by_field_name("name")))
            elif p is not None and p.type == "assignment_expression":
                eng.__dict__.setdefault("_xtr", set()).add(txt(p.child_by_field_name("left")))
        # --- Random.NextBytes is always predictable
        if simple == "NextBytes" and recv is not None and re.search(r"(?i)rand|rnd", txt(recv)) and "RandomNumberGenerator" not in txt(recv) and "RNG" not in txt(recv):
            eng.p.add(rel, "AST-CS-009", "fixed", line, sink=f"{qual} (non-cryptographic generator)")
        # --- HSTS
        if qual.startswith("app.Use") and simple in ("UseDeveloperExceptionPage", "UseExceptionHandler", "UseHttpsRedirection", "UseStaticFiles", "UseCookiePolicy",
                                                     "UseRouting", "UseAuthentication", "UseAuthorization", "UseMvc", "UseEndpoints", "UseSession", "UseCors") \
                and "UseHsts" not in body_txt:
            eng.p.add(rel, "AST-CS-020", "fixed", line, what="The pipeline does not call UseHsts, so browsers are not forced to use HTTPS.")
        # --- exception stack trace shown to the user
        if simple == "ToString" and recv is not None and re.fullmatch(r"(ex|e|exception|err|error)", txt(recv)):
            if re.search(r"Response\.Write|Content\(|BadRequest\(|StatusCode\(|Json\(", body_txt):
                eng.p.add(rel, "AST-CS-015", "unknown", line, sink=qual)

    def on_node(self, eng, n):
        rel = eng.rel
        line = C.line_of(n)
        t = n.type
        if t in self.STMT_TYPES:
            self.track_sql(eng, n)
        if t == "binary_expression" and txt(n.child_by_field_name("operator")) in ("==", "!="):
            if re.search(r"(SubjectName\.Name|\.Subject\b)", txt(n.child_by_field_name("left")) + " " + txt(n.child_by_field_name("right"))) and \
                    (self.expr(n.child_by_field_name("left"))[0] == "const" or self.expr(n.child_by_field_name("right"))[0] == "const"):
                eng.p.add(rel, "AST-CS-010", "fixed", line, sink="comparison on the certificate subject name")
        if t == "assignment_expression":
            l, r = n.child_by_field_name("left"), n.child_by_field_name("right")
            key = txt(l)
            rv = txt(r)
            if re.search(r"(^|\.)(CommandText)$", key):
                v = eng.ev(r)
                if self.sql_built(eng, r) or v[0] == C.TAINT:
                    if not (v[0] == C.TAINT and v[2]):
                        eng.p.add(rel, "AST-CS-002", "confirmed" if v[0] == C.TAINT else "unknown", line, sink=key)
            if re.search(r"(^|\.)(FileName|Arguments)$", key):
                v = eng.ev(r)
                base = key.split(".")[0]
                if v[0] == C.TAINT and not v[2]:
                    eng.p.add(rel, "AST-CS-001", "confirmed", line, sink=key)
                    eng.__dict__.setdefault("_psi", {})[base] = "confirmed"
                elif v[0] == C.PARAM or (v[0] >= C.OTHER and self.expr(r)[0] != "const"):
                    eng.p.add(rel, "AST-CS-001", "unknown", line, sink=key)
                    eng.__dict__.setdefault("_psi", {}).setdefault(base, "unknown")
            if re.search(r"TypeFilterLevel$", key) and re.search(r"TypeFilterLevel\.Full", rv):
                eng.p.add(rel, "AST-CS-007", "fixed", line, sink="TypeFilterLevel.Full")
            if re.search(r"TypeNameHandling$", key) and re.search(r"TypeNameHandling\.(All|Auto|Objects|Arrays)", rv):
                eng.p.add(rel, "AST-CS-007", "fixed", line, sink=f"{key} = {rv}")
            if re.search(r"(DtdProcessing)$", key) and re.search(r"DtdProcessing\.Parse", rv):
                eng.p.add(rel, "AST-CS-008", "fixed", line, sink="DtdProcessing.Parse")
                eng.__dict__.setdefault("_xmlunsafe", set()).add(key.split(".")[0])
            if re.search(r"(^|\.)XmlResolver$", key) and re.search(r"new\s+XmlUrlResolver|XmlSecureResolver_NO", rv):
                eng.p.add(rel, "AST-CS-008", "fixed", line, sink="XmlResolver = new XmlUrlResolver()")
                eng.__dict__.setdefault("_xmlunsafe", set()).add(key.split(".")[0])
            if re.search(r"ProhibitDtd$", key) and rv == "false":
                eng.p.add(rel, "AST-CS-008", "fixed", line, sink="ProhibitDtd = false")
            if re.search(r"(ServerCertificateValidationCallback|ServerCertificateCustomValidationCallback)$", key) or (txt(n).count("+=") and re.search(r"ServerCertificateValidationCallback", key)):
                if re.search(r"=>\s*true|return\s+true|DangerousAcceptAnyServerCertificateValidator", rv):
                    eng.p.add(rel, "AST-CS-010", "fixed", line, sink=key + " accepts every certificate")
            if re.search(r"SecurityProtocol$", key) and re.search(r"SecurityProtocolType\.(Ssl3|Tls|Tls11)\b", rv):
                eng.p.add(rel, "AST-CS-010", "fixed", line, sink=f"{key} = {rv}")
            if re.search(r"(^|\.)(Secure|HttpOnly)$", key) and rv == "false":
                eng.p.add(rel, "AST-CS-011", "fixed", line, what=f"{key} = false disables the cookie protection.")
            if re.search(r"(^|\.)(Mode)$", key) and re.search(r"CipherMode\.ECB", rv):
                eng.p.add(rel, "AST-CS-009", "fixed", line, sink="CipherMode.ECB")
            if re.search(r"Validate(Lifetime|Issuer|Audience|IssuerSigningKey)$", key) and rv == "false":
                eng.p.add(rel, "AST-CS-014", "fixed", line, what=f"{key} = false: the token is not being validated.")
            if re.search(r"RequireExpirationTime$|RequireSignedTokens$", key) and rv == "false":
                eng.p.add(rel, "AST-CS-014", "fixed", line, what=f"{key} = false: the token is not being validated.")
            if re.search(r"(^|\.)Filter$", key):
                v = eng.ev(r)
                if v[0] == C.TAINT and not v[2]:
                    eng.p.add(rel, "AST-CS-012", "confirmed", line, sink=key)
                elif (v[0] == C.PARAM or v[0] >= C.OTHER) and self.expr(r)[0] in ("bin", "tmpl2", "call") and not re.search(r"Escape|Encode", rv):
                    eng.p.add(rel, "AST-CS-012", "unknown", line, sink=key)
        if t == "initializer_expression" or t == "object_creation_expression":
            tx = txt(n)
            if re.search(r"TypeNameHandling\s*=\s*TypeNameHandling\.(All|Auto|Objects|Arrays)", tx):
                eng.p.add(rel, "AST-CS-007", "fixed", line, sink="insecure TypeNameHandling")
            if re.search(r"TypeFilterLevel\s*=\s*TypeFilterLevel\.Full", tx):
                eng.p.add(rel, "AST-CS-007", "fixed", line, sink="TypeFilterLevel.Full")
            if re.search(r"DtdProcessing\s*=\s*DtdProcessing\.Parse", tx):
                eng.p.add(rel, "AST-CS-008", "fixed", line, sink="DtdProcessing.Parse")
            if re.search(r"(Secure|HttpOnly)\s*=\s*false", tx):
                eng.p.add(rel, "AST-CS-011", "fixed", line, what="Cookie with Secure or HttpOnly set to false.")
            if re.search(r"Validate(Lifetime|Issuer|Audience|IssuerSigningKey)\s*=\s*false|RequireExpirationTime\s*=\s*false", tx):
                eng.p.add(rel, "AST-CS-014", "fixed", line, what="TokenValidationParameters with validation checks disabled.")
            if re.search(r"ServerCertificateCustomValidationCallback\s*=.*(=>\s*true|DangerousAcceptAny)", tx, re.S):
                eng.p.add(rel, "AST-CS-010", "fixed", line, sink="certificate validation that accepts everything")
        if t == "invocation_expression" and re.search(r"SetMinimumLevel_NO", txt(n)):
            pass
        if t == "class_declaration" and re.search(r"\bDataContractResolver\b", txt(n)[:300].split("{")[0]):
            eng.p.add(rel, "AST-CS-007", "fixed", line, sink="class derived from DataContractResolver")
        if t == "member_access_expression" and txt(n.child_by_field_name("name")) == "PrivateKey" and re.search(r"(?i)cert|x509", txt(n)):
            eng.p.add(rel, "AST-CS-009", "unknown", line, sink="X509Certificate2.PrivateKey (direct access to the private key)")
        if t == "member_access_expression" and txt(n.child_by_field_name("name")) == "StackTrace":
            p = n.parent
            if p is not None and p.type not in ("assignment_expression",):
                eng.p.add(rel, "AST-CS-015", "unknown", line, sink="StackTrace")
        if t == "method_declaration":
            pl = n.child_by_field_name("parameters")
            body0 = n.child_by_field_name("body")
            if pl is not None and body0 is not None and re.search(r"SslPolicyErrors", txt(pl)) and re.fullmatch(r"\{\s*return\s+true;\s*\}", re.sub(r"//[^\n]*", "", txt(body0)).strip()):
                eng.p.add(rel, "AST-CS-010", "fixed", line, sink="validation callback that accepts every certificate")
        if t == "method_declaration":
            attrs = " ".join(txt(c) for c in n.children if c.type == "attribute_list")
            body = n.child_by_field_name("body")
            if re.search(r"\[(HttpPost|HttpPut|HttpDelete|HttpPatch)", attrs) and not re.search(r"ValidateAntiForgeryToken|IgnoreAntiforgeryToken_NO|AutoValidateAntiforgeryToken", attrs):
                # a class with global anti-forgery, or an API controller, is not a problem
                p = n.parent
                cls = ""
                while p is not None:
                    if p.type in ("class_declaration",):
                        cls = txt(p)[:400].split("{")[0] + " " + " ".join(txt(c) for c in p.children if c.type == "attribute_list")
                        break
                    p = p.parent
                if not re.search(r"ValidateAntiForgeryToken|AutoValidateAntiforgery|ApiController|ControllerBase", cls) and re.search(r"Controller\b", cls):
                    eng.p.add(rel, "AST-CS-017", "unknown", line, what="[HttpPost] action without [ValidateAntiForgeryToken].")
            if re.search(r"TryUpdateModel|UpdateModel", txt(body) if body is not None else ""):
                eng.p.add(rel, "AST-CS-018", "unknown", line, what="UpdateModel/TryUpdateModel populates the object with every submitted field.")


LANG = CSharpLang()


def analyze_csharp_project(sources):
    return C.analyze(LANG, sources)


def analyze_csharp_source(rel_path, text):
    return C.analyze_source(LANG, rel_path, text)
