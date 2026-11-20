# -*- coding: utf-8 -*-
"""
java_engine.py
===============
Security engine for Java (.java: servlet, Spring, JAX-RS, JDBC, Android) built on a real parser (tree-sitter-java) and
data-flow analysis on top of the shared core in lang_core.py.

Vulnerability classes covered: command injection, SQL injection (JDBC, JdbcTemplate, JPA/Hibernate), XSS, path traversal, SSRF,
open redirect, deserialization (ObjectInputStream, XStream, SnakeYAML, Jackson default typing, XMLDecoder), XXE (all XML
factories), weak cryptography (MD5, SHA-1, DES, RC4, AES/ECB, short RSA keys, hardcoded keys and IVs), disabled TLS/host
verification, cookies without Secure/HttpOnly, expression/script injection (SpEL, OGNL, ScriptEngine, Groovy), LDAP injection,
reflection with externally chosen names, disabled CSRF protection, weak random numbers for sensitive data, JWT without
verification, hardcoded passwords, exposed stack traces, cleartext http connections.

Known limitations: no type checker (methods are recognized by name), no framework analysis beyond the most common names,
no inspection of XML/YAML configuration. The code under analysis is never executed.
"""

import logging
import re

import lang_core as C
from lang_core import Sink, Fixed, V_TAINT, V_LOCAL, txt, walk

log = logging.getLogger(__name__)

try:
    from tree_sitter import Language, Parser
    import tree_sitter_java as _tsj
    _PARSER = Parser(Language(_tsj.language()))
    AVAILABLE = True
except Exception as _exc:                           # pragma: no cover
    AVAILABLE = False
    log.warning(
        "Java AST analysis is disabled: tree-sitter or tree-sitter-java could not be loaded (%s: %s). "
        "Only pattern-based rules will run for .java files. Install the missing packages with: "
        "pip install tree-sitter tree-sitter-java", type(_exc).__name__, _exc)

SUPPORTED = (".java",)
MAX_PROJECT_BYTES = C.MAX_PROJECT_BYTES

RULES = {
    "AST-JAVA-001": ("Command execution with untrusted data", "CRITICAL", "HIGH",
                     "{sink} executes a command that is partly built from external input or assembled at runtime.",
                     "Pass arguments as a separate list to ProcessBuilder and validate the input against an allowlist.", "CWE-78"),
    "AST-JAVA-002": ("SQL injection", "CRITICAL", "HIGH",
                     "{sink} receives a query built from externally supplied data.",
                     "Use PreparedStatement with bind parameters (?); never string concatenation or String.format in queries.", "CWE-89"),
    "AST-JAVA-003": ("Unsanitized content written to the response (XSS)", "HIGH", "MEDIUM",
                     "{sink} writes externally supplied data to the response without sanitizing it.",
                     "Encode the output (OWASP Encoder, StringEscapeUtils.escapeHtml4) or use a template engine that escapes automatically.", "CWE-79"),
    "AST-JAVA-004": ("Externally controlled file path (path traversal)", "HIGH", "MEDIUM",
                     "{sink} uses a path supplied by external input.",
                     "Normalize the path (toRealPath/getCanonicalPath), verify it stays inside the permitted directory, and reject '..'.", "CWE-22"),
    "AST-JAVA-005": ("Request to an externally controlled address (SSRF)", "HIGH", "MEDIUM",
                     "{sink} contacts an address supplied by external input, which may allow access to internal services.",
                     "Accept only hosts from an allowlist and block internal addresses.", "CWE-918"),
    "AST-JAVA-006": ("Redirect to an externally controlled address", "MEDIUM", "LOW",
                     "{sink} redirects the user to an address chosen by external input.",
                     "Redirect only to internal paths or to hosts on an allowlist.", "CWE-601"),
    "AST-JAVA-007": ("Insecure deserialization", "HIGH", "MEDIUM",
                     "{sink} rebuilds objects from untrusted data or without restricting the allowed types.",
                     "Avoid native serialization on external data; use schema-validated JSON and disable default typing.", "CWE-502"),
    "AST-JAVA-008": ("XML parser without external entity protection (XXE)", "MEDIUM", "MEDIUM",
                     "{sink} creates an XML parser without disabling DOCTYPE/external entities.",
                     "Set disallow-doctype-decl on the parser (or FEATURE_SECURE_PROCESSING with an empty ACCESS_EXTERNAL_DTD).", "CWE-611"),
    "AST-JAVA-009": ("Weak cryptographic algorithm or hardcoded key", "MEDIUM", "MEDIUM",
                     "{sink} uses an algorithm, mode, key or initialization vector that is weak or fixed.",
                     "Use SHA-256 or stronger and AES-GCM with random keys and IVs (SecureRandom); use RSA keys of at least 2048 bits.", "CWE-327"),
    "AST-JAVA-010": ("Certificate or hostname verification disabled", "HIGH", "HIGH",
                     "{sink}: the connection no longer verifies the identity of the remote peer.",
                     "Keep the default verification enabled; use certificate pinning for special cases.", "CWE-295"),
    "AST-JAVA-011": ("Cookie without protection flags", "MEDIUM", "MEDIUM",
                     "{what}",
                     "Set Secure and HttpOnly (and SameSite) on session cookies.", "CWE-614"),
    "AST-JAVA-012": ("Injection in expressions, scripts or reflection", "HIGH", "MEDIUM",
                     "{sink} interprets externally supplied text as an expression, script or class name.",
                     "Never evaluate external input as code: use an allowlist or parameters.", "CWE-94"),
    "AST-JAVA-013": ("LDAP injection", "HIGH", "MEDIUM",
                     "{sink} builds an LDAP filter from externally supplied data.",
                     "Use parameterized filters and escape special characters (Encode.forLDAP).", "CWE-90"),
    "AST-JAVA-014": ("CSRF or CORS protection disabled", "MEDIUM", "MEDIUM",
                     "{what}",
                     "Keep CSRF protection enabled and restrict CORS origins to trusted ones.", "CWE-352"),
    "AST-JAVA-015": ("Insecure random numbers for sensitive data", "MEDIUM", "MEDIUM",
                     "{sink} is predictable, yet here it generates a value that looks like a secret ('{name}').",
                     "Usa java.security.SecureRandom.", "CWE-330"),
    "AST-JAVA-016": ("JWT token without signature verification", "HIGH", "MEDIUM",
                     "{sink} accepts unverified or unsigned tokens.",
                     "Use the parser that verifies the signature (parseClaimsJws) and reject the 'none' algorithm.", "CWE-347"),
    "AST-JAVA-017": ("Hardcoded password", "HIGH", "HIGH",
                     "{sink} uses a password written directly in the code.",
                     "Read credentials from environment variables or a secrets manager.", "CWE-798"),
    "AST-JAVA-018": ("Exposed stack trace", "LOW", "LOW",
                     "{sink} prints the full stack trace, which can reveal paths, versions and internal structure.",
                     "Log the error with a logger and show only a generic message to the user.", "CWE-209"),
    "AST-JAVA-019": ("Cleartext connection (http)", "MEDIUM", "LOW",
                     "{what}",
                     "Usa https://.", "CWE-319"),
    "AST-JAVA-021": ("Regular expression built from untrusted data (ReDoS)", "MEDIUM", "LOW",
                     "{sink} compiles externally supplied text as a regular expression; a crafted pattern can hang the program.",
                     "Never compile external input as a regex: use Pattern.quote or an allowlist, and enforce a time limit.", "CWE-1333"),
    "AST-JAVA-020": ("Weak password encoding", "HIGH", "HIGH",
                     "{sink} stores or compares passwords without a strong hash.",
                     "Use BCryptPasswordEncoder, Argon2 or Pbkdf2.", "CWE-256"),
}

SENSITIVE = re.compile(r"(token|secret|passw|pwd|nonce|salt|session|csrf|otp|apikey|api_key|\bkey\b|_key|key_|\biv\b|cookie|auth)", re.I)
SQL_RE = re.compile(r"(?i)\b(select|insert\s+into|update\s+\w+\s+set|delete\s+from|drop\s+(table|database)|create\s+table|alter\s+table|truncate|where\s+\w+|order\s+by|union\s+select|from\s+\w+)\b")
HOST_FIXED = re.compile(r"^https?://[A-Za-z0-9.\-]+(:\d+)?(/|\?|$)")
ANN_TAINT = re.compile(r"(RequestParam|PathVariable|RequestBody|QueryParam|FormParam|PathParam|HeaderParam|CookieParam|CookieValue|RequestHeader|MatrixParam|ModelAttribute|RequestPart|BeanParam)")
TYPE_TAINT = re.compile(r"(HttpServletRequest|ServletRequest|HttpRequest|ServerHttpRequest|ServerRequest|MultipartFile|HttpExchange|WebRequest|\bPart\b|UriInfo|HttpHeaders|ContainerRequestContext)")
SECURE_XML = re.compile(r"disallow-doctype-decl|FEATURE_SECURE_PROCESSING|IS_SUPPORTING_EXTERNAL_ENTITIES|ACCESS_EXTERNAL|setExpandEntityReferences|external-general-entities|"
                        r"external-parameter-entities|load-external-dtd|XMLConstants|SUPPORT_DTD|setXIncludeAware|ignoringElementContentWhitespace_NO")


def _fixed_host(eng, n):
    t = n
    while t is not None and t.type == "parenthesized_expression" and t.named_children:
        t = t.named_children[0]
    if t is None:
        return False
    if t.type == "string_literal":
        return True
    if t.type == "binary_expression":
        x = t
        while x.type == "binary_expression" and x.child_by_field_name("left") is not None:
            x = x.child_by_field_name("left")
        return x.type == "string_literal" and bool(HOST_FIXED.match(LANG.literal(x) or ""))
    if t.type == "method_invocation" and txt(t.child_by_field_name("name")) == "format":
        a = LANG._args(t)
        return bool(a) and a[0].type == "string_literal" and bool(HOST_FIXED.match(LANG.literal(a[0]) or ""))
    return False


class JavaLang(C.LangBase):
    ENGINE = "java_ast"
    EXTS = SUPPORTED
    RULES = RULES
    AVAILABLE = AVAILABLE
    CALL_TYPES = {"method_invocation", "object_creation_expression"}
    FUNC_TYPES = {"method_declaration", "constructor_declaration"}
    STMT_TYPES = {"variable_declarator", "assignment_expression", "enhanced_for_statement"}
    TEST_RE = re.compile(r"(^|/)_?(tests?|testdata|examples?|docs?|samples?|src/test)(/|$)|(Test|Tests|IT|Spec)\.java$")
    TEST_QUIET = frozenset({"AST-JAVA-008", "AST-JAVA-010", "AST-JAVA-011", "AST-JAVA-014", "AST-JAVA-015", "AST-JAVA-017", "AST-JAVA-018", "AST-JAVA-019"})
    CLEAN_RE = re.compile(r"(escapeHtml|escapeHtml4|escapeXml|escapeJava|escapeEcmaScript|htmlEscape|HtmlUtils\.htmlEscape|Encode\.for|Encoder\.encode|"
                          r"ESAPI\.encoder|sanitize|Sanitizer|URLEncoder\.encode|FilenameUtils\.getName|\.getFileName$|getCanonicalPath|toRealPath|"
                          r"Pattern\.quote|Matcher\.quoteReplacement|StringEscapeUtils|Jsoup\.clean|PolicyFactory|\.normalize$)")
    NUM_RE = re.compile(r"(Integer\.(parseInt|valueOf)|Long\.(parseLong|valueOf)|Double\.(parseDouble|valueOf)|Float\.parseFloat|Short\.parseShort|"
                        r"Byte\.parseByte|Boolean\.parseBoolean|UUID\.fromString|BigInteger|BigDecimal|\.length$|\.size$|\.hashCode$|\.ordinal$)")
    VALIDATE_RE = re.compile(r"(startsWith|endsWith|contains|matches|equals|equalsIgnoreCase|isValid|validate|isSafe|isAllowed|allowed|whitelist|allowlist|"
                             r"isNumeric|isDigit|isAlphanumeric|checkPath|normalize)")
    LEN_RE = re.compile(r"(\.length|\.size|Math\.min)$")
    SOURCE_CALLS = [
        (re.compile(r"(^|\.)(System\.getenv|System\.getProperty|getenv)$"), V_LOCAL),
        (re.compile(r"\.(nextLine|next|nextInt|readLine)$"), None),   # propagate only from the receiver
        (re.compile(r"\.(getParameter|getParameterValues|getParameterMap|getParameterNames|getHeader|getHeaders|getHeaderNames|getQueryString|getCookies|"
                    r"getRequestURI|getRequestURL|getPathInfo|getPathTranslated|getInputStream|getReader|getRemoteUser|getServletPath|getPart|getParts|"
                    r"getContentType|getMethod_NO|getCharacterEncoding|getAuthType|getRemoteHost|getContextPath_NO|readLine_NO|getFirst|getQueryParameters|"
                    r"getPathParameters|getEntity|getBody|getFileName_NO|getOriginalFilename|getValue_NO)$"), V_TAINT),
    ]
    SOURCE_MEMBERS = [(re.compile(r"^System\.in$"), V_LOCAL)]
    SINKS = [
        Sink("AST-JAVA-001", r"(^|\.)Runtime\.getRuntime(\(\))?\.exec$", audit=True),
        Sink("AST-JAVA-001", r"^(ProcessBuilder|java\.lang\.ProcessBuilder)$", audit=True),
        Sink("AST-JAVA-001", r"\.(command|exec)$", (0,), audit=True),
        Sink("AST-JAVA-002", r"\.(executeQuery|executeUpdate|executeLargeUpdate|execute|addBatch|prepareStatement|prepareCall|nativeSQL|"
                              r"createQuery|createNativeQuery|createSQLQuery|createStatement_NO|queryForObject|queryForList|queryForMap|queryForRowSet|"
                              r"queryForInt|queryForLong|query|update|batchUpdate|find_NO|getResultList_NO|newQuery|setFilter|setGrouping|setOrdering|"
                              r"newPreparedStatementCreator|createPreparedStatementCreator|querySingle|preparedQuery|preparedBatch|updateWithParams|queryWithParams|"
                              r"executeBatch_NO|createCriteria_NO|sqlRestriction|createSQLQuery)$", (0,)),
        Sink("AST-JAVA-002", r"^(PreparedStatementCreatorFactory|PreparedStatementCreator)$", (0,)),
        Sink("AST-JAVA-003", r"\.(write|print|println|printf|append|format|sendError|getRequestDispatcher_NO)$", (0,), kind="str"),
        Sink("AST-JAVA-004", r"^(File|FileInputStream|FileOutputStream|FileReader|FileWriter|RandomAccessFile|PrintWriter_NO|ZipFile|JarFile|"
                              r"FileSystemResource|PathResource)$", None, skip_local=True),
        Sink("AST-JAVA-004", r"^(Paths\.get|Path\.of|Files\.(readAllBytes|readAllLines|readString|newInputStream|newOutputStream|newBufferedReader|"
                              r"newBufferedWriter|write|writeString|copy|move|delete|deleteIfExists|lines|walk|list|createFile|createDirectory|createDirectories|"
                              r"exists|isDirectory|isRegularFile|size))$", None, skip_local=True),
        Sink("AST-JAVA-004", r"\.(getResourceAsStream|getRealPath|getResource|getRequestDispatcher|forward|include)$", (0,), skip_local=True),
        Sink("AST-JAVA-005", r"^(URL|URI|java\.net\.URL|java\.net\.URI)$", (0,), exempt=_fixed_host),
        Sink("AST-JAVA-005", r"^URI\.create$", (0,), exempt=_fixed_host),
        Sink("AST-JAVA-005", r"^(HttpGet|HttpPost|HttpPut|HttpDelete|HttpHead|HttpPatch|HttpOptions|HttpTrace)$", (0,), exempt=_fixed_host),
        Sink("AST-JAVA-005", r"\.(getForObject|getForEntity|postForObject|postForEntity|postForLocation|exchange|execute_NO|headForHeaders|optionsForAllow)$", (0,), exempt=_fixed_host),
        Sink("AST-JAVA-005", r"(Jsoup\.connect|\.uri|WebClient\.create|\.baseUrl|\.target)$", (0,), exempt=_fixed_host),
        Sink("AST-JAVA-006", r"\.(sendRedirect|encodeRedirectURL|encodeRedirectUrl)$", (0,)),
        Sink("AST-JAVA-006", r"^(RedirectView|ModelAndView_NO)$", (0,)),
        Sink("AST-JAVA-007", r"^(ObjectInputStream|XMLDecoder|java\.io\.ObjectInputStream|ValidatingObjectInputStream)$", (0,), audit=True),
        Sink("AST-JAVA-007", r"\.(fromXML|readUnshared|unmarshal|deserialize|readValue_NO)$", (0,)),
        Sink("AST-JAVA-007", r"(^|\.)(Yaml|yaml)\.(load|loadAs|loadAll)$|\.(load|loadAs|loadAll)$", (0,)),
        Sink("AST-JAVA-012", r"\.(eval|evaluate|parseExpression|compileExpression|createExpression|createScript|createValueExpression|createMethodExpression|parseClass|run_NO|parse)$", None, audit=True),
        Sink("AST-JAVA-012", r"^(Ognl\.(getValue|parseExpression|setValue)|MVEL\.eval|Velocity\.evaluate|Class\.forName|ClassLoader\.loadClass|OgnlUtil\.(getValue|setValue)|ValueStack\.(findValue|setValue)|Eval\.me)$", (0,), audit=True),
        Sink("AST-JAVA-012", r"\.(loadClass|forName|getMethod|getDeclaredMethod|getDeclaredField|getField|newInstance_NO)$", (0,)),
        Sink("AST-JAVA-013", r"\.(search|searchForObject_NO|lookup_NO)$", (0, 1), audit=True),
        Sink("AST-JAVA-021", r"^(Pattern\.(compile|matches)|java\.util\.regex\.Pattern\.(compile|matches))$", (0,), audit=True),
    ]
    FIXED = [
        Fixed("AST-JAVA-009", r"(^|\.)MessageDigest\.getInstance$", (0, r"(?i)^(md2|md4|md5|sha-?1|sha-?224|sha-?512/224)$")),
        Fixed("AST-JAVA-009", r"(^|\.)Cipher\.getInstance$", (0, r"(?i)^(des|desede|3des|rc2|rc4|arcfour|blowfish|aes|rsa|.*/ecb/.*|.*pkcs1padding|"
                                                                  r"pbewith(md5|sha1)and\w+|aes/cbc/pkcs5padding|aes/cbc/pkcs7padding|des/.*|desede/.*|rsa/ecb/nopadding)$")),
        Fixed("AST-JAVA-009", r"(^|\.)(KeyGenerator|SecretKeyFactory|Mac|KeyAgreement|Signature)\.getInstance$", (0, r"(?i)^(des|desede|rc2|rc4|blowfish|hmacmd5|hmacsha1_NO|md5with\w+|sha1with\w+|pbewith(md5|sha1)\w+)$")),
        Fixed("AST-JAVA-009", r"^NullCipher$"),
        Fixed("AST-JAVA-009", r"\.initialize$", (0, r"^(512|768|1024)$")),
        Fixed("AST-JAVA-009", r"\.(enableDefaultTyping|activateDefaultTyping)$"),
        Fixed("AST-JAVA-009", r"^(DefaultHttpClient|SSLSocketFactory_NO)$"),
        Fixed("AST-JAVA-009", r"(^|\.)SecretKeySpec$", (1, r"(?i)^(des|desede|rc2|rc4|arcfour|blowfish)$")),
        Fixed("AST-JAVA-009", r"(^|\.)(DigestUtils)\.(md5|md5Hex|md2|md2Hex|getMd5Digest|getMd2Digest|sha1|sha1Hex|shaHex|sha|getSha1Digest|getShaDigest)$"),
        Fixed("AST-JAVA-010", r"\.(setHostnameVerifier|setDefaultHostnameVerifier)$", None, any_lit=r"ALLOW_ALL|AllowAll|NoopHostnameVerifier"),
        Fixed("AST-JAVA-010", r"^(AllowAllHostnameVerifier|NoopHostnameVerifier|TrustAllStrategy|TrustSelfSignedStrategy_NO)$"),
        Fixed("AST-JAVA-010", r"(^|\.)SSLContext\.getInstance$", (0, r"(?i)^(ssl|sslv3|sslv2|tls|tlsv1|tlsv1\.0|tlsv1\.1)$")),
        Fixed("AST-JAVA-010", r"\.(setEnabledProtocols|setSSLProtocol_NO)$", None, any_lit=r"(?i)(SSLv|TLSv1(\.0|\.1)?\")"),
        Fixed("AST-JAVA-011", r"\.(setSecure|setHttpOnly)$", (0, r"^false$")),
        Fixed("AST-JAVA-014", r"\.csrf(\(\))?\.disable$"),
        Fixed("AST-JAVA-014", r"\.csrf\([^)]*\)$", None, any_lit=r"disable"),
        Fixed("AST-JAVA-016", r"Jwts\.parser.*\.parse$"),
        Fixed("AST-JAVA-016", r"^(Algorithm\.none|JWT\.decode|JWT\.require_NO)$"),
        Fixed("AST-JAVA-016", r"\.setAllowedClockSkewSeconds_NO$"),
        Fixed("AST-JAVA-017", r"^(DriverManager\.getConnection)$", (2, r".+")),
        Fixed("AST-JAVA-017", r"\.(setPassword|setCredentials_NO)$", (0, r".+")),
        Fixed("AST-JAVA-017", r"^(PasswordAuthentication)$", (1, r".+")),
        Fixed("AST-JAVA-020", r"(^|\.)NoOpPasswordEncoder\.getInstance$"),
        Fixed("AST-JAVA-020", r"^(StandardPasswordEncoder|Md5PasswordEncoder|ShaPasswordEncoder|LdapShaPasswordEncoder|Md4PasswordEncoder|MessageDigestPasswordEncoder)$"),
        Fixed("AST-JAVA-018", r"\.printStackTrace$", (-1, r"^$")),
    ]
    PROPAGATE = [
        (re.compile(r"\.(append|insert|concat|add|put|set|write|print)$"), "args", ("recv",)),
        (re.compile(r"\.(read|readLine|readAllBytes|readAllLines|readString|lines|getBytes|toCharArray|toString|trim|substring|replace|replaceAll|format|formatted|getValue|getName|split|toLowerCase|toUpperCase|valueOf|join)$"), "recv", ()),
    ]

    # ---- parsing and functions -----------------------------------------------------------------------------
    def parse(self, rel, text):
        return _PARSER.parse(text.encode("utf-8", "ignore"))

    def top_level(self, root, rel):
        return {"name": "<class>", "params": [], "body": root, "receiver": None, "text": "", "top": True}

    def functions(self, root):
        for n in walk(root):
            if n.type not in ("method_declaration", "constructor_declaration"):
                continue
            body = n.child_by_field_name("body")
            if body is None:
                continue
            params = []
            pl = n.child_by_field_name("parameters")
            if pl is not None:
                for p in pl.named_children:
                    if p.type in ("formal_parameter", "spread_parameter"):
                        nm = p.child_by_field_name("name")
                        if nm is None:
                            nm = next((c.child_by_field_name("name") for c in p.children if c.type == "variable_declarator"), None)
                        mods = next((txt(c) for c in p.children if c.type == "modifiers"), "")
                        ty = txt(p.child_by_field_name("type")) if p.child_by_field_name("type") is not None else ""
                        params.append((txt(nm) if nm is not None else None, ty, mods))
            nm = txt(n.child_by_field_name("name"))
            mods = next((txt(c) for c in n.children if c.type == "modifiers"), "")
            yield {"name": nm, "params": params, "body": body, "receiver": None, "text": txt(body), "mods": mods}

    # ---- expressions ----------------------------------------------------------------------------------------
    def qual_of(self, n):
        if n is None:
            return ""
        t = n.type
        if t in ("identifier", "type_identifier", "this", "super"):
            return txt(n)
        if t == "field_access":
            return self.qual_of(n.child_by_field_name("object")) + "." + txt(n.child_by_field_name("field"))
        if t == "scoped_identifier" or t == "scoped_type_identifier":
            return re.sub(r"\s+", "", txt(n))
        if t == "method_invocation":
            obj = n.child_by_field_name("object")
            nm = txt(n.child_by_field_name("name"))
            return (self.qual_of(obj) + "()." if obj is not None and obj.type == "method_invocation" else (self.qual_of(obj) + "." if obj is not None else "")) + nm \
                if obj is None or obj.type != "method_invocation" else self.qual_of(obj) + "." + nm
        if t == "object_creation_expression":
            return self.qual_of(n.child_by_field_name("type")) + "()"
        if t in ("parenthesized_expression", "cast_expression") and n.named_children:
            return self.qual_of(n.named_children[-1])
        if t == "array_access":
            return self.qual_of(n.child_by_field_name("array")) + "[]"
        return re.sub(r"\s+", "", txt(n))[:40]

    def _args(self, n):
        a = n.child_by_field_name("arguments")
        return [c for c in a.named_children if c.type != "comment"] if a is not None else []

    def expr(self, n):
        t = n.type
        if t in ("string_literal", "text_block", "character_literal", "decimal_integer_literal", "hex_integer_literal", "octal_integer_literal",
                 "binary_integer_literal", "decimal_floating_point_literal", "hex_floating_point_literal", "true", "false", "null_literal",
                 "this", "class_literal", "lambda_expression", "method_reference", "instanceof_expression"):
            return ("const",) if t != "instanceof_expression" else ("cmp",)
        if t == "identifier":
            return ("name", txt(n))
        if t == "field_access":
            return ("member", n.child_by_field_name("object"), txt(n.child_by_field_name("field")), self.qual_of(n))
        if t == "array_access":
            return ("index", n.child_by_field_name("array"), n.child_by_field_name("index"))
        if t in ("parenthesized_expression", "unary_expression", "update_expression"):
            return ("wrap", n.named_children[-1] if n.named_children else None)
        if t == "cast_expression":
            return ("wrap", n.child_by_field_name("value"))
        if t == "binary_expression":
            op = txt(n.child_by_field_name("operator"))
            if op in ("==", "!=", "<", ">", "<=", ">=", "&&", "||"):
                return ("cmp",)
            return ("bin", [n.child_by_field_name("left"), n.child_by_field_name("right")], op)
        if t == "ternary_expression":
            return ("cond", (n.child_by_field_name("condition"), n.child_by_field_name("consequence"), n.child_by_field_name("alternative")))
        if t in ("array_initializer", "element_value_array_initializer"):
            return ("list", list(n.named_children))
        if t == "array_creation_expression":
            v = n.child_by_field_name("value")
            return ("list", list(v.named_children)) if v is not None else ("const",)
        if t == "assignment_expression":
            return ("wrap", n.child_by_field_name("right"))
        if t == "method_invocation":
            obj = n.child_by_field_name("object")
            nm = txt(n.child_by_field_name("name"))
            qual = (self.qual_of(obj) + "." + nm) if obj is not None else nm
            if obj is not None and obj.type == "method_invocation":
                qual = self.qual_of(obj) + "." + nm
            return ("call", qual, obj, self._args(n), nm)
        if t == "object_creation_expression":
            ty = n.child_by_field_name("type")
            nm = txt(ty).split(".")[-1].split("<")[0]
            q = re.sub(r"<.*>", "", re.sub(r"\s+", "", txt(ty)))
            return ("call", q, None, self._args(n), nm)
        return ("other",)

    def stmt(self, n):
        t = n.type
        if t == "variable_declarator":
            nm = n.child_by_field_name("name")
            v = n.child_by_field_name("value")
            return ("decl", [txt(nm)], [v] if v is not None else None)
        if t == "assignment_expression":
            return ("assign", [n.child_by_field_name("left")], [n.child_by_field_name("right")], txt(n.child_by_field_name("operator")))
        if t == "enhanced_for_statement":
            nm, v = n.child_by_field_name("name"), n.child_by_field_name("value")
            if nm is not None and v is not None:
                return ("for", [nm], v)
        return None

    def lkey(self, n):
        if n is None:
            return None
        t = n.type
        if t == "identifier":
            return txt(n)
        if t == "field_access":
            return self.qual_of(n)
        if t == "array_access":
            return self.lkey(n.child_by_field_name("array"))
        return None

    def is_simple_target(self, n):
        return n.type in ("identifier", "field_access")

    def is_deep(self, n):
        return n.type in ("if_statement", "for_statement", "enhanced_for_statement", "while_statement", "do_statement", "switch_expression",
                          "switch_statement", "try_statement", "catch_clause", "lambda_expression", "switch_block_statement_group", "ternary_expression")

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
        if n.type == "string_literal":
            return "".join(txt(c) for c in n.children if c.type in ("string_fragment", "escape_sequence"))
        if n.type == "text_block":
            return txt(n)[3:-3]
        if n.type in ("decimal_integer_literal", "true", "false"):
            return txt(n)
        return None

    def sink_label(self, n):
        e = self.expr(n)
        return (e[1] if e[0] == "call" else txt(n))[:60]

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

    # ---- audit and hooks --------------------------------------------------------------------------------------
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
        if t == "binary_expression":
            if txt(n.child_by_field_name("operator")) != "+":
                return False
        elif t == "method_invocation":
            e = self.expr(n)
            if e[4] in ("format", "formatted", "concat", "replace", "replaceAll"):
                pass
            elif e[4] in ("toString", "append") and e[2] is not None:
                base = e[2]
                while base is not None and base.type == "method_invocation":
                    base = base.child_by_field_name("object")
                return base is not None and txt(base) in sv or any(SQL_RE.search(self.literal(x) or "") for x in walk(n) if x.type == "string_literal") and eng.ev(n)[0] >= C.OTHER
            else:
                return False
        else:
            return False
        pieces = [self.literal(x) or "" for x in walk(n) if x.type == "string_literal"]
        sl = getattr(eng, "_sqllit", set())
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
                if v.type == "object_creation_expression" and re.search(r"String(Builder|Buffer)", txt(v.child_by_field_name("type"))):
                    a = self._args(v)
                    if a and SQL_RE.search(self.literal(a[0]) or ""):
                        sl.add(nm)
                if lit is not None and SQL_RE.search(lit):
                    sl.add(nm)
                elif self.sql_built(eng, v):
                    sv.add(nm)
        elif st[0] == "assign":
            key = self.lkey(st[1][0])
            v = st[2][0]
            if key and v is not None:
                if self.literal(v) is not None and SQL_RE.search(self.literal(v) or ""):
                    sl.add(key)
                elif self.sql_built(eng, v) or (st[3] == "+=" and key in sl and eng.ev(v)[0] >= C.OTHER):
                    sv.add(key)

    def call_effects(self, eng, qual, simple, recv, args, vals, node):
        line = C.line_of(node)
        rel = eng.rel
        body_txt = eng.fdef.get("text", "")
        # --- StringBuilder: .append("SELECT ...") then .append(variable) = built query
        if simple == "append" and recv is not None:
            base = recv
            while base is not None and base.type == "method_invocation":
                base = base.child_by_field_name("object")
            if base is not None and base.type == "identifier":
                nm = txt(base)
                sl, sv = getattr(eng, "_sqllit", set()), getattr(eng, "_sqlvars", None)
                if sv is None:
                    sv = eng._sqlvars = set()
                if args and (SQL_RE.search(self.literal(args[0]) or "") or nm in sl):
                    sl.add(nm)
                    eng._sqllit = sl
                if args and nm in sl and any(eng.ev(a)[0] >= C.OTHER or eng.ev(a)[1] for a in args if self.literal(a) is None):
                    sv.add(nm)
        # --- Built SQL (audit)
        if re.search(r"\.(executeQuery|executeUpdate|executeLargeUpdate|execute|addBatch|prepareStatement|prepareCall|nativeSQL|createQuery|"
                     r"createNativeQuery|createSQLQuery|queryForObject|queryForList|queryForMap|queryForRowSet|query|update|batchUpdate)$", qual):
            for a in args[:2]:
                if self.sql_built(eng, a):
                    v = eng.ev(a)
                    if v[0] == C.TAINT and v[2]:
                        continue
                    eng.p.add(rel, "AST-JAVA-002", "confirmed" if v[0] == C.TAINT else "unknown", line, sink=qual)
                    for pi in v[1]:
                        eng.p.summary.setdefault(eng.key, []).append((frozenset([pi]), "AST-JAVA-002", rel, line, {"sink": qual}, "str", False))
        if args and (re.search(r"\.(executeQuery|executeUpdate|executeLargeUpdate|execute|addBatch|prepareStatement|prepareCall|nativeSQL|createQuery|"
                               r"createNativeQuery|createSQLQuery|queryForObject|queryForList|queryForMap|queryForRowSet|queryForInt|queryForLong|query|update|"
                               r"batchUpdate|newQuery|setFilter|querySingle|preparedQuery|newPreparedStatementCreator|createPreparedStatementCreator)$", qual)
                     or simple in ("PreparedStatementCreatorFactory",)):
            a = args[0]
            v = eng.ev(a)
            if v[0] == C.PARAM and self.expr(a)[0] in ("name", "member", "call", "bin", "wrap"):
                eng.p.add(rel, "AST-JAVA-002", "unknown", line, sink=qual)
        # --- command / library call built at runtime (audit): any non-constant argument
        if re.search(r"Runtime\.getRuntime(\(\))?\.exec$", qual) or (simple in ("exec", "loadLibrary", "load") and recv is not None):
            for a in args:
                v = eng.ev(a)
                if self.expr(a)[0] != "const" and (v[0] >= C.OTHER or v[1]) and v[0] != C.TAINT:
                    eng.p.add(rel, "AST-JAVA-001", "unknown", line, sink=qual)
                    break
        # --- XXE
        if re.search(r"(DocumentBuilderFactory|SAXParserFactory|XMLInputFactory|TransformerFactory|SchemaFactory|XMLReaderFactory|SAXTransformerFactory|"
                     r"XPathFactory_NO|SAXBuilder|SAXReader|DocumentBuilder|XMLReader|Digester|TransformerFactory)\.(newInstance|newFactory|createXMLReader|newDefaultInstance|newSchema|newTransformer)$|^(SAXBuilder|SAXReader|Digester)$", qual):
            if not SECURE_XML.search(body_txt):
                eng.p.add(rel, "AST-JAVA-008", "unknown", line, sink=qual)
        # --- cookies without protection flags
        if simple == "addCookie" and args:
            miss = [w for w in ("HttpOnly", "Secure") if not re.search(r"set" + w + r"\(\s*true\s*\)", body_txt)]
            if miss:
                eng.p.add(rel, "AST-JAVA-011", "fixed", line, what="Cookie added to the response without " + " and ".join(miss) + ".")
        # --- XSS: write to the response writer (including via a variable)
        writers = getattr(eng, "_writers", set())
        base = recv
        while base is not None and base.type == "method_invocation":
            base = base.child_by_field_name("object")
        is_writer = recv is not None and ("getWriter()" in qual or "getOutputStream()" in qual or (base is not None and txt(base) in writers) or
                                           (recv.type == "identifier" and txt(recv) in writers))
        if is_writer and simple in ("write", "print", "println", "printf", "format", "append") and args:
            for a in args:
                v = eng.ev(a)
                if v[0] == C.TAINT and not v[2]:
                    eng.p.add(rel, "AST-JAVA-003", "confirmed", line, sink=qual)
                elif v[1]:
                    for pi in v[1]:
                        eng.p.summary.setdefault(eng.key, []).append((frozenset([pi]), "AST-JAVA-003", rel, line, {"sink": qual}, "str", False))
                elif v[0] >= C.OTHER and self.expr(a)[0] != "const" and self.expr(a)[0] in ("bin", "call", "name", "member") and not re.search(r"escape|encode|sanitize", txt(a), re.I):
                    eng.p.add(rel, "AST-JAVA-003", "unknown", line, sink=qual)
        # --- weak random in sensitive contexts
        if re.search(r"(^|\.)(Math\.random|nextInt|nextLong|nextDouble|nextBytes|nextBoolean)$", qual) or (qual == "Random" and False):
            if not re.search(r"SecureRandom", body_txt):
                tgt = eng.name
                hit = SENSITIVE.search(tgt)
                nm = tgt
                if not hit:
                    p = node.parent
                    while p is not None and p.type not in ("variable_declarator", "assignment_expression", "block", "expression_statement"):
                        p = p.parent
                    if p is not None and p.type in ("variable_declarator", "assignment_expression"):
                        lhs = p.child_by_field_name("name") or p.child_by_field_name("left")
                        nm = txt(lhs)
                        hit = SENSITIVE.search(nm)
                if hit and "new Random" in body_txt or (hit and qual == "Math.random"):
                    eng.p.add(rel, "AST-JAVA-015", "fixed", line, sink=qual, name=nm)
        # --- cleartext socket
        if qual in ("Socket", "ServerSocket", "java.net.Socket", "java.net.ServerSocket") and not (args and (self.literal(args[0]) or "") == "0"):
            eng.p.add(rel, "AST-JAVA-019", "fixed", line, what=f"{qual} opens an unencrypted connection (no TLS).")
        # --- overly broad permissions
        atxt = " ".join(txt(a) for a in args)
        if simple in ("setPosixFilePermissions", "fromString", "setWritable", "setReadable", "setExecutable", "setAttribute", "createFile", "createDirectory", "createTempFile", "createTempDirectory"):
            if re.search(r"rwx.{0,3}rw|rwxrwxrwx|rw-rw-rw-|OTHERS_(WRITE|READ|EXECUTE)|GROUP_WRITE_NO|\(\s*true\s*,\s*false\s*\)", atxt) and simple != "createTempFile":
                eng.p.add(rel, "AST-JAVA-009", "fixed", line, sink=f"{qual} with permissions for everyone")
        # --- static IV
        if qual in ("IvParameterSpec", "GCMParameterSpec") and args:
            a = args[-1]
            if any(x.type == "string_literal" for x in walk(a)) or (a.type == "array_creation_expression" and a.child_by_field_name("value") is not None):
                eng.p.add(rel, "AST-JAVA-009", "fixed", line, sink=f"{qual} with a fixed initialization vector")
            elif a.type == "identifier":
                pass
        # --- cleartext http strings and passwords compared in cleartext
        if simple == "equals" and recv is not None and re.search(r"(?i)pass(word|wd)?$", txt(recv)) and args and re.search(r"(?i)pass(word|wd)?", txt(args[0])) is None and False:
            pass

    def on_enter(self, eng, n):
        pass

    def on_node(self, eng, n):
        rel = eng.rel
        line = C.line_of(n)
        t = n.type
        if t in self.STMT_TYPES:
            self.track_sql(eng, n)
        if t == "variable_declarator":
            v = n.child_by_field_name("value")
            if v is not None and v.type == "method_invocation" and txt(v.child_by_field_name("name")) in ("getWriter", "getOutputStream"):
                w = getattr(eng, "_writers", None)
                if w is None:
                    w = eng._writers = set()
                w.add(txt(n.child_by_field_name("name")))
        if t == "string_literal":
            lit = self.literal(n) or ""
            m = re.match(r"^http://([^/\s\"]+)", lit)
            if m and not re.match(r"(localhost|127\.|10\.0\.2\.2|0\.0\.0\.0|www\.w3\.org|schemas\.|java\.sun\.com|xml\.apache\.org|maven\.apache|www\.springframework|"
                                  r"www\.opengis|example\.|www\.apache|xmlns|ns\.adobe|purl\.org|www\.sun\.com|jboss\.org|xmlpull|json-schema|javax\.|ant\.apache|tempuri|"
                                  r"hibernate\.org|mybatis\.org|java\.sun|jakarta\.|eclipse\.org|openjpa|struts\.apache|www\.jcp\.org)", m.group(1)):
                eng.p.add(rel, "AST-JAVA-019", "unknown", line, what=f"The address http://{m.group(1)} uses an unencrypted connection.")
        # --- TrustManager / HostnameVerifier that accept everything
        if t == "method_declaration":
            nm = txt(n.child_by_field_name("name"))
            body = n.child_by_field_name("body")
            if body is not None:
                bt = re.sub(r"\s+", " ", re.sub(r"//[^\n]*|/\*.*?\*/", "", txt(body), flags=re.S)).strip()
                if nm in ("checkServerTrusted", "checkClientTrusted") and (bt in ("{ }", "{}") or re.fullmatch(r"\{ ?return; ?\}", bt)):
                    eng.p.add(rel, "AST-JAVA-010", "fixed", line, sink="TrustManager that accepts every certificate")
                if nm == "verify" and re.fullmatch(r"\{ ?return true; ?\}", bt):
                    eng.p.add(rel, "AST-JAVA-010", "fixed", line, sink="HostnameVerifier that accepts every host")
                if nm == "getAcceptedIssuers" and re.fullmatch(r"\{ ?return (null|new X509Certificate\[0?\]|new java\.security\.cert\.X509Certificate\[0?\]); ?\}", bt):
                    pass
            ann = next((txt(c) for c in n.children if c.type == "modifiers"), "")
            if re.search(r"@CrossOrigin\s*(\(\s*\))?\s*$|@CrossOrigin\([^)]*\*", ann):
                eng.p.add(rel, "AST-JAVA-014", "fixed", line, what="@CrossOrigin accepts requests from any origin.")
        if t == "lambda_expression":
            body = n.child_by_field_name("body")
            if body is not None and txt(body) == "true":
                p = n.parent
                while p is not None and p.type not in ("method_invocation", "object_creation_expression"):
                    p = p.parent
                if p is not None and re.search(r"(?i)hostnameverifier", txt(p)[:160]):
                    eng.p.add(rel, "AST-JAVA-010", "fixed", line, sink="HostnameVerifier that accepts every host")
        if t == "method_invocation" and txt(n.child_by_field_name("name")) == "setHeader" or (t == "method_invocation" and txt(n.child_by_field_name("name")) == "addHeader"):
            a = self._args(n)
            if len(a) >= 2 and (self.literal(a[0]) or "").lower() == "location":
                v = eng.ev(a[1])
                if v[0] == C.TAINT and not v[2]:
                    eng.p.add(rel, "AST-JAVA-006", "confirmed", line, sink="Location header")
            if len(a) >= 2 and (self.literal(a[0]) or "").lower() == "access-control-allow-origin" and (self.literal(a[1]) == "*"):
                eng.p.add(rel, "AST-JAVA-014", "fixed", line, what="Access-Control-Allow-Origin: * accepts requests from any origin.")
        if t == "binary_expression" and txt(n.child_by_field_name("operator")) == "+" or (t == "method_invocation" and txt(n.child_by_field_name("name")) in ("format", "formatted")):
            lits = [self.literal(x) or "" for x in walk(n) if x.type == "string_literal"]
            if any(re.search(r"<\s*/?[a-zA-Z!]", p) for p in lits):
                v = eng.ev(n)
                if v[0] == C.TAINT and not v[2] and n.parent is not None and n.parent.type not in ("binary_expression",):
                    eng.p.add(rel, "AST-JAVA-003", "confirmed", line, sink="HTML built from external data")
        if t == "binary_expression" and txt(n.child_by_field_name("operator")) == "+":
            l = n.child_by_field_name("left")
            if l is not None and l.type == "string_literal" and (self.literal(l) or "").startswith("redirect:"):
                v = eng.ev(n.child_by_field_name("right"))
                if v[0] == C.TAINT and not v[2]:
                    eng.p.add(rel, "AST-JAVA-006", "confirmed", line, sink="redirect:")
                elif v[0] >= C.OTHER or v[1]:
                    eng.p.add(rel, "AST-JAVA-006", "unknown", line, sink="redirect:")


LANG = JavaLang()


def analyze_java_project(sources):
    return C.analyze(LANG, sources)


def analyze_java_source(rel_path, text):
    return C.analyze_source(LANG, rel_path, text)
