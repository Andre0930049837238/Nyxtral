# -*- coding: utf-8 -*-
"""
sql_engine.py
==============
Security engine for SQL files (.sql and variants: migration scripts, schemas, procedures, triggers) targeting PostgreSQL,
MySQL/MariaDB, SQL Server (T-SQL) and Oracle (PL/SQL). No external dependencies: a lexical analyzer (comments,
strings, quoted identifiers, PostgreSQL dollar-quoting, GO and DELIMITER separators) splits the script into statements
while preserving line numbers, and each statement is then checked against the rules.

Classes covered: excessive privileges (GRANT ALL, TO PUBLIC, WITH GRANT OPTION, superuser, administrative roles),
passwords written in the script (CREATE/ALTER USER, INSERT of plaintext passwords), dynamic SQL built by concatenation
(EXEC, EXECUTE IMMEDIATE, PL/pgSQL EXECUTE, PREPARE), command execution and file-system access (xp_cmdshell, COPY PROGRAM,
LOAD_FILE, INTO OUTFILE, UTL_FILE, UNSAFE assemblies, untrusted languages), weak hashes (MD5, SHA1, PASSWORD(), weak HASHBYTES),
risky configuration (TRUSTWORTHY, local_infile, xp_cmdshell enabled, CHECK_POLICY = OFF, '@%' users),
SECURITY DEFINER functions without search_path, disabled row level security, sensitive plaintext columns in the schema.

Known limitations: this is not a complete parser for any dialect; SQL embedded in other languages (strings in Go, Kotlin,
Python...) is analyzed by those languages' engines. Sensitive columns are only reported as "potential": a column name
does not prove that the data is stored in plaintext.
"""

import logging
import re

log = logging.getLogger(__name__)

AVAILABLE = True
SUPPORTED = (".sql", ".psql", ".pgsql", ".tsql", ".ddl", ".mysql", ".plsql", ".prc", ".fnc")
MAX_PROJECT_BYTES = 20 * 1024 * 1024

CONF_LABEL = {
    "confirmed": "Confirmed: built from variable data",
    "unknown": "Potential: needs manual review (the name or context is not enough to prove it)",
    "fixed": "Detected with certainty in the script",
}
SEV_DOWN = {"CRITICAL": "HIGH", "HIGH": "MEDIUM", "MEDIUM": "LOW", "LOW": "LOW", "INFO": "INFO"}
TEST_RE = re.compile(r"(^|/)(tests?|testdata|fixtures?|examples?|docs?|samples?|demo|seeds?)(/|$)|(_test|\.test|_seed|seed)\.sql$", re.I)

RULES = {
    "AST-SQL-001": ("Excessive privileges", "HIGH", "MEDIUM",
                    "{what}",
                    "Grant only the privileges that are needed, to specific roles, never to PUBLIC; avoid WITH GRANT OPTION and avoid administrator accounts for applications.", "CWE-250"),
    "AST-SQL-002": ("Password written in the script", "HIGH", "HIGH",
                    "{what}",
                    "Do not write passwords in scripts: use environment variables or a secrets manager and supply them at execution time.", "CWE-798"),
    "AST-SQL-003": ("Dynamic SQL built by concatenation", "HIGH", "MEDIUM",
                    "{what}",
                    "Use parameters (sp_executesql with parameters, EXECUTE ... USING, format with %L and %I, QUOTENAME) instead of concatenating values.", "CWE-89"),
    "AST-SQL-004": ("Command execution or file-system access from the database", "CRITICAL", "HIGH",
                    "{what}",
                    "Disable and avoid features that reach outside the database; if they are required, restrict them to a dedicated account with minimal permissions.", "CWE-78"),
    "AST-SQL-005": ("Weak hash function", "MEDIUM", "MEDIUM",
                    "{what}",
                    "Use SHA-256 or stronger for data; for passwords use a slow, salted algorithm (bcrypt, scrypt, argon2, crypt with gen_salt('bf')).", "CWE-328"),
    "AST-SQL-006": ("Risky database configuration", "HIGH", "MEDIUM",
                    "{what}",
                    "Restore the configuration to secure values and enable dangerous features only when strictly necessary.", "CWE-16"),
    "AST-SQL-007": ("SECURITY DEFINER function without search_path", "MEDIUM", "MEDIUM",
                    "{what}",
                    "Add SET search_path = pg_catalog, <schema> to the function so that it cannot be hijacked by objects with the same name.", "CWE-426"),
    "AST-SQL-008": ("Row-level protection disabled", "MEDIUM", "MEDIUM",
                    "{what}",
                    "Keep row level security enabled on tables that hold data belonging to multiple users.", "CWE-284"),
    "AST-SQL-009": ("Sensitive column possibly stored in plaintext", "MEDIUM", "LOW",
                    "{what}",
                    "Store passwords as salted hashes, and encrypt or tokenize card numbers and similar data; never store the CVV.", "CWE-311"),
    "AST-SQL-010": ("User without a password or with access from any host", "HIGH", "MEDIUM",
                    "{what}",
                    "Always set a strong password and restrict the host (for example to localhost or an internal network).", "CWE-306"),
}

# ---------------------------------------------------------------------------------------------------
# Lexical analysis: comments, strings, identifiers, dollar-quoting, GO and DELIMITER
# ---------------------------------------------------------------------------------------------------

def _mask(text):
    """Return the masked text with the same length as the input: comments and string contents become spaces."""
    out = list(text)
    n, i = len(text), 0
    while i < n:
        c = text[i]
        two = text[i:i + 2]
        if two == "--":
            j = text.find("\n", i)
            j = n if j == -1 else j
            for k in range(i, j):
                out[k] = " "
            i = j
        elif two == "/*":
            j = text.find("*/", i + 2)
            j = n if j == -1 else j + 2
            for k in range(i, j):
                if out[k] != "\n":
                    out[k] = " "
            i = j
        elif c == "'":
            j = i + 1
            while j < n:
                if text[j] == "'" and text[j:j + 2] == "''":
                    j += 2
                    continue
                if text[j] == "'":
                    break
                j += 1
            for k in range(i + 1, min(j, n)):
                if out[k] != "\n":
                    out[k] = " "
            i = j + 1
        elif c in ('"', "`"):
            j = text.find(c, i + 1)
            j = n - 1 if j == -1 else j
            for k in range(i + 1, j):
                if out[k] != "\n":
                    out[k] = " "
            i = j + 1
        elif c == "[" and (i == 0 or text[i - 1] in " \t\n,.(="):
            j = text.find("]", i + 1)
            nl = text.find("\n", i + 1)
            if j != -1 and (nl == -1 or j < nl):
                for k in range(i + 1, j):
                    out[k] = " "
                i = j + 1
            else:
                i += 1
        elif c == "$":
            m = re.match(r"\$([A-Za-z_]*)\$", text[i:])
            if m:
                tag = m.group(0)
                j = text.find(tag, i + len(tag))
                j = n if j == -1 else j
                for k in range(i + len(tag), j):
                    if out[k] != "\n":
                        out[k] = " "
                i = j + len(tag)
            else:
                i += 1
        else:
            i += 1
    return "".join(out)


def _dollar_bodies(text):
    """Dollar-quoted bodies (PostgreSQL): (start_offset, text), used to analyze procedures from the inside."""
    out, n, i = [], len(text), 0
    masked = _mask(text)
    for m in re.finditer(r"\$([A-Za-z_]*)\$", masked):
        pass
    i = 0
    while i < n:
        m = re.compile(r"\$([A-Za-z_]*)\$").match(masked, i) if masked[i] == "$" else None
        if m:
            tag = m.group(0)
            j = text.find(tag, i + len(tag))
            if j == -1:
                break
            out.append((i + len(tag), text[i + len(tag):j]))
            i = j + len(tag)
        else:
            i += 1
    return out


def _split(text, delimiter=";"):
    """Split into statements: returns [(start_line, offset, original_text, masked_text)]."""
    masked = _mask(text)
    stmts, start, i, n = [], 0, 0, len(text)
    delim = delimiter
    line_starts = [0] + [m.end() for m in re.finditer(r"\n", text)]

    def lineno(pos):
        lo, hi = 0, len(line_starts) - 1
        while lo < hi:
            mid = (lo + hi + 1) // 2
            if line_starts[mid] <= pos:
                lo = mid
            else:
                hi = mid - 1
        return lo + 1

    def flush(end):
        seg_o, seg_m = text[start:end], masked[start:end]
        if seg_m.strip():
            lead = len(seg_m) - len(seg_m.lstrip())
            stmts.append((lineno(start + lead), start + lead, seg_o[lead:], seg_m[lead:]))

    # batch separators on their own line (GO) and DELIMITER
    while i < n:
        if masked[i] == "\n" or i == 0:
            m = re.compile(r"[ \t]*(GO|go|Go)[ \t]*(\d+)?[ \t]*(?=\n|$)").match(masked, i + (1 if masked[i] == "\n" else 0))
            if m and (i == 0 or masked[i] == "\n"):
                flush(i if masked[i] == "\n" else 0)
                start = m.end()
                i = m.end()
                continue
            m = re.compile(r"[ \t]*DELIMITER[ \t]+(\S+)[ \t]*(?=\n|$)", re.I).match(masked, i + (1 if masked[i] == "\n" else 0))
            if m:
                flush(i if masked[i] == "\n" else 0)
                delim = m.group(1)
                start = m.end()
                i = m.end()
                continue
        if masked.startswith(delim, i):
            flush(i)
            start = i + len(delim)
            i = start
            continue
        i += 1
    flush(n)
    return stmts


# ---------------------------------------------------------------------------------------------------
# Rules
# ---------------------------------------------------------------------------------------------------
SENS_COL = re.compile(r"^(password|passwd|pwd|pass|secret|api_?key|apikey|access_?token|auth_?token|token|ssn|social_security\w*|cvv|cvc|cvv2|card_?number|"
                      r"credit_?card\w*|cc_?number|pin|private_?key|iban)$", re.I)
SAFE_COL_SUFFIX = re.compile(r"(hash|salt|digest|encrypted|enc|cipher|hmac|crypt|masked|last4|last_four|expires?|expiry|_at|_id|_type|_count|_length|_len)$", re.I)
PLACEHOLDER = re.compile(r"^(\$\{.*\}|\{\{.*\}\}|%s|%\(.*\)s|\?|:\w+|\$\d+|@\w+|<.*>|\$\w+|\[.*\]|\{.*\}|:\{.*\})$")
WEAK_PW = re.compile(r"(?i)^(password|passw0rd|pass|pass123|password1|password123|123456|12345678|admin|admin123|root|toor|test|test123|qwerty|letmein|"
                     r"changeme|welcome|secret|default|guest|sa|oracle|manager|tiger|postgres|mysql)$")
HASHY = re.compile(r"^(\$2[abxy]\$|\$argon2|\$pbkdf2|\$scrypt|\$[156]\$|pbkdf2_|sha\d*[:$]|md5[a-f0-9]{32}$|\*[A-F0-9]{40}$|[A-Fa-f0-9]{32,128}$|\{SSHA\}|\{SHA\}|\{PBKDF2|0x[0-9A-Fa-f]{20,}|SCRAM-SHA)")


def _is_placeholder(v):
    v = v.strip()
    if not v:
        return False
    return bool(PLACEHOLDER.match(v)) or v.upper() in ("NULL", "PASSWORD_HERE", "YOUR_PASSWORD", "XXX", "XXXX", "********", "<PASSWORD>", "PLACEHOLDER", "REDACTED")


class _Ctx:
    def __init__(self, rel, text):
        self.rel, self.text = rel, text
        self.findings = {}
        self.test = bool(TEST_RE.search(rel.replace("\\", "/")))
        self.lines = text.splitlines()
        self.concat_vars = set()

    def add(self, sid, conf, line, what="", **kw):
        key = (sid, line, what[:40])
        if key in self.findings:
            return
        name, sev_c, sev_u, desc, rec, cwe = RULES[sid]
        sev = sev_c if conf in ("confirmed", "fixed") else sev_u
        if kw.get("sev"):
            sev = kw["sev"]
        desc = desc.format(what=what)
        if self.test:
            sev = SEV_DOWN.get(sev, sev)
            desc += " [Test script or sample data: severity reduced.]"
        snip = self.lines[line - 1].strip() if 0 < line <= len(self.lines) else ""
        self.findings[key] = {"id": sid, "name": name, "severity": sev, "confidence": "confirmed" if conf == "fixed" else conf,
                              "confidence_label": CONF_LABEL[conf], "file": self.rel, "line": line,
                              "snippet": snip[:160] + (" …" if len(snip) > 160 else ""), "description": desc,
                              "recommendation": rec, "engine": "sql_ast", "cwe": kw.get("cwe", cwe)}


def _line_at(base_line, stmt_text, idx):
    return base_line + stmt_text.count("\n", 0, idx)


def _literal_after(o, m, pos):
    """First quoted literal after pos in (o, m): returns (value, index) or (None, -1)."""
    q = o.find("'", pos)
    if q == -1:
        return None, -1
    # the contents are masked in m: look for the closing quote in the original text
    j = q + 1
    while j < len(o):
        if o[j] == "'" and o[j:j + 2] == "''":
            j += 2
            continue
        if o[j] == "'":
            break
        j += 1
    return o[q + 1:j].replace("''", "'"), q


def _check_statement(cx, line, o, m):
    u = m.upper()
    # ---------------- privileges --------------------------------------------------------------
    if re.match(r"\s*(GRANT|ALTER\s+ROLE|ALTER\s+USER|CREATE\s+(USER|ROLE|LOGIN)|EXEC(UTE)?\s+SP_ADDSRVROLEMEMBER|EXEC(UTE)?\s+SP_ADDROLEMEMBER|ALTER\s+SERVER\s+ROLE)", u):
        g = re.search(r"\bGRANT\s+ALL(\s+PRIVILEGES)?\b[^;]*?\bON\b\s+(\*\.\*|\*|ALL\s+TABLES|DATABASE|SCHEMA|[\w.`\"\[\]]*\.\*)", u)
        if g:
            cx.add("AST-SQL-001", "fixed", _line_at(line, o, g.start()), what="GRANT ALL grants every privilege on an entire database or on all tables.")
        p = re.search(r"\bTO\s+PUBLIC\b", u) if u.lstrip().startswith("GRANT") else None
        if p:
            cx.add("AST-SQL-001", "fixed", _line_at(line, o, p.start()), what="The privilege is granted to PUBLIC: anyone with an account receives it.")
        w = re.search(r"\bWITH\s+GRANT\s+OPTION\b", u)
        if w:
            cx.add("AST-SQL-001", "fixed", _line_at(line, o, w.start()), what="WITH GRANT OPTION allows the grantee to pass the privileges on to others.", sev="MEDIUM")
        s = re.search(r"\b(SUPERUSER|CREATEROLE|BYPASSRLS)\b", u)
        if s and not re.search(r"\bNO(SUPERUSER|CREATEROLE|BYPASSRLS)\b", u[max(0, s.start() - 2):s.end() + 0]):
            cx.add("AST-SQL-001", "fixed", _line_at(line, o, s.start()), what=f"{s.group(1)} grants full administrative powers.")
        r = re.search(r"SP_ADDSRVROLEMEMBER[^;]*?['\"]?(SYSADMIN|SECURITYADMIN|SERVERADMIN|DB_OWNER)\b|ADD\s+MEMBER\s+\[?(SYSADMIN|DB_OWNER)\b|GRANT\s+(DBA|SUPER|SYSDBA|SYSOPER)\b", o.upper())
        if r:
            cx.add("AST-SQL-001", "fixed", _line_at(line, o, r.start()), what="An administrative role is being assigned (sysadmin, db_owner, DBA, SUPER).")
        h = re.search(r"'[^']*'\s*@\s*'%'|'[^']*'@'%'", o)
        if h and re.match(r"\s*(CREATE|GRANT|ALTER)", u):
            cx.add("AST-SQL-010", "fixed", _line_at(line, o, h.start()), what="The user is defined with host '%': it can connect from any address.", sev="MEDIUM")

    # ---------------- passwords in the script ---------------------------------------------------
    if re.match(r"\s*(CREATE|ALTER)\s+(USER|ROLE|LOGIN|SERVER|PUBLIC|DATABASE\s+LINK|SHARED|APPLICATION\s+ROLE)|\s*SET\s+PASSWORD|\s*GRANT\b.*IDENTIFIED\s+BY", u) or \
            re.search(r"\bIDENTIFIED\s+BY\b|\bWITH\s+PASSWORD\b|\bPASSWORD\s*=?\s*'|\bCONNECT\s+TO\b[^;]*IDENTIFIED", u):
        for pm in re.finditer(r"\b(IDENTIFIED\s+(?:WITH\s+\w+\s+)?BY(?:\s+PASSWORD)?|WITH\s+PASSWORD\s*=?|PASSWORD\s*=?|ENCRYPTED\s+PASSWORD|UNENCRYPTED\s+PASSWORD)\s*(?=')", u):
            val, qi = _literal_after(o, m, pm.end())
            if val is None:
                continue
            ln = _line_at(line, o, pm.start())
            if val == "":
                cx.add("AST-SQL-010", "fixed", ln, what="The user is created with an empty password.")
            elif _is_placeholder(val) or HASHY.match(val):
                continue
            else:
                weak = " (and it is weak or a well-known default)" if WEAK_PW.match(val) else ""
                cx.add("AST-SQL-002", "fixed", ln, what=f"A password is written in plaintext in the script{weak}.")
        for pm in re.finditer(r"\bSET\s+PASSWORD\b[^;=]*=\s*(?:PASSWORD\s*\(\s*)?(?=')", u):
            val, qi = _literal_after(o, m, pm.end())
            if val and not _is_placeholder(val) and not HASHY.match(val):
                cx.add("AST-SQL-002", "fixed", _line_at(line, o, pm.start()), what="A password is written in plaintext in the script (SET PASSWORD).")
        if re.search(r"\bWITHOUT\s+PASSWORD\b|\bIDENTIFIED\s+BY\s+(''|\"\")|\bNO\s+PASSWORD\b|\bIDENTIFIED\s+EXTERNALLY\b_NO", u):
            mm = re.search(r"\bWITHOUT\s+PASSWORD\b|\bNO\s+PASSWORD\b|\bIDENTIFIED\s+BY\s+(''|\"\")", u)
            cx.add("AST-SQL-010", "fixed", _line_at(line, o, mm.start()), what="The user is created without a password.")
        if re.search(r"\bCHECK_POLICY\s*=\s*OFF\b", u):
            mm = re.search(r"\bCHECK_POLICY\s*=\s*OFF\b", u)
            cx.add("AST-SQL-006", "fixed", _line_at(line, o, mm.start()), what="CHECK_POLICY = OFF: the login is not subject to the password strength policy.", sev="MEDIUM")
        if re.search(r"\bCHECK_EXPIRATION\s*=\s*OFF\b", u):
            pass
    # INSERT with a plaintext password
    ins = re.match(r"\s*INSERT\s+(?:IGNORE\s+|OR\s+\w+\s+)?INTO\s+[\w.`\"\[\]]+\s*\(([^)]*)\)\s*VALUES\s*\(", u)
    if ins:
        cols = [c.strip(' `"[]') for c in o[ins.start(1):ins.end(1)].split(",")]
        vpos = ins.end()
        # comma-separated literal values at the top level (simplified)
        vals, depth, buf, k = [], 0, "", vpos
        while k < len(o):
            ch = o[k]
            if ch == "'":
                j = k + 1
                while j < len(o):
                    if o[j] == "'" and o[j:j + 2] == "''":
                        j += 2
                        continue
                    if o[j] == "'":
                        break
                    j += 1
                buf += o[k:j + 1]
                k = j + 1
                continue
            if ch == "(":
                depth += 1
            elif ch == ")":
                if depth == 0:
                    vals.append(buf.strip())
                    break
                depth -= 1
            elif ch == "," and depth == 0:
                vals.append(buf.strip())
                buf = ""
                k += 1
                continue
            buf += ch
            k += 1
        for c, v in zip(cols, vals):
            if re.fullmatch(r"(?i)(password|passwd|pwd|pass|user_?password|secret)", c) and v.startswith("'") and v.endswith("'"):
                lit = v[1:-1]
                if lit and not _is_placeholder(lit) and not HASHY.match(lit):
                    cx.add("AST-SQL-002", "fixed", _line_at(line, o, ins.start()), what=f"The column '{c}' is being filled with a plaintext password.")

    # ---------------- dynamic SQL ---------------------------------------------------------------
    for em in re.finditer(r"\bEXEC(?:UTE)?\s*\(\s*([^)]*)\)", u):
        inner = o[em.start(1):em.end(1)]
        if "+" in inner and re.search(r"@\w+|\b\w+\.\w+\b|\b[A-Za-z_]\w*\b(?!\s*')", re.sub(r"'(?:[^']|'')*'", "''", inner)) and re.search(r"@\w+", inner):
            cx.add("AST-SQL-003", "confirmed", _line_at(line, o, em.start()), what="EXEC concatenates variables into the SQL text to be executed.")
    mset = re.match(r"\s*(?:SET|SELECT)\s+(@\w+)\s*=\s*(.*)", m, re.S | re.I)
    if mset:
        var = mset.group(1).upper()
        rhs = o[mset.start(2):]
        rhs_nostr = re.sub(r"'(?:[^']|'')*'", "''", rhs)
        if (("+" in rhs_nostr and re.search(r"@\w+", rhs_nostr)) or re.search(r"\bCONCAT(_WS)?\s*\(", rhs_nostr, re.I) and re.search(r"@\w+|\b[a-z_]\w*\b(?!\s*\()", re.sub(r"(?i)concat(_ws)?", "", rhs_nostr))) \
                and re.search(r"'(?i:[^']*\b(select|insert|update|delete|exec|drop|alter|create|from|where)\b)", rhs):
            cx.concat_vars.add(var)
    for em in re.finditer(r"\bEXEC(?:UTE)?\s+(?:SP_EXECUTESQL|SYS\.SP_EXECUTESQL)\s+(@\w+)|\bPREPARE\s+\w+\s+FROM\s+(@\w+)|\bEXEC(?:UTE)?\s+\(?\s*(@\w+)\s*\)?\s*$", u, re.M):
        var = next((g for g in em.groups() if g), None)
        if var and var.upper() in cx.concat_vars:
            cx.add("AST-SQL-003", "confirmed", _line_at(line, o, em.start()), what=f"{var} is executed, and it was built by concatenating variables into the SQL text.")
    for em in re.finditer(r"\bEXECUTE\s+IMMEDIATE\s+(.*?)(?:\bUSING\b|\bINTO\b|$)", u, re.S):
        seg = o[em.start(1):em.end(1)]
        if "||" in seg and re.search(r"\|\|\s*[A-Za-z_:]|[A-Za-z_]\w*\s*\|\|", re.sub(r"'(?:[^']|'')*'", "''", seg)):
            cx.add("AST-SQL-003", "confirmed", _line_at(line, o, em.start()), what="EXECUTE IMMEDIATE concatenates variables into the SQL text.")
    for em in re.finditer(r"(?<![\w.])EXECUTE\s+(?!IMMEDIATE\b|PROCEDURE\b|FUNCTION\b|AS\b|SP_|XP_|STATEMENT\b)((?:(?!\bLOOP\b|\bUSING\b|\bINTO\b|;)[\s\S])*)", u):
        seg = o[em.start(1):em.end(1)]
        seg_ns = re.sub(r"'(?:[^']|'')*'", "''", seg)
        if re.match(r"\s*(FORMAT\s*\(|'|\w+\s*\|\|)", seg, re.I) or "||" in seg_ns:
            if re.match(r"\s*FORMAT\s*\(", seg, re.I):
                fmt = re.match(r"\s*FORMAT\s*\(\s*'((?:[^']|'')*)'", seg, re.I | re.S)
                if fmt and re.search(r"%s", fmt.group(1)) and not re.search(r"%[IL]", fmt.group(1)):
                    cx.add("AST-SQL-003", "confirmed", _line_at(line, o, em.start()), what="EXECUTE format() uses %s: values are not quoted (use %L for values and %I for identifiers).")
            elif "||" in seg_ns and re.search(r"\|\|\s*[A-Za-z_]|[A-Za-z_]\w*\s*\|\|", seg_ns) and "USING" not in seg.upper().split("||")[-1][:0]:
                cx.add("AST-SQL-003", "confirmed", _line_at(line, o, em.start()), what="EXECUTE concatenates variables into the SQL text (PL/pgSQL).")

    # ---------------- commands and file system --------------------------------------------------
    for rx, what in (
        (r"\bXP_CMDSHELL\b", "xp_cmdshell runs operating-system commands from the database."),
        (r"\bSP_OA(CREATE|METHOD)\b", "sp_OACreate can create COM objects and launch programs."),
        (r"\bCOPY\b[^;]*\b(FROM|TO)\s+PROGRAM\b", "COPY ... PROGRAM runs an operating-system command."),
        (r"\bLO_(IMPORT|EXPORT)\s*\(", "lo_import/lo_export read or write files on the server."),
        (r"\bPG_(READ_FILE|READ_BINARY_FILE|LS_DIR|STAT_FILE)\s*\(", "pg_read_file and similar functions read files on the server."),
        (r"\bLOAD_FILE\s*\(", "LOAD_FILE reads files on the server."),
        (r"\bINTO\s+(OUTFILE|DUMPFILE)\b", "INTO OUTFILE/DUMPFILE writes files on the server."),
        (r"\bLOAD\s+DATA\s+(LOCAL\s+)?INFILE\b", "LOAD DATA INFILE reads files (including from the client)."),
        (r"\bUTL_(FILE|HTTP|TCP|SMTP|INADDR)\b", "The UTL_* packages allow file and network access from the database."),
        (r"\bDBMS_(SCHEDULER|JAVA|JAVA_TEST)\.\w+|\bDBMS_SCHEDULER\b", "DBMS_SCHEDULER/DBMS_JAVA can launch external commands."),
        (r"\bOPENROWSET\s*\(\s*BULK\b|\bBULK\s+INSERT\b", "BULK INSERT / OPENROWSET(BULK) read files from the server."),
        (r"\bCREATE\s+EXTENSION\b[^;]*\b(PLPYTHONU|PLPYTHON3U|PLPERLU|PLTCLU|FILE_FDW|DBLINK|ADMINPACK)\b", "The installed extension allows code execution or reading files outside the database."),
        (r"\bLANGUAGE\s+(PLPYTHONU|PLPYTHON3U|PLPERLU|PLTCLU|C)\b", "The function uses an unrestricted language (it can access the system)."),
        (r"\b(SYS_EXEC|SYS_EVAL)\s*\(", "sys_exec/sys_eval (UDFs) run system commands."),
        (r"\bCREATE\s+ASSEMBLY\b[^;]*\bPERMISSION_SET\s*=\s*(UNSAFE|EXTERNAL_ACCESS)\b", "A CLR assembly with UNSAFE/EXTERNAL_ACCESS permissions can do anything on the server."),
        (r"\bCREATE\s+(OR\s+REPLACE\s+)?(PUBLIC\s+)?(DIRECTORY)\b", "An Oracle DIRECTORY exposes server folders to the database."),
    ):
        mm = re.search(rx, u)
        if mm:
            conf = "unknown" if "LANGUAGE" in rx and "C" in rx[-6:] else "fixed"
            cx.add("AST-SQL-004", conf, _line_at(line, o, mm.start()), what=what)

    # ---------------- weak hashes ---------------------------------------------------------------
    for mm in re.finditer(r"(?<![\w.])(MD5|SHA1|SHA|PASSWORD|OLD_PASSWORD|ENCRYPT)\s*\(\s*([^)]{0,60})", u):
        fn = mm.group(1)
        if fn == "SHA" and not re.search(r"\bSHA\s*\(", u[mm.start():mm.start() + 6]):
            continue
        arg = o[mm.start(2):mm.end(2)]
        on_pw = bool(re.search(r"(?i)pass|pwd|secret", arg))
        if fn in ("PASSWORD", "OLD_PASSWORD") and not re.search(r"\b(SET|SELECT|INSERT|UPDATE|VALUES|WHERE)\b|=", u[:mm.start()]):
            continue
        if fn == "ENCRYPT" and not on_pw:
            continue
        if on_pw:
            cx.add("AST-SQL-005", "fixed", _line_at(line, o, mm.start()), what=f"{fn}() is weak and here it protects a password.", sev="HIGH")
        else:
            cx.add("AST-SQL-005", "unknown", _line_at(line, o, mm.start()),
                   what=f"{fn}() is weak: acceptable for a simple integrity check, but not for protecting data or passwords.", sev="LOW")
    for mm in re.finditer(r"\bHASHBYTES\s*\(\s*'(MD2|MD4|MD5|SHA|SHA1)'", u.replace('"', "'") if False else o.upper()):
        cx.add("AST-SQL-005", "fixed", _line_at(line, o, mm.start()), what=f"HASHBYTES('{mm.group(1)}') uses a weak algorithm.")
    for mm in re.finditer(r"\bCRYPT\s*\([^;]*?\bGEN_SALT\s*\(\s*'(DES|MD5|XDES)'", o.upper()):
        cx.add("AST-SQL-005", "fixed", _line_at(line, o, mm.start()), what=f"gen_salt('{mm.group(1).lower()}') uses a weak hashing scheme.", sev="HIGH")
    for mm in re.finditer(r"\bDBMS_OBFUSCATION_TOOLKIT\.(MD5|DESENCRYPT|DES3ENCRYPT)\b", u):
        cx.add("AST-SQL-005", "fixed", _line_at(line, o, mm.start()), what="DBMS_OBFUSCATION_TOOLKIT uses deprecated algorithms.")

    # ---------------- configuration -------------------------------------------------------------
    for mm in re.finditer(r"\bSP_CONFIGURE\s+'?\"?(XP_CMDSHELL|AD\s+HOC\s+DISTRIBUTED\s+QUERIES|OLE\s+AUTOMATION\s+PROCEDURES|CLR\s+ENABLED|CLR\s+STRICT\s+SECURITY|"
                          r"REMOTE\s+ACCESS|SCAN\s+FOR\s+STARTUP\s+PROCS|DATABASE\s+MAIL\s+XPS)'?\"?\s*,\s*(1|'1')", o.upper()):
        cx.add("AST-SQL-006", "fixed", _line_at(line, o, mm.start()), what=f"sp_configure enables '{mm.group(1).lower()}', which adds to the attack surface.")
    for rx, what in (
        (r"\bTRUSTWORTHY\s+ON\b", "TRUSTWORTHY ON allows system-level privileges to be obtained through the database."),
        (r"\bSET\s+(GLOBAL\s+)?LOCAL_INFILE\s*=\s*(1|ON|TRUE)\b", "local_infile is enabled: the server can be tricked into reading client files."),
        (r"\bSKIP[-_]GRANT[-_]TABLES\b", "skip-grant-tables disables access control checks."),
        (r"\bALTER\s+LOGIN\s+\[?SA\]?\s+ENABLE\b", "The 'sa' account is being re-enabled."),
        (r"\bALTER\s+SYSTEM\s+SET\s+SSL\s*=\s*(OFF|FALSE)\b", "SSL is disabled on the server."),
        (r"\bREQUIRE\s+NONE\b", "The user can connect without TLS (REQUIRE NONE)."),
        (r"\bSET\s+ENCRYPTION\s+OFF\b", "Database encryption (TDE) is being turned off."),
        (r"\bALTER\s+USER\b[^;]*\bPASSWORD\s+EXPIRE\s+NEVER\b", "The password never expires."),
        (r"\bAUTHENTICATION\s+METHOD\s*=\s*'?TRUST\b|\bHOST\s+ALL\s+ALL\b[^;]*\bTRUST\b", "'trust' authentication: no password is required."),
    ):
        mm = re.search(rx, o.upper())
        if mm:
            cx.add("AST-SQL-006", "fixed", _line_at(line, o, mm.start()), what=what, sev="MEDIUM" if "never expires" in what or "TLS" in what else None)

    # ---------------- SECURITY DEFINER without search_path --------------------------------------
    un = re.sub(r"\s+", " ", u)
    if re.search(r"\bCREATE (OR REPLACE )?(FUNCTION|PROCEDURE)\b", un) and re.search(r"(?:(?<=LANGUAGE SQL )|(?<!SQL ))SECURITY DEFINER\b", un):
        if not re.search(r"\bSET SEARCH_PATH\b", un):
            mm = re.search(r"SECURITY\s+DEFINER\b", u)
            cx.add("AST-SQL-007", "fixed", _line_at(line, o, mm.start()), what="The SECURITY DEFINER function does not pin the search_path.")

    # ---------------- RLS ---------------------------------------------------------------------
    mm = re.search(r"\bALTER\s+TABLE\b[^;]*\b(DISABLE|NO\s+FORCE)\s+ROW\s+LEVEL\s+SECURITY\b", u)
    if mm:
        cx.add("AST-SQL-008", "fixed", _line_at(line, o, mm.start()), what="Row level security is being disabled on a table.")
    mm = re.match(r"\s*DROP\s+POLICY\b", u)
    if mm:
        cx.add("AST-SQL-008", "unknown", line, what="A row-level security policy is being dropped.")

    # ---------------- schema: sensitive columns -------------------------------------------------
    ct = re.match(r"\s*CREATE\s+(?:OR\s+REPLACE\s+)?(?:(?:GLOBAL\s+|LOCAL\s+)?(?:TEMP(?:ORARY)?\s+)|UNLOGGED\s+)?TABLE\s+(?:IF\s+NOT\s+EXISTS\s+)?[\w.`\"\[\]]+\s*\(", u)
    if ct:
        body_start = ct.end()
        depth, k, colstart = 1, body_start, body_start
        defs = []
        while k < len(m) and depth > 0:
            ch = m[k]
            if ch == "(":
                depth += 1
            elif ch == ")":
                depth -= 1
                if depth == 0:
                    defs.append((colstart, k))
            elif ch == "," and depth == 1:
                defs.append((colstart, k))
                colstart = k + 1
            k += 1
        for a, b in defs:
            d = o[a:b].strip()
            cm = re.match(r"[`\"\[]?([A-Za-z_]\w*)[`\"\]]?\s+([A-Za-z]+)", d)
            if not cm:
                continue
            col, typ = cm.group(1), cm.group(2).upper()
            if typ in ("PRIMARY", "FOREIGN", "UNIQUE", "CONSTRAINT", "KEY", "INDEX", "CHECK"):
                continue
            if not re.match(r"(VARCHAR|VARCHAR2|NVARCHAR|CHAR|NCHAR|TEXT|STRING|CLOB|CITEXT|LONGTEXT|MEDIUMTEXT|BPCHAR|CHARACTER)$", typ):
                continue
            if SENS_COL.match(col) and not SAFE_COL_SUFFIX.search(col):
                ln = _line_at(line, o, a + (len(o[a:b]) - len(o[a:b].lstrip())))
                if re.match(r"(?i)(cvv\d?|cvc)$", col):
                    cx.add("AST-SQL-009", "fixed", ln, what=f"The column '{col}' stores the card security code, which must never be stored.", sev="HIGH", cwe="CWE-311")
                elif re.match(r"(?i)(password|passwd|pwd|pass)$", col):
                    cx.add("AST-SQL-009", "unknown", ln, what=f"The column '{col}' is named like a plaintext password (if it holds a hash, consider renaming it to '{col}_hash').", cwe="CWE-256")
                else:
                    cx.add("AST-SQL-009", "unknown", ln, what=f"The column '{col}' appears to hold sensitive data stored as text: consider encryption or tokenization.")


def _analyze_text(cx, text, base_line=1, depth=0):
    delim = ";"
    for line, off, o, m in _split(text, delim):
        _check_statement(cx, line + base_line - 1, o, m)
        # dollar-quoted bodies (PostgreSQL procedures and functions) and DELIMITER blocks: analyze the inner text
        if depth < 3:
            for boff, body in _dollar_bodies(o):
                inner_line = line + base_line - 1 + o.count("\n", 0, boff)
                _analyze_text(cx, body, inner_line, depth + 1)
            if re.match(r"\s*CREATE\s+(OR\s+REPLACE\s+|DEFINER\s*=\s*\S+\s+)*(PROCEDURE|FUNCTION|TRIGGER|EVENT|PACKAGE)\b", m.upper()) and "$$" not in m:
                inner = re.search(r"\bBEGIN\b(.*)\bEND\b", m, re.S | re.I)
                if inner:
                    boff = inner.start(1)
                    _analyze_text(cx, o[boff:inner.end(1)], line + base_line - 1 + o.count("\n", 0, boff), depth + 1)


def analyze_sql_source(rel_path, text):
    if not rel_path.lower().endswith(SUPPORTED):
        return []
    cx = _Ctx(rel_path, text)
    try:
        _analyze_text(cx, text)
    except RecursionError:
        log.warning("SQL analysis of '%s' was stopped: the nesting is too deep (RecursionError). "
                    "Results for this file may be incomplete; consider splitting the script into smaller files.", rel_path)
    except Exception:
        log.exception("SQL analysis of '%s' failed unexpectedly; partial results (if any) are returned. "
                      "Please report this together with the offending script.", rel_path)
    return sorted(cx.findings.values(), key=lambda f: f["line"])


def analyze_sql_project(sources):
    return {rel: analyze_sql_source(rel, t) for rel, t in sources.items()}
