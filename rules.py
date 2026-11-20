# -*- coding: utf-8 -*-
"""
rules.py
Pattern-based rules for static security analysis.
Each rule is a dictionary with:
    id            -> unique identifier
    name          -> short title
    severity      -> "CRITICAL" | "HIGH" | "MEDIUM" | "LOW" | "INFO"
    languages     -> list of file extensions the rule applies to, or ["*"] for all text files
    pattern       -> regex (case-insensitive) searched line by line
    description   -> explanation of the problem
    recommendation-> practical advice on how to fix it
"""

RULES = [
    # =====================================================================
    # GENERIC RULES (apply to any text file)
    # =====================================================================
    {
        "id": "GEN-001",
        "name": "Possible hardcoded AWS Access Key",
        "severity": "CRITICAL",
        "languages": ["*"],
        "pattern": r"AKIA[0-9A-Z]{16}",
        "description": "A string matching the format of an AWS Access Key ID was found.",
        "recommendation": "Remove the key from the code, revoke/regenerate it in AWS IAM, and use environment variables or a secret manager (e.g. AWS Secrets Manager, Vault).",
    },
    {
        "id": "GEN-002",
        "name": "Possible hardcoded Google API Key",
        "severity": "HIGH",
        "languages": ["*"],
        "pattern": r"AIza[0-9A-Za-z\-_]{35}",
        "description": "A string matching the format of a Google API Key was found.",
        "recommendation": "Move the key to an environment variable, restrict it by domain/IP in the Google Cloud Console, and regenerate it if it has already been exposed.",
    },
    {
        "id": "GEN-003",
        "name": "Possible hardcoded Slack Token",
        "severity": "HIGH",
        "languages": ["*"],
        "pattern": r"xox[baprs]-[0-9A-Za-z\-]{10,}",
        "description": "A string matching the format of a Slack token was found.",
        "recommendation": "Revoke the token in Slack and move it to a secret manager or an environment variable.",
    },
    {
        "id": "GEN-004",
        "name": "Private key embedded in code",
        "severity": "CRITICAL",
        "languages": ["*"],
        "pattern": r"-----BEGIN (RSA |EC |DSA |OPENSSH )?PRIVATE KEY-----",
        "description": "The file contains a private key block (PEM).",
        "recommendation": "Never commit private keys. Remove them from the repository, regenerate them, and load them at runtime from a secret store or environment variables.",
    },
    {
        "id": "GEN-005",
        "name": "Possible hardcoded JWT",
        "severity": "MEDIUM",
        "languages": ["*"],
        "pattern": r"eyJ[A-Za-z0-9_\-]{10,}\.[A-Za-z0-9_\-]{10,}\.[A-Za-z0-9_\-]{10,}",
        "description": "A string matching the format of a JSON Web Token was found.",
        "recommendation": "Do not hardcode JWTs in source code, especially if they are valid/production tokens. Use them only as fictitious examples or move them out of the repository.",
    },
    {
        "id": "GEN-006",
        "name": "Hardcoded password or secret (heuristic)",
        "severity": "HIGH",
        "languages": ["*"],
        "pattern": r"(?i)(password|passwd|pwd|secret|api[_\-]?key|token)\s*[:=]\s*[\"'][^\"'\n]{4,}[\"']",
        "description": "A value is assigned directly to a variable that appears to hold a password, a secret or a key.",
        "recommendation": "Check whether it is a real value. If so, move it to environment variables or a secret manager, and add the file to .gitignore if it contains local secrets.",
    },
    {
        "id": "GEN-007",
        "name": "Database connection string with credentials",
        "severity": "CRITICAL",
        "languages": ["*"],
        "pattern": r"(?i)(mongodb(\+srv)?|postgres(ql)?|mysql|redis|amqp)://[^:\s\"']+:[^@\s\"']+@",
        "description": "A connection string containing a username and password in clear text was found.",
        "recommendation": "Move the connection string to an environment variable or to a configuration file excluded from version control (an uncommitted .env).",
    },
    {
        "id": "GEN-008",
        "name": "TLS/SSL certificate verification disabled",
        "severity": "HIGH",
        "languages": ["*"],
        "pattern": r"(?i)(verify\s*=\s*False|rejectUnauthorized\s*:\s*false|ssl_verify\s*=\s*false|InsecureSkipVerify\s*:\s*true|ServicePointManager\.ServerCertificateValidationCallback)",
        "description": "The code appears to disable TLS/SSL certificate validation.",
        "recommendation": "Never disable certificate verification in production: it exposes you to man-in-the-middle attacks. If it is needed in tests, keep this configuration isolated from the production environment.",
    },
    {
        "id": "GEN-009",
        "name": "Secret in environment variable (.env format)",
        "severity": "HIGH",
        "languages": [".env"],
        "pattern": r"(?i)^[A-Z0-9_]*(SECRET|PASSWORD|PASSWD|PWD|API[_-]?KEY|TOKEN|PRIVATE[_-]?KEY|ACCESS[_-]?KEY|CLIENT[_-]?SECRET)[A-Z0-9_]*\s*=\s*.+$",
        "description": "This line of a .env file assigns a value to a variable that appears to hold a password, a secret or a key (.env files do not use quotes, so rule GEN-006 alone does not detect them).",
        "recommendation": "Check whether it is a real value. If so, make sure this .env file is NOT included in the repository (it must be listed in .gitignore) and that production secrets never end up in a shared or versioned .env.",
    },

    # =====================================================================
    # PYTHON
    # =====================================================================
    {
        "id": "PY-001",
        "name": "Use of eval()/exec()",
        "severity": "CRITICAL",
        "languages": [".py"],
        "pattern": r"\b(eval|exec)\s*\(",
        "description": "eval()/exec() execute arbitrary code and are dangerous if the input comes, even indirectly, from the user.",
        "recommendation": "Avoid eval/exec. Use ast.literal_eval() for simple data, or rewrite the logic without dynamic code execution.",
    },
    {
        "id": "PY-002",
        "name": "System command with shell=True or os.system",
        "severity": "CRITICAL",
        "languages": [".py"],
        "pattern": r"(os\.system\s*\(|subprocess\.(Popen|call|run|check_output)\([^)]*shell\s*=\s*True)",
        "description": "Running shell commands with untrusted input can lead to command injection.",
        "recommendation": "Use subprocess with shell=False and pass the arguments as a list, or strictly validate/whitelist the input.",
    },
    {
        "id": "PY-003",
        "name": "Unsafe deserialization with pickle",
        "severity": "HIGH",
        "languages": [".py"],
        "pattern": r"\bpickle\.(loads?|Unpickler)\s*\(",
        "description": "pickle.load/loads can execute arbitrary code if they deserialize untrusted data.",
        "recommendation": "Never deserialize pickle data coming from external sources. Use safe formats such as JSON whenever possible.",
    },
    {
        "id": "PY-004",
        "name": "yaml.load without SafeLoader",
        "severity": "HIGH",
        "languages": [".py"],
        "pattern": r"yaml\.load\s*\((?!.*Loader\s*=\s*yaml\.SafeLoader)",
        "description": "yaml.load without SafeLoader can instantiate arbitrary Python objects from a malicious YAML file.",
        "recommendation": "Use yaml.safe_load() or yaml.load(data, Loader=yaml.SafeLoader).",
    },
    {
        "id": "PY-005",
        "name": "Weak hash (MD5/SHA1) for passwords",
        "severity": "MEDIUM",
        "languages": [".py"],
        "pattern": r"hashlib\.(md5|sha1)\s*\(",
        "description": "MD5 and SHA1 are weak hashing algorithms, unsuitable for protecting passwords.",
        "recommendation": "For passwords use dedicated algorithms such as bcrypt, scrypt or Argon2 (e.g. the 'passlib' or 'argon2-cffi' library).",
    },
    {
        "id": "PY-006",
        "name": "Non-cryptographic random generator for tokens/secrets",
        "severity": "MEDIUM",
        "languages": [".py"],
        "pattern": r"\brandom\.(random|randint|choice|randrange)\s*\(",
        "description": "The 'random' module is not cryptographically secure; if used to generate tokens, passwords or keys, the output is predictable.",
        "recommendation": "For security purposes use the 'secrets' module (e.g. secrets.token_urlsafe()).",
    },
    {
        "id": "PY-007",
        "name": "Debug mode enabled (Flask/Django)",
        "severity": "HIGH",
        "languages": [".py"],
        "pattern": r"(app\.run\([^)]*debug\s*=\s*True|DEBUG\s*=\s*True)",
        "description": "Debug mode exposes detailed stack traces and can enable code execution through the Werkzeug debugger.",
        "recommendation": "Disable debug mode in production (DEBUG = False) and manage it through environment variables.",
    },
    {
        "id": "PY-008",
        "name": "Possible SQL injection (query built with strings)",
        "severity": "CRITICAL",
        "languages": [".py"],
        "pattern": r"\.execute\s*\(\s*(f[\"']|[\"'][^\"']*[\"']\s*(\+|%)|[\"'][^\"']*\{)",
        "description": "The SQL query appears to be built through concatenation, f-strings or '%' formatting, exposing it to SQL injection.",
        "recommendation": "Use parameterized queries (? or %s placeholders handled by the driver/ORM), never string concatenation to build SQL.",
    },
    {
        "id": "PY-009",
        "name": "XML parsing vulnerable to XXE",
        "severity": "MEDIUM",
        "languages": [".py"],
        "pattern": r"xml\.etree\.ElementTree",
        "description": "Python's standard XML parser is vulnerable to XXE (XML External Entity) attacks when it processes untrusted XML.",
        "recommendation": "Use the 'defusedxml' library instead of xml.etree.ElementTree when processing XML from external sources.",
    },
    {
        "id": "PY-010",
        "name": "Overly permissive file permissions",
        "severity": "LOW",
        "languages": [".py"],
        "pattern": r"os\.chmod\s*\([^)]*0o?7[0-7][0-7]",
        "description": "Very broad permissions (e.g. 777) are set on a file or directory.",
        "recommendation": "Apply the principle of least privilege: grant only the strictly necessary permissions (e.g. 600 for files containing secrets).",
    },
    {
        "id": "PY-011",
        "name": "Use of assert for security checks",
        "severity": "LOW",
        "languages": [".py"],
        "pattern": r"^\s*assert\s+.*(auth|permission|is_admin|logged_in|token)",
        "description": "'assert' statements are removed when Python runs with the -O optimization flag, so they are unreliable for security checks.",
        "recommendation": "Replace security asserts with explicit checks (if ... raise ...).",
    },

    # =====================================================================
    # JAVASCRIPT / TYPESCRIPT
    # =====================================================================
    {
        "id": "JS-001",
        "name": "Use of eval() or new Function()",
        "severity": "CRITICAL",
        "languages": [".js", ".jsx", ".ts", ".tsx"],
        "pattern": r"\b(eval\s*\(|new\s+Function\s*\()",
        "description": "eval() and new Function() execute arbitrary code from strings and are dangerous with untrusted input.",
        "recommendation": "Avoid eval/new Function. If you need to evaluate dynamic data, use JSON.parse() or explicit data structures.",
    },
    {
        "id": "JS-002",
        "name": "Direct assignment to innerHTML/outerHTML/document.write",
        "severity": "HIGH",
        "languages": [".js", ".jsx", ".ts", ".tsx", ".html"],
        "pattern": r"(\.innerHTML\s*=|\.outerHTML\s*=|document\.write\s*\()",
        "description": "Inserting unsanitized HTML content into the DOM can cause XSS (Cross-Site Scripting) vulnerabilities.",
        "recommendation": "Use textContent for plain text, or sanitize the HTML with a library such as DOMPurify before inserting it.",
    },
    {
        "id": "JS-003",
        "name": "dangerouslySetInnerHTML (React) without evident sanitization",
        "severity": "HIGH",
        "languages": [".jsx", ".tsx", ".js", ".ts"],
        "pattern": r"dangerouslySetInnerHTML",
        "description": "dangerouslySetInnerHTML inserts raw HTML into the DOM, exposing the app to XSS if the content is not sanitized.",
        "recommendation": "Always sanitize the HTML with DOMPurify (or similar) before passing it to dangerouslySetInnerHTML.",
    },
    {
        "id": "JS-004",
        "name": "Shell command execution with concatenated input",
        "severity": "CRITICAL",
        "languages": [".js", ".ts"],
        "pattern": r"child_process\.(exec|execSync)\s*\([^)]*(\+|\$\{)",
        "description": "child_process.exec with concatenated/interpolated strings can lead to command injection.",
        "recommendation": "Use execFile/spawn passing the arguments as a separate array, avoiding interpretation by the shell.",
    },
    {
        "id": "JS-005",
        "name": "Fully open CORS",
        "severity": "MEDIUM",
        "languages": [".js", ".ts"],
        "pattern": r"Access-Control-Allow-Origin[\"']?\s*[:,]\s*[\"']\*[\"']",
        "description": "The server allows cross-origin requests from any domain.",
        "recommendation": "Restrict Access-Control-Allow-Origin to the domains that are actually authorized, avoiding the '*' wildcard, especially when credentials are used.",
    },
    {
        "id": "JS-006",
        "name": "Hardcoded JWT secret in token signing",
        "severity": "CRITICAL",
        "languages": [".js", ".ts"],
        "pattern": r"jwt\.sign\s*\([^)]*[\"'][A-Za-z0-9_\-]{6,}[\"']\s*\)",
        "description": "The secret key used to sign JWTs appears to be a string hardcoded in the code.",
        "recommendation": "Move the secret to an environment variable and use long, random keys generated with a CSPRNG.",
    },
    {
        "id": "JS-007",
        "name": "SQL query built with template strings/concatenation",
        "severity": "CRITICAL",
        "languages": [".js", ".ts"],
        "pattern": r"\.(query|execute)\s*\(\s*(`[^`]*\$\{|[\"'][^\"']*[\"']\s*\+)",
        "description": "The SQL query is built by interpolating variables directly into the string, exposing it to SQL injection.",
        "recommendation": "Use parameterized queries/prepared statements provided by the driver or the ORM (e.g. ? or $1 placeholders).",
    },
    {
        "id": "JS-008",
        "name": "Weak hash (MD5/SHA1) via crypto",
        "severity": "MEDIUM",
        "languages": [".js", ".ts"],
        "pattern": r"crypto\.createHash\s*\(\s*[\"'](md5|sha1)[\"']",
        "description": "MD5/SHA1 are weak algorithms, unsuitable for protecting passwords or sensitive data.",
        "recommendation": "For passwords use bcrypt/argon2 (e.g. the 'bcrypt' or 'argon2' library); for generic hashes prefer SHA-256 or stronger.",
    },
    {
        "id": "JS-009",
        "name": "Token/password stored in localStorage",
        "severity": "MEDIUM",
        "languages": [".js", ".jsx", ".ts", ".tsx"],
        "pattern": r"localStorage\.setItem\s*\(\s*[\"'][^\"']*(token|password|secret|jwt)[^\"']*[\"']",
        "description": "localStorage is accessible to any JS script on the page, making the data vulnerable to XSS that steals tokens/credentials.",
        "recommendation": "Prefer HttpOnly + Secure + SameSite cookies for session tokens, so they cannot be read by JavaScript.",
    },

    # =====================================================================
    # JAVA
    # =====================================================================
    {
        "id": "JAVA-001",
        "name": "System command execution with concatenated input",
        "severity": "CRITICAL",
        "languages": [".java"],
        "pattern": r"Runtime\.getRuntime\(\)\.exec\s*\([^)]*\+",
        "description": "Runtime.exec with concatenated strings can lead to command injection.",
        "recommendation": "Use ProcessBuilder with a list of separate arguments, avoiding direct concatenation of user input.",
    },
    {
        "id": "JAVA-002",
        "name": "SQL query built with concatenation (Statement)",
        "severity": "CRITICAL",
        "languages": [".java"],
        "pattern": r"\.execute(Query|Update)?\s*\([^)]*\+",
        "description": "Using Statement with concatenated queries exposes the code to SQL injection.",
        "recommendation": "Use PreparedStatement with bind parameters (?) instead of concatenating strings into the query.",
    },
    {
        "id": "JAVA-003",
        "name": "Weak hash/encryption algorithm",
        "severity": "MEDIUM",
        "languages": [".java"],
        "pattern": r"(MessageDigest\.getInstance\s*\(\s*[\"'](MD5|SHA1|SHA-1)[\"']|Cipher\.getInstance\s*\(\s*[\"'](DES|RC4|AES/ECB)[^\"']*[\"'])",
        "description": "Weak or obsolete cryptographic algorithms are used (MD5, SHA1, DES, RC4, AES in ECB mode).",
        "recommendation": "Use SHA-256/SHA-3 for hashes, AES-GCM for symmetric encryption, and bcrypt/Argon2 for passwords.",
    },
    {
        "id": "JAVA-004",
        "name": "TLS certificate validation disabled",
        "severity": "HIGH",
        "languages": [".java"],
        "pattern": r"X509TrustManager\s*\(\)\s*\{",
        "description": "A custom TrustManager may disable certificate validation (a 'trust all' pattern).",
        "recommendation": "Verify that checkClientTrusted/checkServerTrusted perform real validation; never accept all certificates in production.",
    },

    # =====================================================================
    # C# / .NET
    # =====================================================================
    {
        "id": "CS-001",
        "name": "SQL query built with concatenation/interpolation",
        "severity": "CRITICAL",
        "languages": [".cs"],
        "pattern": r"new SqlCommand\s*\(\s*(\$?\"[^\"]*\{|\"[^\"]*\"\s*\+)",
        "description": "SqlCommand is built with interpolated or concatenated strings, exposing it to SQL injection.",
        "recommendation": "Use parameters (SqlParameter) instead of concatenating/interpolating values directly into the query.",
    },
    {
        "id": "CS-002",
        "name": "Weak hash for passwords (MD5/SHA1)",
        "severity": "MEDIUM",
        "languages": [".cs"],
        "pattern": r"(MD5\.Create\s*\(|SHA1\.Create\s*\()",
        "description": "MD5 and SHA1 are not suitable for protecting passwords.",
        "recommendation": "Use Rfc2898DeriveBytes (PBKDF2), BCrypt.Net or Argon2 for password hashing.",
    },
    {
        "id": "CS-003",
        "name": "Server certificate validation disabled",
        "severity": "HIGH",
        "languages": [".cs"],
        "pattern": r"ServerCertificateValidationCallback\s*=\s*.*=>\s*true",
        "description": "The server certificate validation callback always returns 'true', effectively disabling TLS verification.",
        "recommendation": "Implement real certificate validation or remove the callback to use the default one.",
    },
    {
        "id": "CS-004",
        "name": "Process execution with concatenated arguments",
        "severity": "HIGH",
        "languages": [".cs"],
        "pattern": r"Process\.Start\s*\([^)]*\+",
        "description": "Process.Start with arguments built by concatenation can lead to command injection.",
        "recommendation": "Pass the arguments through ProcessStartInfo.ArgumentList, avoiding concatenation of untrusted input.",
    },

    # =====================================================================
    # PHP
    # =====================================================================
    {
        "id": "PHP-001",
        "name": "Use of eval()",
        "severity": "CRITICAL",
        "languages": [".php"],
        "pattern": r"\beval\s*\(",
        "description": "eval() executes arbitrary PHP code and is extremely dangerous with untrusted input.",
        "recommendation": "Avoid eval() entirely; rethink the logic so that it does not require dynamic code execution.",
    },
    {
        "id": "PHP-002",
        "name": "Shell command execution",
        "severity": "CRITICAL",
        "languages": [".php"],
        "pattern": r"\b(exec|system|shell_exec|passthru)\s*\(\s*\$",
        "description": "A variable is passed directly to a shell execution function, creating a risk of command injection.",
        "recommendation": "Strictly validate/whitelist the input and avoid passing user data to shell functions; use escapeshellarg() at a minimum.",
    },
    {
        "id": "PHP-003",
        "name": "SQL query with deprecated functions/concatenation (SQLi)",
        "severity": "CRITICAL",
        "languages": [".php"],
        "pattern": r"(mysql_query\s*\(|mysqli_query\s*\([^)]*\.\s*\$)",
        "description": "The mysql_query functions are deprecated/removed, and using concatenation in the query exposes it to SQL injection.",
        "recommendation": "Use PDO or mysqli with prepared statements and bind parameters, never direct concatenation of user input.",
    },
    {
        "id": "PHP-004",
        "name": "Weak hash for passwords (md5)",
        "severity": "MEDIUM",
        "languages": [".php"],
        "pattern": r"\bmd5\s*\(\s*\$",
        "description": "md5() is not suitable for protecting passwords.",
        "recommendation": "Use password_hash() (bcrypt/Argon2) and password_verify() to handle passwords securely.",
    },
    {
        "id": "PHP-005",
        "name": "extract() on user input ($_GET/$_POST/$_REQUEST)",
        "severity": "CRITICAL",
        "languages": [".php"],
        "pattern": r"extract\s*\(\s*\$_(GET|POST|REQUEST|COOKIE)",
        "description": "extract() on user input can overwrite arbitrary variables in the current scope (variable injection).",
        "recommendation": "Do not use extract() on superglobals; access values explicitly through $_GET['key'] with validation.",
    },
    {
        "id": "PHP-006",
        "name": "Dynamic file inclusion from user input (RFI/LFI)",
        "severity": "CRITICAL",
        "languages": [".php"],
        "pattern": r"(include|require)(_once)?\s*\(\s*\$_(GET|POST|REQUEST)",
        "description": "Including files based directly on user input can lead to Remote/Local File Inclusion.",
        "recommendation": "Never build the include/require path from user input; use a whitelist of allowed files.",
    },
    {
        "id": "PHP-007",
        "name": "unserialize() on untrusted input",
        "severity": "HIGH",
        "languages": [".php"],
        "pattern": r"unserialize\s*\(\s*\$_(GET|POST|REQUEST|COOKIE)",
        "description": "unserialize() on user-controlled data can lead to object injection and code execution.",
        "recommendation": "Use json_decode()/json_encode() instead of native PHP serialization for data that crosses trust boundaries.",
    },

    # =====================================================================
    # FILE-LEVEL CHECKS (handled separately by the engine, listed here for documentation)
    # =====================================================================
]

# File names that are reported whenever present in the project, regardless of their content
SENSITIVE_FILENAMES = [
    (r"^\.env$", "HIGH", ".env file present in the project",
     "Verify that the .env file is NOT included in the Git repository (it must be listed in .gitignore). If it contains real secrets, rotate them."),
    (r"^id_rsa$|^id_dsa$|^id_ecdsa$|^id_ed25519$", "CRITICAL", "SSH private key present in the project",
     "Remove the private key from the project/repository, regenerate it, and distribute it only through secure channels."),
    (r".*\.pem$|.*\.pfx$|.*\.p12$|.*\.key$", "HIGH", "Private key/certificate file present in the project",
     "Make sure these files are not versioned in Git; move them outside the repository or into a secret store."),
    (r"^\.git-credentials$|^\.npmrc$", "MEDIUM", "Tool credentials file present in the project",
     "Check that it does not contain tokens/passwords in clear text and that it is excluded from version control."),
]

SEVERITY_ORDER = {"CRITICAL": 0, "HIGH": 1, "MEDIUM": 2, "LOW": 3, "INFO": 4}

SEVERITY_WEIGHT = {"CRITICAL": 12, "HIGH": 6, "MEDIUM": 3, "LOW": 1, "INFO": 0}
