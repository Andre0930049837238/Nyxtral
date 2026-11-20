# -*- coding: utf-8 -*-
"""
quality_engine.py
=================
Code QUALITY engine (not security) for 10 languages:

    JavaScript, TypeScript, Java, C#, Go, PHP, Rust, Kotlin, Swift, SQL

(C, C++ and Python are left out on purpose: Python already has the AST
engine, and C/C++ would need a real parser.)

How it works, in three steps, using only the standard library:

  1. MASKING: a small per-language "lexer" replaces the content of comments
     and strings with spaces, keeping length and line numbers identical.
     This way curly braces and keywords inside a string or a comment are not
     mistaken for real code.
  2. STRUCTURAL METRICS (language independent): finds the functions (with a
     combination of keywords and brace matching) and measures length,
     approximate cyclomatic complexity, nesting and number of parameters; at
     file level: length, long lines, TODO/FIXME, commented-out code,
     duplicate blocks, empty catch blocks.
  3. PER-LANGUAGE RULES: typical bad practices of each language (== in JS,
     `any` in TS, async void in C#, unwrap() in Rust, !! in Kotlin, try! in
     Swift, UPDATE without WHERE in SQL...).

Every finding has the same format as the rest of the scanner, plus:
    "category": "quality"   -> to tell it apart from security issues
    "language": "Rust" ...  -> recognised language
    "impact": "..."         -> ready-made "in practice" explanation

Honest limitations: it is not a compiler. Function detection is heuristic
(it works well on normally formatted code, but can be wrong on
obfuscated/minified code or with very creative macros); JavaScript regular
expressions (/.../) and PHP heredoc strings are not interpreted by the
lexer; complexity is an estimate, not the exact value a dedicated tool for
that language would give.
"""

import logging
import math
import re
from bisect import bisect_right
from collections import defaultdict

log = logging.getLogger(__name__)

# ---------------------------------------------------------------------------
# Thresholds (adjustable)
# ---------------------------------------------------------------------------
FILE_LINES_LOW = 500
FILE_LINES_MEDIUM = 1000
FUNC_LINES_LOW = 60
FUNC_LINES_MEDIUM = 120
COMPLEXITY_LOW = 11        # from 11 upwards
COMPLEXITY_MEDIUM = 21
PARAMS_LOW = 6             # from 6 upwards
PARAMS_MEDIUM = 9
NESTING_LOW = 5            # levels of braces inside the function
NESTING_MEDIUM = 7
LONG_LINE_CHARS = 140
LONG_LINES_MIN_COUNT = 5   # report only if there are at least N long lines
DUP_WINDOW = 6             # identical consecutive lines needed to call it a duplicate
DUP_MIN_CHARS = 150
MAX_PER_RULE_PER_FILE = 25
MAX_TODO_PER_FILE = 15
MAX_DUPLICATES_PER_FILE = 3

QUALITY_WEIGHT = {"CRITICAL": 8, "HIGH": 5, "MEDIUM": 3, "LOW": 1, "INFO": 0}

LANG_BY_EXT = {
    ".js": "javascript", ".jsx": "javascript", ".mjs": "javascript", ".cjs": "javascript",
    ".ts": "typescript", ".tsx": "typescript",
    ".java": "java", ".cs": "csharp", ".go": "go", ".php": "php",
    ".rs": "rust", ".kt": "kotlin", ".kts": "kotlin", ".swift": "swift",
    ".sql": "sql",
}
LANG_LABEL = {
    "javascript": "JavaScript", "typescript": "TypeScript", "java": "Java", "csharp": "C#",
    "go": "Go", "php": "PHP", "rust": "Rust", "kotlin": "Kotlin", "swift": "Swift", "sql": "SQL",
}
SUPPORTED_EXTENSIONS = set(LANG_BY_EXT)


# ---------------------------------------------------------------------------
# 1) Masking lexer
# ---------------------------------------------------------------------------
def _cfg(line, block=("/*", "*/"), nest=False, quotes=("'", '"'), multi=(), raw=(),
         triple=False, verbatim=False, sql=False):
    return dict(line=line, block=block, nest=nest, quotes=quotes, multi=multi, raw=raw,
                triple=triple, verbatim=verbatim, sql=sql)


_LEX = {
    "javascript": _cfg(("//",), quotes=("'", '"', "`"), multi=("`",)),
    "typescript": _cfg(("//",), quotes=("'", '"', "`"), multi=("`",)),
    "java": _cfg(("//",), triple=True),
    "csharp": _cfg(("//",), triple=True, verbatim=True),
    "go": _cfg(("//",), quotes=("'", '"', "`"), multi=("`",), raw=("`",)),
    "php": _cfg(("//", "#"), multi=("'", '"')),
    "rust": _cfg(("//",), nest=True, quotes=("'", '"'), multi=('"',)),
    "kotlin": _cfg(("//",), nest=True, triple=True),
    "swift": _cfg(("//",), nest=True, quotes=('"',), triple=True),
    "sql": _cfg(("--",), quotes=("'", '"', "`"), multi=("'", '"', "`"), sql=True),
}
_RUST_CHAR = re.compile(r"'(?:\\(?:u\{[0-9a-fA-F]+\}|x[0-9a-fA-F]{2}|.)|[^\\'\n])'")
_LEX_REGEX_CACHE = {}


def _line_starts(src):
    starts = [0]
    starts.extend(m.end() for m in re.finditer("\n", src))
    return starts


def _find_block_end(src, p, cfg):
    start_tok, end_tok = cfg["block"]
    if not cfg["nest"]:
        idx = src.find(end_tok, p + len(start_tok))
        return len(src) if idx == -1 else idx + len(end_tok)
    depth, j = 1, p + len(start_tok)
    while j < len(src):
        nxt_open = src.find(start_tok, j)
        nxt_close = src.find(end_tok, j)
        if nxt_close == -1:
            return len(src)
        if nxt_open != -1 and nxt_open < nxt_close:
            depth += 1
            j = nxt_open + len(start_tok)
        else:
            depth -= 1
            j = nxt_close + len(end_tok)
            if depth == 0:
                return j
    return len(src)


def mask_source(src, lang):
    """
    Returns (masked_text, comments).
    The masked text has the same length and the same line breaks as the original, with
    the content of comments and strings replaced by spaces.
    comments: list of (line_number, text, kind) where kind is "line" or "block".
    """
    cfg = _LEX[lang]
    n = len(src)
    out = list(src)
    comments = []
    starts = _line_starts(src)

    rx = _LEX_REGEX_CACHE.get(lang)
    if rx is None:
        tokens = set(cfg["line"]) | set(cfg["quotes"])
        if cfg["block"]:
            tokens.add(cfg["block"][0])
        if cfg["verbatim"]:
            tokens.add('@"')
        rx = re.compile("|".join(re.escape(t) for t in sorted(tokens, key=len, reverse=True)))
        _LEX_REGEX_CACHE[lang] = rx

    def blank(a, b):
        for k in range(a, min(b, n)):
            if out[k] not in "\r\n":
                out[k] = " "

    i = 0
    while True:
        m = rx.search(src, i)
        if not m:
            break
        p, tok = m.start(), m.group()

        if tok in cfg["line"]:
            if lang == "php" and tok == "#" and src.startswith("#[", p):
                i = p + 1
                continue
            e = src.find("\n", p)
            e = n if e == -1 else e
            comments.append((bisect_right(starts, p), src[p:e], "line"))
            blank(p, e)
            i = e
            continue

        if cfg["block"] and tok == cfg["block"][0]:
            e = _find_block_end(src, p, cfg)
            first_line = bisect_right(starts, p)
            for k, part in enumerate(src[p:e].split("\n")):
                comments.append((first_line + k, part, "block"))
            blank(p, e)
            i = e
            continue

        if tok == "@\"":  # C# verbatim string
            j = p + 2
            while j < n:
                if src[j] == '"':
                    if src[j + 1:j + 2] == '"':
                        j += 2
                        continue
                    break
                j += 1
            blank(p + 2, j)
            i = min(n, j + 1)
            continue

        if tok == '"' and cfg["triple"] and src.startswith('"""', p):
            e = src.find('"""', p + 3)
            e = n if e == -1 else e
            blank(p + 3, e)
            i = min(n, e + 3)
            continue

        if tok == "'" and lang == "rust":
            mm = _RUST_CHAR.match(src, p)
            if mm:
                blank(p + 1, mm.end() - 1)
                i = mm.end()
            else:
                i = p + 1  # it is a lifetime ('a), not a string
            continue

        q = tok
        j = p + 1
        escapes = q not in cfg["raw"] and not cfg["sql"]
        while j < n:
            ch = src[j]
            if escapes and ch == "\\":
                j += 2
                continue
            if ch == q:
                if cfg["sql"] and src[j + 1:j + 2] == q:
                    j += 2
                    continue
                break
            if ch == "\n" and q not in cfg["multi"]:
                break
            j += 1
        j = min(j, n)
        blank(p + 1, j)
        i = j + 1 if (j < n and src[j] == q) else j

    return "".join(out), comments


# ---------------------------------------------------------------------------
# 2) Structure: functions
# ---------------------------------------------------------------------------
_KW_FUNC = {
    "javascript": re.compile(r"\bfunction\b\s*\*?\s*([A-Za-z_$][\w$]*)?"),
    "typescript": re.compile(r"\bfunction\b\s*\*?\s*([A-Za-z_$][\w$]*)?"),
    "php": re.compile(r"\bfunction\b\s*&?\s*([A-Za-z_]\w*)?"),
    "go": re.compile(r"\bfunc\b\s*(?:\([^)]*\)\s*)?([A-Za-z_]\w*)"),
    "rust": re.compile(r"\bfn\b\s+([A-Za-z_]\w*)"),
    "kotlin": re.compile(r"\bfun\b\s*(?:<[^>]*>\s*)?(?:[\w<>?]+\.)?([A-Za-z_]\w*)"),
    "swift": re.compile(r"\b(?:func\s+([A-Za-z_]\w*)|(init)\s*[?!]?(?=\s*\())"),
}
_OPEN_PAREN = re.compile(r"\s*(?:<[^>(]*>|\[[^\]]*\])?\s*\(")
_NAME_PAREN = re.compile(r"(?<![\w$.])([A-Za-z_$][\w$]*)\s*\(")
_STOP = re.compile(r"[{;=}]")
_TAIL_STRICT = re.compile(
    r"\s*(?:throws\s+[\w.,\s<>]+?|:\s*[\w.<>\[\]|&?,\s]+?|where\s+[\w\s:,<>.()]+?)?\s*")
_NOT_FUNC = {
    "if", "else", "for", "foreach", "while", "do", "switch", "catch", "try", "finally", "lock",
    "using", "fixed", "synchronized", "return", "throw", "new", "sizeof", "typeof", "nameof",
    "when", "where", "yield", "await", "async", "checked", "unchecked", "default", "case",
    "function", "with", "super", "this", "base", "assert", "elif", "unless", "select", "in",
    "of", "delete", "void", "instanceof", "typeof", "constructor_",
}
_ARROW = re.compile(r"=>\s*\{")


def _bracket_maps(masked):
    paren, rparen, brace = {}, {}, {}
    ps, bs = [], []
    for m in re.finditer(r"[(){}]", masked):
        c, p = m.group(), m.start()
        if c == "(":
            ps.append(p)
        elif c == ")":
            if ps:
                o = ps.pop()
                paren[o] = p
                rparen[p] = o
        elif c == "{":
            bs.append(p)
        elif bs:
            brace[bs.pop()] = p
    return paren, rparen, brace


def _count_params(text):
    text = text.strip()
    if not text:
        return 0
    depth, count = 0, 1
    for ch in text:
        if ch in "([{<":
            depth += 1
        elif ch in ")]}>":
            depth = max(0, depth - 1)
        elif ch == "," and depth == 0:
            count += 1
    if text.endswith(","):
        count -= 1
    return count


def _next_body_brace(masked, pos, strict=False):
    m = _STOP.search(masked, pos, pos + 400)
    if not m or m.group() != "{":
        return None
    if strict and not _TAIL_STRICT.fullmatch(masked[pos:m.start()]):
        return None
    return m.start()


def find_functions(masked, lang, line_of):
    paren, rparen, brace = _bracket_maps(masked)
    funcs = {}

    def register(name, start_idx, params_text, body_open):
        body_close = brace.get(body_open)
        if body_close is None or body_open in funcs:
            return
        funcs[body_open] = {
            "name": name, "start": line_of(start_idx), "end": line_of(body_close),
            "params": _count_params(params_text), "body": (body_open, body_close),
        }

    kw = _KW_FUNC.get(lang)
    if kw:
        for m in kw.finditer(masked):
            name = next((g for g in m.groups() if g), None)
            if name is None and lang not in ("javascript", "typescript", "php"):
                continue
            mp = _OPEN_PAREN.match(masked, m.end())
            if not mp:
                continue
            op = mp.end() - 1
            cp = paren.get(op)
            if cp is None:
                continue
            bp = _next_body_brace(masked, cp + 1)
            if bp is not None:
                register(name or "<anonymous>", m.start(), masked[op + 1:cp], bp)

    if lang in ("java", "csharp", "javascript", "typescript"):
        for m in _NAME_PAREN.finditer(masked):
            name = m.group(1)
            if name in _NOT_FUNC:
                continue
            if re.search(r"\bnew\s+$", masked[max(0, m.start() - 12):m.start()]):
                continue
            op = m.end() - 1
            cp = paren.get(op)
            if cp is None:
                continue
            bp = _next_body_brace(masked, cp + 1, strict=True)
            if bp is not None:
                register(name, m.start(), masked[op + 1:cp], bp)

    if lang in ("javascript", "typescript"):
        for m in _ARROW.finditer(masked):
            bo = m.end() - 1
            base = max(0, m.start() - 250)
            head = masked[base:m.start()]
            name, params_text, start_idx = "<anonymous>", "", m.start()
            mm = re.search(r"\)\s*(?::\s*[^=(){};]+?)?\s*$", head)
            if mm:
                op = rparen.get(base + mm.start())
                if op is not None:
                    params_text = masked[op + 1:base + mm.start()]
                    start_idx = op
                    pre = masked[max(0, op - 80):op]
                    nm = re.search(r"([A-Za-z_$][\w$]*)\s*(?::[^=]+)?=\s*(?:async\s*)?$", pre)
                    if nm:
                        name = nm.group(1)
            elif re.search(r"[A-Za-z_$][\w$]*\s*$", head):
                params_text = "x"
            register(name, start_idx, params_text, bo)

    return sorted(funcs.values(), key=lambda f: f["start"])


_CX_BASE = r"\b(?:if|for|while|case|catch)\b|&&|\|\|"
_CX_EXTRA = {
    "javascript": r"|\s\?\s", "typescript": r"|\s\?\s", "java": r"|\s\?\s",
    "csharp": r"|\bforeach\b|\s\?\s|\?\?", "go": r"|\bselect\b",
    "php": r"|\belseif\b|\bforeach\b|\s\?\s", "rust": r"|\bloop\b|=>",
    "kotlin": r"|\bwhen\b|\?:", "swift": r"|\bguard\b|\brepeat\b", "sql": "",
}
_CX_RX = {lang: re.compile(_CX_BASE + extra) for lang, extra in _CX_EXTRA.items()}


def _complexity(body, lang):
    return 1 + len(_CX_RX[lang].findall(body))


def _max_depth(body):
    depth = best = 0
    for m in re.finditer(r"[{}]", body):
        if m.group() == "{":
            depth += 1
            best = max(best, depth)
        else:
            depth = max(0, depth - 1)
    return best


# ---------------------------------------------------------------------------
# 3) Per-language rules
# ---------------------------------------------------------------------------
def _R(rid, name, sev, langs, pattern, desc, rec, impact, scope="line", raw=False,
       exclude=None, flags=0):
    return {
        "id": rid, "name": name, "severity": sev, "langs": tuple(langs),
        "regex": re.compile(pattern, flags), "description": desc, "recommendation": rec,
        "impact": impact, "scope": scope, "raw": raw,
        "exclude": re.compile(exclude) if exclude else None,
    }


JS = ("javascript", "typescript")
CATCH_LANGS = ("javascript", "typescript", "java", "csharp", "php", "kotlin", "swift")

RULES_Q = [
    # ---- cross-language ---------------------------------------------------
    _R("QG-010", "Exception caught and ignored (empty catch)", "MEDIUM", CATCH_LANGS,
       r"\bcatch\b\s*(?:\([^()]*\))?\s*\{\s*\}",
       "The catch block is completely empty: if something goes wrong, nobody will ever know.",
       "At least log the error or rethrow it. If ignoring it is intentional, add a comment explaining why.",
       "Errors vanish silently: the program carries on as if nothing happened and the bug shows up "
       "later, somewhere far away, and is much harder to understand.",
       scope="text", raw=True),

    # ---- JavaScript / TypeScript ----------------------------------------
    _R("QJS-001", "Use of 'var' instead of let/const", "LOW", JS, r"\bvar\s+[A-Za-z_$]",
       "'var' is function-scoped (not block-scoped) and is hoisted: surprising behaviour.",
       "Use 'const' by default and 'let' only if the value must change.",
       "Variables that 'survive' outside the block where you wrote them and overwrite each other: "
       "bugs that are hard to spot when reading the code."),
    _R("QJS-002", "Loose comparison (== / !=) instead of === / !==", "LOW", JS,
       r"(?<![=!<>+\-*/%&|^])(?:==|!=)(?!=)(?!\s*null\b)",
       "== and != silently convert types before comparing (0 == '' is true).",
       "Use === and !==, which also compare the type.",
       "Comparisons that evaluate to 'true' where you do not expect it, producing wrong results that are hard to track down."),
    _R("QJS-003", "console.log left in the code", "LOW", JS, r"\bconsole\.(?:log|debug|info)\s*\(",
       "Debug statement that was probably forgotten.",
       "Remove it or use a proper logging system with levels (that can be disabled in production).",
       "Noise in the logs and, if you print user data, information that ends up where it should not."),
    _R("QJS-004", "'debugger' statement left in the code", "MEDIUM", JS, r"\bdebugger\b\s*;?",
       "Pauses execution when the browser's developer tools are open.",
       "Remove it before release.",
       "If it reaches production, the app freezes for anyone who opens the developer tools."),
    _R("QJS-005", "alert/confirm/prompt in the code", "LOW", JS, r"(?<![\w$.])(?:alert|confirm|prompt)\s*\(",
       "Blocking browser dialogs: poor user experience and hard to test.",
       "Use a UI component (modal, toast) instead.",
       "An interface that freezes and does not blend in with the rest of the app."),
    _R("QJS-006", "forEach with an async function (it is not awaited)", "MEDIUM", JS,
       r"\.forEach\s*\(\s*async\b",
       "forEach does not wait for async functions: the operations all start together and the code after the loop continues without waiting for them.",
       "Use a 'for...of' loop with await, or Promise.all(array.map(async ...)).",
       "The following code runs before the work has finished, and errors in the calls are never handled."),
    _R("QJS-007", "new Promise(async ...) (anti-pattern)", "MEDIUM", JS, r"\bnew\s+Promise\s*\(\s*async\b",
       "If the async function throws, the Promise is never rejected and stays pending.",
       "Write an async function directly, without wrapping it in new Promise.",
       "Requests that hang forever without any error message."),
    _R("QTS-001", "'any' type in TypeScript", "LOW", ("typescript",),
       r"(?::\s*any\b|\bas\s+any\b|<any>)",
       "'any' turns off type checking exactly where it would be most useful.",
       "Use a precise type, an interface or 'unknown' (which forces a check before the value is used).",
       "The compiler stops warning you about errors at that point: the bugs of plain JavaScript are back."),
    _R("QTS-002", "@ts-ignore / @ts-nocheck: type errors silenced", "MEDIUM", ("typescript",),
       r"@ts-(?:ignore|nocheck)\b",
       "The compiler is being told not to report an error instead of the error being fixed.",
       "Fix the type; if it is truly needed, use @ts-expect-error with a comment explaining why.",
       "The error stays there, hidden, and no longer warns you even when the surrounding code changes.",
       raw=True),
    _R("QTS-003", "Non-null assertion (!)", "LOW", ("typescript",),
       r"(?<=[\w\)\]])!(?=[.\[])",
       "The '!' operator tells the compiler 'trust me, it is not null' without any check.",
       "Check the value (if / ?.) or use a default value with ??.",
       "If the value is null at runtime, the program stops with a 'Cannot read properties of null' error."),

    # ---- Java -----------------------------------------------------------
    _R("QJV-001", "System.out/err.print in the code", "LOW", ("java",), r"\bSystem\.(?:out|err)\.print",
       "Direct console output instead of a logging system.",
       "Use a logger (SLF4J, java.util.logging) with configurable levels and format.",
       "You cannot filter, turn off or centralize these messages; in production they end up wherever they happen to go."),
    _R("QJV-002", "printStackTrace() instead of logging", "MEDIUM", ("java", "kotlin"), r"\.printStackTrace\s*\(\s*\)",
       "Writes the error to standard error, outside the application's logging system.",
       "Record the exception with a logger (logger.error(\"message\", e)).",
       "The error does not appear in the centralized logs: if it happens in production, you will not know."),
    _R("QJV-003", "Overly generic catch of Exception/Throwable", "MEDIUM", ("java",),
       r"\bcatch\s*\(\s*(?:final\s+)?(?:java\.lang\.)?(?:Exception|Throwable)\s+\w+\s*\)",
       "Catching everything also hides unexpected programming errors.",
       "Catch only the specific exceptions you know how to handle.",
       "Real bugs (NullPointerException, etc.) are absorbed and treated as 'normal' errors."),
    _R("QJV-004", "Public mutable field", "LOW", ("java",),
       r"^\s*public\s+(?![^;=(){]*\b(?:final|class|interface|enum|record|abstract)\b)[\w<>\[\],.?\s]+?\s+\w+\s*(?:=[^=]|;)",
       "A non-final public field can be changed from anywhere in the program.",
       "Make it private and provide getter/setter methods (or make it final/immutable).",
       "Any class can change its value without checks: it is impossible to guarantee that it stays consistent."),
    _R("QJV-005", "Deprecated wrapper constructor (new Integer(...))", "MEDIUM", ("java",),
       r"\bnew\s+(?:Integer|Long|Double|Float|Short|Byte|Boolean|Character)\s*\(",
       "These constructors are deprecated and create needless objects.",
       "Use the static valueOf(...) method or the primitive type directly.",
       "Wasted memory and an == comparison that gives unexpected results."),
    _R("QJV-006", "Wildcard import (import package.*)", "LOW", ("java", "kotlin"),
       r"^\s*import\s+(?!static)[\w.]+\.\*\s*;?\s*$",
       "Imports a whole package: it is no longer clear where each name comes from.",
       "Import only the classes you use (the IDE does this automatically).",
       "Name clashes when the package adds a new class, and code that is harder to read."),
    _R("QJV-007", "System.exit() in the code", "LOW", ("java", "kotlin"), r"\bSystem\.exit\s*\(",
       "Abruptly shuts down the whole application from any point.",
       "Let the entry point decide when to terminate; propagate the error instead.",
       "Skips the orderly closing of files and connections; makes the code untestable."),

    # ---- C# -------------------------------------------------------------
    _R("QCS-001", "async void (unhandleable exceptions)", "MEDIUM", ("csharp",), r"\basync\s+void\b",
       "An async void method cannot be awaited and its exceptions can crash the app.",
       "Return Task (async Task). async void should only be used for event handlers.",
       "An error inside the method cannot be caught by its caller and can terminate the whole process."),
    _R("QCS-002", "Console.Write/WriteLine in the code", "LOW", ("csharp",), r"\bConsole\.Write(?:Line)?\s*\(",
       "Direct output instead of a logging system.",
       "Use ILogger (Microsoft.Extensions.Logging) or Serilog.",
       "No severity levels and no configuration: in production these messages get lost or create noise."),
    _R("QCS-003", "Generic catch (Exception or catch without a type)", "MEDIUM", ("csharp",),
       r"\bcatch\s*(?:\(\s*(?:System\.)?Exception(?:\s+\w+)?\s*\)|(?=\s*\{))",
       "Catches every error, including those you do not know how to handle.",
       "Catch specific exceptions; if you must catch everything, log and rethrow with 'throw;'.",
       "Real programming errors are absorbed and treated as normal situations."),
    _R("QCS-004", "Blocking wait on a Task (.Result / .Wait())", "MEDIUM", ("csharp",),
       r"\.(?:Result\b(?!\s*[(\w])|Wait\s*\(\s*\)|GetAwaiter\s*\(\s*\)\s*\.GetResult\s*\(\s*\))",
       "Blocking a Task synchronously can cause deadlocks, especially in UI/ASP.NET apps.",
       "Make the method async and use 'await'.",
       "The application can hang with no error or message, only in certain environments, and is hard to reproduce."),
    _R("QCS-005", "'throw ex;' resets the stack trace", "MEDIUM", ("csharp",),
       r"\bthrow\s+(?:ex|e|exception|err)\s*;",
       "Rethrowing the exception this way erases the information about where it originated.",
       "Simply use 'throw;' to rethrow while preserving the original stack.",
       "When the error appears in the logs, the real point where it happened can no longer be seen."),
    _R("QCS-006", "GC.Collect() called manually", "LOW", ("csharp",), r"\bGC\.Collect\s*\(",
       "Forcing the garbage collector almost always hurts performance.",
       "Remove it and let the runtime manage memory.",
       "Slowdowns and unpredictable pauses with no real benefit."),

    # ---- Go -------------------------------------------------------------
    _R("QGO-001", "fmt.Print* in the code", "LOW", ("go",), r"\bfmt\.Print(?:ln|f)?\s*\(",
       "Direct output instead of a log.",
       "Use the log package (or slog/zap) with configurable levels and format.",
       "Messages with no level or date, impossible to filter in production."),
    _R("QGO-002", "panic() in the code", "MEDIUM", ("go",), r"(?<![\w.])panic\s*\(",
       "panic terminates the whole program instead of returning a handleable error.",
       "Return an 'error' to the caller. Reserve panic for truly unrecoverable cases.",
       "A single unexpected input can bring down the whole service."),
    _R("QGO-003", "Error ignored with '_'", "MEDIUM", ("go",),
       r"(?:^\s*_\s*=\s*|,\s*_\s*:?=\s*)[\w.]+\s*\(",
       "The returned error value is explicitly discarded.",
       "Always check the error (if err != nil { ... }) or document why it can be ignored.",
       "If the operation fails, the program continues as if it had succeeded: lost or corrupted data with no signs."),
    _R("QGO-004", "if err != nil with an empty block", "MEDIUM", ("go",),
       r"\bif\s+err\s*!=\s*nil\s*\{\s*\}",
       "The error is checked but then nothing is done.",
       "Handle it (return it with context, log it) or remove the useless check.",
       "Gives the illusion that the error is handled, while in reality it is ignored.",
       scope="text", raw=True),
    _R("QGO-005", "Deprecated io/ioutil package", "LOW", ("go",), r"\bioutil\.",
       "io/ioutil has been deprecated since Go 1.16.", "Use the equivalents in 'io' and 'os' (os.ReadFile, io.ReadAll...).",
       "Code that will eventually stop being maintained by the standard library."),

    # ---- PHP ------------------------------------------------------------
    _R("QPH-001", "Debug function left in the code", "LOW", ("php",),
       r"(?<![\w$>:])(?:var_dump|print_r|var_export|debug_zval_dump)\s*\(",
       "Prints the contents of variables: a typical debugging leftover.",
       "Remove it; for debugging use a logger or Xdebug.",
       "Internal data shown to users on the page."),
    _R("QPH-002", "die()/exit() in the code", "MEDIUM", ("php",), r"\b(?:die|exit)\b\s*(?:\(|;)",
       "Abruptly stops the entire script, with no orderly shutdown.",
       "Throw an exception or return an error response from the entry point.",
       "Blank or truncated pages and code that is impossible to test."),
    _R("QPH-003", "Error suppression operator '@'", "MEDIUM", ("php",),
       r"(?<![\w$@])@\s*[\\$A-Za-z_]",
       "The @ in front of an expression hides PHP errors instead of handling them.",
       "Check the error condition (file_exists, isset...) or use try/catch.",
       "Real problems (missing file, failed connection) go unnoticed."),
    _R("QPH-004", "Use of 'global'", "LOW", ("php",), r"\bglobal\s+\$",
       "Global variables create invisible dependencies between parts of the program.",
       "Pass values as parameters or use dependency injection.",
       "Any function can change that value: bugs that are hard to trace and code that cannot be tested."),
    _R("QPH-005", "mysql_* functions removed from PHP", "MEDIUM", ("php",), r"\bmysql_[a-z_]+\s*\(",
       "The mysql_* extension was removed in PHP 7.",
       "Switch to PDO or mysqli.",
       "The code does not work on modern PHP versions."),

    # ---- Rust -----------------------------------------------------------
    _R("QRS-001", "unwrap() (can crash the program)", "LOW", ("rust",), r"\.unwrap\s*\(\s*\)",
       "unwrap() panics the program if the value is None/Err.",
       "Handle the case with match / if let, use '?' to propagate the error, or expect(\"reason\") if it is truly impossible.",
       "Unexpected data terminates the whole program instead of being handled."),
    _R("QRS-002", "'unsafe' block or function", "MEDIUM", ("rust",), r"\bunsafe\b",
       "The compiler no longer verifies memory safety at this point.",
       "Keep unsafe to a minimum, encapsulate it and document (// SAFETY: ...) why it is correct.",
       "A mistake here can cause memory corruption: exactly what Rust aims to prevent."),
    _R("QRS-003", "todo!() / unimplemented!() in the code", "MEDIUM", ("rust",), r"\b(?:todo|unimplemented)!\s*[(\[{]",
       "Part of the code has not been written: it panics if executed.",
       "Implement the missing part or return an explicit error.",
       "The program crashes as soon as someone takes that branch."),
    _R("QRS-004", "println!/eprintln!/dbg! in the code", "LOW", ("rust",), r"\b(?:println|eprintln|dbg)!\s*[(\[{]",
       "Direct or debug output.",
       "Use a logging crate (log, tracing) with configurable levels.",
       "Noise in the output and no control over what gets printed in production."),
    _R("QRS-005", "Explicit panic!()", "MEDIUM", ("rust",), r"\bpanic!\s*[(\[{]",
       "Terminates the thread (or the whole program).",
       "Return a Result with a descriptive error.",
       "An edge case brings everything down instead of being handled."),
    _R("QRS-006", "Result ignored with 'let _ ='", "LOW", ("rust",), r"^\s*let\s+_\s*=\s*[\w:.]+.*\(",
       "The returned Result/value is explicitly discarded.",
       "Handle the error, or explain with a comment why it can be ignored.",
       "A failed operation goes unnoticed."),
    _R("QRS-007", "Error ignored in a match (Err(_) => {})", "MEDIUM", ("rust",),
       r"\bErr\s*\([^)]*\)\s*=>\s*(?:\{\s*\}|\(\s*\))",
       "The error branch does nothing.", "Log or propagate the error.",
       "Failures become invisible.", scope="text"),

    # ---- Kotlin ---------------------------------------------------------
    _R("QKT-001", "'!!' operator (can throw NullPointerException)", "MEDIUM", ("kotlin",), r"(?<=[\w\)\]])!!",
       "'!!' forces the value to non-null without checking it: if it is null, the app crashes.",
       "Use ?. (safe call), ?: (default value), let { }, or an explicit check.",
       "Defeats Kotlin's main advantage (null safety): an unexpected null crashes the app."),
    _R("QKT-002", "println/print in the code", "LOW", ("kotlin",), r"(?<![\w.])(?:println|print)\s*\(",
       "Direct output instead of a log.", "Use a logger (Timber, SLF4J, Log.d on Android).",
       "Noise and no control over messages in production."),
    _R("QKT-003", "GlobalScope.launch/async", "MEDIUM", ("kotlin",), r"\bGlobalScope\s*\.\s*(?:launch|async)\b",
       "Coroutines in GlobalScope are not tied to any lifecycle and are never cancelled.",
       "Use a structured scope (viewModelScope, lifecycleScope, coroutineScope).",
       "Work that continues after the screen is closed: wasted battery and possible crashes."),
    _R("QKT-004", "Overly generic catch of Exception/Throwable", "MEDIUM", ("kotlin",),
       r"\bcatch\s*\(\s*\w+\s*:\s*(?:Exception|Throwable)\s*\)",
       "Catching everything also hides programming errors.",
       "Catch specific exceptions; for coroutines, rethrow CancellationException.",
       "Real errors are treated as normal events; it can break coroutine cancellation."),

    # ---- Swift ----------------------------------------------------------
    _R("QSW-001", "Force unwrap (!) of an Optional", "LOW", ("swift",),
       r"(?<=[\w\)\]])(?<!\bas)(?<!\btry)!(?!=)(?=[\s.\[\),;:]|$)",
       "The exclamation mark forces the value to be extracted: if it is nil, the app crashes.",
       "Use 'if let', 'guard let' or '??' with a default value.",
       "An unexpected missing value terminates the app instantly.",
       exclude=r"@IBOutlet|@IBInspectable"),
    _R("QSW-002", "try! (error ignored with a crash)", "MEDIUM", ("swift",), r"\btry!",
       "If the operation throws an error, the app crashes.",
       "Use do/catch or 'try?' with nil handling.",
       "Any error (missing file, invalid JSON) terminates the app."),
    _R("QSW-003", "as! (forced cast)", "MEDIUM", ("swift",), r"\bas!",
       "If the type is not the expected one, the app crashes.",
       "Use 'as?' with 'if let' or 'guard let'.",
       "Data of a type different from the expected one terminates the app."),
    _R("QSW-004", "print/NSLog/debugPrint in the code", "LOW", ("swift",),
       r"(?<![\w.])(?:print|NSLog|debugPrint|dump)\s*\(",
       "Direct output instead of a log.", "Use os.Logger (or a logging system) with levels.",
       "Console noise and potentially sensitive data in the logs."),
    _R("QSW-005", "fatalError() in the code", "MEDIUM", ("swift",), r"\bfatalError\s*\(",
       "Terminates the app immediately.", "Return or throw a handleable error (throws / Result).",
       "The edge case crashes the app instead of being handled."),

    # ---- SQL ------------------------------------------------------------
    _R("QSQL-001", "SELECT * (columns not listed)", "LOW", ("sql",),
       r"\bSELECT\s+(?:DISTINCT\s+|TOP\s+\d+\s+)?\*",
       "Reads all columns, even those that are not needed.",
       "List only the columns you need.",
       "More data transferred than necessary and queries that break (or change their result) if columns are added to the table.",
       exclude=r"(?i)EXISTS\s*\(\s*SELECT", flags=re.I),
    _R("QSQL-002", "Implicit comma join (FROM a, b)", "LOW", ("sql",),
       r"\bFROM\s+[\w.\"\[\]`]+(?:\s+(?:AS\s+)?\w+)?\s*,\s*[\w.\"\[\]`]+",
       "Old syntax: the join condition lives in the WHERE clause and can be forgotten.",
       "Use an explicit JOIN ... ON ....",
       "If you forget the condition, you get a Cartesian product: millions of rows and a very slow query.", flags=re.I),
    _R("QSQL-003", "INSERT without a column list", "LOW", ("sql",),
       r"\bINSERT\s+INTO\s+[\w.\"\[\]`]+\s+(?:VALUES|SELECT)\b",
       "Depends on the order of the table's columns.",
       "Write INSERT INTO table (col1, col2) VALUES (...).",
       "If the table changes, values end up in the wrong columns with no error.", flags=re.I),
    _R("QSQL-004", "ORDER BY with a column number", "LOW", ("sql",), r"\bORDER\s+BY\s+\d+\b",
       "Ordering by position breaks if the column list changes.",
       "Use the column name (or alias).",
       "The ordering silently changes when you modify the SELECT.", flags=re.I),
    _R("QSQL-005", "NOT IN with a subquery (NULL problems)", "LOW", ("sql",),
       r"\bNOT\s+IN\s*\(\s*SELECT\b",
       "If the subquery returns even a single NULL, NOT IN returns no rows.",
       "Use NOT EXISTS or LEFT JOIN ... IS NULL.",
       "Inexplicable empty results that only appear when a NULL shows up in the data.", flags=re.I),
]


def _sql_statement_findings(masked, rel_path, line_of, raw_lines):
    """Checks at SQL statement level (UPDATE/DELETE without WHERE, tables without a key)."""
    out = []
    for m in re.finditer(r"[^;]+;?", masked):
        text = m.group()
        stripped = text.lstrip()
        if not stripped:
            continue
        offset = m.start() + (len(text) - len(stripped))
        line = line_of(offset)
        head = stripped[:200].upper()
        if re.match(r"(?:UPDATE\b|DELETE\s+FROM\b)", head) and not re.search(r"\bWHERE\b", stripped, re.I):
            out.append(_make(
                "QSQL-006", "UPDATE/DELETE without WHERE", "MEDIUM", "unknown", rel_path, line,
                _snippet(raw_lines, line),
                "The statement modifies or deletes ALL rows of the table.",
                "Add a WHERE condition. If you really need to empty the table, use TRUNCATE and write it explicitly.",
                "A moment of carelessness can delete or overwrite the entire table in one go.",
                "sql"))
        elif re.match(r"CREATE\s+(?:TEMP(?:ORARY)?\s+)?TABLE\b", head) and not re.search(r"\bPRIMARY\s+KEY\b", stripped, re.I):
            out.append(_make(
                "QSQL-007", "Table without a primary key", "LOW", "unknown", rel_path, line,
                _snippet(raw_lines, line),
                "The table does not declare a PRIMARY KEY in this statement.",
                "Define a primary key (if you add it later with ALTER TABLE, you can ignore this warning).",
                "Duplicate rows that cannot be told apart, ambiguous updates and worse join performance.",
                "sql"))
    return out


# ---------------------------------------------------------------------------
# Building the findings
# ---------------------------------------------------------------------------
def _snippet(raw_lines, line):
    if 1 <= line <= len(raw_lines):
        s = raw_lines[line - 1].strip()
        return s if len(s) <= 160 else s[:160] + " …"
    return ""


def _make(rid, name, severity, confidence, rel_path, line, snippet, description,
          recommendation, impact, lang):
    conf_label = {
        "confirmed": "Measured directly on the code",
        "unknown": "Heuristic: verify the context",
    }[confidence]
    return {
        "id": rid, "name": name, "severity": severity,
        "confidence": confidence, "confidence_label": conf_label,
        "file": rel_path, "line": line, "snippet": snippet,
        "description": description, "recommendation": recommendation, "impact": impact,
        "engine": "quality", "category": "quality", "language": LANG_LABEL.get(lang, lang),
    }


def _tier(value, low, medium):
    if value >= medium:
        return "MEDIUM"
    if value >= low:
        return "LOW"
    return None


_TODO_RX = re.compile(r"\b(TODO|FIXME|HACK|XXX|BUG)\b")
_CODE_LIKE_RX = re.compile(
    r"(?:[;{}]\s*$)|(?:^\s*(?:if|for|while|return|import|using|var|let|const|public|private|protected|"
    r"func|fn|fun|function|class|else|echo)\b[^.]*[({=])")
_TRIVIAL_LINE_RX = re.compile(r"^(?:[\{\}\(\)\[\];,]*|import\b.*|using\b.*|use\b.*|package\b.*|@\w+.*)$")


def _line_scope_rules(lang, raw_lines, masked_lines, rel_path):
    findings = []
    counts = defaultdict(int)
    for rule in RULES_Q:
        if lang not in rule["langs"] or rule["scope"] != "line":
            continue
        source_lines = raw_lines if rule["raw"] else masked_lines
        for idx, text in enumerate(source_lines):
            if not rule["regex"].search(text):
                continue
            if rule["exclude"] and rule["exclude"].search(raw_lines[idx]):
                continue
            counts[rule["id"]] += 1
            if counts[rule["id"]] > MAX_PER_RULE_PER_FILE:
                continue
            findings.append(_make(rule["id"], rule["name"], rule["severity"], "unknown", rel_path,
                                  idx + 1, _snippet(raw_lines, idx + 1), rule["description"],
                                  rule["recommendation"], rule["impact"], lang))
    for rule_id, total in counts.items():
        if total > MAX_PER_RULE_PER_FILE:
            extra = total - MAX_PER_RULE_PER_FILE
            last = [f for f in findings if f["id"] == rule_id][-1]
            last["description"] += f" ({extra} more occurrences of the same kind in this file are not listed.)"
    return findings


def _text_scope_rules(lang, raw, masked, line_of, raw_lines, rel_path):
    findings = []
    for rule in RULES_Q:
        if lang not in rule["langs"] or rule["scope"] != "text":
            continue
        target = raw if rule["raw"] else masked
        n = 0
        for m in rule["regex"].finditer(target):
            line = line_of(m.start())
            n += 1
            if n > MAX_PER_RULE_PER_FILE:
                break
            findings.append(_make(rule["id"], rule["name"], rule["severity"], "unknown", rel_path,
                                  line, _snippet(raw_lines, line), rule["description"],
                                  rule["recommendation"], rule["impact"], lang))
    return findings


def _comment_findings(comments, lang, raw_lines, rel_path):
    findings = []

    todo_count = 0
    seen_lines = set()
    for line, text, _kind in comments:
        m = _TODO_RX.search(text)
        if not m or line in seen_lines:
            continue
        seen_lines.add(line)
        todo_count += 1
        if todo_count > MAX_TODO_PER_FILE:
            break
        tag = m.group(1)
        findings.append(_make(
            "QG-006", f"Pending note in the code ({tag})", "INFO" if tag == "TODO" else "LOW", "confirmed",
            rel_path, line, text.strip()[:160],
            f"A comment contains '{tag}': something remains to be finished, fixed or reviewed.",
            "Resolve the matter, or turn it into a tracked ticket and remove the comment.",
            "Forgotten notes pile up and become technical debt that nobody remembers any more.", lang))

    # commented-out code: >=3 consecutive "line" comments that look like code
    run_start, run_len, last_line = None, 0, None

    def flush():
        if run_len >= 3:
            findings.append(_make(
                "QG-007", "Commented-out code left in the file", "LOW", "unknown", rel_path, run_start,
                _snippet(raw_lines, run_start),
                f"At least {run_len} consecutive comment lines look like disabled code.",
                "Delete it: version control (Git) already preserves the history. Dead code confuses readers.",
                "Readers cannot tell whether that code was forgotten or will be needed again, which slows down understanding of the file.",
                lang))

    for line, text, kind in comments:
        body = re.sub(r"^\s*(?://|#|--)\s?", "", text)
        is_doc = text.lstrip().startswith(("///", "//!", "/**"))
        looks_code = kind == "line" and not is_doc and bool(_CODE_LIKE_RX.search(body))
        if looks_code and (last_line is not None and line == last_line + 1):
            run_len += 1
            last_line = line
        elif looks_code:
            flush()
            run_start, run_len, last_line = line, 1, line
        else:
            flush()
            run_start, run_len, last_line = None, 0, None
    flush()
    return findings


def _duplicate_findings(raw_lines, lang, rel_path):
    entries = []  # (line number, normalized text)
    for i, line in enumerate(raw_lines, start=1):
        s = " ".join(line.split())
        if len(s) < 4 or _TRIVIAL_LINE_RX.match(s) or s.startswith(("//", "#", "--", "*", "/*")):
            continue
        entries.append((i, s))

    seen = {}
    findings = []
    idx = 0
    while idx + DUP_WINDOW <= len(entries) and len(findings) < MAX_DUPLICATES_PER_FILE:
        window = tuple(t for _, t in entries[idx:idx + DUP_WINDOW])
        if sum(len(t) for t in window) < DUP_MIN_CHARS:
            idx += 1
            continue
        earlier = seen.get(window)
        if earlier is not None and earlier + DUP_WINDOW <= idx:
            this_line = entries[idx][0]
            first_line = entries[earlier][0]
            findings.append(_make(
                "QG-008", "Duplicated code block", "LOW", "unknown", rel_path, this_line,
                _snippet(raw_lines, this_line),
                f"This block of at least {DUP_WINDOW} lines is identical to the one at line {first_line} of the same file.",
                "Extract the common code into a function and call it from both places.",
                "A fix made in one place must be remembered in the others: sooner or later the copies diverge and bugs appear.",
                lang))
            idx += DUP_WINDOW
            continue
        seen.setdefault(window, idx)
        idx += 1
    return findings


def _function_findings(funcs, masked, lang, raw_lines, rel_path):
    findings = []
    for fn in funcs:
        body_open, body_close = fn["body"]
        body = masked[body_open + 1:body_close]
        length = fn["end"] - fn["start"] + 1
        label = "The anonymous function" if fn["name"] in ("<anonymous>", "<arrow>") else f"Function '{fn['name']}'"
        snippet = _snippet(raw_lines, fn["start"])

        sev = _tier(length, FUNC_LINES_LOW, FUNC_LINES_MEDIUM)
        if sev:
            findings.append(_make(
                "QG-002", "Function too long", sev, "confirmed", rel_path, fn["start"], snippet,
                f"{label} is {length} lines long (recommended threshold: {FUNC_LINES_LOW}).",
                "Split it into smaller functions, each with a single job and a clear name.",
                "Long functions are hard to understand, test and modify without breaking something.", lang))

        cx = _complexity(body, lang)
        sev = _tier(cx, COMPLEXITY_LOW, COMPLEXITY_MEDIUM)
        if sev:
            findings.append(_make(
                "QG-003", "High complexity (too many different paths)", sev, "confirmed", rel_path,
                fn["start"], snippet,
                f"{label} has an estimated cyclomatic complexity of {cx} (recommended threshold: {COMPLEXITY_LOW - 1}): "
                "many ifs, loops and combined conditions.",
                "Simplify with early returns (guard clauses), extract sub-functions, replace chains of ifs with a lookup table or polymorphism.",
                "The more paths there are, the more tests are needed to cover them all, and the easier it is for a change to break one without you noticing.",
                lang))

        sev = _tier(fn["params"], PARAMS_LOW, PARAMS_MEDIUM)
        if sev:
            findings.append(_make(
                "QG-004", "Too many parameters", sev, "confirmed", rel_path, fn["start"], snippet,
                f"{label} takes {fn['params']} parameters (recommended threshold: {PARAMS_LOW - 1}).",
                "Group related parameters into an object/struct, or split the function.",
                "Long calls that are easy to get wrong (parameters swapped without the compiler noticing).",
                lang))

        depth = _max_depth(body)
        sev = _tier(depth, NESTING_LOW, NESTING_MEDIUM)
        if sev:
            findings.append(_make(
                "QG-005", "Excessive nesting", sev, "confirmed", rel_path, fn["start"], snippet,
                f"{label} has blocks nested up to {depth} levels deep.",
                "Exit early from special cases (early return/continue) and extract the inner blocks into functions.",
                "Staircase-shaped code that is hard to follow: too many conditions have to be kept in mind at once.", lang))
    return findings


# ---------------------------------------------------------------------------
# Entry point
# ---------------------------------------------------------------------------
def language_for_extension(ext):
    return LANG_BY_EXT.get(ext)


_RUST_TEST_ATTR = re.compile(r"#\[\s*(?:cfg\(test\)|(?:\w+::)*(?:test|rstest|bench)(?:\([^\]]*\))?)\s*\]\s*(?:#\[[^\]]*\]\s*)*(?:pub(?:\([^)]*\))?\s+)?(?:async\s+|unsafe\s+)*(?:mod|fn)\b[^{;]*\{")
_RUST_TESTY_RULES = {"QRS-001", "QRS-004", "QRS-005", "QRS-006", "QG-006"}


def _rust_test_regions(masked, line_of):
    """Line ranges of #[cfg(test)] modules and #[test] functions: there, unwrap/println/panic are normal."""
    _, _, brace = _bracket_maps(masked)
    regions = []
    for m in _RUST_TEST_ATTR.finditer(masked):
        close = brace.get(m.end() - 1)
        if close is not None:
            regions.append((line_of(m.start()), line_of(close)))
    return regions


def analyze_quality(rel_path, ext, content):
    """Returns the list of quality findings for a file. Never raises exceptions."""
    lang = LANG_BY_EXT.get(ext)
    if not lang:
        return []
    findings = []
    try:
        raw_lines = content.split("\n")
        raw_lines = [l.rstrip("\r") for l in raw_lines]
        starts = _line_starts(content)

        def line_of(idx):
            return bisect_right(starts, idx)

        masked, comments = mask_source(content, lang)
        masked_lines = masked.split("\n")

        # --- file ---
        total_lines = len(content.splitlines())
        sev = _tier(total_lines, FILE_LINES_LOW, FILE_LINES_MEDIUM)
        if sev:
            findings.append(_make(
                "QG-001", "File too long", sev, "confirmed", rel_path, 1, rel_path,
                f"The file has {total_lines} lines (recommended threshold: {FILE_LINES_LOW}).",
                "Split it into smaller modules/files, one per responsibility.",
                "Huge files are tiring to navigate and encourage merge conflicts when several people work together.",
                lang))

        if lang != "sql":
            long_lines = [i for i, l in enumerate(raw_lines, start=1) if len(l) > LONG_LINE_CHARS]
            if len(long_lines) >= LONG_LINES_MIN_COUNT:
                first = long_lines[0]
                findings.append(_make(
                    "QG-009", "Very long lines", "INFO", "confirmed", rel_path, first,
                    _snippet(raw_lines, first),
                    f"{len(long_lines)} lines exceed {LONG_LINE_CHARS} characters (the first is here).",
                    "Wrap the lines and format the code; many languages have an automatic formatter.",
                    "Long lines force horizontal scrolling and make it harder to compare changes.",
                    lang))

        # --- functions ---
        if lang != "sql":
            funcs = find_functions(masked, lang, line_of)
            findings.extend(_function_findings(funcs, masked, lang, raw_lines, rel_path))

        # --- rules ---
        findings.extend(_line_scope_rules(lang, raw_lines, masked_lines, rel_path))
        findings.extend(_text_scope_rules(lang, content, masked, line_of, raw_lines, rel_path))
        if lang == "sql":
            findings.extend(_sql_statement_findings(masked, rel_path, line_of, raw_lines))

        # --- comments and duplicates ---
        findings.extend(_comment_findings(comments, lang, raw_lines, rel_path))
        findings.extend(_duplicate_findings(raw_lines, lang, rel_path))
    except Exception as exc:
        # The quality engine must never block a scan: return whatever was found so far.
        log.warning("Quality analysis of '%s' stopped early (%s: %s); the results for this file may be "
                    "incomplete. The file may be minified, obfuscated or use unusual syntax.",
                    rel_path, type(exc).__name__, exc)

    if lang == "rust":
        try:
            regions = _rust_test_regions(masked, line_of)
            testy_path = bool(re.search(r"(^|/)(tests?|examples?|benches)(/|$)|_test\.rs$", rel_path.replace("\\", "/")))
            findings = [f for f in findings if not any(a <= f["line"] <= b for a, b in regions) and
                        not (testy_path and f["id"] in _RUST_TESTY_RULES)]
        except Exception as exc:
            log.warning("Could not exclude Rust test code from the quality results of '%s' (%s); "
                        "test-only findings may be included.", rel_path, exc)
    seen, unique = set(), []
    for f in findings:
        key = (f["id"], f["line"], f["snippet"])
        if key not in seen:
            seen.add(key)
            unique.append(f)
    return unique


def quality_score(findings):
    """
    Quality score 0-100 (exponential decay of the penalty), separate from the security score. Only counts
    non-suppressed quality findings. The same rule repeated many times
    weighs less with each repetition (logarithmically): 200 console.log
    calls must not zero the score the way 200 different problems would.
    """
    per_rule = {}
    for f in findings:
        if f.get("category") != "quality" or f.get("suppressed"):
            continue
        weight = QUALITY_WEIGHT.get(f["severity"], 0)
        count, w = per_rule.get(f["id"], (0, 0))
        per_rule[f["id"]] = (count + 1, max(w, weight))
    penalty = sum(w * (1 + math.log2(c)) for c, w in per_rule.values())
    return max(0, min(100, round(100 * math.exp(-penalty / 60))))  # gradual decay: no sudden collapse to 0
