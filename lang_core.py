# -*- coding: utf-8 -*-
"""
lang_core.py
=============
Common core of the tree-sitter based security engines for Go, Kotlin and Swift (go_engine.py, kotlin_engine.py,
swift_engine.py). Each language only provides an "adapter" (how to recognise functions, calls, assignments,
strings) and its own tables of sources / dangerous sinks / rules; all the data-flow logic lives here:

  - propagation of untrusted data through variables, concatenations, string templates, fields, casts;
  - distinction between truly external data (network, requests) and "local" data (program arguments, environment
    variables, keyboard), which for paths and sizes is the intended behaviour;
  - per-function summaries, to follow data as it passes from one function (or file) to another;
  - recognition of the most common validity checks (comparisons, allowlists, HasPrefix/isNumeric...).

Honest limitations: no type checker (methods on unknown types stay opaque), no alias analysis and no branch
analysis beyond an approximation, no macro/generics expansion. It never executes the code.
"""

import logging
import re

log = logging.getLogger(__name__)

CONST, PARAM, OTHER, TAINT = 0, 1, 2, 3
# value: (level, parameters, numeric, local)
V_CONST = (CONST, frozenset(), True, False)
V_OTHER = (OTHER, frozenset(), False, False)
V_TAINT = (TAINT, frozenset(), False, False)      # requests, network, files: truly external data
V_LOCAL = (TAINT, frozenset(), False, True)       # argv, environment, keyboard

CONF_LABEL = {
    "confirmed": "Confirmed: the tracked data comes from an external source",
    "unknown": "Potential: the origin of the data cannot be determined automatically, verify manually",
    "fixed": "Detected with certainty in the code: inherently unsafe usage",
}
SEV_DOWN = {"CRITICAL": "HIGH", "HIGH": "MEDIUM", "MEDIUM": "LOW", "LOW": "LOW", "INFO": "INFO"}
STRING_KINDS = ("str",)
MAX_PROJECT_BYTES = 20 * 1024 * 1024
MAX_PROJECT_FILES = 3000


def join(vals):
    vals = [v for v in vals if v is not None]
    if not vals:
        return V_CONST
    lvl = max(v[0] for v in vals)
    params = frozenset().union(*[v[1] for v in vals])
    live = [v for v in vals if v[0] >= OTHER or v[1]]
    num = all(v[2] for v in live) if live else True
    tainted = [v for v in vals if v[0] == TAINT]
    return (lvl, params, num, bool(tainted) and all(v[3] for v in tainted))


def txt(n):
    return n.text.decode("utf-8", "ignore") if n is not None else ""


def line_of(n):
    return n.start_point[0] + 1


def walk(n):
    stack = [n]
    while stack:
        x = stack.pop()
        yield x
        stack.extend(reversed(x.children))


class Sink:
    """Dangerous sink that receives untrusted data. kind: 'str' (strings only), 'any' (numeric sizes too)."""
    def __init__(self, sid, qual, args=None, kind="str", label=None, skip_local=False, template_only=False, exempt=None, audit=False):
        self.sid, self.rx, self.args, self.kind, self.label = sid, re.compile(qual), args, kind, label
        self.skip_local, self.template_only, self.exempt, self.audit = skip_local, template_only, exempt, audit


class Fixed:
    """Inherently insecure usage. If lit is (index, regex) it fires only when the literal argument matches."""
    def __init__(self, sid, qual, lit=None, label=None, any_lit=None):
        self.sid, self.rx, self.lit, self.label = sid, re.compile(qual), lit, label
        self.any_lit = re.compile(any_lit) if any_lit else None
        if lit:
            self.lit = (lit[0], re.compile(lit[1]))


class Project:
    def __init__(self, lang):
        self.lang = lang
        self.funcs, self.defs, self.summary, self.calls = {}, {}, {}, []
        self.findings, self.seen, self.lines, self.is_test = {}, {}, {}, {}

    def resolve(self, name, rel):
        files = self.defs.get(name)
        if not files:
            return None
        if rel in files:
            return (rel, name)
        return (next(iter(files)), name) if len(files) == 1 else None

    def add(self, rel, sid, conf, line, via=None, **fmt):
        key = (rel, sid, line)
        if self.is_test.get(rel) and sid in getattr(self.lang, "TEST_QUIET", ()):
            return                          # in tests and examples these findings are almost always noise
        name, sev_c, sev_u, desc, rec, cwe = self.lang.RULES[sid]
        cwe = fmt.get("cwe", cwe)
        sev = sev_c if conf in ("confirmed", "fixed") else sev_u
        prev = self.seen.get(key)
        if prev is not None:
            if conf == "confirmed" and prev["confidence"] != "confirmed":
                prev.update({"severity": sev_c, "confidence": "confirmed", "confidence_label": CONF_LABEL["confirmed"]})
            return
        desc = desc.format(sink=fmt.get("sink", "the function"), name=fmt.get("name", ""), what=fmt.get("what", ""))
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
             "recommendation": rec, "engine": self.lang.ENGINE, "cwe": cwe}
        self.seen[key] = f
        self.findings.setdefault(rel, []).append(f)


class LangBase:
    """Default values: each language only overrides what it needs."""
    ENGINE, EXTS, RULES, AVAILABLE = "ast", (), {}, False
    CALL_TYPES, STMT_TYPES, FUNC_TYPES = set(), set(), set()
    SINKS, FIXED, PROPAGATE = [], [], []
    CONST_NAMES = frozenset()
    CLEAN_RE = NUM_RE = VALIDATE_RE = LEN_RE = re.compile(r"(?!x)x")
    TEST_RE = re.compile(r"(^|/)_?(tests?|testdata|examples?|docs?|samples?)(/|$)")
    TEST_QUIET = ()

    def parse(self, rel, text): raise NotImplementedError
    def functions(self, root): return []
    def top_level(self, root, rel): return None
    def expr(self, n): return ("other",)
    def stmt(self, n): return None
    def is_deep(self, n): return False
    def cond_of(self, n): return None
    def is_relational(self, x): return False
    def is_equality(self, x): return False
    def is_name_node(self, x): return x.type == "identifier"
    def lkey(self, n): return txt(n) if n is not None and n.type == "identifier" else None
    def is_simple_target(self, n): return n.type == "identifier"
    def literal(self, n): return None
    def is_built_string(self, n): return False
    def sink_label(self, n): return txt(n.child_by_field_name("function") or n)[:60]
    def param_taint(self, fname, pname, ptype, pann): return None
    def source_member(self, key): return None
    def source_call(self, qual, simple): return None
    def call_effects(self, eng, qual, simple, recv, args, vals, node): pass
    def on_enter(self, eng, n): pass
    def on_node(self, eng, n): pass


class FuncAnalyzer:
    def __init__(self, proj, rel, fdef):
        self.p, self.L, self.rel = proj, proj.lang, rel
        self.name, self.key = fdef["name"], (rel, fdef["name"])
        self.env, self.checked, self.validated = {}, set(), set()
        self.depth = 0
        self.fdef = fdef
        for i, (pn, ptype, pann) in enumerate(fdef["params"]):
            if pn:
                v = self.L.param_taint(self.name, pn, ptype, pann)
                self.env[pn] = v if v is not None else (PARAM, frozenset([i]), False, False)
        rn = fdef.get("receiver")
        if rn:
            v = self.L.param_taint(self.name, rn[0], rn[1], "")
            if v is not None:
                self.env[rn[0]] = v

    # ---- evaluation --------------------------------------------------------------------------------
    def ev(self, n):
        if n is None:
            return V_CONST
        e = self.L.expr(n)
        k = e[0]
        if k == "const":
            return V_CONST
        if k == "name":
            return self.name_value(e[1])
        if k == "tmpl2":                       # string template with names extracted from the text ($name) and expressions
            return join([self.name_value(nm) for nm in e[1]] + [self.ev(c) for c in e[2]])
        if k == "wrap":
            return self.ev(e[1])
        if k == "member":
            key = e[3]
            sm = self.L.source_member(key)
            if sm is not None:
                return sm
            if key in self.env:
                return self.env[key]
            v = self.ev(e[1])
            return V_OTHER if v[0] == PARAM else v
        if k == "index":
            return self.ev(e[1])
        if k == "bin":
            return join([self.ev(c) for c in e[1]])
        if k == "cmp":
            return V_CONST
        if k == "tmpl":
            return join([self.ev(c) for c in e[1]])
        if k == "list":
            return join([self.ev(c) for c in e[1]])
        if k == "cond":
            cond, a, b = e[1]
            if cond is not None and any(self.L.is_relational(x) for x in walk(cond)):
                cn = self.names(cond)
                bn = self.names(a) | self.names(b)
                if cn & bn:
                    return V_CONST
            return join([self.ev(a), self.ev(b)])
        if k == "call":
            return self.ev_call(e)
        return V_OTHER

    def name_value(self, nm):
        v = self.env.get(nm)
        if v is not None:
            return v
        sm = self.L.source_member(nm)
        if sm is not None:
            return sm
        return V_CONST if (nm.isupper() and len(nm) > 1) or nm in self.L.CONST_NAMES else V_OTHER

    def is_namespace(self, n):
        """An unknown name before the dot (fmt, strconv, Runtime, String...) is a package/type, not data."""
        return n.type in ("identifier", "simple_identifier", "type_identifier") and txt(n) not in self.env

    def names(self, n):
        return {txt(x) for x in walk(n) if self.L.is_name_node(x)} if n is not None else set()

    def ev_call(self, e):
        _, qual, recv, args, simple = e
        L = self.L
        if L.CLEAN_RE.search(qual):
            return V_CONST
        sv = L.source_call(qual, simple)
        if sv is not None:
            return sv
        vals = [self.ev(a) for a in args]
        if recv is not None and not self.is_namespace(recv):
            vals.append(self.ev(recv))
        if L.NUM_RE.search(qual):
            j = join(vals)
            return (j[0], j[1], True, j[3]) if (j[0] >= OTHER or j[1]) else V_CONST
        if any(v[0] == TAINT for v in vals) or any(v[1] for v in vals):
            return join(vals)
        return V_OTHER

    # ---- environment -----------------------------------------------------------------------------------
    def setv(self, key, v, overwrite):
        if not key:
            return
        if overwrite and self.depth == 0:
            self.env[key] = v
        else:
            old = self.env.get(key)
            self.env[key] = join([old, v]) if old is not None else v

    # ---- traversal -------------------------------------------------------------------------------------
    def visit(self, n):
        L = self.L
        if self.fdef.get("top") and n.type in L.FUNC_TYPES:
            L.on_node(self, n)             # class methods are analysed separately, but the checks on the node still apply
            return
        L.on_enter(self, n)
        deep = L.is_deep(n)
        cond = L.cond_of(n)
        post = set()
        if cond is not None:
            post = self.collect_checks(cond)
        if deep:
            self.depth += 1
        for c in n.children:
            self.visit(c)
        if deep:
            self.depth -= 1
        self.validated |= post
        t = n.type
        if t in L.CALL_TYPES:
            e = L.expr(n)
            if e[0] == "call":
                self.on_call(n, e)
        st = L.stmt(n) if t in L.STMT_TYPES else None
        if st is not None:
            self.on_stmt(st)
        L.on_node(self, n)

    def negated(self, x, cond):
        p = x.parent
        while p is not None and p is not cond.parent:
            if p.type in ("unary_expression", "prefix_expression", "prefix_unary_expression") and txt(p).lstrip().startswith("!"):
                return True
            p = p.parent
        return False

    def collect_checks(self, cond):
        """Records comparisons and validations. Returns the 'validated' names only after the if (negated condition)."""
        L = self.L
        post = set()
        for x in walk(cond):
            if L.is_relational(x):
                for y in walk(x):
                    if L.is_name_node(y):
                        self.checked.add(txt(y))
                        self.validated.add(txt(y))
            e = L.expr(x) if x.type in L.CALL_TYPES else None
            if e is not None and e[0] == "call":
                if L.VALIDATE_RE.search(e[1]):
                    names = {txt(y) for y in walk(x) if L.is_name_node(y)}
                    if self.negated(x, cond):
                        post |= names
                    else:
                        self.validated |= names
                if L.LEN_RE.search(e[1]):
                    for y in walk(x):
                        if L.is_name_node(y):
                            self.checked.add(txt(y))
            if L.is_equality(x):          # allowlist: if x == "a" || x == "b"
                kids = [c for c in x.named_children]
                if any(self.L.expr(c)[0] == "const" for c in kids):
                    names = {txt(z) for y in kids for z in walk(y) if L.is_name_node(z)}
                    if self.negated(x, cond):
                        post |= names
                    else:
                        self.validated |= names
        return post

    def on_stmt(self, st):
        kind = st[0]
        if kind == "assign":
            _, targets, value, op = st
            if isinstance(value, list):
                vs = [self.ev(v) for v in value]
                if len(vs) == len(targets):
                    pairs = zip(targets, vs)
                else:
                    j = join(vs)
                    pairs = [(t, j) for t in targets]
            else:
                v = self.ev(value)
                pairs = [(t, v) for t in targets]
            for t, v in pairs:
                key = self.L.lkey(t)
                if key is None:
                    continue
                if op not in ("=", ":=") and op is not None:
                    v = join([self.ev(t), v])
                    self.setv(key, v, False)
                else:
                    self.setv(key, v, self.L.is_simple_target(t))
        elif kind == "decl":
            _, names, value = st
            if value is None:
                for nm in names:
                    if nm not in self.env:
                        self.env[nm] = V_OTHER
                return
            if isinstance(value, list) and len(value) == len(names):
                for nm, vn in zip(names, value):
                    self.setv(nm, self.ev(vn), True)
            else:
                v = join([self.ev(x) for x in value]) if isinstance(value, list) else self.ev(value)
                for nm in names:
                    self.setv(nm, v, True)
        elif kind == "for":
            _, targets, it = st
            v = self.ev(it)
            for t in targets:
                self.setv(self.L.lkey(t), v, False)

    # ---- calls -----------------------------------------------------------------------------------
    def on_call(self, n, e):
        _, qual, recv, args, simple = e
        L, line = self.L, line_of(n)
        vals = [self.ev(a) for a in args]
        rv = self.ev(recv) if recv is not None else None

        if simple in self.p.funcs:
            ck = self.p.resolve(simple, self.rel)
            if ck is not None:
                self.p.calls.append((self.key, ck, vals, line))

        # propagation "into" the arguments (json.Unmarshal(data, &v), scanner.Scan(&x)...)
        for rx, frm, into in L.PROPAGATE:
            if rx.search(qual):
                src = join(vals if frm == "args" else ([rv] if rv is not None else []))
                if src[0] == TAINT or src[1]:
                    for i in (into if into is not None else range(len(args))):
                        if i == "recv":
                            if recv is not None:
                                self.setv(L.lkey(recv), src, False)
                        elif i < len(args):
                            self.setv(L.lkey(args[i]), src, False)
        L.call_effects(self, qual, simple, recv, args, vals, n)

        for s in L.SINKS:
            if not (s.rx.search(qual) or s.rx.search(simple)):
                continue
            idxs = range(len(args)) if s.args is None else [i for i in s.args if i < len(args)]
            for i in idxs:
                if s.template_only and not L.is_built_string(args[i]):
                    continue
                if s.exempt is not None and s.exempt(self, args[i]):
                    continue
                self.sink_hit(s, args[i], vals[i], n)
        for f in L.FIXED:
            if not (f.rx.search(qual) or f.rx.search(simple)):
                continue
            if f.lit is not None:
                i, rx = f.lit
                lit = L.literal(args[i]) if i < len(args) else None
                if lit is None or not rx.search(lit):
                    continue
            elif f.any_lit is not None:
                if not any(f.any_lit.search(L.literal(a) or txt(a)) for a in args):
                    continue
            self.p.add(self.rel, f.sid, "fixed", line, sink=f.label or simple)

    def sink_hit(self, s, argnode, v, n):
        names = self.names(argnode)
        line = line_of(n)
        label = s.label or self.L.sink_label(n)
        if s.kind == "str" and names & self.validated:
            return
        if v[0] == TAINT:
            if s.kind == "str" and v[2]:
                return
            if s.skip_local and v[3]:
                return
            if s.kind == "any" and names & self.checked:
                return
            self.p.add(self.rel, s.sid, "confirmed", line, sink=label)
        elif v[0] == OTHER and s.audit == "any" and self.L.expr(argnode)[0] != "const":
            self.p.add(self.rel, s.sid, "unknown", line, sink=label)      # dangerous function with a non-constant argument
        elif v[1]:
            if s.audit and v[0] == PARAM:           # high-risk sink: a non-constant parameter already deserves verification
                self.p.add(self.rel, s.sid, "unknown", line, sink=label)
            for pi in v[1]:
                self.p.summary.setdefault(self.key, []).append((frozenset([pi]), s.sid, self.rel, line, {"sink": label}, s.kind, s.skip_local))


def resolve_calls(proj):
    done = set()
    for _ in range(4):
        changed = False
        for caller, ckey, vals, line in proj.calls:
            for entry in list(proj.summary.get(ckey, [])):
                params, sid, rel, sline, kw, kind, skip_local = entry
                for pi in params:
                    if pi >= len(vals):
                        continue
                    v = vals[pi]
                    if v[0] == TAINT and not (kind == "str" and v[2]) and not (skip_local and v[3]):
                        key = (rel, sid, sline)
                        if key not in done:
                            done.add(key)
                            proj.add(rel, sid, "confirmed", sline, via=ckey[1], **kw)
                            changed = True
                    elif v[1]:
                        new = (v[1], sid, rel, sline, kw, kind, skip_local)
                        lst = proj.summary.setdefault(caller, [])
                        if not any(x[1:] == new[1:] and x[0] == new[0] for x in lst):
                            lst.append(new)
                            changed = True
        if not changed:
            break


def analyze(lang, sources):
    """sources: {path: text}. Returns {path: [findings]}."""
    if not lang.AVAILABLE:
        if getattr(lang, "_unavailable_warned", False):
            return {}
        lang._unavailable_warned = True
        log.warning("The %s engine is disabled: its tree-sitter grammar is not installed "
                    "(install the matching 'tree-sitter-*' package). Only pattern-based rules will run.",
                    lang.ENGINE)
        return {}
    if len(sources) > MAX_PROJECT_FILES or sum(len(t) for t in sources.values()) > MAX_PROJECT_BYTES:
        return {p: _run(lang, {p: t}).get(p, []) for p, t in sources.items()}
    return _run(lang, sources)


def _run(lang, sources):
    proj = Project(lang)
    parsed = {}
    for rel, text in sources.items():
        try:
            tree = lang.parse(rel, text)
        except Exception as exc:
            log.warning("Could not parse '%s' with the %s engine (%s): the file was skipped. "
                        "It may contain a syntax error or use unsupported syntax.", rel, lang.ENGINE, exc)
            continue
        proj.lines[rel] = text.splitlines()
        proj.is_test[rel] = bool(lang.TEST_RE.search(rel.replace("\\", "/")))
        funcs = list(lang.functions(tree.root_node))
        parsed[rel] = (tree, funcs)
        for fd in funcs:
            proj.funcs.setdefault(fd["name"], (rel, fd["name"]))
            proj.defs.setdefault(fd["name"], set()).add(rel)
    for rel, (tree, funcs) in parsed.items():
        # file-level code (Swift/Kotlin scripts, global initialisers)
        top = lang.top_level(tree.root_node, rel)
        for fd in ([top] if top else []) + list(funcs):
            fa = FuncAnalyzer(proj, rel, fd)
            try:
                fa.visit(fd["body"])
            except RecursionError:
                log.warning("Analysis of function '%s' in '%s' was abandoned: the code is nested too deeply.",
                            fd.get("name"), rel)
            except Exception as exc:
                log.warning("Analysis of function '%s' in '%s' failed (%s): its findings may be incomplete.",
                            fd.get("name"), rel, exc)
    try:
        resolve_calls(proj)
    except Exception as exc:
        log.warning("Cross-function data-flow resolution failed (%s): some findings that depend on "
                    "calls between functions may be missing.", exc)
    out = {rel: proj.findings.get(rel, []) for rel in sources}
    for fl in out.values():
        fl.sort(key=lambda f: f["line"])
    return out


def analyze_source(lang, rel, text):
    if not lang.AVAILABLE or not rel.lower().endswith(lang.EXTS):
        return []
    return _run(lang, {rel: text}).get(rel, [])
