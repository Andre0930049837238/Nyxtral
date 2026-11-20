# -*- coding: utf-8 -*-
"""
External benchmark for Rust: the CodeQL security tests (github.com/github/codeql, rust/ql/test/query-tests/security).
Every line with "// $ ... Alert[rust/<rule>]" is an expected finding; "MISSING:" marks a real issue that even CodeQL does
not detect yet (counted separately). Only the classes the engine claims to cover are evaluated.
Usage:  python tools/benchmark_codeql_rust.py /path/to/codeql/rust/ql/test/query-tests/security [-v]
"""
import collections, glob, os, re, sys
sys.path.insert(0, os.path.join(os.path.dirname(os.path.abspath(__file__)), ".."))
import rust_engine

RULE_CLASS = {"sql-injection": "sql", "path-injection": "path", "command-line-injection": "cmd", "request-forgery": "ssrf", "xss": "xss",
              "regex-injection": "regex", "log-injection": "log", "cleartext-logging": "clog", "cleartext-storage-database": "cstore",
              "cleartext-transmission": "ctrans", "uncontrolled-allocation-size": "alloc", "weak-cryptographic-algorithm": "algo",
              "weak-sensitive-data-hashing": "pwhash", "hard-coded-cryptographic-value": "hc", "insecure-cookie": "cookie",
              "disabled-certificate-check": "cert", "non-https-url": "nohttps"}
SID_CLASS = {"AST-RS-001": "cmd", "AST-RS-002": "sql", "AST-RS-003": "path", "AST-RS-004": "ssrf", "AST-RS-005": "redirect", "AST-RS-006": "xss",
             "AST-RS-007": "regex", "AST-RS-008": "log", "AST-RS-009": "alloc", "AST-RS-010": "tpl", "AST-RS-011": "mem", "AST-RS-012": "clog",
             "AST-RS-013": "cstore", "AST-RS-014": "pwhash", "AST-RS-015": "ctrans", "AST-RS-016": "cert", "AST-RS-017": "nohttps",
             "AST-RS-018": "algo", "AST-RS-019": "hc", "AST-RS-020": "cookie"}
ALERT = re.compile(r"Alert\[rust/([a-z\-]+)\]")


def main(root, verbose=False, tol=1):
    stats = collections.defaultdict(collections.Counter)
    fails = []
    for path in sorted(glob.glob(os.path.join(root, "**", "*.rs"), recursive=True)):
        src = open(path, encoding="utf-8", errors="ignore").read()
        exp, miss = collections.defaultdict(set), collections.defaultdict(set)
        for i, line in enumerate(src.splitlines(), 1):
            m = re.search(r"//\s*\$\s*(.*)$", line)
            if not m:
                continue
            body = m.group(1)
            head, _, tail = body.partition("MISSING:")
            for r in ALERT.findall(head):
                if r in RULE_CLASS:
                    exp[RULE_CLASS[r]].add(i)
            for r in ALERT.findall(tail):
                if r in RULE_CLASS:
                    miss[RULE_CLASS[r]].add(i)
        classes = set(exp) | set(miss)
        if not classes:
            continue
        found = rust_engine.analyze_rust_source(os.path.relpath(path, root), src)
        byclass = collections.defaultdict(set)
        for f in found:
            c = SID_CLASS.get(f["id"])
            if c:
                byclass[c].add(f["line"])
        rel = os.path.relpath(path, root)
        for c in classes:
            have = byclass.get(c, set())
            hit = lambda ln: any(abs(ln - h) <= tol for h in have)
            for ln in sorted(exp[c]):
                if hit(ln): stats[c]["TP"] += 1
                else:
                    stats[c]["FN"] += 1; fails.append(("FN", rel, ln, c))
            for ln in sorted(miss[c]):
                stats[c]["MISS_OK" if hit(ln) else "MISS_NO"] += 1
            allowed = exp[c] | miss[c]
            for h in sorted(have):
                if not any(abs(h - a) <= tol for a in allowed):
                    stats[c]["FP"] += 1; fails.append(("FP", rel, h, c))
    tot = collections.Counter()
    print(f"{'class':9} {'TP':>4} {'FN':>4} {'FP':>4}   recall  precision   (issues even CodeQL misses: found/total)")
    for c, s in sorted(stats.items()):
        tot.update(s)
        print(f"{c:9} {s['TP']:>4} {s['FN']:>4} {s['FP']:>4}   {s['TP']/max(1,s['TP']+s['FN']):5.0%}   {s['TP']/max(1,s['TP']+s['FP']):5.0%}       {s['MISS_OK']}/{s['MISS_OK']+s['MISS_NO']}")
    print(f"{'TOTAL':9} {tot['TP']:>4} {tot['FN']:>4} {tot['FP']:>4}   {tot['TP']/max(1,tot['TP']+tot['FN']):5.0%}   {tot['TP']/max(1,tot['TP']+tot['FP']):5.0%}       "
          f"{tot['MISS_OK']}/{tot['MISS_OK']+tot['MISS_NO']}")
    if verbose:
        for f in fails: print(*f)
    return fails


if __name__ == "__main__":
    if len(sys.argv) < 2:
        print("ERROR: missing corpus path.\nUsage: python tools/benchmark_codeql_rust.py <codeql-security-tests-dir> [-v]", file=sys.stderr)
        sys.exit(2)
    if not os.path.isdir(sys.argv[1]):
        print(f"ERROR: CodeQL test folder not found: '{sys.argv[1]}'.", file=sys.stderr)
        sys.exit(2)
    main(sys.argv[1], "-v" in sys.argv)
