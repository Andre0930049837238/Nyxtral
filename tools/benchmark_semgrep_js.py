# -*- coding: utf-8 -*-
"""
External benchmark for JavaScript/TypeScript: labeled test files from the Semgrep rules
("// ruleid: X" must fire, "// ok: X" must not). Only the vulnerability classes (CWE) we cover.
Usage:  python tools/benchmark_semgrep_js.py /path/to/semgrep-rules/javascript [-v]
"""
import glob, os, re, sys, collections
try:
    import yaml
except ImportError:
    print("ERROR: the 'PyYAML' package is required to read the Semgrep rule files. Install it with: pip install pyyaml", file=sys.stderr)
    sys.exit(2)
sys.path.insert(0, os.path.join(os.path.dirname(os.path.abspath(__file__)), ".."))
import scanner
import js_engine

GROUPS = {"xss": (79, 80, 116), "cmd": (78, 77, 88), "code": (94, 95, 96), "sql": (89, 564), "nosql": (943,),
          "path": (22, 23, 73), "ssrf": (918,), "redirect": (601,), "deser": (502,), "xml": (611, 776),
          "crypto": (327, 326, 328, 759, 760), "random": (338, 330), "jwt": (345, 347, 287), "redos": (1333,),
          "proto": (1321, 915), "ssti": (1336,), "tls": (295, 297), "cors": (942,), "cookie": (614, 1004, 1275)}
GROUP_OF = {n: g for g, ns in GROUPS.items() for n in ns}
ANN = re.compile(r"(?://|/\*|#)\s*(ruleid|ok|todoruleid|todook)\s*:\s*([\w\-.]+)")
EXTS = (".js", ".jsx", ".ts", ".tsx", ".mjs", ".cjs")

# incorrect metadata in the Semgrep rules (verified manually)
GROUP_OVERRIDE = {"node-postgres-sqli": {"sql"}}


def cwe_groups(rule):
    if rule.get("id") in GROUP_OVERRIDE:
        return set(GROUP_OVERRIDE[rule["id"]])
    cw = rule.get("metadata", {}).get("cwe") or []
    cw = [cw] if isinstance(cw, str) else cw
    return {GROUP_OF[int(m.group(1))] for c in cw for m in [re.match(r"CWE-(\d+)", str(c))] if m and int(m.group(1)) in GROUP_OF}

def finding_group(f):
    m = re.search(r"\d+", f.get("cwe", "") or "")
    return GROUP_OF.get(int(m.group())) if m else None

def main(root, verbose=False, mode_filter=None):
    stats = collections.defaultdict(collections.Counter)
    fails = []
    for path in sorted(p for e in EXTS for p in glob.glob(os.path.join(root, "**", "*" + e), recursive=True)):
        ym = os.path.splitext(path)[0] + ".yaml"
        if not os.path.exists(ym):
            continue
        try:
            rules = {r["id"]: r for r in (yaml.safe_load(open(ym, encoding="utf-8")) or {}).get("rules", [])}
        except Exception as exc:
            print(f"WARNING: could not parse rule file '{ym}' ({type(exc).__name__}: {exc}); skipping it.", file=sys.stderr)
            continue
        src = open(path, encoding="utf-8", errors="ignore").read()
        lines = src.splitlines()
        anns = [(i + 1, m.group(1), m.group(2)) for i, l in enumerate(lines) for m in [ANN.search(l)] if m]
        if not anns:
            continue
        rel = os.path.relpath(path, root)
        ext = os.path.splitext(path)[1].lower()
        found = scanner.analyze_single_file(rel, ext, src) + js_engine.analyze_js_source(rel, ext, src)
        for k, (ln, kind, rid) in enumerate(anns):
            if kind.startswith("todo") or rid not in rules:
                continue
            groups = cwe_groups(rules[rid])
            if not groups:
                continue
            is_taint = rules[rid].get("mode") == "taint"
            if (mode_filter == "taint" and not is_taint) or (mode_filter == "pattern" and is_taint):
                continue
            nxt = anns[k + 1][0] if k + 1 < len(anns) else len(lines) + 2
            lo, hi = ln + 1, min(ln + 6, nxt - 1)
            hit = [f for f in found if lo <= f["line"] <= hi and finding_group(f) in groups]
            g = sorted(groups)[0]
            if kind == "ruleid":
                stats[g]["TP" if hit else "FN"] += 1
                if not hit: fails.append(("FN", rel, ln, rid))
            else:
                stats[g]["FP" if hit else "TN"] += 1
                if hit: fails.append(("FP", rel, ln, rid))
    tot = collections.Counter()
    print(f"{'class':9} {'TP':>4} {'FN':>4} {'FP':>4} {'TN':>4}   recall  false-alarm-rate")
    for g, c in sorted(stats.items()):
        tot.update(c)
        print(f"{g:9} {c['TP']:>4} {c['FN']:>4} {c['FP']:>4} {c['TN']:>4}   {c['TP']/max(1,c['TP']+c['FN']):5.0%}   {c['FP']/max(1,c['FP']+c['TN']):5.0%}")
    print(f"{'TOTAL':9} {tot['TP']:>4} {tot['FN']:>4} {tot['FP']:>4} {tot['TN']:>4}   {tot['TP']/max(1,tot['TP']+tot['FN']):5.0%}   "
          f"{tot['FP']/max(1,tot['FP']+tot['TN']):5.0%}   precision {tot['TP']/max(1,tot['TP']+tot['FP']):.0%}")
    if verbose:
        for f in fails: print(*f)
    return fails

if __name__ == "__main__":
    if len(sys.argv) < 2 or not os.path.isdir(sys.argv[1]):
        print("ERROR: missing or invalid corpus folder.\nUsage: python tools/benchmark_semgrep_js.py <semgrep-rules/javascript-dir> [-v]", file=sys.stderr)
        sys.exit(2)
    base = sys.argv[1]
    roots = [base, os.path.join(os.path.dirname(base.rstrip('/')), "typescript")] if os.path.basename(base.rstrip('/')) == "javascript" else [base]
    for r in roots:
        for mf in ("taint", "pattern"):
            if os.path.isdir(r):
                print(f"\n=== {os.path.basename(r)} / {mf} rules ===")
                main(r, "-v" in sys.argv, mf)
