# -*- coding: utf-8 -*-
"""
External benchmark: uses the test files of the Semgrep rules (github.com/semgrep/semgrep-rules, python/ folder),
where each case is labeled by others with "# ruleid: X" (must fire) and "# ok: X" (must not fire).
Only the vulnerability classes (CWE) that the AST engine claims to cover are considered.
Usage:  python tools/benchmark_semgrep.py /path/to/semgrep-rules/python [-v]
"""
import glob, os, re, sys, collections
try:
    import yaml
except ImportError:
    print("ERROR: the 'PyYAML' package is required to read the Semgrep rule files. Install it with: pip install pyyaml", file=sys.stderr)
    sys.exit(2)
sys.path.insert(0, os.path.join(os.path.dirname(os.path.abspath(__file__)), ".."))
from ast_engine import analyze_python_source
import py_audit

GROUPS = {"cmd": (78, 77, 88), "code": (94, 95, 96, 470, 1336), "sql": (89, 564), "path": (22, 23, 73), "ssrf": (918,),
          "redirect": (601,), "xss": (79, 80), "deser": (502,), "xml": (611, 776), "crypto": (327, 326, 328),
          "debug": (489, 215), "random": (338, 330), "tmp": (377,), "perm": (732,), "jwt": (347,)}
GROUP_OF = {n: g for g, ns in GROUPS.items() for n in ns}
ANN = re.compile(r"#\s*(ruleid|ok|todoruleid|todook)\s*:\s*([\w\-.]+)")

def cwe_groups(rule):
    cw = rule.get("metadata", {}).get("cwe") or []
    cw = [cw] if isinstance(cw, str) else cw
    out = set()
    for c in cw:
        m = re.match(r"CWE-(\d+)", str(c))
        if m and int(m.group(1)) in GROUP_OF:
            out.add(GROUP_OF[int(m.group(1))])
    return out

def main(root, verbose=False, mode_filter=None):
    """mode_filter: None = all rules, 'taint' = data-flow rules only, 'pattern' = pattern/audit rules only."""
    stats = collections.defaultdict(lambda: collections.Counter())
    fails = []
    for py in sorted(glob.glob(os.path.join(root, "**", "*.py"), recursive=True)):
        ym = os.path.splitext(py)[0] + ".yaml"
        if not os.path.exists(ym):
            continue
        try:
            rules = {r["id"]: r for r in (yaml.safe_load(open(ym, encoding="utf-8")) or {}).get("rules", [])}
        except Exception as exc:
            print(f"WARNING: could not parse rule file '{ym}' ({type(exc).__name__}: {exc}); skipping it.", file=sys.stderr)
            continue
        src = open(py, encoding="utf-8", errors="ignore").read()
        lines = src.splitlines()
        anns = [(i + 1, m.group(1), m.group(2)) for i, l in enumerate(lines) for m in [ANN.search(l)] if m]
        if not anns:
            continue
        found = analyze_python_source(os.path.relpath(py, root), src) + py_audit.analyze_py_audit(os.path.relpath(py, root), src)
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
            hit = [f for f in found if lo <= f["line"] <= hi and GROUP_OF.get(int(re.sub(r"\D", "", f.get("cwe", "0")) or 0)) in groups]
            g = sorted(groups)[0]
            if kind == "ruleid":
                stats[g]["TP" if hit else "FN"] += 1
                if not hit: fails.append(("FN", os.path.relpath(py, root), ln, rid))
            else:
                stats[g]["FP" if hit else "TN"] += 1
                if hit: fails.append(("FP", os.path.relpath(py, root), ln, rid))
    tot = collections.Counter()
    print(f"{'class':10} {'TP':>4} {'FN':>4} {'FP':>4} {'TN':>4}   recall  false-alarm-rate")
    for g, c in sorted(stats.items()):
        tot.update(c)
        rec = c['TP'] / max(1, c['TP'] + c['FN']); fpr = c['FP'] / max(1, c['FP'] + c['TN'])
        print(f"{g:10} {c['TP']:>4} {c['FN']:>4} {c['FP']:>4} {c['TN']:>4}   {rec:5.0%}   {fpr:5.0%}")
    rec = tot['TP'] / max(1, tot['TP'] + tot['FN']); fpr = tot['FP'] / max(1, tot['FP'] + tot['TN'])
    prec = tot['TP'] / max(1, tot['TP'] + tot['FP'])
    print(f"{'TOTAL':10} {tot['TP']:>4} {tot['FN']:>4} {tot['FP']:>4} {tot['TN']:>4}   {rec:5.0%}   {fpr:5.0%}   precision {prec:.0%}")
    if verbose:
        for f in fails: print(*f)
    return fails

if __name__ == "__main__":
    if len(sys.argv) < 2 or not os.path.isdir(sys.argv[1]):
        print("ERROR: missing or invalid corpus folder.\nUsage: python tools/benchmark_semgrep.py <semgrep-rules/python-dir> [-v]", file=sys.stderr)
        sys.exit(2)
    for mf in ("taint", "pattern"):
        print(f"\n=== {mf} rules ===")
        main(sys.argv[1], "-v" in sys.argv, mf)
