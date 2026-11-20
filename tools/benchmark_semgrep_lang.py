# -*- coding: utf-8 -*-
"""
External benchmark for Go / Kotlin / Swift (also Java, C#, PHP, C): labeled test files from the Semgrep rules
("// ruleid: X" must fire, "// ok: X" must not). Only the vulnerability classes (CWE) we cover.
Usage:  python tools/benchmark_semgrep_lang.py go|kotlin|swift /path/to/semgrep-rules/<language> [-v]
"""
import glob, os, re, sys, collections
try:
    import yaml
except ImportError:
    print("ERROR: the 'PyYAML' package is required to read the Semgrep rule files. Install it with: pip install pyyaml", file=sys.stderr)
    sys.exit(2)
sys.path.insert(0, os.path.join(os.path.dirname(os.path.abspath(__file__)), ".."))

GROUPS = {"cmd": (78, 77, 88, 94, 95, 96, 1336), "sql": (89, 564), "path": (22, 23, 73, 36), "ssrf": (918,), "redirect": (601,), "xss": (79, 80, 116),
          "crypto": (327, 326, 328, 759, 760, 916, 310, 311, 696, 780), "tls": (295, 297, 322), "random": (338, 331),
          "perm": (732, 276, 277), "cookie": (614, 1004, 1275), "tmp": (377,),
          "unsafe": (242, 119, 787, 125), "dos": (400, 409, 770, 789, 1333), "deser": (502,),
          "storage": (312, 313, 922, 532, 359), "webview": (749, 939, 940, 272), "net": (319, 1327), "jwt": (345, 347, 287), "ldap": (90,), "mem": (119, 120, 121, 122, 125, 134, 190, 242, 252, 415, 416, 457, 467, 676, 758, 787, 908, 1342), "xxe": (611, 776), "csrf": (352, 346, 942), "info": (200, 209, 489, 215), "authz": (862, 285, 639, 915, 1275), "pw": (256, 259, 798, 321, 329, 330, 521)}
GROUP_OF = {n: g for g, ns in GROUPS.items() for n in ns}
ANN = re.compile(r"(?://|/\*|#)\s*(ruleid|ok|todoruleid|todook)\s*:\s*([\w\-.]+)")
EXTS = {"go": (".go",), "kotlin": (".kt", ".kts"), "swift": (".swift",), "java": (".java",), "csharp": (".cs",), "php": (".php",), "c": (".c", ".h")}


def engine_for(lang):
    if lang == "go":
        import go_engine as E; return E.analyze_go_source
    if lang == "kotlin":
        import kotlin_engine as E; return E.analyze_kotlin_source
    if lang == "c":
        import c_engine as E; return E.analyze_c_source
    if lang == "java":
        import java_engine as E; return E.analyze_java_source
    if lang == "csharp":
        import csharp_engine as E; return E.analyze_csharp_source
    if lang == "php":
        import php_engine as E; return E.analyze_php_source
    import swift_engine as E; return E.analyze_swift_source


def cwe_groups(rule):
    cw = rule.get("metadata", {}).get("cwe") or []
    cw = [cw] if isinstance(cw, str) else cw
    return {GROUP_OF[int(m.group(1))] for c in cw for m in [re.match(r"CWE-(\d+)", str(c))] if m and int(m.group(1)) in GROUP_OF}


def finding_group(f):
    m = re.search(r"\d+", f.get("cwe", "") or "")
    return GROUP_OF.get(int(m.group())) if m else None


def main(lang, root, verbose=False):
    analyze = engine_for(lang)
    stats = collections.defaultdict(collections.Counter)
    fails = []
    for path in sorted(p for e in EXTS[lang] for p in glob.glob(os.path.join(root, "**", "*" + e), recursive=True)):
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
        found = analyze(rel, src)
        for k, (ln, kind, rid) in enumerate(anns):
            if kind.startswith("todo") or rid not in rules:
                continue
            groups = cwe_groups(rules[rid])
            if not groups:
                continue
            nxt = anns[k + 1][0] if k + 1 < len(anns) else len(lines) + 2
            lo, hi = ln + 1, min(ln + 6, nxt - 1)
            # if the label precedes a method declaration, the Semgrep rule covers the whole method (reported on its first line)
            decl = lines[ln] if ln < len(lines) else ""
            if re.match(r"^\s*((public|private|protected|internal|static|override|async|final|abstract)\s+)+[\w<>\[\],.? ]+\s+\w+\s*\(|^\s*(function|func|fun|def)\s+\w+\s*\(", decl) \
                    and not re.search(r"[;=]\s*$", decl):
                hi = min(ln + 40, nxt - 1)
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
    if len(sys.argv) < 3 or sys.argv[1] not in EXTS or not os.path.isdir(sys.argv[2]):
        print(f"ERROR: missing or invalid arguments.\nUsage: python tools/benchmark_semgrep_lang.py {'|'.join(EXTS)} <semgrep-rules-dir> [-v]", file=sys.stderr)
        sys.exit(2)
    main(sys.argv[1], sys.argv[2], "-v" in sys.argv)
