# -*- coding: utf-8 -*-
"""Regression tests for the Swift engine: (name, code, expected ids among the CONFIRMED findings). Run: python tools/test_swift_engine.py"""
import os, sys
sys.path.insert(0, os.path.join(os.path.dirname(os.path.abspath(__file__)), ".."))
import swift_engine as S

def f(body, params=""): return "import Foundation\nfunc f(" + params + ") {\n" + body + "\n}\n"
CASES = [
 # ---- MUST be reported ----
 ("cmd Process argv", f('let t = Process()\n t.launchPath = "/bin/sh"\n t.arguments = ["-c", CommandLine.arguments[1]]'), {"AST-SW-001"}),
 ("cmd system", f("system(CommandLine.arguments[1])"), {"AST-SW-001"}),
 ("sql interpolated", f('let q = "SELECT * FROM t WHERE id = \\(id)"\n sqlite3_exec(db, q, nil, nil, nil)', "id: String"), set()),
 ("md5", f("CC_MD5(data, len, &digest)"), {"AST-SW-003"}),
 ("insecure sha1", f("let h = Insecure.SHA1.hash(data: d)"), {"AST-SW-003"}),
 ("DES", f("CCCrypt(op, kCCAlgorithmDES, 0, key, 8, nil, d, n, out, m, &c)"), {"AST-SW-003"}),
 ("userdefaults password", f('UserDefaults.standard.set(passphrase, forKey: "passphrase")'), {"AST-SW-005"}),
 ("userdefaults sensitive key", f('UserDefaults.standard.set(v, forKey: "apiKey")', "v: String"), {"AST-SW-005"}),
 ("keychain always", f("let a = kSecAttrAccessibleAlways"), {"AST-SW-005"}),
 ("rand", f("let r = rand()"), {"AST-SW-011"}),
 ("log token", f('print("token: \\(token)")', "token: String"), {"AST-SW-010"}),
 ("unarchiveObject", f("let o = NSKeyedUnarchiver.unarchiveObject(with: d)", "d: Data"), {"AST-SW-009"}),
 ("webview js windows", f("prefs.javaScriptCanOpenWindowsAutomatically = true"), {"AST-SW-014"}),
 ("ssl allow invalid", f("policy.allowInvalidCertificates = true"), {"AST-SW-004"}),
 ("evaluateJavaScript from text", f("webView.evaluateJavaScript(field.text!, completionHandler: nil)", "field: UITextField"), {"AST-SW-006"}),
 ("path from argv", f("let d = FileManager.default.contents(atPath: p)\n _ = d", "p: String"), set()),
 ("across functions", "import Foundation\nfunc run(_ c: String) { system(c) }\nfunc go() { run(CommandLine.arguments[1]) }\n", {"AST-SW-001"}),
 ("URL scheme -> WebView", "import Foundation\nclass A {\n func application(_ app: UIApplication, open url: URL, options: [UIApplication.OpenURLOptionsKey : Any] = [:]) -> Bool {\n webView.loadHTMLString(url.absoluteString, baseURL: nil)\n return true\n }\n}\n", {"AST-SW-006"}),
 ("UIWebView as a type", "import UIKit\nclass A { @IBOutlet var web: UIWebView! }\n", {"AST-SW-014"}),
 ("evaluatePolicy is only potential", f("ctx.evaluatePolicy(.deviceOwnerAuthentication, localizedReason: \"x\") { ok, e in }"), set()),
 # ---- MUST NOT be reported ----
 ("sql constant", f('sqlite3_exec(db, "SELECT 1", nil, nil, nil)'), set()),
 ("Int.random is secure", f("let n = Int.random(in: 0..<6)"), set()),
 ("non-sensitive arc4random_uniform", f("let n = arc4random_uniform(6)"), set()),
 ("userdefaults non-sensitive", f('UserDefaults.standard.set(name, forKey: "userName")', "name: String"), set()),
 ("sha256", f("let h = SHA256.hash(data: d)", "d: Data"), set()),
 ("log without sensitive data", f('print("avvio")'), set()),
 ("constant cmd", f('let t = Process()\n t.launchPath = "/bin/ls"\n t.arguments = ["-la"]'), set()),
]

def main():
    if not S.AVAILABLE:
        print("WARNING: tree-sitter-swift is not installed, so no tests were run. Install it with: pip install tree-sitter tree-sitter-swift"); return 0
    bad = 0
    for name, code, exp in CASES:
        got = {x["id"] for x in S.analyze_swift_source("App/Main.swift", code) if x["confidence"] == "confirmed"}
        ok = got == exp; bad += not ok
        print(("OK   " if ok else "FAIL ") + name + ("" if ok else f"   expected={sorted(exp)} got={sorted(got)}"))
    print(f"\n{len(CASES) - bad}/{len(CASES)} tests passed")
    return 1 if bad else 0

if __name__ == "__main__":
    sys.exit(main())
