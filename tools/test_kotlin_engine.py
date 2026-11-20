# -*- coding: utf-8 -*-
"""Regression tests for the Kotlin engine: (name, code, expected ids among the CONFIRMED findings). Run: python tools/test_kotlin_engine.py"""
import os, sys
sys.path.insert(0, os.path.join(os.path.dirname(os.path.abspath(__file__)), ".."))
import kotlin_engine as K

H = "package app\nimport java.io.File\nimport java.net.URL\nimport java.security.MessageDigest\n"
def h(body, params="req: HttpServletRequest"): return H + "fun h(" + params + ") {\n" + body + "\n}\n"
CASES = [
 # ---- MUST be reported ----
 ("cmd exec", h('Runtime.getRuntime().exec(req.getParameter("c"))'), {"AST-KT-001"}),
 ("cmd ProcessBuilder", h('ProcessBuilder("sh", "-c", req.getParameter("c")).start()'), {"AST-KT-001"}),
 ("cmd from @RequestParam", h('Runtime.getRuntime().exec("ls " + c)', "@RequestParam c: String"), {"AST-KT-001"}),
 ("cmd template", h('Runtime.getRuntime().exec("ls $c")', "@RequestParam c: String"), {"AST-KT-001"}),
 ("sql rawQuery template", h('val id = req.getParameter("id")\n db.rawQuery("SELECT * FROM t WHERE id = $id", null)'), {"AST-KT-002"}),
 ("sql executeQuery concat", h('stmt.executeQuery("SELECT * FROM t WHERE n = \'" + req.getParameter("n") + "\'")'), {"AST-KT-002"}),
 ("sql from variable", h('val q = "DELETE FROM t WHERE id = " + req.getParameter("id")\n db.execSQL(q)'), {"AST-KT-002"}),
 ("webview loadUrl", h('webView.loadUrl(req.getParameter("u"))'), {"AST-KT-003"}),
 ("webview JS", h("webView.settings.setJavaScriptEnabled(true)"), {"AST-KT-004"}),
 ("md5", h('MessageDigest.getInstance("MD5")'), {"AST-KT-005"}),
 ("sha1", h('MessageDigest.getInstance("SHA-1")'), {"AST-KT-005"}),
 ("cipher ECB", h('Cipher.getInstance("AES/ECB/PKCS5Padding")'), {"AST-KT-005"}),
 ("cipher DES", h('Cipher.getInstance("DES")'), {"AST-KT-005"}),
 ("DigestUtils.md5Hex", h("DigestUtils.md5Hex(x)"), {"AST-KT-005"}),
 ("empty TrustManager", "package app\nclass T : X509TrustManager {\n    override fun checkServerTrusted(c: Array<X509Certificate>, a: String) {}\n}\n", {"AST-KT-006"}),
 ("HostnameVerifier true", h("conn.setHostnameVerifier { _, _ -> true }"), {"AST-KT-006"}),
 ("Random for token", h("val token = Random().nextInt()"), {"AST-KT-007"}),
 ("path traversal", h('File("/data/" + req.getParameter("f")).readText()'), {"AST-KT-008"}),
 ("ssrf URL", h('URL(req.getParameter("u")).openConnection()'), {"AST-KT-009"}),
 ("password logging", h('Log.d("TAG", "password=" + password)', "password: String"), {"AST-KT-010"}),
 ("world readable", h('openFileOutput("x", Context.MODE_WORLD_READABLE)', ""), {"AST-KT-011"}),
 ("ObjectInputStream", h("ObjectInputStream(req.getInputStream()).readObject()"), {"AST-KT-012"}),
 ("cookie without flags", h('val c = Cookie("a", "b")\n resp.addCookie(c)', "resp: HttpServletResponse"), {"AST-KT-015"}),
 ("cleartext socket", h('Socket("host", 80)', ""), {"AST-KT-014"}),
 ("across functions", H + "fun run(c: String) { Runtime.getRuntime().exec(c) }\nfun h(req: HttpServletRequest) { run(req.getParameter(\"c\")) }\n", {"AST-KT-001"}),
 ("intent -> startActivity", h("startActivity(intent.getParcelableExtra<Intent>(\"x\"))", ""), {"AST-KT-016"}),
 ("main args", H + "fun main(args: Array<String>) { Runtime.getRuntime().exec(args[0]) }\n", {"AST-KT-001"}),
 # ---- MUST NOT be reported (as CONFIRMED) ----
 ("constant cmd", h('Runtime.getRuntime().exec("ls -la")', ""), set()),
 ("sql parameterized", h('db.rawQuery("SELECT * FROM t WHERE id = ?", arrayOf(req.getParameter("id")))'), set()),
 ("sql with number", h('val n = req.getParameter("n").toInt()\n stmt.executeQuery("SELECT * FROM t WHERE id = " + n)'), set()),
 ("sha256", h('MessageDigest.getInstance("SHA-256")', ""), set()),
 ("cipher GCM", h('Cipher.getInstance("AES/GCM/NoPadding")', ""), set()),
 ("SecureRandom", h("val token = SecureRandom().nextInt()", ""), set()),
 ("non-sensitive Random", h("val dice = Random().nextInt(6)", ""), set()),
 ("constant File", h('File("/etc/app.conf").readText()', ""), set()),
 ("URL with fixed host", h('URL("https://api.example.com/v1/" + req.getParameter("id")).openConnection()'), set()),
 ("log without sensitive data", h('Log.d("TAG", "ok")', ""), set()),
 ("cookie with flags", h('val c = Cookie("a", "b")\n c.isHttpOnly = true\n c.isSecure = true\n resp.addCookie(c)', "resp: HttpServletResponse"), set()),
 ("ServerSocket ephemeral port", h("ServerSocket(0)", ""), set()),
 ("function never called with tainted data", H + "fun run(c: String) { Runtime.getRuntime().exec(c) }\nfun main() { run(\"ls\") }\n", set()),
]

def main():
    if not K.AVAILABLE:
        print("WARNING: tree-sitter-kotlin is not installed, so no tests were run. Install it with: pip install tree-sitter tree-sitter-kotlin"); return 0
    bad = 0
    for name, code, exp in CASES:
        got = {f["id"] for f in K.analyze_kotlin_source("app/Main.kt", code) if f["confidence"] == "confirmed"}
        ok = got == exp; bad += not ok
        print(("OK   " if ok else "FAIL ") + name + ("" if ok else f"   expected={sorted(exp)} got={sorted(got)}"))
    print(f"\n{len(CASES) - bad}/{len(CASES)} tests passed")
    return 1 if bad else 0

if __name__ == "__main__":
    sys.exit(main())
