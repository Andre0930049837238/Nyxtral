# -*- coding: utf-8 -*-
"""Regression tests for the Java engine: (name, code, expected ids among the CONFIRMED findings). Run: python tools/test_java_engine.py"""
import os, sys
sys.path.insert(0, os.path.join(os.path.dirname(os.path.abspath(__file__)), ".."))
import java_engine as J

def h(body, params="HttpServletRequest req, HttpServletResponse resp"):
    return "import java.io.*;\nimport java.sql.*;\nimport javax.servlet.http.*;\npublic class A {\n void h(" + params + ") throws Exception {\n" + body + "\n }\n}\n"
CASES = [
 # ---- MUST be reported ----
 ("cmd exec", h('Runtime.getRuntime().exec(req.getParameter("c"));'), {"AST-JAVA-001"}),
 ("cmd ProcessBuilder", h('new ProcessBuilder("sh", "-c", req.getParameter("c")).start();'), {"AST-JAVA-001"}),
 ("sql concat", h('Statement s = conn.createStatement();\n s.executeQuery("SELECT * FROM t WHERE n = \'" + req.getParameter("n") + "\'");'), {"AST-JAVA-002"}),
 ("sql variable", h('String q = "DELETE FROM t WHERE id = " + req.getParameter("id");\n stmt.executeUpdate(q);'), {"AST-JAVA-002"}),
 ("sql format", h('stmt.execute(String.format("SELECT * FROM t WHERE n = \'%s\'", req.getParameter("n")));'), {"AST-JAVA-002"}),
 ("sql @RequestParam", "public class A {\n void h(@RequestParam String n) {\n jdbcTemplate.queryForList(\"SELECT * FROM t WHERE n = '\" + n + \"'\");\n }\n}\n", {"AST-JAVA-002"}),
 ("xss writer", h('resp.getWriter().println("<p>" + req.getParameter("n") + "</p>");'), {"AST-JAVA-003"}),
 ("xss writer in variable", h('PrintWriter out = resp.getWriter();\n out.println(req.getParameter("n"));'), {"AST-JAVA-003"}),
 ("path traversal", h('new FileInputStream("/data/" + req.getParameter("f"));'), {"AST-JAVA-004"}),
 ("ssrf URL", h('new URL(req.getParameter("u")).openConnection();'), {"AST-JAVA-005"}),
 ("redirect", h('resp.sendRedirect(req.getParameter("next"));'), {"AST-JAVA-006"}),
 ("ObjectInputStream", h("new ObjectInputStream(req.getInputStream()).readObject();"), {"AST-JAVA-007"}),
 ("md5", h('MessageDigest.getInstance("MD5");', ""), {"AST-JAVA-009"}),
 ("DES", h('Cipher.getInstance("DES");', ""), {"AST-JAVA-009"}),
 ("AES ECB", h('Cipher.getInstance("AES/ECB/PKCS5Padding");', ""), {"AST-JAVA-009"}),
 ("static IV", h('new IvParameterSpec("0123456789abcdef".getBytes());', ""), {"AST-JAVA-009"}),
 ("empty TrustManager", "public class T implements X509TrustManager {\n public void checkServerTrusted(X509Certificate[] c, String a) {}\n}\n", {"AST-JAVA-010"}),
 ("HostnameVerifier true", h("conn.setHostnameVerifier((host, session) -> true);", ""), {"AST-JAVA-010"}),
 ("cookie without flags", h('Cookie c = new Cookie("a", "b");\n resp.addCookie(c);'), {"AST-JAVA-011"}),
 ("SpEL", h("new SpelExpressionParser().parseExpression(req.getParameter(\"e\"));"), {"AST-JAVA-012"}),
 ("script engine", h('engine.eval(req.getParameter("s"));'), {"AST-JAVA-012"}),
 ("LDAP", h('ctx.search("ou=users", "(uid=" + req.getParameter("u") + ")", null);'), {"AST-JAVA-013"}),
 ("csrf disabled", "public class C {\n void c(HttpSecurity http) throws Exception { http.csrf().disable(); }\n}\n", {"AST-JAVA-014"}),
 ("Random for token", h("String token = Long.toString(new Random().nextLong());", ""), {"AST-JAVA-015"}),
 ("hardcoded password", h('DriverManager.getConnection("jdbc:x", "u", "hunter2");', ""), {"AST-JAVA-017"}),
 ("across functions", "public class A {\n void run(String c) throws Exception { Runtime.getRuntime().exec(c); }\n void h(HttpServletRequest req) throws Exception { run(req.getParameter(\"c\")); }\n}\n", {"AST-JAVA-001"}),
 ("main args", "public class A {\n public static void main(String[] args) throws Exception { Runtime.getRuntime().exec(args[0]); }\n}\n", {"AST-JAVA-001"}),
 # ---- MUST NOT be reported (as CONFIRMED) ----
 ("constant cmd", h('Runtime.getRuntime().exec("ls -la");', ""), set()),
 ("sql parameterized", h('PreparedStatement p = conn.prepareStatement("SELECT * FROM t WHERE n = ?");\n p.setString(1, req.getParameter("n"));'), set()),
 ("sql with number", h('int id = Integer.parseInt(req.getParameter("id"));\n stmt.executeQuery("SELECT * FROM t WHERE id = " + id);'), set()),
 ("xss with escape", h('resp.getWriter().println(StringEscapeUtils.escapeHtml4(req.getParameter("n")));'), set()),
 ("constant path", h('new File("/etc/app.conf");', ""), set()),
 ("ssrf fixed host", h('new URL("https://api.example.com/v1/" + req.getParameter("id")).openConnection();'), set()),
 ("sha256", h('MessageDigest.getInstance("SHA-256");', ""), set()),
 ("AES GCM", h('Cipher.getInstance("AES/GCM/NoPadding");', ""), set()),
 ("cookie with flags", h('Cookie c = new Cookie("a", "b");\n c.setHttpOnly(true);\n c.setSecure(true);\n resp.addCookie(c);'), set()),
 ("SecureRandom", h("String token = Long.toString(new SecureRandom().nextLong());", ""), set()),
 ("function never called with tainted data", "public class A {\n void run(String c) throws Exception { Runtime.getRuntime().exec(c); }\n void main2() throws Exception { run(\"ls\"); }\n}\n", set()),
]

def main():
    if not J.AVAILABLE:
        print("WARNING: tree-sitter-java is not installed, so no tests were run. Install it with: pip install tree-sitter tree-sitter-java"); return 0
    bad = 0
    for name, code, exp in CASES:
        got = {f["id"] for f in J.analyze_java_source("src/main/A.java", code) if f["confidence"] == "confirmed"}
        ok = got == exp; bad += not ok
        print(("OK   " if ok else "FAIL ") + name + ("" if ok else f"   expected={sorted(exp)} got={sorted(got)}"))
    print(f"\n{len(CASES) - bad}/{len(CASES)} tests passed")
    return 1 if bad else 0

if __name__ == "__main__":
    sys.exit(main())
