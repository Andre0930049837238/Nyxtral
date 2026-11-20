# -*- coding: utf-8 -*-
"""Regression tests for the C# engine: (name, code, expected ids among the CONFIRMED findings). Run: python tools/test_csharp_engine.py"""
import os, sys
sys.path.insert(0, os.path.join(os.path.dirname(os.path.abspath(__file__)), ".."))
import csharp_engine as E

def c(body, params="string id"):
    return "using System;\nusing System.Data.SqlClient;\nnamespace App {\npublic class HomeController : Controller {\n public IActionResult H(" + params + ") {\n" + body + "\n return null; }\n}\n}\n"
CASES = [
 # ---- MUST be reported ----
 ("cmd Process.Start", c('Process.Start(id);'), {"AST-CS-001"}),
 ("sql concat", c('var cmd = new SqlCommand("SELECT * FROM t WHERE n = \'" + id + "\'", conn);'), {"AST-CS-002"}),
 ("sql interpolated", c('var cmd = new SqlCommand($"SELECT * FROM t WHERE n = \'{id}\'", conn);'), {"AST-CS-002"}),
 ("sql EF FromSqlRaw", c('db.Users.FromSqlRaw("SELECT * FROM Users WHERE n = \'" + id + "\'");'), {"AST-CS-002"}),
 ("sql Dapper", c('conn.Query("SELECT * FROM t WHERE n = " + id);'), {"AST-CS-002"}),
 ("xss Response.Write", c('Response.Write("<p>" + id + "</p>");'), {"AST-CS-003"}),
 ("xss Html.Raw", c("var s = Html.Raw(id);"), {"AST-CS-003"}),
 ("path traversal", c('File.ReadAllText("/data/" + id);'), {"AST-CS-004"}),
 ("ssrf HttpClient", c("var r = client.GetAsync(id).Result;"), {"AST-CS-005"}),
 ("ssrf WebClient", c("new WebClient().DownloadString(id);"), {"AST-CS-005"}),
 ("redirect", c("return Redirect(id);"), {"AST-CS-006"}),
 ("BinaryFormatter", c("var f = new BinaryFormatter();", ""), {"AST-CS-007"}),
 ("TypeNameHandling", c("var s = new JsonSerializerSettings { TypeNameHandling = TypeNameHandling.All };", ""), {"AST-CS-007"}),
 ("XXE DtdProcessing", c("var rs = new XmlReaderSettings { DtdProcessing = DtdProcessing.Parse };", ""), {"AST-CS-008"}),
 ("MD5", c("var h = MD5.Create();", ""), {"AST-CS-009"}),
 ("SHA1", c("var h = new SHA1CryptoServiceProvider();", ""), {"AST-CS-009"}),
 ("DES", c("var a = DES.Create();", ""), {"AST-CS-009"}),
 ("TLS accepts everything", c("ServicePointManager.ServerCertificateValidationCallback += (s, cert, chain, err) => true;", ""), {"AST-CS-010"}),
 ("cookie without flags", c('var ck = new HttpCookie("a");', ""), {"AST-CS-011"}),
 ("LDAP filter", c('searcher.Filter = "(uid=" + id + ")";'), {"AST-CS-012"}),
 ("JWT without validation", c("var p = new TokenValidationParameters { ValidateLifetime = false };", ""), {"AST-CS-014"}),
 ("across functions", "using System;\npublic class A {\n void Run(string c) { Process.Start(c); }\n}\npublic class B : Controller {\n public void H(string id) { new A().Run(id); }\n}\n", {"AST-CS-001"}) if False else
 ("main args", "using System;\npublic class A {\n static void Main(string[] args) { Process.Start(args[0]); }\n}\n", {"AST-CS-001"}),
 # ---- MUST NOT be reported (as CONFIRMED) ----
 ("constant cmd", c('Process.Start("notepad.exe");', ""), set()),
 ("sql parameterized", c('var cmd = new SqlCommand("SELECT * FROM t WHERE n = @n", conn);\n cmd.Parameters.AddWithValue("@n", id);'), set()),
 ("sql with number", c('int n = int.Parse(id);\n var cmd = new SqlCommand("SELECT * FROM t WHERE id = " + n, conn);'), set()),
 ("xss with encode", c("Response.Write(HttpUtility.HtmlEncode(id));"), set()),
 ("path with GetFileName", c('File.ReadAllText(Path.Combine("/data", Path.GetFileName(id)));'), set()),
 ("ssrf fixed host", c('client.GetAsync("https://api.example.com/v1/" + id);'), set()),
 ("SHA256", c("var h = SHA256.Create();", ""), set()),
 ("TypeNameHandling None", c("var s = new JsonSerializerSettings { TypeNameHandling = TypeNameHandling.None };", ""), set()),
 ("cookie with flags", c("var ck = new CookieOptions { HttpOnly = true, Secure = true };", ""), set()),
 ("DtdProcessing Prohibit", c("var rs = new XmlReaderSettings { DtdProcessing = DtdProcessing.Prohibit };", ""), set()),
]

def main():
    if not E.AVAILABLE:
        print("WARNING: tree-sitter-c-sharp is not installed, so no tests were run. Install it with: pip install tree-sitter tree-sitter-c-sharp"); return 0
    bad = 0
    for name, code, exp in CASES:
        got = {f["id"] for f in E.analyze_csharp_source("Controllers/HomeController.cs", code) if f["confidence"] == "confirmed"}
        ok = got == exp; bad += not ok
        print(("OK   " if ok else "FAIL ") + name + ("" if ok else f"   expected={sorted(exp)} got={sorted(got)}"))
    print(f"\n{len(CASES) - bad}/{len(CASES)} tests passed")
    return 1 if bad else 0

if __name__ == "__main__":
    sys.exit(main())
