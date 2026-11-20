# -*- coding: utf-8 -*-
"""Regression tests for the PHP engine: (name, code, expected ids among the CONFIRMED findings). Run: python tools/test_php_engine.py"""
import os, sys
sys.path.insert(0, os.path.join(os.path.dirname(os.path.abspath(__file__)), ".."))
import php_engine as P

def f(body, params=""):
    return "<?php\nfunction h(" + params + ") {\n" + body + "\n}\n"
CASES = [
 # ---- MUST be reported ----
 ("cmd system", f('system($_GET["c"]);'), {"AST-PHP-001"}),
 ("cmd backtick", f('$o = `ls ${_GET["d"]}`;') if False else f('$d = $_GET["d"];\n $o = `ls $d`;'), {"AST-PHP-001"}),
 ("eval", f('eval($_POST["code"]);'), {"AST-PHP-002"}),
 ("sql concat", f('mysqli_query($c, "SELECT * FROM t WHERE n = \'" . $_GET["n"] . "\'");'), {"AST-PHP-003"}),
 ("sql interpolated", f('$n = $_GET["n"];\n $db->query("SELECT * FROM t WHERE n = \'$n\'");'), {"AST-PHP-003"}),
 ("sql wpdb", f('$wpdb->query("DELETE FROM t WHERE id = " . $_GET["id"]);'), {"AST-PHP-003"}),
 ("sql Laravel raw", f('DB::select("select * from users where id = " . $request->input("id"));', "Request $request"), {"AST-PHP-003"}),
 ("include", f('include $_GET["page"];'), {"AST-PHP-004"}),
 ("file_get_contents path", f('echo file_get_contents("/data/" . $_GET["f"]);'), {"AST-PHP-004", "AST-PHP-005", "AST-PHP-006"}),
 ("xss echo", f('echo "<p>" . $_GET["n"] . "</p>";'), {"AST-PHP-005"}),
 ("xss print", f('print $_GET["n"];'), {"AST-PHP-005"}),
 ("ssrf curl_init", f('$ch = curl_init($_GET["u"]);'), {"AST-PHP-006"}),
 ("redirect header", f('header("Location: " . $_GET["next"]);'), {"AST-PHP-007"}),
 ("unserialize", f('unserialize($_COOKIE["d"]);'), {"AST-PHP-008"}),
 ("XXE LIBXML_NOENT", f('simplexml_load_string($x, "SimpleXMLElement", LIBXML_NOENT);'), {"AST-PHP-008"}),
 ("md5", f('$h = md5($p);'), {"AST-PHP-009"}),
 ("sha1", f('$h = sha1($p);'), {"AST-PHP-009"}),
 ("md5 hash", f('$h = hash("md5", $p);'), {"AST-PHP-009"}),
 ("TLS curl", f('curl_setopt($ch, CURLOPT_SSL_VERIFYPEER, false);'), {"AST-PHP-010"}),
 ("rand for token", f('$token = rand();'), {"AST-PHP-011"}),
 ("CORS", f('header("Access-Control-Allow-Origin: *");'), {"AST-PHP-012"}),
 ("phpinfo", f('phpinfo();'), {"AST-PHP-013"}),
 ("extract", f('extract($_POST);'), {"AST-PHP-014"}),
 ("md5 loose", f('if (md5($a) == md5($b)) { return 1; }'), {"AST-PHP-009", "AST-PHP-015"}),
 ("anonymous ldap", f('ldap_bind($conn);'), {"AST-PHP-017"}),
 ("across functions", "<?php\nfunction run($c) { system($c); }\nfunction h() { run($_GET['c']); }\n", {"AST-PHP-001"}),
 # ---- MUST NOT be reported (as CONFIRMED) ----
 ("constant cmd", f('system("ls -la");'), set()),
 ("cmd with escapeshellarg", f('system("ls " . escapeshellarg($_GET["d"]));'), set()),
 ("sql with intval", f('mysqli_query($c, "SELECT * FROM t WHERE id = " . intval($_GET["id"]));'), set()),
 ("sql prepared", f('$stmt = $pdo->prepare("SELECT * FROM t WHERE n = ?");\n $stmt->execute([$_GET["n"]]);'), set()),
 ("xss with htmlspecialchars", f('echo htmlspecialchars($_GET["n"], ENT_QUOTES);'), set()),
 ("constant include", f('include "header.php";'), set()),
 ("constant redirect", f('header("Location: /home");'), set()),
 ("password_hash", f('$h = password_hash($p, PASSWORD_DEFAULT);'), set()),
 ("sha256 hash", f('$h = hash("sha256", $p);'), set()),
 ("TLS curl correct", f('curl_setopt($ch, CURLOPT_SSL_VERIFYPEER, true);'), set()),
 ("random_int", f('$token = random_int(0, 99999);'), set()),
 ("constant echo", f('echo "hello";'), set()),
]

def main():
    if not P.AVAILABLE:
        print("WARNING: tree-sitter-php is not installed, so no tests were run. Install it with: pip install tree-sitter tree-sitter-php"); return 0
    bad = 0
    for name, code, exp in CASES:
        got = {x["id"] for x in P.analyze_php_source("web/index.php", code) if x["confidence"] == "confirmed"}
        ok = got == exp; bad += not ok
        print(("OK   " if ok else "FAIL ") + name + ("" if ok else f"   expected={sorted(exp)} got={sorted(got)}"))
    print(f"\n{len(CASES) - bad}/{len(CASES)} tests passed")
    return 1 if bad else 0

if __name__ == "__main__":
    sys.exit(main())
