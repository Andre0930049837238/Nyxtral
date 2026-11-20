# -*- coding: utf-8 -*-
"""Regression tests for the Go engine: (name, code, expected ids among the CONFIRMED findings). Run: python tools/test_go_engine.py"""
import os, sys
sys.path.insert(0, os.path.join(os.path.dirname(os.path.abspath(__file__)), ".."))
import go_engine as G

H = 'package main\nimport ("net/http"; "os"; "os/exec"; "fmt"; "database/sql"; "strconv"; "path/filepath"; "html/template")\n'
def h(body): return H + "func h(w http.ResponseWriter, r *http.Request) {\n" + body + "\n}\n"
CASES = [
 # ---- MUST be reported ----
 ("cmd concat", h('id := r.URL.Query().Get("id")\n exec.Command("sh", "-c", "ls "+id).Run()'), {"AST-GO-001"}),
 ("cmd FormValue", h('exec.Command(r.FormValue("c")).Run()'), {"AST-GO-001"}),
 ("sql Sprintf", h('id := r.FormValue("id")\n db.Query(fmt.Sprintf("SELECT * FROM t WHERE id = %s", id))'), {"AST-GO-002"}),
 ("sql concat", h('db.Exec("DELETE FROM t WHERE n = \'" + r.FormValue("n") + "\'")'), {"AST-GO-002"}),
 ("sql QueryContext", h('db.QueryContext(r.Context(), "SELECT * FROM t WHERE n = " + r.FormValue("n"))'), {"AST-GO-002"}),
 ("path traversal", h('os.Open("/data/" + r.FormValue("f"))'), {"AST-GO-003"}),
 ("path ReadFile", h('os.ReadFile(filepath.Join("/srv", r.URL.Path))'), {"AST-GO-003"}),
 ("ssrf", h('http.Get(r.FormValue("url"))'), {"AST-GO-004"}),
 ("ssrf client", h('client := &http.Client{}\n client.Get(r.FormValue("u"))'), {"AST-GO-004"}),
 ("xss Fprintf", h('fmt.Fprintf(w, "<p>%s</p>", r.FormValue("n"))'), {"AST-GO-005"}),
 ("xss template.HTML", h('t := template.HTML(r.FormValue("n"))\n _ = t'), {"AST-GO-005"}),
 ("xss Write", h('w.Write([]byte(r.FormValue("n")))'), {"AST-GO-005"}),
 ("redirect", h('http.Redirect(w, r, r.FormValue("next"), 302)'), {"AST-GO-006"}),
 ("md5", h("md5.New()"), {"AST-GO-007"}),
 ("sha1 Sum", 'package main\nimport "crypto/sha1"\nfunc f(b []byte) { sha1.Sum(b) }\n', {"AST-GO-007"}),
 ("short rsa", 'package main\nimport ("crypto/rsa"; "crypto/rand")\nfunc f() { rsa.GenerateKey(rand.Reader, 1024) }\n', {"AST-GO-007"}),
 ("InsecureSkipVerify", 'package main\nimport "crypto/tls"\nfunc f() { _ = &tls.Config{InsecureSkipVerify: true} }\n', {"AST-GO-008"}),
 ("package-level InsecureSkipVerify", 'package main\nimport "crypto/tls"\nvar cfg = &tls.Config{InsecureSkipVerify: true}\n', {"AST-GO-008"}),
 ("MinVersion TLS10", 'package main\nimport "crypto/tls"\nvar cfg = &tls.Config{MinVersion: tls.VersionTLS10}\n', {"AST-GO-008"}),
 ("ssh without host key", 'package main\nimport "golang.org/x/crypto/ssh"\nfunc f() { _ = ssh.InsecureIgnoreHostKey() }\n', {"AST-GO-008"}),
 ("math/rand for token", 'package main\nimport "math/rand"\nfunc f() { token := rand.Int63()\n _ = token }\n', {"AST-GO-009"}),
 ("chmod 777", 'package main\nimport "os"\nfunc f() { os.Chmod("/tmp/x", 0777) }\n', {"AST-GO-010", "AST-GO-014"}) if False else
 ("chmod 777", 'package main\nimport "os"\nfunc f() { os.Chmod("/etc/x", 0777) }\n', {"AST-GO-010"}),
 ("WriteFile 666", 'package main\nimport "os"\nfunc f() { os.WriteFile("/etc/x", nil, 0666) }\n', {"AST-GO-010"}),
 ("unsafe", 'package main\nimport "unsafe"\nfunc f(p *int) { _ = unsafe.Pointer(p) }\n', {"AST-GO-011"}),
 ("cookie without flags", h('http.SetCookie(w, &http.Cookie{Name: "s", Value: "x"})'), {"AST-GO-012"}),
 ("ListenAndServe", 'package main\nimport "net/http"\nfunc main() { http.ListenAndServe(":8080", nil) }\n', {"AST-GO-013", "AST-GO-018", "AST-GO-019"}),
 ("predictable tmp", 'package main\nimport "os"\nfunc f() { os.Create("/tmp/out.txt") }\n', {"AST-GO-014"}),
 ("decompression bomb", 'package main\nimport ("compress/gzip"; "io"; "os")\nfunc f(r io.Reader) { z, _ := gzip.NewReader(r)\n io.Copy(os.Stdout, z) }\n', {"AST-GO-015"}),
 ("across functions", H + "func run(c string) { exec.Command(\"sh\", \"-c\", c).Run() }\nfunc h(w http.ResponseWriter, r *http.Request) { run(r.FormValue(\"c\")) }\n", {"AST-GO-001"}),
 ("anonymous handler", 'package main\nimport ("net/http"; "os/exec")\nfunc main() { http.HandleFunc("/", func(w http.ResponseWriter, r *http.Request) { exec.Command(r.FormValue("c")).Run() }) }\n', {"AST-GO-001", "AST-GO-013", "AST-GO-019"}) if False else
 ("anonymous handler", 'package main\nimport ("net/http"; "os/exec")\nfunc init() { http.HandleFunc("/", func(w http.ResponseWriter, r *http.Request) { exec.Command(r.FormValue("c")).Run() }) }\n', {"AST-GO-001"}),
 ("gin Context", 'package main\nimport ("github.com/gin-gonic/gin"; "os/exec")\nfunc h(c *gin.Context) { exec.Command(c.Query("c")).Run() }\n', {"AST-GO-001"}),
 ("SQL Builder", h('var sb strings.Builder\n sb.WriteString("SELECT * FROM t WHERE n = ")\n sb.WriteString(r.FormValue("n"))\n db.Query(sb.String())'), {"AST-GO-002"}),
 ("Unmarshal body", h('var req struct{ Cmd string }\n json.NewDecoder(r.Body).Decode(&req)\n exec.Command(req.Cmd).Run()'), {"AST-GO-001"}),
 # ---- MUST NOT be reported (as CONFIRMED) ----
 ("constant cmd", 'package main\nimport "os/exec"\nfunc f() { exec.Command("ls", "-la").Run() }\n', set()),
 ("sql parameterized", h('db.Query("SELECT * FROM t WHERE id = $1", r.FormValue("id"))'), set()),
 ("sql with number", h('n, _ := strconv.Atoi(r.FormValue("id"))\n db.Query(fmt.Sprintf("SELECT * FROM t WHERE id = %d", n))'), set()),
 ("path with Base", h('os.Open(filepath.Join("/data", filepath.Base(r.FormValue("f"))))'), set()),
 ("path with HasPrefix check", h('p := filepath.Join("/data", r.FormValue("f"))\n if !strings.HasPrefix(p, "/data/") { return }\n os.Open(p)'), set()),
 ("ssrf fixed host", h('http.Get(fmt.Sprintf("https://api.example.com/v1/%s", r.FormValue("id")))'), set()),
 ("xss with EscapeString", h('fmt.Fprintf(w, "<p>%s</p>", html.EscapeString(r.FormValue("n")))'), set()),
 ("xss json", h('w.Header().Set("Content-Type", "application/json")\n w.Write([]byte(r.FormValue("n")))'), set()),
 ("constant redirect", h('http.Redirect(w, r, "/home", 302)'), set()),
 ("sha256", 'package main\nimport "crypto/sha256"\nfunc f(b []byte) { sha256.Sum256(b) }\n', set()),
 ("math/rand non-sensitive", 'package main\nimport "math/rand"\nfunc f() { dice := rand.Intn(6)\n _ = dice }\n', set()),
 ("chmod 600", 'package main\nimport "os"\nfunc f() { os.Chmod("/etc/x", 0600) }\n', set()),
 ("cookie with flags", h('http.SetCookie(w, &http.Cookie{Name: "s", Value: "x", Secure: true, HttpOnly: true})'), set()),
 ("CLI: path from the command line", 'package main\nimport "os"\nfunc main() { os.Open(os.Args[1]) }\n', set()),
 ("allowlist", h('c := r.FormValue("c")\n if c != "a" && c != "b" { return }\n exec.Command(c).Run()'), set()),
 ("function never called with tainted data", 'package main\nimport "os/exec"\nfunc run(c string) { exec.Command("sh", "-c", c).Run() }\nfunc main() { run("ls") }\n', set()),
 ("Itoa", h('exec.Command("echo", strconv.Itoa(len(r.FormValue("x")))).Run()'), set()),
]
PROJECT_CASES = [
 ("project: function in another file", {
    "util/sh.go": 'package util\nimport "os/exec"\nfunc Run(c string) { exec.Command("sh", "-c", c).Run() }\n',
    "main.go": 'package main\nimport "net/http"\nfunc h(w http.ResponseWriter, r *http.Request) { Run(r.FormValue("c")) }\n'}, {("util/sh.go", "AST-GO-001")}),
 ("project: call with a constant", {
    "util/sh.go": 'package util\nimport "os/exec"\nfunc Run(c string) { exec.Command("sh", "-c", c).Run() }\n',
    "main.go": 'package main\nfunc main() { Run("ls") }\n'}, set()),
]

def main():
    if not G.AVAILABLE:
        print("WARNING: tree-sitter-go is not installed, so no tests were run. Install it with: pip install tree-sitter tree-sitter-go"); return 0
    bad = 0
    for name, code, exp in CASES:
        got = {f["id"] for f in G.analyze_go_source("app/main.go", code) if f["confidence"] == "confirmed"}
        ok = got == exp; bad += not ok
        print(("OK   " if ok else "FAIL ") + name + ("" if ok else f"   expected={sorted(exp)} got={sorted(got)}"))
    for name, files, exp in PROJECT_CASES:
        res = G.analyze_go_project(files)
        got = {(r, f["id"]) for r, fs in res.items() for f in fs if f["confidence"] == "confirmed"}
        ok = got == exp; bad += not ok
        print(("OK   " if ok else "FAIL ") + name + ("" if ok else f"   expected={sorted(exp)} got={sorted(got)}"))
    total = len(CASES) + len(PROJECT_CASES)
    print(f"\n{total - bad}/{total} tests passed")
    return 1 if bad else 0

if __name__ == "__main__":
    sys.exit(main())
