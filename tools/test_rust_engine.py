# -*- coding: utf-8 -*-
"""Regression tests for the Rust engine: (name, code, expected ids). Run: python tools/test_rust_engine.py"""
import os, sys
sys.path.insert(0, os.path.join(os.path.dirname(os.path.abspath(__file__)), ".."))
import rust_engine as R

H = "use std::process::Command;\nuse actix_web::{get, web, HttpResponse};\nuse serde::Deserialize;\n#[derive(Deserialize)] struct P { id: u32, name: String }\n"
def handler(body, params="q: web::Query<P>, path: web::Path<String>"):
    return H + "#[get(\"/a\")]\nasync fn a(" + params + ") -> HttpResponse {\n" + body + "\n    HttpResponse::Ok().finish()\n}\n"
CASES = [
 # ---- MUST be reported ----
 ("cmd sh -c", handler('Command::new("sh").arg("-c").arg(format!("ls {}", path)).output();'), {"AST-RS-001"}),
 ("cmd arg diretto", handler('Command::new("grep").arg(&q.name).output();'), {"AST-RS-001"}),
 ("cmd programma", handler("Command::new(path.as_str()).output();"), {"AST-RS-001"}),
 ("sql format!", handler('let s = format!("SELECT * FROM t WHERE n = \'{}\'", q.name); sqlx::query(&s).execute(&pool).await;'), {"AST-RS-002"}),
 ("sql inline {nome}", handler('let n = &q.name; let s = format!("SELECT * FROM t WHERE n = \'{n}\'"); conn.execute(&s);'), {"AST-RS-002"}),
 ("path traversal", handler('std::fs::read_to_string(format!("/data/{}", q.name));'), {"AST-RS-003"}),
 ("ssrf reqwest", handler("reqwest::blocking::get(&q.name);"), {"AST-RS-004"}),
 ("redirect", handler("let _ = Redirect::to(&q.name);"), {"AST-RS-005"}),
 ("xss Html", handler('let _ = Html(format!("<p>{}</p>", q.name));'), {"AST-RS-006"}),
 ("regex injection", handler("let _ = regex::Regex::new(&q.name);"), {"AST-RS-007"}),
 ("alloc size", handler("let n = q.id as usize; let _v: Vec<u8> = Vec::with_capacity(n);"), {"AST-RS-009"}),
 ("across functions", H + "fn run(c: &str) { Command::new(c).output(); }\n#[get(\"/a\")]\nasync fn a(path: web::Path<String>) { run(&path); }\n", {"AST-RS-001"}),
 ("args -> function", "use std::process::Command;\nfn run(c: &str) { Command::new(c).arg(\"x\").output(); }\nfn main() { let a: Vec<String> = std::env::args().collect(); run(&a[1]); }\n", {"AST-RS-001"}),
 ("TLS disabled", "fn f() { let _c = reqwest::Client::builder().danger_accept_invalid_certs(true).build(); }\n", {"AST-RS-016"}),
 ("weak cipher", "fn f(k: &[u8]) { let _c = rc4::Rc4::new_from_slice(k); }\n", {"AST-RS-018"}),
 ("fixed key", "use aes_gcm::{Aes256Gcm, Key, KeyInit};\nfn f() { let k = [0u8; 32]; let _c = Aes256Gcm::new(Key::<Aes256Gcm>::from_slice(&k)); }\n", {"AST-RS-019"}),
 ("cookie without secure", "fn f() { let _c = Cookie::build((\"a\", \"b\")).path(\"/\").build(); }\n", {"AST-RS-020"}),
 ("passwords in logs", "fn f() { let password = get_pw(); println!(\"login {}\", password); }\n", {"AST-RS-012"}),
 ("password hash", "use sha2::{Sha256, Digest};\nfn f() { let password = get_pw(); let _h = Sha256::digest(password.as_bytes()); }\n", {"AST-RS-014"}),
 # ---- MUST NOT be reported ----
 ("constant command", 'use std::process::Command;\nfn main() { Command::new("ls").arg("-la").output(); }\n', set()),
 ("sql parameterized", handler('sqlx::query("SELECT * FROM t WHERE n = $1").bind(&q.name).execute(&pool).await;'), set()),
 ("sql query! macro", handler('sqlx::query!("SELECT * FROM t WHERE id = ?", q.id).fetch_one(&pool).await;'), set()),
 ("numeric id in sql", handler('let s = format!("SELECT * FROM t WHERE id = {}", q.id); sqlx::query(&s).execute(&pool).await;'), set()),
 ("numeric extractor", handler('std::fs::read_to_string(format!("/data/{}", id));', params="id: web::Path<u32>"), set()),
 ("std &Path is not an extractor", "use std::path::Path;\nfn sink(p1: &Path) { let _ = std::fs::read_to_string(p1); }\n", set()),
 ("parse::<u32>", "fn main() { let a: Vec<String> = std::env::args().collect(); let n = a[1].parse::<u32>().unwrap(); let s = format!(\"SELECT {}\", n); db.execute(&s); }\n", set()),
 ("contains(\"..\") + return", handler('if q.name.contains("..") || q.name.contains("/") { return HttpResponse::BadRequest().finish(); }\n    std::fs::read_to_string(format!("/data/{}", q.name));'), set()),
 ("allowlist", handler('let ok = ["a", "b"]; if !ok.contains(&path.as_str()) { return HttpResponse::BadRequest().finish(); }\n    Command::new(path.as_str()).output();'), set()),
 ("fixed host", handler('reqwest::blocking::get(format!("https://api.example.com/v1/{}", q.name));'), set()),
 ("cookie secure(true)", "fn f() { let _c = Cookie::build((\"a\", \"b\")).secure(true).build(); }\n", set()),
 ("random key", "fn f() { let mut k = [0u8; 32]; getrandom::fill(&mut k).unwrap(); let _c = Aes256Gcm::new(Key::<Aes256Gcm>::from_slice(&k)); }\n", set()),
 ("expect message is not a key", "fn f() { let s = std::env::var(\"X\").expect(\"X must be set\"); let _c = Aes256Gcm::new(Key::<Aes256Gcm>::from_slice(s.as_bytes())); }\n", set()),
 ("local http URL", "fn f() { let _ = reqwest::blocking::get(\"http://localhost:8080/x\"); }\n", set()),
]
PROJECT_CASES = [
 ("project: use crate::", {
    "src/util.rs": "use std::process::Command;\npub fn run(c: &str) { Command::new(\"sh\").arg(\"-c\").arg(c).output().unwrap(); }\n",
    "src/main.rs": "mod util;\nuse crate::util::run;\nfn main() { let a: Vec<String> = std::env::args().collect(); run(&a[1]); }\n"}, {("src/util.rs", "AST-RS-001")}),
 ("project: call with a constant", {
    "src/util.rs": "use std::process::Command;\npub fn run(c: &str) { Command::new(\"sh\").arg(\"-c\").arg(c).output().unwrap(); }\n",
    "src/main.rs": "mod util;\nuse crate::util::run;\nfn main() { run(\"ls\"); }\n"}, set()),
 ("project: typed struct in another file", {
    "src/model.rs": "pub struct Params { pub id: u32, pub name: String }\n",
    "src/web.rs": "use crate::model::Params;\n#[get(\"/a\")]\nasync fn a(q: web::Query<Params>) { let s = format!(\"SELECT {}\", q.name); db.execute(&s); let t = format!(\"SELECT {}\", q.id); db.execute(&t); }\n"},
  {("src/web.rs", "AST-RS-002")}),
]

def main():
    if not R.AVAILABLE:
        print("WARNING: tree-sitter-rust is not installed, so no tests were run. Install it with: pip install tree-sitter tree-sitter-rust"); return 0
    bad = 0
    for name, code, exp in CASES:
        got = {f["id"] for f in R.analyze_rust_source("src/main.rs", code) if f["confidence"] in ("confirmed",)}
        ok = got == exp; bad += not ok
        print(("OK   " if ok else "FAIL ") + name + ("" if ok else f"   expected={sorted(exp)} got={sorted(got)}"))
    for name, files, exp in PROJECT_CASES:
        res = R.analyze_rust_project(files)
        got = {(r, f["id"]) for r, fs in res.items() for f in fs if f["confidence"] == "confirmed"}
        ok = got == exp; bad += not ok
        print(("OK   " if ok else "FAIL ") + name + ("" if ok else f"   expected={sorted(exp)} got={sorted(got)}"))
    total = len(CASES) + len(PROJECT_CASES)
    print(f"\n{total - bad}/{total} tests passed")
    return 1 if bad else 0

if __name__ == "__main__":
    sys.exit(main())
