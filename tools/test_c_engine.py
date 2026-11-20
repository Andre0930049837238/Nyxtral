# -*- coding: utf-8 -*-
"""Regression tests for the C/C++ engine: (name, extension, code, expected ids among the CONFIRMED findings). Run: python tools/test_c_engine.py"""
import os, sys
sys.path.insert(0, os.path.join(os.path.dirname(os.path.abspath(__file__)), ".."))
import c_engine as C

H = "#include <stdio.h>\n#include <stdlib.h>\n#include <string.h>\n#include <unistd.h>\n"
def main_(body): return H + "int main(int argc, char **argv) {\n" + body + "\n    return 0;\n}\n"
def fn(body, params="const char *in"): return H + "void f(" + params + ") {\n" + body + "\n}\n"
CPP = "#include <iostream>\n#include <string>\n#include <fstream>\n#include <cstdlib>\nusing namespace std;\n"
def cpp(body): return CPP + "int main(int argc, char **argv) {\n" + body + "\n    return 0;\n}\n"

CASES = [
 # ---- MUST be reported ----
 ("cmd argv", ".c", main_("system(argv[1]);"), {"AST-C-001"}),
 ("cmd snprintf", ".c", main_('char c[128]; snprintf(c, sizeof c, "ls %s", argv[1]); system(c);'), {"AST-C-001"}),
 ("cmd popen getenv", ".c", main_('char c[128]; sprintf(c, "cat %s", getenv("F")); popen(c, "r");'), {"AST-C-001", "AST-C-003"}),
 ("cmd execvp argv", ".c", main_("execvp(argv[1], argv + 1);"), {"AST-C-001"}),
 ("cmd from fgets stdin", ".c", main_('char b[64]; fgets(b, sizeof b, stdin); system(b);'), {"AST-C-001"}),
 ("cmd from scanf", ".c", main_('char b[64]; scanf("%63s", b); system(b);'), {"AST-C-001"}),
 ("cmd from recv", ".c", fn('char b[128]; recv(3, b, sizeof b, 0); system(b);'), {"AST-C-001"}),
 ("cmd C++ concatenation", ".cpp", cpp('string cmd = "ls " + string(argv[1]); system(cmd.c_str());'), {"AST-C-001"}),
 ("cmd c++ cin", ".cpp", cpp('string s; cin >> s; system(s.c_str());'), {"AST-C-001"}),
 ("cmd c++ getline cin", ".cpp", cpp('string s; getline(cin, s); system(("echo " + s).c_str());'), {"AST-C-001"}),
 ("format string argv", ".c", main_("printf(argv[1]);"), {"AST-C-002"}),
 ("format string fprintf", ".c", main_("fprintf(stderr, argv[1]);"), {"AST-C-002"}),
 ("format string syslog", ".c", main_('char b[64]; fgets(b, 64, stdin); syslog(1, b);'), {"AST-C-002"}),
 ("strcpy argv", ".c", main_("char b[16]; strcpy(b, argv[1]);"), {"AST-C-003"}),
 ("strcat argv", ".c", main_('char b[16] = "x"; strcat(b, argv[1]);'), {"AST-C-003"}),
 ("sprintf %s argv", ".c", main_('char b[16]; sprintf(b, "%s", argv[1]);'), {"AST-C-003"}),
 ("strcpy of an oversized literal", ".c", main_('char b[4]; strcpy(b, "too long");'), {"AST-C-003"}),
 ("gets", ".c", main_("char b[8]; gets(b);"), {"AST-C-004"}),
 ("scanf %s", ".c", main_('char b[8]; scanf("%s", b);'), {"AST-C-005"}),
 ("sscanf %s", ".c", main_('char b[8]; sscanf(argv[1], "%s", b);'), {"AST-C-005"}),
 ("memcpy with atoi size", ".c", main_("char d[16]; int n = atoi(argv[2]); memcpy(d, argv[1], n);"), {"AST-C-006"}),
 ("read with size from stdin", ".c", main_('char b[8], l[8]; fgets(l, 8, stdin); read(0, b, atoi(l));'), {"AST-C-006"}),
 ("strncpy with strlen of the source", ".c", main_("char d[8]; strncpy(d, argv[1], strlen(argv[1]));"), {"AST-C-006"}),
 ("malloc with size from the network", ".c", fn('char l[16]; recv(3, l, 16, 0); char *p = malloc(atoi(l));'), {"AST-C-007"}),
 ("alloca from the network", ".c", fn('char l[16]; recv(3, l, 16, 0); char *p = alloca(atoi(l));'), {"AST-C-007"}),
 ("new[] from the network", ".cpp", CPP + "void f(int s) { char l[16]; recv(s, l, 16, 0); int n = atoi(l); char *p = new char[n]; }\n", {"AST-C-007"}),
 ("fopen from the network", ".c", fn('char p[64]; recv(3, p, 63, 0); FILE *f = fopen(p, "r");'), {"AST-C-008"}),
 ("concatenated fopen from the network", ".c", fn('char n[32], p[64]; recv(3, n, 31, 0); snprintf(p, 64, "/data/%s", n); fopen(p, "r");'), {"AST-C-008"}),
 ("ifstream from the network", ".cpp", CPP + "void f(int s) { char b[64]; recv(s, b, 63, 0); string p(b); ifstream f(p); }\n", {"AST-C-008"}),
 ("md5", ".c", fn("unsigned char d[16]; MD5((unsigned char*)in, 4, d);"), {"AST-C-009"}),
 ("EVP_sha1", ".c", fn("const void *m = EVP_sha1();"), {"AST-C-009"}),
 ("TLS verify none", ".c", fn("SSL_CTX_set_verify(ctx, SSL_VERIFY_NONE, NULL);", "SSL_CTX *ctx"), {"AST-C-010"}),
 ("curl verifypeer 0", ".c", fn("curl_easy_setopt(h, CURLOPT_SSL_VERIFYPEER, 0L);", "void *h"), {"AST-C-010"}),
 ("tmpnam", ".c", fn("char b[L_tmpnam]; tmpnam(b);"), {"AST-C-011"}),
 ("rand for token", ".c", fn("int token = rand();"), {"AST-C-012"}),
 ("rand for salt C++", ".cpp", cpp("int salt; salt = rand() % 256;"), {"AST-C-012"}),
 ("use after free", ".c", fn("char *p = malloc(8); free(p); p[0] = 1;"), {"AST-C-013"}),
 ("double free", ".c", fn("char *p = malloc(8); free(p); free(p);"), {"AST-C-013"}),
 ("delete then use", ".cpp", cpp("int *p = new int(1); delete p; *p = 2;"), {"AST-C-013"}),
 ("chmod 777", ".c", fn('chmod("/tmp/x", 0777);'), {"AST-C-014"}),
 ("across functions", ".c", H + "void run(const char *c) { system(c); }\nint main(int argc, char **argv) { run(argv[1]); return 0; }\n", {"AST-C-001"}),
 ("across functions, 2 levels", ".c", H + "void run(const char *c) { system(c); }\nvoid mid(const char *x) { run(x); }\nint main(int argc, char **argv) { mid(argv[1]); return 0; }\n", {"AST-C-001"}),
 ("struct field", ".c", H + "struct R { char *cmd; };\nint main(int argc, char **argv) { struct R r; r.cmd = argv[1]; system(r.cmd); return 0; }\n", {"AST-C-001"}),
 ("after if/else", ".c", main_("char *c = \"ls\"; if (argc > 2) { c = argv[1]; } system(c);"), {"AST-C-001"}),
 ("std::string append method branch", ".cpp", cpp('string s = "ls "; s.append(argv[1]); system(s.c_str());'), {"AST-C-001"}),
 ("fread from file -> malloc", ".c", fn('struct H { int w, h; } hd; FILE *fp = fopen("a.img", "rb"); fread(&hd, sizeof hd, 1, fp); char *p = malloc(hd.w + hd.h);'), {"AST-C-007"}),
 ("fixed copy into a buffer with externally controlled size", ".c", fn('struct H { int w; char d[64]; } hd; FILE *fp = fopen("a", "rb"); fread(&hd, sizeof hd, 1, fp); char *p = malloc(hd.w); memcpy(p, hd.d, sizeof(hd.d));'), {"AST-C-007", "AST-C-015"}),
 ("fgets from file -> system", ".c", fn('char b[64]; FILE *fp = fopen("c", "r"); fgets(b, 64, fp); system(b);'), {"AST-C-001"}),
 ("field: tainted struct field", ".c", H + "struct R { char *cmd; int n; };\nint main(int argc, char **argv) { struct R r; r.cmd = argv[1]; system(r.cmd); return 0; }\n", {"AST-C-001"}),
 ("strtok", ".c", main_("char *t = strtok(argv[1], \",\");"), {"AST-C-016"}),
 ("use after free of a field", ".c", fn("struct S *s = malloc(8); free(s->p); s->p[0] = 1;"), {"AST-C-013"}),
 # ---- MUST NOT be reported (as CONFIRMED) ----
 ("free of a field then zeroed", ".c", fn("struct S *s = malloc(8); free(s->p); s->p = NULL;"), set()),
 ("fixed copy after size comparison", ".c", fn('struct H { int w; char d[64]; } hd; FILE *fp = fopen("a", "rb"); fread(&hd, sizeof hd, 1, fp); if (hd.w < 64) return; char *p = malloc(hd.w); memcpy(p, hd.d, 64);'), set()),
 ("field: other, untainted field", ".c", H + "struct R { char *cmd; char *name; };\nint main(int argc, char **argv) { struct R r; r.name = argv[1]; r.cmd = \"ls\"; system(r.cmd); return 0; }\n", set()),
 ("minimum with ternary", ".c", main_("char d[16]; int n = atoi(argv[2]); int m = n > 16 ? 16 : n; memcpy(d, argv[1], m);"), set()),
 ("pointer-parameter field is not tainted", ".c", H + "struct S { int len; char *buf; };\nvoid g(struct S *s, char *d) { memcpy(d, s->buf, s->len); }\nint main(int argc, char **argv) { struct S s; g(&s, argv[1]); return 0; }\n", set()),
 ("constant cmd", ".c", main_('system("ls -la");'), set()),
 ("cmd from a parameter never called with tainted data", ".c", fn("system(in);"), set()),
 ("cmd with atoi", ".c", main_('char c[32]; snprintf(c, 32, "sleep %d", atoi(argv[1])); system(c);'), set()),
 ("cmd with constant in a clean branch", ".c", main_('char *c = argv[1]; c = "ls"; system(c);'), set()),
 ("constant format", ".c", main_('printf("%s\\n", argv[1]);'), set()),
 ("fprintf with fixed format", ".c", main_('fprintf(stderr, "errore: %s\\n", argv[1]);'), set()),
 ("snprintf sicura", ".c", main_('char b[16]; snprintf(b, sizeof b, "%s", argv[1]);'), set()),
 ("strncpy with sizeof", ".c", main_("char b[16]; strncpy(b, argv[1], sizeof b - 1);"), set()),
 ("strcpy with verified strlen", ".c", main_("char b[16]; if (strlen(argv[1]) < sizeof b) { strcpy(b, argv[1]); }"), set()),
 ("strcpy of a constant that fits", ".c", main_('char b[16]; strcpy(b, "hello");'), set()),
 ("sprintf with numbers only", ".c", main_('char b[32]; sprintf(b, "%d", 42);'), set()),
 ("scanf with field width", ".c", main_('char b[8]; scanf("%7s", b);'), set()),
 ("memcpy with compared size", ".c", main_("char d[16]; int n = atoi(argv[2]); if (n > 16) return 1; memcpy(d, argv[1], n);"), set()),
 ("memcpy with sizeof", ".c", main_("char d[16], s[16]; memcpy(d, s, sizeof d);"), set()),
 ("memcpy with min", ".c", main_("char d[16]; int n = MIN(atoi(argv[2]), 16); memcpy(d, argv[1], n);"), set()),
 ("constant malloc", ".c", main_("char *p = malloc(64);"), set()),
 ("malloc with limit", ".c", main_("int n = atoi(argv[1]); if (n > 4096) return 1; char *p = malloc(n);"), set()),
 ("constant fopen", ".c", main_('FILE *f = fopen("/etc/app.conf", "r");'), set()),
 ("non-weak sha256", ".c", fn("unsigned char d[32]; SHA256((unsigned char*)in, 4, d);"), set()),
 ("TLS verify peer", ".c", fn("SSL_CTX_set_verify(ctx, SSL_VERIFY_PEER, NULL);", "SSL_CTX *ctx"), set()),
 ("curl verifypeer 1", ".c", fn("curl_easy_setopt(h, CURLOPT_SSL_VERIFYPEER, 1L);", "void *h"), set()),
 ("mkstemp", ".c", fn('char t[] = "/tmp/xXXXXXX"; mkstemp(t);'), set()),
 ("non-sensitive rand", ".c", fn("int dice = rand() % 6;"), set()),
 ("free then NULL", ".c", fn("char *p = malloc(8); free(p); p = NULL;"), set()),
 ("free then reassign", ".c", fn("char *p = malloc(8); free(p); p = malloc(4); p[0] = 1;"), set()),
 ("free then NULL check", ".c", fn("char *p = malloc(8); free(p); if (p == NULL) return;"), set()),
 ("free in a branch closed by return", ".c", fn("char *p = malloc(8); if (!p) { free(p); return; } p[0] = 1;"), set()),
 ("chmod 600", ".c", fn('chmod("/tmp/x", 0600);'), set()),
 ("fopen of a path passed on the command line", ".c", main_('FILE *f = fopen(argv[1], "r");'), set()),
 ("ifstream of a path read from the keyboard", ".cpp", cpp("string p; cin >> p; ifstream f(p);"), set()),
 ("malloc with a number from the command line", ".c", main_("char *p = malloc(atoi(argv[1]));"), set()),
 ("memcpy on a buffer created with the same size", ".c", fn("size_t l = strlen(in); char *p = malloc(l + 1); memcpy(p, in, l);"), set()),
 ("memcpy with size from a buffer created by a function", ".c", H + "char *ensure(int n);\nvoid f(const char *in) { size_t n = strlen(in); char *o = ensure(n + 2); memcpy(o + 1, in, n); }\n", set()),
 ("comment containing system", ".c", main_("// system(argv[1]);"), set()),
]
PROJECT_CASES = [
 ("project: function in another file", {
    "src/sh.c": "#include <stdlib.h>\nvoid run_cmd(const char *c) { system(c); }\n",
    "src/main.c": "void run_cmd(const char *c);\nint main(int argc, char **argv) { run_cmd(argv[1]); return 0; }\n"}, {("src/sh.c", "AST-C-001")}),
 ("project: call with a constant", {
    "src/sh.c": "#include <stdlib.h>\nvoid run_cmd(const char *c) { system(c); }\n",
    "src/main.c": "void run_cmd(const char *c);\nint main(void) { run_cmd(\"ls\"); return 0; }\n"}, set()),
 ("project: size across files", {
    "src/buf.c": "#include <string.h>\nvoid fill(char *d, const char *s, int n) { memcpy(d, s, n); }\n",
    "src/main.c": "void fill(char *d, const char *s, int n);\n#include <stdlib.h>\nint main(int argc, char **argv) { char b[16]; fill(b, argv[1], atoi(argv[2])); return 0; }\n"}, {("src/buf.c", "AST-C-006")}),
 ("project: same-named (static) functions in different files are not confused", {
    "a.c": "#include <stdlib.h>\nstatic void go(const char *c) { system(c); }\nvoid a(void) { go(\"ls\"); }\n",
    "b.c": "static void go(const char *c) { (void)c; }\nint main(int argc, char **argv) { go(argv[1]); return 0; }\n"}, set()),
 ("project: C++ method and free function", {
    "lib.cpp": "#include <cstdlib>\n#include <string>\nvoid exec_line(const std::string &s) { system(s.c_str()); }\n",
    "main.cpp": "#include <string>\nvoid exec_line(const std::string &s);\nint main(int argc, char **argv) { exec_line(std::string(\"echo \") + argv[1]); return 0; }\n"}, {("lib.cpp", "AST-C-001")}),
]

def main():
    if not C.AVAILABLE:
        print("WARNING: tree-sitter-c / tree-sitter-cpp are not installed, so no tests were run. Install them with: pip install tree-sitter tree-sitter-c tree-sitter-cpp"); return 0
    bad = 0
    for name, ext, code, exp in CASES:
        got = {f["id"] for f in C.analyze_c_source("src/app" + ext, code) if f["confidence"] == "confirmed"}
        ok = got == exp; bad += not ok
        print(("OK   " if ok else "FAIL ") + name + ("" if ok else f"   expected={sorted(exp)} got={sorted(got)}"))
    for name, files, exp in PROJECT_CASES:
        res = C.analyze_c_project(files)
        got = {(r, f["id"]) for r, fs in res.items() for f in fs if f["confidence"] == "confirmed"}
        ok = got == exp; bad += not ok
        print(("OK   " if ok else "FAIL ") + name + ("" if ok else f"   expected={sorted(exp)} got={sorted(got)}"))
    total = len(CASES) + len(PROJECT_CASES)
    print(f"\n{total - bad}/{total} tests passed")
    return 1 if bad else 0

if __name__ == "__main__":
    sys.exit(main())
