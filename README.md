<p align="center">
  <img src="assets/logo-512.png" alt="Nyxtral logo" width="140">
</p>

<h1 align="center">Nyxtral</h1>

<p align="center">
  A desktop security scanner for source code.<br>
  Finds hardcoded secrets, injection flaws and risky patterns, explains each issue in plain English and exports a PDF report. Runs locally.
</p>

---

## Features

- **Multi-language analysis:** AST-based engines for Python, JavaScript/TypeScript, Java, C#, Go, PHP, Rust, Kotlin, Swift, C/C++ and SQL, plus pattern rules that work on any text file.
- **Secrets detection:** cloud keys, tokens, private keys, JWTs, connection strings with credentials and hardcoded passwords.
- **Plain-language explanations:** every finding says what it means, what you risk in practice and how to fix it.
- **Code quality checks:** overly long or complex functions, swallowed errors and leftover debug statements (can be turned off).
- **Dependency check:** looks up known vulnerabilities for `requirements.txt` and `package.json` through [OSV.dev](https://osv.dev) (the only feature that needs internet).
- **Baseline:** ignore a finding or a whole file, and restore it later.
- **Continuous mode:** re-scans automatically when files in the project change.
- **PDF report:** a shareable report with a security score.
- **Local first:** your code is analysed on your machine and never uploaded.

## Download

Get the latest installer or the portable build from the [**Releases**](../../releases) page:

| File | Description |
|------|-------------|
| `Nyxtral-Setup-<version>.exe` | Installer (Start menu entry, optional desktop shortcut, uninstaller) |
| `Nyxtral-Portable-<version>.zip` | Single executable, no installation needed |

> Windows SmartScreen may warn about an unsigned app. Choose **More info → Run anyway** if you trust the source.

## Run from source

Requires Python 3.9 or newer.

```bash
pip install -r requirements.txt
python main.py                    # opens the app
python main.py "C:\path\to\project"   # opens it with a folder preselected and scans immediately
```

The modern interface uses [pywebview](https://pywebview.flowrl.com/) (WebView2 on Windows). If it cannot start, Nyxtral falls back to a Tkinter interface.

## Build the executable and installer

On Windows, run `build.bat`. It installs the dependencies, builds `dist\Nyxtral.exe` with PyInstaller and, if [Inno Setup 6](https://jrsoftware.org/isinfo.php) is available, creates `installer_output\Nyxtral-Setup-<version>.exe`.

A GitHub Actions workflow (`.github/workflows/build-windows.yml`) does the same automatically: push a tag such as `v1.0.0` and the installer and the portable zip are attached to the release.

## Tests

Regression tests for each engine live in `tools/`:

```bash
python tools/test_python_engine.py
python tools/test_js_engine.py
```

They need the tree-sitter packages from `requirements.txt`.

## Troubleshooting

Logs are written to `%APPDATA%\Nyxtral\` (`scanner.log` and `crash.log`). Attach them when you report a problem. If a language engine is missing its tree-sitter package, Nyxtral keeps running with pattern rules only and logs the exact `pip install` command to fix it.

## License

Nyxtral is proprietary software: the compiled program is free to use, while the source code is published for viewing and review only and may not be copied, modified or redistributed. See [LICENSE](LICENSE). Third-party components and data sources are listed in [THIRD_PARTY_NOTICES.md](THIRD_PARTY_NOTICES.md); vulnerability data comes from [OSV.dev](https://osv.dev).

## Disclaimer

Nyxtral is a static analysis aid. It does not replace a manual code review, a full SAST/DAST analysis or a professional penetration test.
