# Third-party notices

Nyxtral uses the following third-party components. Each is licensed under its own terms, which
remain in force for that component.

| Component | Use | License |
|-----------|-----|---------|
| [ReportLab](https://www.reportlab.com/opensource/) | PDF report generation | BSD |
| [pywebview](https://pywebview.flowrl.com/) | Desktop window for the web interface | BSD-3-Clause |
| [tree-sitter](https://tree-sitter.github.io/) and the language grammars (JavaScript, TypeScript, Rust, C, C++, Go, Kotlin, Swift, Java, C#, PHP) | Source code parsing | MIT |
| [PyInstaller](https://pyinstaller.org/) | Packaging the executable (build time only) | GPL-2.0 with the bootloader exception that permits distributing the resulting program under any license |
| [Inno Setup](https://jrsoftware.org/isinfo.php) | Creating the installer (build time only) | Inno Setup License |
| [Inter](https://github.com/rsms/inter) font, bundled in `webui/fonts/` | User interface typography | SIL Open Font License 1.1 (full text in `webui/fonts/Inter-LICENSE.txt`) |

## Data sources

- **Vulnerability data:** the dependency check queries [OSV.dev](https://osv.dev). OSV data is
  provided by the OSV project and the individual advisory databases it aggregates, under their
  respective licenses (mainly CC-BY 4.0 and Apache-2.0).
- **Weakness identifiers:** the CWE identifiers shown in findings refer to the Common Weakness
  Enumeration, a trademark of The MITRE Corporation ([cwe.mitre.org](https://cwe.mitre.org)).

## Runtime dependency not bundled

On Windows, the modern interface relies on the Microsoft Edge WebView2 Runtime, which is installed
separately and licensed by Microsoft.

Please verify the license of each dependency version you ship: the licenses above are those
published by each project at the time of writing and may change.
