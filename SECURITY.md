# Security Policy

## Supported versions

Only the latest release of Nyxtral receives security updates.

| Version | Supported          |
| ------- | ------------------ |
| 1.0.x   | :white_check_mark: |
| < 1.0   | :x:                |

## Reporting a vulnerability

Please do **not** open a public issue for security problems.

Report them privately through GitHub: open the **Security** tab of this repository, choose
**Report a vulnerability** and describe the problem. Include:

- the Nyxtral version and your Windows version;
- the steps needed to reproduce the issue;
- the impact you expect, and a proof of concept if you have one.

You can expect an acknowledgement within 7 days and a status update at least every 14 days.
If the report is accepted, a fix will be released as soon as possible and you will be credited
in the release notes unless you prefer to stay anonymous. If it is declined, you will receive an
explanation.

Please give us a reasonable time to fix the problem before disclosing it publicly.

## Scope

Nyxtral analyses code locally and does not upload it. The only network request it makes is the
dependency check against OSV.dev. Reports about the app, its installer or its release process are
in scope. Findings produced by Nyxtral about *other* projects (false positives or missed
vulnerabilities) are not security issues in Nyxtral itself: report those as normal issues.
