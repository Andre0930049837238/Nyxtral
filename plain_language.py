# -*- coding: utf-8 -*-
"""
plain_language.py
Adds to every finding a "what you actually risk" explanation, written for
people who are not security experts, and — where the original technical
recommendation was too terse — a more conversational version of the advice.

Why a separate module instead of simply longer texts inside
rules.py/ast_engine.py: the "technical" data (also used by anyone who wants
to extend the rules) stays compact, while the end-user explanation is
updated in a single place and reused identically by the GUI, the PDF and (in
the future) any other view.

If an id is not mapped, a generic explanation based on severity is
generated, so nothing is ever missing even for rules added in the future.
"""

IMPACT = {
    # --- Generic: secrets, keys, sensitive files ----------------------------
    "GEN-001": "Anyone who finds this key (even just by looking at the code on GitHub) can use your Amazon "
               "account as if it were their own: create resources at your expense, read or delete your data.",
    "GEN-002": "Anyone who finds this key can use your quotas on Google services (maps, translation, AI...) "
               "at your expense, or access data tied to that project.",
    "GEN-003": "Anyone who finds this token can read the messages in your Slack workspace, or post messages on your behalf.",
    "GEN-004": "This is the key that 'opens' a protected system (server, service). If someone finds it, "
               "they can get into that system in your place.",
    "GEN-005": "A token of this kind proves 'who you are' to a service: if someone finds it before it expires, "
               "they can impersonate you.",
    "GEN-006": "If this is a real value (not an example), anyone who reads the code knows the password/key. "
               "This happens a lot on GitHub: automated bots scan public repositories precisely to find them.",
    "GEN-007": "This line contains, in clear text, the username and password to get into your database. It is like "
               "leaving your house keys written on the door.",
    "GEN-008": "The program stops checking whether it is talking to the right server: an attacker on the same "
               "network (e.g. public wifi) could intercept or modify the data without anyone noticing.",

    # --- AST engine (Python) -------------------------------------------------
    "AST-PY-001": "eval() runs any text you pass it as a program. If that text comes, even partly, from a "
                  "user, whoever uses your program can make it do whatever they want: read files, delete "
                  "data, open a port on your server.",
    "AST-PY-002": "Like eval(), but for longer Python statements: same risk, a malicious user can "
                  "make the program run arbitrary code on your behalf.",
    "AST-PY-003": "This line passes a command to the operating system shell. If part of the command comes "
                  "from outside, a user can 'hook' extra commands onto it (e.g. delete files, install software).",
    "AST-PY-004": "If this data comes from outside (an uploaded file, a web request...) and is not trusted, "
                  "opening it this way can run code hidden inside it, like opening an infected attachment.",
    "AST-PY-005": "Same risk as a shell command: if the command is not written entirely by you but includes "
                  "an external piece, whoever controls it can run other commands in your place.",
    "AST-PY-006": "A configuration file written in YAML can, this way, tell the program to run Python "
                  "code. If the file comes from outside, it is like letting a stranger run code.",
    "AST-PY-007": "This kind of data 'fingerprint' is easy to guess with free tools available "
                  "online: if you use it for passwords, an attacker who steals the database recovers them quickly.",
    "AST-PY-008": "If the text of the query changes based on external data, someone can deliberately craft a value "
                  "that 'escapes' the intended question and asks a different one: reading the whole table, deleting it, "
                  "or bypassing a login.",

    # --- JavaScript / TypeScript ---------------------------------------------
    "JS-001": "eval()/new Function() run text as if it were code. If that text depends, even partly, "
              "on what a user types, they can run their own code in your site or app.",
    "JS-002": "If the inserted content comes from a user (a comment, a name, a message) and is not cleaned, "
              "that user can inject a piece of page that, for example, steals the session data of whoever visits it.",
    "JS-003": "Same risk: unchecked HTML content inserted into the page can hide code that "
              "runs in the browser of whoever visits the page, without their knowledge.",
    "JS-004": "If the command includes a piece that comes from outside, whoever controls it can make the server "
              "that runs the code execute commands other than the intended ones.",
    "JS-005": "Any website, even a malicious one, can call your API from a user's browser. If the API "
              "handles sensitive data, this opens the door to cross-site data theft.",
    "JS-006": "Anyone who knows this key can create 'passes' (tokens) on their own that your system "
              "will consider valid, impersonating any user.",
    "JS-007": "As with SQL queries in Python: a value crafted by a user can alter the question "
              "asked of the database, reading or modifying data they should not be able to touch.",
    "JS-008": "Fingerprints that are easy to 'reverse' with free tools: they do not really protect a password.",
    "JS-009": "Any script that manages to run on the page (even by mistake elsewhere on the site) can read "
              "this data and steal it, because it is accessible to all the code on the page.",

    # --- Java ------------------------------------------------------------------
    "JAVA-001": "If the command includes an external piece, whoever controls it can make the system running the "
                "program execute commands other than the intended ones.",
    "JAVA-002": "A value crafted by a user can alter the question asked of the database: reading, "
                "modifying or deleting data they should not be able to touch.",
    "JAVA-003": "A weak data protection scheme: with the right tools (free and widespread) it can be "
                "'broken' in a reasonable amount of time.",
    "JAVA-004": "If server certificate verification is turned off, anyone who gets 'in the middle' of the "
                "connection (e.g. on an untrusted network) can read or alter the exchanged data without the "
                "program noticing.",

    # --- C# / .NET ---------------------------------------------------------------
    "CS-001": "A value crafted by a user can alter the question asked of the database: reading, "
              "modifying or deleting data they should not be able to touch.",
    "CS-002": "A weak data protection scheme: with the right tools (free and widespread) it can be "
              "'broken' in a reasonable amount of time, especially for passwords.",
    "CS-003": "If server certificate verification is turned off, anyone who gets 'in the middle' of the "
              "connection can read or alter the exchanged data without the program noticing.",
    "CS-004": "If the command arguments include an external piece, whoever controls it can make the program run "
              "commands other than the intended ones.",

    # --- PHP -------------------------------------------------------------------
    "PHP-001": "eval() runs any text you pass it as a program: if that text depends on a user, "
               "they can run their own code on your server.",
    "PHP-002": "If the command includes a piece that comes from outside, whoever controls it can make the "
               "server execute commands other than the intended ones.",
    "PHP-003": "A value crafted by a user can alter the question asked of the database: reading, "
               "modifying or deleting data they should not be able to touch.",
    "PHP-004": "A fingerprint that is easy to 'reverse' with free tools: it does not really protect a password.",
    "PHP-005": "This statement lets the user create variables with any names they like in your program: they can "
               "overwrite internal values and change the program's behavior in unexpected ways.",
    "PHP-006": "The program includes and runs a file chosen by the user: a user can make it load and "
               "run their own file, even one hosted on another site.",
    "PHP-007": "Rebuilding an object from data supplied by a user can run code hidden in "
               "that data, by exploiting functions already present in the program.",


    # --- C / C++ -------------------------------------------------------------------
    "AST-C-001": "The program passes a command to the system shell. If part of it comes from outside, whoever controls it "
                 "can run their own commands (delete files, install software) with the program's permissions.",
    "AST-C-002": "If whoever uses the program decides the format text, they can read pieces of the program's memory (even "
                 "passwords or keys) or write into memory areas they should not touch.",
    "AST-C-003": "Copying text into a smaller space writes past its boundaries and overwrites other data: this is "
                 "the classic error that allows taking control of a C program.",
    "AST-C-004": "gets() reads whatever it is given with no limit at all: any sufficiently long text breaks the "
                 "program or makes it run something else. That is why it was removed from the standard.",
    "AST-C-005": "Without a length limit in the format, a long text writes beyond the reserved space and "
                 "overwrites nearby memory.",
    "AST-C-006": "If the amount of data to copy is decided by whoever uses the program, they can ask for more than "
                 "the space can hold and overwrite other data in memory.",
    "AST-C-007": "A size chosen from the outside makes it possible to request huge amounts of memory (and freeze the "
                 "program) or to corrupt later size calculations.",
    "AST-C-008": "Whoever controls the file name can get different files read or modified than the intended ones "
                 "(for example by using '../' to escape the allowed folder).",
    "AST-C-009": "An algorithm that can today be broken quickly with common tools: it does not really protect passwords, "
                 "signatures or confidential data.",
    "AST-C-010": "Without verifying the certificate, anyone who gets in the middle of the connection (for example on an "
                 "untrusted network) can read or alter the data without the program noticing.",
    "AST-C-011": "A predictable file name in a shared folder lets another user create it before "
                 "the program does and make it read or write wherever they want.",
    "AST-C-012": "Predictable numbers used for keys, tokens or salts allow an attacker to guess them.",
    "AST-C-013": "Using memory that has already been returned to the system can leak other people's data or, with a bit of skill, "
                 "run code chosen by an attacker.",
    "AST-C-015": "The program prepares a space whose size is decided by whoever supplies the data, then copies a fixed "
                 "amount into it: if the space is smaller, the extra bytes land on top of other data in memory.",
    "AST-C-014": "With permissions open to everyone, any user on the computer can modify the file, and thus "
                 "change the program's behavior or its data.",

    # --- File name checks ---------------------------------------------------------
    "FILE-CHECK": "If this file ends up in a shared or public repository (e.g. GitHub), anyone who can "
                  "see it gets what it contains: passwords, private keys or access tokens.",
}

# Generic fallback by severity, used when an id is not (yet) mapped above
GENERIC_IMPACT_BY_SEVERITY = {
    "CRITICAL": "A problem of this kind, if exploited, can give an outside user control of data or "
                "functions that should remain private: it is the most serious category of risk.",
    "HIGH": "A problem of this kind exposes sensitive data or functions to misuse, even if the "
            "conditions needed to actually exploit it may be more specific.",
    "MEDIUM": "It is not the most dangerous flaw by any means, but it weakens the program's defenses and is worth "
              "fixing whenever you happen to be working on that line of code.",
    "LOW": "Limited impact in most cases, but it is still good practice to fix it.",
    "INFO": "It is not a security risk in itself: it is useful information for the code review.",
}


# Explanations by category (CWE), used by the Go, Kotlin, Swift and SQL engines
CWE_IMPACT = {
    "CWE-78": "If part of the command comes from outside, whoever controls it can run their own commands with the program's permissions: delete files, steal data, install software.",
    "CWE-89": "A cleverly crafted value can change the question asked of the database: reading the whole table, modifying or deleting it, or skipping a login.",
    "CWE-22": "Whoever controls the file name can get different files read or written than the intended ones (for example by using '../' to escape the allowed folder).",
    "CWE-918": "The program can be tricked into contacting addresses chosen by a stranger, for example internal services that are not reachable from outside.",
    "CWE-79": "Unsanitized content ends up in the page and can run code in the browser of whoever visits it, for example stealing their session.",
    "CWE-601": "A user can be sent to a fake site from a link that looks like it belongs to your service.",
    "CWE-327": "An algorithm that can today be broken quickly with common tools: it does not really protect passwords, signatures or confidential data.",
    "CWE-328": "A fingerprint that is easy to reverse or forge with free tools: it does not really protect a password.",
    "CWE-295": "Without verifying who is on the other end, anyone who gets in the middle of the connection can read or alter the data without anyone noticing.",
    "CWE-338": "Predictable numbers used for tokens, keys or salts allow an attacker to guess them.",
    "CWE-732": "With permissions open to everyone, any user on the computer can modify the file and thus change the program's behavior or its data.",
    "CWE-276": "Other apps or other users can read or modify this file or these preferences.",
    "CWE-614": "An unprotected cookie can be intercepted on an unencrypted connection or read by code in the page, and allows the session to be stolen.",
    "CWE-377": "A predictable file name in a shared folder lets another user create it before the program does and make it read or write wherever they want.",
    "CWE-409": "A small file can expand until it fills the memory and freezes the program.",
    "CWE-94": "Text coming from outside is executed as a program or as a template: whoever controls it can make the program do whatever they want.",
    "CWE-347": "Anyone can forge a valid token without knowing any secret key and impersonate any user.",
    "CWE-502": "Rebuilding objects from untrusted data can run code hidden in that data.",
    "CWE-611": "A crafted XML file can make the server read its own files or contact internal addresses.",
    "CWE-319": "Data travels in clear text: anyone on the same network (for example a public wifi) can read or modify it.",
    "CWE-532": "Passwords, tokens or keys end up in log files, which many people and tools can read.",
    "CWE-311": "Confidential data is stored without encryption: whoever gets the device or the backup reads it directly.",
    "CWE-312": "Confidential data is stored in clear text: whoever gets the device or the backup reads it directly.",
    "CWE-321": "A key written in the code can be read by anyone who has the app or the code: encryption no longer protects anything.",
    "CWE-749": "Untrusted pages can use WebView functions they should not have, up to reading files on the device.",
    "CWE-927": "Another app can make your program launch unintended components, with its own permissions.",
    "CWE-1327": "The service is reachable from any computer on the network, not only from the ones that should use it.",
    "CWE-400": "A server without time limits can be blocked by a few slow clients: it is enough to keep many connections open.",
    "CWE-242": "This usage bypasses the language's safety checks: a mistake here can corrupt memory or open a vulnerability.",
    "CWE-250": "An account with more privileges than needed turns every mistake or credential theft into much greater damage.",
    "CWE-798": "Anyone who reads the script (even in a shared repository) knows the password and can get into the system in your place.",
    "CWE-256": "If someone steals the database, they immediately read every user's password, which is often reused on other services.",
    "CWE-306": "Access without a password, or open to any address, allows anyone to connect to the database.",
    "CWE-426": "An object with the same name, created by an ordinary user, can be executed with the function's privileges.",
    "CWE-284": "Without row-level protection, a user can see or modify rows that belong to others.",
    "CWE-16": "A dangerous feature is left enabled: it is one more door for anyone who manages to obtain even limited access.",
    "CWE-787": "Writing beyond the boundaries of a buffer overwrites other data and can give control of the program.",
}


EXTRA_CWE = {
    "CWE-95": "Text coming from outside is executed as program code: whoever controls it can make it do whatever they want.",
    "CWE-98": "Whoever controls the name of the included file can make the server run a file of their choosing, even one hosted on another site.",
    "CWE-90": "Whoever controls the filter can read entries of the corporate directory (users, groups) that they should not see.",
    "CWE-330": "Predictable numbers used for tokens, keys or sessions allow an attacker to guess them.",
    "CWE-352": "Another site can make the logged-in user perform actions without their noticing, because there is no proof that the request comes from you.",
    "CWE-697": "Two different values can appear 'equal' because of a comparison error, opening the door to unwanted access.",
    "CWE-621": "The user can create program variables with any names they like and overwrite internal values.",
    "CWE-915": "A user can set model fields (such as the role or the price) that they should not be able to touch, by sending them in the request.",
    "CWE-1333": "A crafted regular expression can freeze the service by taking minutes of computation for a single request.",
    "CWE-521": "Access without a password, or with a weak one, allows anyone to connect.",
    "CWE-125": "Reading beyond the boundaries of a buffer exposes data that should not be visible and can crash the program.",
    "CWE-200": "The program reveals internal information that helps an attacker prepare the attack.",
    "CWE-209": "Detailed error messages reveal paths, versions and internal structure to people who should not see them.",
    "CWE-613": "A token accepted without checking its expiry, issuer or signature can be reused or forged.",
    "CWE-942": "Any website can call your API from a user's browser: if it handles sensitive data, cross-site data theft becomes possible.",
    "CWE-776": "A crafted XML file can make the program consume all the memory or contact internal addresses.",
    "CWE-1004": "A cookie without HttpOnly can be read by code in the page and used to steal the session.",
    "CWE-696": "An attacker can use the system's error responses to decrypt the data one piece at a time.",
    "CWE-1288": "Unverified input data can produce unexpected results or errors.",
}
CWE_IMPACT.update(EXTRA_CWE)


def plain_impact(finding):
    """Return the 'what you actually risk' explanation for a finding."""
    if finding["id"] not in IMPACT and finding.get("cwe") in CWE_IMPACT:
        return CWE_IMPACT[finding["cwe"]]
    return IMPACT.get(finding["id"], GENERIC_IMPACT_BY_SEVERITY.get(finding["severity"],
                       "Check this spot: it may weaken the program's security."))
