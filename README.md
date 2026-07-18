# MIS5303 Lab 1 — Static Analysis & Secure Coding

> ⚠️ **This repository contains a DELIBERATELY VULNERABLE application.**
> The Flask app in `app.py` was written with intentional security flaws as a
> teaching target for static-analysis practice. It is **not** production code,
> must **never** be deployed, and should only be run locally on `127.0.0.1`.
> Every planted flaw is tagged `[VULN]` in the source.

Coursework for **MIS5303 Securing Software** — Master of Information Systems
(Cyber Security), Apex Australia Higher Education.

**Author:** Ashraful Islam · Student ID 240135

---

## The exercise

A small Flask + SQLite notes application with registration, login, note CRUD,
file upload, and an admin "ping" utility. The lab:

1. Run static analysis (Bandit, Semgrep) against the app
2. Document findings with IDs, severity, and CWE references
3. Remediate selected vulnerabilities and prove it with a re-scan
4. Propose architecture-level controls
5. Reflect on what static tooling *cannot* catch

---

## Findings

`bandit -r app.py` on the vulnerable app reports **7 issues** across 177 lines:

| Line | Bandit ID | CWE | Vulnerability | Severity |
|---|---|---|---|---|
| 13 | B404 | CWE-78 | `subprocess` module imported | Low |
| 26 | B105 | CWE-259 | Hardcoded secret key | Low |
| 114 | B608 | CWE-89 | SQL built with an f-string (notes query) | Medium |
| 151 | B608 | CWE-89 | SQL built by concatenation (login query) | Medium |
| 196 | B324 | CWE-327 | Weak MD5 hash on uploads | High |
| 205 | B602 | CWE-78 | `subprocess.run` with `shell=True` on user input | High |
| 215 | B201 | CWE-94 | Flask started with `debug=True` | High |

Full output: [`bandit_report.txt`](bandit_report.txt)

### What static analysis did *not* find

Scanners match patterns, not intent. These flaws are present but unflagged,
and were identified by manual review:

- **Stored XSS** — note content rendered through Jinja's `|safe` filter
- **Unrestricted file upload** — attacker-controlled filename, no type or size
  limit, enabling path traversal
- **Plaintext password storage** — no hashing or salting
- **No CSRF protection** on any state-changing form

This gap is the core lesson of the lab: automated tooling is necessary but not
sufficient, and manual review plus threat modelling remain essential.

---

## Remediation

Two versions of the fixed app are included.

### `app.py` — the documented lab fix

The working copy now has B105 and the login-query B608 remediated, matching the
before/after evidence in the writeup.

```diff
- app.secret_key = "dev-secret-123"
+ app.secret_key = os.environ.get("SECRET_KEY") or secrets.token_hex(32)

- query = ("SELECT * FROM users WHERE username = '" + username + "' ...")
- user = conn.execute(query).fetchone()
+ user = conn.execute(
+     "SELECT * FROM users WHERE username = ? AND password = ?",
+     (username, password),
+ ).fetchone()
```

### `app_fixed.py` — full remediation

Goes further and fixes every finding, including the four issues static analysis
missed: passwords hashed with `generate_password_hash`, the `|safe` filter
removed, uploads constrained by `secure_filename()` and an extension allow-list,
session cookie flags enabled, `shell=False` with host validation, SHA-256
replacing MD5, and `debug=False`.

### Scan comparison

| Version | Low | Medium | High | Total |
|---|---|---|---|---|
| Original vulnerable app | 2 | 2 | 3 | **7** |
| `app.py` (two fixes applied) | 1 | 1 | 3 | **5** |
| `app_fixed.py` (full remediation) | 2 | 0 | 0 | **2** |

The two residual Low findings in the fully hardened version are informational
notes about the `subprocess` module (B404, B603), retained because the ping
feature still shells out — now with an argument list, `shell=False`, host
validation, and a timeout.

Reports: [`bandit_report.txt`](bandit_report.txt) · [`bandit_after.txt`](bandit_after.txt)

---

## Running it locally

```bash
python -m venv venv
venv\Scripts\activate          # Windows
# source venv/bin/activate     # macOS / Linux

pip install -r requirements.txt
python app.py
```

Then open <http://127.0.0.1:5000/login>.

Reproduce the analysis:

```bash
pip install bandit semgrep
bandit -r app.py > bandit_report.txt
semgrep --config=p/ci app.py
```

---

## Layout

```
├── app.py                  # current app (with the two lab fixes applied)
├── app_fixed.py            # full remediation of every finding
├── requirements.txt
├── bandit_report.txt       # scan before fixes  (7 findings)
├── bandit_after.txt        # scan after fixes   (5 findings)
├── docs/                   # writeup and submission document
└── screenshots/            # workflow evidence
```

---

## Academic integrity

This repository documents my own completed coursework and is published as a
portfolio artefact. It is not intended as a solution set for anyone currently
enrolled in this unit.

## Licence

Educational use only. The vulnerable application is a learning artefact and
carries no warranty of any kind.
