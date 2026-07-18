# MIS5303 — Securing Software

Coursework repository for **MIS5303 Securing Software**, part of the Master of
Information Systems (Cyber Security) at Apex Australia Higher Education.

**Author:** Ashraful Islam

> ⚠️ **Several labs in this repository contain DELIBERATELY VULNERABLE code.**
> These applications are teaching targets for security analysis. They are not
> production code, must never be deployed, and should only be run locally on
> `127.0.0.1`. Intentional flaws are tagged `[VULN]` in the source.

---

## Labs

| Lab | Topic | Tools | Status |
|---|---|---|---|
| [Lab 1](lab1/) | Static analysis, secure coding & security design | Bandit, Semgrep | ✅ Complete |
| Lab 2 | *to be added* | | 🔜 |

---

## Lab 1 — Static analysis, secure coding & security design

Analysis of a deliberately insecure Flask + SQLite notes application:
static scanning, documented findings, targeted remediation with before/after
evidence, and an architecture-level review.

**Result:** 7 findings identified (2 Low, 2 Medium, 3 High), including SQL
injection, command injection, a hardcoded secret, weak hashing, and an exposed
debugger. Two were remediated and verified by re-scan; a fully hardened version
addresses all of them plus four flaws that static analysis could not detect.

→ [Full writeup](lab1/docs/writeup.md) · [Findings and reports](lab1/reports/)

---

## Skills demonstrated

- Static application security testing (SAST) with Bandit and Semgrep
- Mapping findings to CWE classifications and severity ratings
- Secure coding remediation: parameterised queries, secrets management,
  password hashing, input validation, output encoding
- Security architecture review and control selection with justification
- Understanding the limits of automated tooling and where manual review and
  threat modelling are required

---

## Repository layout

```
├── lab1/
│   ├── app.py                  # analysis target
│   ├── app_fixed.py            # fully remediated version
│   ├── requirements.txt
│   ├── reports/                # Bandit output, before and after
│   ├── docs/                   # writeup and submission document
│   └── screenshots/            # workflow evidence
└── README.md
```

Each lab folder is self-contained with its own dependencies and writeup.

---

## Academic integrity

This repository documents my own completed coursework and is published as a
portfolio artefact. It is not intended as a solution set for anyone currently
enrolled in this unit.

## Licence

Educational use only. Vulnerable applications are learning artefacts and carry
no warranty of any kind.
