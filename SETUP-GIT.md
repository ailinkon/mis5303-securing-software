# Turning this folder into a Git repository

Run these in Command Prompt from inside
`G:\MIS5303 Securing Software, S2B1`.

## 1. Put the drop-in files in place first

Copy `.gitignore`, `README.md`, and `app_fixed.py` into this folder
**before** running any git command. The `.gitignore` is what stops the
`venv` folder (hundreds of MB) from being committed.

## 2. Initialise

```cmd
cd /d "G:\MIS5303 Securing Software, S2B1"
git init
git branch -M main
```

## 3. CHECK BEFORE YOU COMMIT

```cmd
git status
```

Read the list carefully. You should see roughly:

```
app.py
app_fixed.py
requirements.txt
bandit_report.txt
bandit_after.txt
README.md
.gitignore
```

You should **NOT** see `venv/`, `app.db`, `uploads/`, or `__pycache__`.
If any of those appear, stop — the `.gitignore` is not in the right place
or is named wrong (Windows may have saved it as `.gitignore.txt`).

## 4. Commit

```cmd
git add .
git commit -m "MIS5303 Lab 1: static analysis, remediation and secure design review"
```

## 5. Create the empty repo on GitHub

On github.com: **New repository** → name it (e.g.
`mis5303-lab1-static-analysis`) → choose **Private** unless you have
confirmed the lab app can be published → do **not** tick "add a README",
since you already have one.

## 6. Push

```cmd
git remote add origin https://github.com/<your-username>/mis5303-lab1-static-analysis.git
git push -u origin main
```

## If you accidentally committed venv

```cmd
git rm -r --cached venv
git commit -m "Remove venv from tracking"
```

Then confirm `venv/` is listed in `.gitignore`.

## Optional tidy-up

These make the repo read better but are not required:

```cmd
mkdir docs
mkdir screenshots
```

Move your submission document into `docs\` and your evidence images into
`screenshots\`, then `git add .` and commit again.
