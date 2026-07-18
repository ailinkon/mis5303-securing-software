# Restructuring into a course repository

You have already run `git init` but have **not committed yet**, so
reorganising now is completely safe.

Run these from Command Prompt inside
`G:\MIS5303 Securing Software, S2B1`.

## 1. Create the lab1 folder and move Lab 1 files into it

```cmd
cd /d "G:\MIS5303 Securing Software, S2B1"

mkdir lab1
mkdir lab1\reports
mkdir lab1\screenshots

move app.py lab1\
move app_fixed.py lab1\
move requirements.txt lab1\
move bandit_report.txt lab1\reports\
move bandit_after.txt lab1\reports\
move docs lab1\
```

## 2. Replace the README

Delete the old `README.md` in the main folder and copy in the new
course-level `README.md` from this kit. Also copy in the new `.gitignore`
(it replaces the old one and now covers every lab folder).

Delete `SETUP-GIT.md` and the file named `x` — they were scaffolding.

## 3. Move your screenshots in

Copy your evidence images into `lab1\screenshots\`.

## 4. Decide about "week 2"

If it is Lab 2 material, rename it:

```cmd
move "week 2" lab2
```

If it is unfinished or unrelated, leave it — the `.gitignore` does not
exclude it, so either delete it or add `lab2/` to `.gitignore` until it
is ready.

## 5. Check before committing

```cmd
git status
```

Expected: `.gitignore`, `README.md`, `lab1/`, and possibly `lab2/`.

You must NOT see `venv/`, `app.db`, `uploads/`, or `__pycache__/`.

## 6. Commit and push

```cmd
git add .
git commit -m "Add Lab 1: static analysis, remediation and secure design review"
git remote add origin https://github.com/ailinkon/mis5303-securing-software.git
git push -u origin main
```

## Running a lab afterwards

The venv stays at the top level, so:

```cmd
venv\Scripts\activate
cd lab1
python app.py
```
