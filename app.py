"""
MIS5303 Lab 2 - Input Validation, SQL Injection, XSS, and Secure Data Flow.

Starting from the deliberately insecure Lab 1 app. This Lab 2 copy fixes
ONLY the input-flow vulnerabilities in scope for this lab:
  - SQL injection in the notes query
  - Stored XSS in the notes list
  - Missing input validation on notes
Other planted flaws (passwords, cookies, access control, upload, etc.) are
left untouched - they belong to other labs.
"""

import os
import secrets
import hashlib
import sqlite3
import subprocess
from flask import (
    Flask,
    request,
    redirect,
    url_for,
    session,
    render_template_string,
)

app = Flask(__name__)

# [VULN] Hardcoded/auto secret key (Lab 1 scope - left as-is).
app.secret_key = os.environ.get("SECRET_KEY") or secrets.token_hex(32)

# [VULN] Insecure session cookie config (Lab 3 scope - left as-is).
app.config["SESSION_COOKIE_HTTPONLY"] = False
app.config["SESSION_COOKIE_SECURE"] = False

DATABASE = "app.db"
UPLOAD_DIR = "uploads"

# FIXED (Lab 2): simple input-validation limit for notes.
MAX_NOTE_LENGTH = 500


def get_db():
    conn = sqlite3.connect(DATABASE)
    conn.row_factory = sqlite3.Row
    return conn


def init_db():
    os.makedirs(UPLOAD_DIR, exist_ok=True)
    conn = get_db()
    conn.execute(
        """CREATE TABLE IF NOT EXISTS users (
               id INTEGER PRIMARY KEY AUTOINCREMENT,
               username TEXT UNIQUE NOT NULL,
               password TEXT NOT NULL
           )"""
    )
    conn.execute(
        """CREATE TABLE IF NOT EXISTS notes (
               id INTEGER PRIMARY KEY AUTOINCREMENT,
               username TEXT NOT NULL,
               content TEXT NOT NULL
           )"""
    )
    conn.commit()
    conn.close()


PAGE = """
<!doctype html>
<title>Secure(?) Notes</title>
<h1>Secure(?) Notes App</h1>
{% if session.get('username') %}
  <p>Logged in as <b>{{ session['username'] }}</b> -
     <a href="/logout">Logout</a></p>
  <h2>Your Notes</h2>
  <form method="post" action="/notes">
    <input name="content" placeholder="Write a note">
    <button type="submit">Add Note</button>
  </form>
  <ul>
    {% for n in notes %}<li>{{ n['content'] }}</li>{% endfor %}
  </ul>
  {% if error %}<p style="color:red">{{ error }}</p>{% endif %}
  <h2>Upload a File</h2>
  <form method="post" action="/upload" enctype="multipart/form-data">
    <input type="file" name="file">
    <button type="submit">Upload</button>
  </form>
  <h2>Admin: Ping a Host</h2>
  <form method="post" action="/admin/ping">
    <input name="host" placeholder="e.g. 127.0.0.1">
    <button type="submit">Ping</button>
  </form>
  <pre>{{ ping_output }}</pre>
{% else %}
  <p><a href="/login">Login</a> | <a href="/register">Register</a></p>
{% endif %}
"""

AUTH_PAGE = """
<!doctype html>
<title>{{ mode }}</title>
<h1>{{ mode }}</h1>
<form method="post">
  Username: <input name="username"><br><br>
  Password: <input type="password" name="password"><br><br>
  <button type="submit">{{ mode }}</button>
</form>
<p style="color:red">{{ error }}</p>
<a href="/">Home</a>
"""


@app.route("/")
def index():
    notes = []
    error = request.args.get("error", "")
    if session.get("username"):
        conn = get_db()
        # FIXED (Lab 2): parameterised query - username is passed as a bound
        # parameter, so it can never break out of the SQL and inject logic.
        notes = conn.execute(
            "SELECT * FROM notes WHERE username = ?",
            (session["username"],),
        ).fetchall()
        conn.close()
    return render_template_string(PAGE, notes=notes, ping_output="", error=error)


@app.route("/register", methods=["GET", "POST"])
def register():
    error = ""
    if request.method == "POST":
        username = request.form["username"]
        password = request.form["password"]
        conn = get_db()
        try:
            # [VULN] Password stored in PLAINTEXT (Lab 3 scope - left as-is).
            conn.execute(
                "INSERT INTO users (username, password) VALUES (?, ?)",
                (username, password),
            )
            conn.commit()
        except sqlite3.IntegrityError:
            error = "Username already taken"
        conn.close()
        if not error:
            return redirect(url_for("login"))
    return render_template_string(AUTH_PAGE, mode="Register", error=error)


@app.route("/login", methods=["GET", "POST"])
def login():
    error = ""
    if request.method == "POST":
        username = request.form["username"]
        password = request.form["password"]
        conn = get_db()
        # Parameterised query (already safe in Lab 1 for login).
        user = conn.execute(
            "SELECT * FROM users WHERE username = ? AND password = ?",
            (username, password),
        ).fetchone()
        conn.close()
        if user:
            session["username"] = user["username"]
            return redirect(url_for("index"))
        error = "Invalid credentials"
    return render_template_string(AUTH_PAGE, mode="Login", error=error)


@app.route("/logout")
def logout():
    session.clear()
    return redirect(url_for("index"))


@app.route("/notes", methods=["POST"])
def add_note():
    if not session.get("username"):
        return redirect(url_for("login"))
    content = request.form["content"]
    # FIXED (Lab 2): input validation - reject empty or over-long notes
    # before they ever reach the database.
    if not content or not content.strip():
        return redirect(url_for("index", error="Note cannot be empty."))
    if len(content) > MAX_NOTE_LENGTH:
        return redirect(url_for("index", error="Note is too long (max 500 characters)."))
    conn = get_db()
    conn.execute(
        "INSERT INTO notes (username, content) VALUES (?, ?)",
        (session["username"], content),
    )
    conn.commit()
    conn.close()
    return redirect(url_for("index"))


@app.route("/upload", methods=["POST"])
def upload():
    if not session.get("username"):
        return redirect(url_for("login"))
    f = request.files["file"]
    # [VULN] Unrestricted upload (Lab 4 scope - left as-is).
    path = os.path.join(UPLOAD_DIR, f.filename)
    f.save(path)
    # [VULN] Weak hash function MD5 (Lab 1/5 scope - left as-is).
    digest = hashlib.md5(open(path, "rb").read()).hexdigest()
    return f"Uploaded {f.filename} (md5={digest}). <a href='/'>Back</a>"


@app.route("/admin/ping", methods=["POST"])
def ping():
    host = request.form["host"]
    # [VULN] Command injection (Lab 4 scope - left as-is).
    result = subprocess.run(
        "ping -n 1 " + host, shell=True, capture_output=True, text=True
    )
    return render_template_string(
        PAGE, notes=[], ping_output=result.stdout + result.stderr, error=""
    )


if __name__ == "__main__":
    init_db()
    # [VULN] Debug mode enabled (Lab 1 scope - left as-is).
    app.run(debug=True)