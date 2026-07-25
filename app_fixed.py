"""
MIS5303 Lab 1 - HARDENED version of the lab application.

This is the remediated counterpart to app.py. Each change is marked
FIXED with the Bandit ID it addresses, so the two files can be diffed
to show the before/after for the lab writeup. Still intended for local
educational use only.
"""

import os
import re
import hashlib
import secrets
import shutil
import sqlite3
import subprocess
from werkzeug.security import check_password_hash, generate_password_hash
from werkzeug.utils import secure_filename
from flask import (
    Flask,
    request,
    redirect,
    url_for,
    session,
    render_template_string,
)

app = Flask(__name__)

# FIXED (B105): key loaded from the environment, random fallback for dev.
app.secret_key = os.environ.get("SECRET_KEY") or secrets.token_hex(32)

# FIXED: protective session cookie flags enabled.
app.config["SESSION_COOKIE_HTTPONLY"] = True
app.config["SESSION_COOKIE_SECURE"] = True
app.config["SESSION_COOKIE_SAMESITE"] = "Lax"

DATABASE = "app.db"
UPLOAD_DIR = "uploads"
ALLOWED_EXTENSIONS = {".txt", ".png", ".jpg", ".jpeg", ".pdf"}
HOST_RE = re.compile(r"^[A-Za-z0-9.\-]{1,253}$")


def hash_password(password):
    return generate_password_hash(password)


def verify_password(password, stored):
    return check_password_hash(stored, password)


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
    if session.get("username"):
        conn = get_db()
        # FIXED (B608): parameterised query.
        notes = conn.execute(
            "SELECT * FROM notes WHERE username = ?", (session["username"],)
        ).fetchall()
        conn.close()
    return render_template_string(PAGE, notes=notes, ping_output="")


@app.route("/register", methods=["GET", "POST"])
def register():
    error = ""
    if request.method == "POST":
        username = request.form["username"]
        password = request.form["password"]
        conn = get_db()
        try:
            # FIXED: password stored as a salted hash, never plaintext.
            conn.execute(
                "INSERT INTO users (username, password) VALUES (?, ?)",
                (username, hash_password(password)),
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
        # FIXED (B608): parameterised query; password verified via hash.
        user = conn.execute(
            "SELECT * FROM users WHERE username = ?", (username,)
        ).fetchone()
        conn.close()
        if user and verify_password(password, user["password"]):
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
    # FIXED: filename sanitised and extension checked against an allow-list.
    filename = secure_filename(f.filename or "")
    ext = os.path.splitext(filename)[1].lower()
    if not filename or ext not in ALLOWED_EXTENSIONS:
        return "File type not allowed. <a href='/'>Back</a>", 400
    path = os.path.join(UPLOAD_DIR, filename)
    f.save(path)
    # FIXED (B324): SHA-256 replaces MD5 for the integrity digest.
    with open(path, "rb") as fh:
        digest = hashlib.sha256(fh.read()).hexdigest()
    return f"Uploaded {filename} (sha256={digest}). <a href='/'>Back</a>"


@app.route("/admin/ping", methods=["POST"])
def ping():
    host = request.form["host"]
    # FIXED (B602): input validated, args passed as a list, no shell.
    if not HOST_RE.match(host):
        return render_template_string(
            PAGE, notes=[], ping_output="Invalid host format."
        )
    ping_bin = shutil.which("ping")
    if not ping_bin:
        return render_template_string(
            PAGE, notes=[], ping_output="ping unavailable."
        )
    result = subprocess.run(
        [ping_bin, "-n", "1", host],
        shell=False,
        capture_output=True,
        text=True,
        timeout=5,
    )
    return render_template_string(
        PAGE, notes=[], ping_output=result.stdout + result.stderr
    )


if __name__ == "__main__":
    init_db()
    # FIXED (B201): debugger disabled; use a WSGI server in production.
    app.run(debug=False)
