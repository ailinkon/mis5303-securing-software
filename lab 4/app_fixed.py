"""
MIS5303 Lab 4 - FIXED app (Dangerous Functions & Insecure File Handling).
Remediated counterpart to app.py. Each change is marked FIX.

  [FIX-D] Command injection closed: input is validated against a strict
          hostname/IP pattern, and ping is run with an argument LIST and
          shell=False, so no shell metacharacters are interpreted.
  [FIX-E] File upload secured: werkzeug secure_filename strips path components,
          an extension allow-list blocks .py/.exe/.php, a size limit is set,
          and files are served with send_from_directory so ../ traversal is
          rejected.

Local, authorised educational use only.
"""

import os
import re
import secrets
import shutil
import sqlite3
import subprocess
from werkzeug.utils import secure_filename
from flask import (
    Flask,
    request,
    redirect,
    url_for,
    session,
    abort,
    send_from_directory,
    render_template_string,
)

app = Flask(__name__)
app.secret_key = os.environ.get("SECRET_KEY") or secrets.token_hex(32)

DATABASE = "app.db"
UPLOAD_DIR = "uploads"

# [FIX-E] Allow-list of safe extensions + a max upload size (2 MB).
ALLOWED_EXTENSIONS = {".txt", ".jpg", ".jpeg", ".png", ".pdf"}
app.config["MAX_CONTENT_LENGTH"] = 2 * 1024 * 1024

# [FIX-D] A host must look like a hostname or IPv4 - no ; & | or spaces.
HOST_RE = re.compile(r"^[A-Za-z0-9.\-]{1,253}$")


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
    conn.commit()
    conn.close()


PAGE = """
<!doctype html>
<title>Secure(?) Notes</title>
<h1>Secure(?) Notes App</h1>
{% if session.get('username') %}
  <p>Logged in as <b>{{ session['username'] }}</b> -
     <a href="/logout">Logout</a></p>
  <h2>Upload a File</h2>
  <form method="post" action="/upload" enctype="multipart/form-data">
    <input type="file" name="file">
    <button type="submit">Upload</button>
  </form>
  {% if message %}<p style="color:green">{{ message }}</p>{% endif %}
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
    return render_template_string(PAGE, ping_output="", message="")


@app.route("/register", methods=["GET", "POST"])
def register():
    error = ""
    if request.method == "POST":
        username = request.form["username"]
        password = request.form["password"]
        conn = get_db()
        try:
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


@app.route("/upload", methods=["POST"])
def upload():
    if not session.get("username"):
        return redirect(url_for("login"))
    f = request.files["file"]
    # [FIX-E] Strip any path components and check the extension allow-list.
    filename = secure_filename(f.filename or "")
    ext = os.path.splitext(filename)[1].lower()
    if not filename or ext not in ALLOWED_EXTENSIONS:
        return (
            "File type not allowed. Permitted: "
            + ", ".join(sorted(ALLOWED_EXTENSIONS))
            + ". <a href='/'>Back</a>"
        ), 400
    path = os.path.join(UPLOAD_DIR, filename)
    f.save(path)
    return render_template_string(
        PAGE, ping_output="",
        message=f"Uploaded {filename} safely.",
    )


@app.route("/uploads/<path:filename>")
def serve_upload(filename):
    # [FIX-E] send_from_directory rejects any traversal outside UPLOAD_DIR.
    safe = secure_filename(os.path.basename(filename))
    if not safe:
        abort(404)
    return send_from_directory(UPLOAD_DIR, safe)


@app.route("/admin/ping", methods=["POST"])
def ping():
    host = request.form["host"]
    # [FIX-D] Validate first: reject anything that isn't a plain host/IP.
    if not HOST_RE.match(host):
        return render_template_string(
            PAGE, ping_output="Invalid host. Only letters, digits, dots and "
            "hyphens are allowed.", message="",
        )
    ping_bin = shutil.which("ping")
    if not ping_bin:
        return render_template_string(
            PAGE, ping_output="ping is not available.", message="",
        )
    # [FIX-D] Argument LIST + shell=False: metacharacters are never interpreted.
    result = subprocess.run(
        [ping_bin, "-n", "1", host],
        shell=False, capture_output=True, text=True, timeout=5,
    )
    return render_template_string(
        PAGE, ping_output=result.stdout + result.stderr, message="",
    )


if __name__ == "__main__":
    init_db()
    app.run(debug=True)
