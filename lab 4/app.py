"""
MIS5303 Lab 4 - VULNERABLE app (Dangerous Functions, Insecure File Handling &
Threat Modelling). Focuses on the two Lab 4 features:
  [VULN-D] Command injection: /admin/ping runs a shell command built by string
           concatenation with shell=True, so extra commands can be chained.
  [VULN-E] Insecure file upload + path traversal: /upload saves the file under
           its attacker-controlled name with no extension/type check, and
           /uploads/<name> serves files back, so ../ traversal is possible.

Auth/session and SQLi/XSS flaws are out of scope for this lab and are kept
simple. Local, authorised educational use only. Run on 127.0.0.1.
"""

import os
import secrets
import sqlite3
import subprocess
from flask import (
    Flask,
    request,
    redirect,
    url_for,
    session,
    send_file,
    render_template_string,
)

app = Flask(__name__)
app.secret_key = os.environ.get("SECRET_KEY") or secrets.token_hex(32)

DATABASE = "app.db"
UPLOAD_DIR = "uploads"


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
    return render_template_string(PAGE, ping_output="")


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
    # [VULN-E] Attacker-controlled filename used directly - no extension check,
    # no secure_filename, so "../../hack.txt" escapes the uploads directory.
    path = os.path.join(UPLOAD_DIR, f.filename)
    f.save(path)
    return (
        f"Uploaded {f.filename} to {path}. "
        f"<a href='/uploads/{f.filename}'>view</a> | <a href='/'>Back</a>"
    )


@app.route("/uploads/<path:filename>")
def serve_upload(filename):
    # [VULN-E] Serves files by joining the raw name - path traversal lets a
    # request read files outside the uploads directory.
    return send_file(os.path.join(UPLOAD_DIR, filename))


@app.route("/admin/ping", methods=["POST"])
def ping():
    host = request.form["host"]
    # [VULN-D] Command injection: user input concatenated into a shell string
    # with shell=True, so "8.8.8.8; ls" (or "& dir" on Windows) runs extra
    # commands.
    result = subprocess.run(
        "ping -n 1 " + host, shell=True, capture_output=True, text=True
    )
    return render_template_string(
        PAGE, ping_output=result.stdout + result.stderr
    )


if __name__ == "__main__":
    init_db()
    app.run(debug=True)
