"""
MIS5303 Lab 3 - VULNERABLE app (Authentication, Session Security, Privilege
Escalation). Extends the Lab 1/2 application with the admin features the Lab 3
sheet requires (an is_admin column, a /make_admin route, and an /admin panel)
so the auth/session/privilege flaws can be exploited and then fixed.

This file deliberately contains the Lab 3 vulnerabilities:
  [VULN-A] Passwords stored in PLAINTEXT.
  [VULN-B] Session cookies missing HttpOnly/Secure/SameSite; session fixation.
  [VULN-C] Privilege escalation: /make_admin has no authorisation check and the
           /admin panel is reachable by any logged-in (or logged-out) user.

Other planted flaws (SQLi/XSS = Lab 2, upload/command-injection = Lab 4) are
kept as their original insecure form and are out of scope for this lab.
Local educational use only. Run on 127.0.0.1.
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

# [VULN-B] Hardcoded/auto secret key (Lab 1 scope).
app.secret_key = os.environ.get("SECRET_KEY") or secrets.token_hex(32)

# [VULN-B] Insecure session cookie config - protective flags left OFF.
app.config["SESSION_COOKIE_HTTPONLY"] = False
app.config["SESSION_COOKIE_SECURE"] = False

DATABASE = "app.db"
UPLOAD_DIR = "uploads"


def get_db():
    conn = sqlite3.connect(DATABASE)
    conn.row_factory = sqlite3.Row
    return conn


def init_db():
    os.makedirs(UPLOAD_DIR, exist_ok=True)
    conn = get_db()
    # NOTE: users table now carries an is_admin flag for the Lab 3 scenario.
    conn.execute(
        """CREATE TABLE IF NOT EXISTS users (
               id INTEGER PRIMARY KEY AUTOINCREMENT,
               username TEXT UNIQUE NOT NULL,
               password TEXT NOT NULL,
               is_admin INTEGER NOT NULL DEFAULT 0
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
  <p>Logged in as <b>{{ session['username'] }}</b>
     {% if session.get('is_admin') %}(ADMIN){% endif %} -
     <a href="/logout">Logout</a></p>
  <p><a href="/admin">Admin panel</a></p>
  <h2>Your Notes</h2>
  <form method="post" action="/notes">
    <input name="content" placeholder="Write a note">
    <button type="submit">Add Note</button>
  </form>
  <ul>
    {% for n in notes %}<li>{{ n['content'] }}</li>{% endfor %}
  </ul>
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

ADMIN_PAGE = """
<!doctype html>
<title>Admin Panel</title>
<h1>Admin Panel</h1>
<p>Secret admin area. Logged in as <b>{{ session.get('username') }}</b>.</p>
<ul>
  {% for u in users %}
    <li>{{ u['id'] }} - {{ u['username'] }}
        (admin={{ u['is_admin'] }})</li>
  {% endfor %}
</ul>
<a href="/">Home</a>
"""


@app.route("/")
def index():
    notes = []
    if session.get("username"):
        conn = get_db()
        notes = conn.execute(
            "SELECT * FROM notes WHERE username = ?", (session["username"],)
        ).fetchall()
        conn.close()
    return render_template_string(PAGE, notes=notes)


@app.route("/register", methods=["GET", "POST"])
def register():
    error = ""
    if request.method == "POST":
        username = request.form["username"]
        password = request.form["password"]
        conn = get_db()
        try:
            # [VULN-A] Password stored in PLAINTEXT - no hashing/salting.
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
        # [VULN-A] Plaintext comparison of the password.
        user = conn.execute(
            "SELECT * FROM users WHERE username = ? AND password = ?",
            (username, password),
        ).fetchone()
        conn.close()
        if user:
            # [VULN-B] No session.clear() before setting identity -> the
            # pre-login session id is reused (session fixation).
            session["username"] = user["username"]
            session["is_admin"] = bool(user["is_admin"])
            return redirect(url_for("index"))
        error = "Invalid credentials"
    return render_template_string(AUTH_PAGE, mode="Login", error=error)


@app.route("/logout")
def logout():
    session.clear()
    return redirect(url_for("index"))


@app.route("/make_admin")
def make_admin():
    # [VULN-C] PRIVILEGE ESCALATION: no authorisation check at all. Any user
    # (in fact anyone who knows the URL) can promote an account to admin by
    # passing a user_id in the query string.
    user_id = request.args.get("user_id")
    conn = get_db()
    conn.execute("UPDATE users SET is_admin = 1 WHERE id = ?", (user_id,))
    conn.commit()
    conn.close()
    # reflect the new privilege into the current session if it's the same user
    session["is_admin"] = True
    return redirect(url_for("admin"))


@app.route("/admin")
def admin():
    # [VULN-C] BROKEN ACCESS CONTROL: the admin panel only checks that SOMEONE
    # is logged in, not that they are an admin. A normal user reaches it.
    if not session.get("username"):
        return redirect(url_for("login"))
    conn = get_db()
    users = conn.execute("SELECT * FROM users").fetchall()
    conn.close()
    return render_template_string(ADMIN_PAGE, users=users)


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


if __name__ == "__main__":
    init_db()
    app.run(debug=True)
