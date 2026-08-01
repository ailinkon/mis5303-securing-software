"""
MIS5303 Lab 3 - FIXED app (Authentication, Session Security, Privilege
Escalation). Remediated counterpart to app.py. Each change is marked FIXED so
the two files can be diffed for the before/after write-up.

Fixes in scope for Lab 3:
  [FIX-A] Password hashing - bcrypt with a per-password salt (as the lab sheet
          specifies). argon2 would be an equally valid choice.
  [FIX-B] Session hardening - HttpOnly, Secure, SameSite cookie flags, an idle
          timeout, and session.clear() on login to stop session fixation.
  [FIX-C] Access control - an admin_required check protects the /admin panel,
          and /make_admin now verifies the caller is already an admin and is
          POST-only, closing the privilege-escalation path.

Out-of-scope flaws (SQLi/XSS = Lab 2, upload/command-injection = Lab 4) are left
as their original state so Lab 3's evidence stays focused. Local use only.
"""

import os
import secrets
import sqlite3
from datetime import timedelta
from functools import wraps
import bcrypt
from flask import (
    Flask,
    request,
    redirect,
    url_for,
    session,
    abort,
    render_template_string,
)

app = Flask(__name__)

# Secret key from the environment, random fallback for local dev.
app.secret_key = os.environ.get("SECRET_KEY") or secrets.token_hex(32)

# [FIX-B] Protective session cookie flags + idle timeout.
app.config.update(
    SESSION_COOKIE_HTTPONLY=True,   # JavaScript cannot read the cookie
    SESSION_COOKIE_SAMESITE="Lax",  # not sent on cross-site requests (CSRF)
    # NOTE: Secure=True is REQUIRED in production behind HTTPS. On plain
    # http://127.0.0.1 the browser would then refuse to send the cookie and
    # login would appear to break, so it is False for local testing only.
    SESSION_COOKIE_SECURE=False,
    PERMANENT_SESSION_LIFETIME=timedelta(minutes=15),
)

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


def admin_required(view):
    # [FIX-C] Authorisation guard: reads the admin flag from the DATABASE
    # (authoritative), never trusting a client-held value alone.
    @wraps(view)
    def wrapper(*args, **kwargs):
        if not session.get("username"):
            return redirect(url_for("login"))
        conn = get_db()
        row = conn.execute(
            "SELECT is_admin FROM users WHERE username = ?",
            (session["username"],),
        ).fetchone()
        conn.close()
        if not row or not row["is_admin"]:
            abort(403)
        return view(*args, **kwargs)
    return wrapper


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
            # [FIX-A] Store a bcrypt salted hash, never the plaintext.
            pw_hash = bcrypt.hashpw(
                password.encode("utf-8"), bcrypt.gensalt(rounds=12)
            ).decode("utf-8")
            conn.execute(
                "INSERT INTO users (username, password) VALUES (?, ?)",
                (username, pw_hash),
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
            "SELECT * FROM users WHERE username = ?", (username,)
        ).fetchone()
        conn.close()
        # [FIX-A] Verify the supplied password against the stored bcrypt hash.
        if user and bcrypt.checkpw(
            password.encode("utf-8"), user["password"].encode("utf-8")
        ):
            # [FIX-B] Clear any pre-login session to defeat session fixation,
            # then issue a fresh session bound to this user.
            session.clear()
            session.permanent = True
            session["username"] = user["username"]
            session["is_admin"] = bool(user["is_admin"])
            return redirect(url_for("index"))
        error = "Invalid credentials"
    return render_template_string(AUTH_PAGE, mode="Login", error=error)


@app.route("/logout")
def logout():
    session.clear()
    return redirect(url_for("index"))


@app.route("/make_admin", methods=["POST"])
@admin_required
def make_admin():
    # [FIX-C] Only an authenticated admin can reach this (admin_required), and
    # it is POST-only so it cannot be triggered by a crafted link/GET.
    user_id = request.form.get("user_id")
    conn = get_db()
    conn.execute("UPDATE users SET is_admin = 1 WHERE id = ?", (user_id,))
    conn.commit()
    conn.close()
    return redirect(url_for("admin"))


@app.route("/admin")
@admin_required
def admin():
    # [FIX-C] Protected by admin_required - normal users get 403.
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
