"""
MIS5303 Lab 5 - PROTECTED app (Cryptography, Hashing & Data Protection).
Adds three controls on top of app.py:

  [CRYPTO-1] Password hashing: bcrypt with a per-password salt (Part 2).
  [CRYPTO-2] Note encryption: Fernet symmetric encryption of note content,
             so the database never holds readable clinical/personal text
             (Part 3).
  [CRYPTO-3] Secure session cookies: HttpOnly/SameSite flags (supports the
             "Sessions" row of the Part 4 architect table).

Key management (documented for Part 3/4):
  The Fernet key is loaded from the FERNET_KEY environment variable. If it
  is not set, a key is generated and written to secret.key for local
  demo purposes ONLY, with a warning printed to the console. In production
  this key must instead be generated and stored in a managed secret store
  (e.g. AWS Secrets Manager or AWS KMS), never committed to source control
  or left on disk in plain text, and rotated on a schedule with re-
  encryption of existing data - a manual key file is a demo convenience,
  not a production design.

Local, authorised educational use only. Run on 127.0.0.1.
"""

import os
import secrets
import sqlite3
from datetime import timedelta
import bcrypt
from cryptography.fernet import Fernet, InvalidToken
from flask import (
    Flask,
    request,
    redirect,
    url_for,
    session,
    render_template_string,
)

app = Flask(__name__)
app.secret_key = os.environ.get("SECRET_KEY") or secrets.token_hex(32)

# [CRYPTO-3] Harden session cookies + add an idle timeout.
app.config.update(
    SESSION_COOKIE_HTTPONLY=True,
    SESSION_COOKIE_SAMESITE="Lax",
    # NOTE: Secure=True is required in production behind HTTPS; it is left
    # False here only so the cookie still works over local http://127.0.0.1.
    SESSION_COOKIE_SECURE=False,
    PERMANENT_SESSION_LIFETIME=timedelta(minutes=15),
)

DATABASE = "app.db"
KEY_FILE = "secret.key"


def load_or_create_fernet_key():
    # [CRYPTO-2] Key management: prefer an environment variable; fall back to
    # a local demo key file with a loud warning. See module docstring.
    env_key = os.environ.get("FERNET_KEY")
    if env_key:
        return env_key.encode("utf-8")
    if os.path.exists(KEY_FILE):
        with open(KEY_FILE, "rb") as fh:
            return fh.read()
    print(
        "[WARNING] No FERNET_KEY set - generating a NEW local demo key at "
        f"{KEY_FILE}. This is NOT safe for production. In production, "
        "generate the key with a managed secret store (e.g. AWS Secrets "
        "Manager / KMS), never store it beside the code, and rotate it "
        "on a schedule."
    )
    key = Fernet.generate_key()
    with open(KEY_FILE, "wb") as fh:
        fh.write(key)
    return key


FERNET = Fernet(load_or_create_fernet_key())


def get_db():
    conn = sqlite3.connect(DATABASE)
    conn.row_factory = sqlite3.Row
    return conn


def init_db():
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
               owner_id INTEGER NOT NULL,
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
    {% for n in notes %}<li>{{ n }}</li>{% endfor %}
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


@app.route("/")
def index():
    notes = []
    if session.get("user_id"):
        conn = get_db()
        rows = conn.execute(
            "SELECT content FROM notes WHERE owner_id = ?",
            (session["user_id"],),
        ).fetchall()
        conn.close()
        # [CRYPTO-2] Decrypt on the way out so the app still displays
        # readable notes even though the database only holds ciphertext.
        for r in rows:
            try:
                notes.append(FERNET.decrypt(r["content"].encode("utf-8")).decode("utf-8"))
            except InvalidToken:
                notes.append("[unreadable - wrong key]")
    return render_template_string(PAGE, notes=notes)


@app.route("/register", methods=["GET", "POST"])
def register():
    error = ""
    if request.method == "POST":
        username = request.form["username"]
        password = request.form["password"].encode("utf-8")
        conn = get_db()
        try:
            # [CRYPTO-1] Hash with bcrypt (auto-salted) before storing.
            hashed = bcrypt.hashpw(password, bcrypt.gensalt(rounds=12))
            conn.execute(
                "INSERT INTO users (username, password) VALUES (?, ?)",
                (username, hashed.decode("utf-8")),
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
        password = request.form["password"].encode("utf-8")
        conn = get_db()
        row = conn.execute(
            "SELECT id, password, is_admin FROM users WHERE username = ?",
            (username,),
        ).fetchone()
        conn.close()
        # [CRYPTO-1] Verify against the bcrypt hash, never a raw comparison.
        if row and bcrypt.checkpw(password, row["password"].encode("utf-8")):
            # [CRYPTO-3] Clear any pre-login session first (fixation defence).
            session.clear()
            session.permanent = True
            session["user_id"] = row["id"]
            session["username"] = username
            return redirect(url_for("index"))
        error = "Invalid credentials"
    return render_template_string(AUTH_PAGE, mode="Login", error=error)


@app.route("/logout")
def logout():
    session.clear()
    return redirect(url_for("index"))


@app.route("/notes", methods=["POST"])
def add_note():
    if not session.get("user_id"):
        return redirect(url_for("login"))
    content = request.form["content"]
    # [CRYPTO-2] Encrypt before it ever reaches the database.
    encrypted_content = FERNET.encrypt(content.encode("utf-8"))
    conn = get_db()
    conn.execute(
        "INSERT INTO notes (owner_id, content) VALUES (?, ?)",
        (session["user_id"], encrypted_content.decode("utf-8")),
    )
    conn.commit()
    conn.close()
    return redirect(url_for("index"))


if __name__ == "__main__":
    init_db()
    app.run(debug=True)
