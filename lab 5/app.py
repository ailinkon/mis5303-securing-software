"""
MIS5303 Lab 5 - BASELINE app (Cryptography, Hashing & Data Protection).
This is the "before" state: passwords and note content are stored as plain
text. Part 2 and Part 3 of the lab add bcrypt password hashing and Fernet
note encryption on top of this baseline - see app_fixed.py.

Local, authorised educational use only. Run on 127.0.0.1.
"""

import os
import secrets
import sqlite3
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

DATABASE = "app.db"


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
        # [BASELINE] content read straight from the DB - plain text.
        notes = [r["content"] for r in rows]
    return render_template_string(PAGE, notes=notes)


@app.route("/register", methods=["GET", "POST"])
def register():
    error = ""
    if request.method == "POST":
        username = request.form["username"]
        password = request.form["password"]
        conn = get_db()
        try:
            # [BASELINE] Password stored in PLAINTEXT - no hashing/salting.
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
        row = conn.execute(
            "SELECT id, password, is_admin FROM users WHERE username = ?",
            (username,),
        ).fetchone()
        conn.close()
        # [BASELINE] Plain-text comparison of the password.
        if row and row["password"] == password:
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
    conn = get_db()
    # [BASELINE] Note content stored in PLAINTEXT.
    conn.execute(
        "INSERT INTO notes (owner_id, content) VALUES (?, ?)",
        (session["user_id"], content),
    )
    conn.commit()
    conn.close()
    return redirect(url_for("index"))


if __name__ == "__main__":
    init_db()
    app.run(debug=True)
