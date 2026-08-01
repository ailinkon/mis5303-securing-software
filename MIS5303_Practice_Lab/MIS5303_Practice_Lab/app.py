from flask import Flask,request,redirect,session,render_template
import sqlite3
app=Flask(__name__)
app.secret_key="hardcoded_secret"

def db():
    c=sqlite3.connect("notes.db")
    c.execute("CREATE TABLE IF NOT EXISTS users(id INTEGER PRIMARY KEY, username TEXT,password TEXT)")
    c.execute("CREATE TABLE IF NOT EXISTS notes(id INTEGER PRIMARY KEY, owner_id INT, content TEXT)")
    return c

@app.route("/register",methods=["GET","POST"])
def register():
    if request.method=="POST":
        con=db();con.execute(f"INSERT INTO users(username,password) VALUES('{request.form['username']}','{request.form['password']}')");con.commit()
        return redirect("/login")
    return render_template("register.html")

@app.route("/login",methods=["GET","POST"])
def login():
    if request.method=="POST":
        con=db();cur=con.execute(f"SELECT id FROM users WHERE username='{request.form['username']}' AND password='{request.form['password']}'")
        r=cur.fetchone()
        if r: session["user_id"]=r[0]; return redirect("/notes")
    return render_template("login.html")

@app.route("/notes",methods=["GET","POST"])
def notes():
    if "user_id" not in session:return redirect("/login")
    con=db()
    if request.method=="POST":
        con.execute(f"INSERT INTO notes(owner_id,content) VALUES({session['user_id']},'{request.form['content']}')");con.commit()
    owner=request.args.get("owner_id",session["user_id"])
    rows=con.execute(f"SELECT content FROM notes WHERE owner_id={owner}").fetchall()
    return render_template("notes.html",notes=rows)

app.run(debug=True)
