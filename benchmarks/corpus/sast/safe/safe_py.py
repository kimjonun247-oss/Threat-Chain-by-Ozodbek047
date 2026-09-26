import sqlite3, subprocess, hashlib, yaml
from flask import Flask, request, redirect, url_for
app = Flask(__name__)
@app.route("/u")
def u():
    conn = sqlite3.connect("db")
    return str(conn.execute("SELECT * FROM users WHERE id = ?", (request.args.get("id"),)).fetchall())
@app.route("/ls")
def ls():
    return subprocess.run(["ls", "--", request.args.get("d", ".")], capture_output=True).stdout
def cfg(t): return yaml.safe_load(t)
def h(b): return hashlib.sha256(b).hexdigest()
@app.route("/go")
def go(): return redirect(url_for("u"))
