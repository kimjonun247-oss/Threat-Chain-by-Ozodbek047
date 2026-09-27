from flask import Flask, request
import sqlite3
app = Flask(__name__)
@app.route("/u")
def u():
    conn = sqlite3.connect("db")
    cur = conn.cursor()
    cur.execute("SELECT * FROM users WHERE id = '%s'" % request.args.get("id"))
    return str(cur.fetchall())
