import os
from flask import Flask, request
app = Flask(__name__)
@app.route("/ping")
def ping():
    host = request.args.get("host")
    return os.popen("ping -c 1 " + host).read()
