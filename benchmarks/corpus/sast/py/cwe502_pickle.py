import pickle
from flask import Flask, request
app = Flask(__name__)
@app.route("/load", methods=["POST"])
def load():
    return str(pickle.loads(request.data))
