from flask import Flask, request, make_response
app = Flask(__name__)
@app.route("/hi")
def hi():
    return make_response("<h1>Hello " + request.args.get("name") + "</h1>")
