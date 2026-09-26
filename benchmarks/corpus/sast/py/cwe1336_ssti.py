from flask import Flask, request, render_template_string
app = Flask(__name__)
@app.route("/t")
def t():
    return render_template_string("Hi " + request.args.get("n"))
