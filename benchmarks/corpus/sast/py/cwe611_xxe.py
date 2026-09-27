from lxml import etree
from flask import request, Flask
app = Flask(__name__)
@app.route("/x", methods=["POST"])
def x():
    parser = etree.XMLParser(resolve_entities=True)
    return etree.tostring(etree.fromstring(request.data, parser))
