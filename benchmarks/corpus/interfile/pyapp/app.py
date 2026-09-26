from flask import Flask, request

from store import find_user, archive

app = Flask(__name__)


@app.route('/user')
def user():
    # The request value leaves this file here; the query is built in store.py.
    return find_user(request.args.get('name', ''))


@app.route('/archive')
def make_archive():
    return archive(request.args.get('folder', '.'))
