import sqlite3
import subprocess


def find_user(name):
    connection = sqlite3.connect('app.db')
    query = build_query(name)
    return str(connection.execute(query).fetchall())


def build_query(name):
    return "SELECT * FROM users WHERE name = '" + name + "'"


def archive(folder):
    return subprocess.run('tar czf out.tgz ' + folder, shell=True, capture_output=True).stdout.decode()
