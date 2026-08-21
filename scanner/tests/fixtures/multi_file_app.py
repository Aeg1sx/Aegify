"""Test fixture: App with inter-function calls for call graph testing."""

from flask import Flask, request

app = Flask(__name__)


def validate_input(data):
    if not data:
        raise ValueError("empty input")
    return data.strip()


def query_database(user_id):
    import sqlite3

    conn = sqlite3.connect("app.db")
    cursor = conn.cursor()
    cursor.execute("SELECT * FROM users WHERE id = " + user_id)
    return cursor.fetchone()


@app.route("/users")
def get_user():
    user_id = request.args.get("id")
    validated = validate_input(user_id)
    result = query_database(validated)
    return str(result)
