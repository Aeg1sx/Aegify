"""Test fixture: Safe Flask application - all vulnerabilities properly mitigated."""

import html
import shlex
import sqlite3
import subprocess
from functools import wraps

from flask import Flask, jsonify, request

app = Flask(__name__)


def auth_required(f):
    @wraps(f)
    def decorated(*args, **kwargs):
        token = request.headers.get("Authorization")
        if not token:
            return jsonify({"error": "unauthorized"}), 401
        return f(*args, **kwargs)

    return decorated


@app.route("/users")
@auth_required
def get_user():
    user_id = request.args.get("id")
    conn = sqlite3.connect("app.db")
    cursor = conn.cursor()
    # Safe: parameterized query
    cursor.execute("SELECT * FROM users WHERE id = ?", (user_id,))
    return jsonify(cursor.fetchone())


@app.route("/search")
@auth_required
def search():
    query = request.args.get("q")
    if not query or len(query) > 100:
        return jsonify({"error": "invalid query"}), 400
    conn = sqlite3.connect("app.db")
    cursor = conn.cursor()
    # Safe: parameterized query
    cursor.execute("SELECT * FROM products WHERE name LIKE ?", (f"%{query}%",))
    return jsonify(cursor.fetchall())


@app.route("/ping")
@auth_required
def ping():
    host = request.args.get("host")
    # Safe: using shlex.quote and list args
    sanitized = shlex.quote(host)
    result = subprocess.run(["ping", "-c", "1", sanitized], capture_output=True)
    return result.stdout


@app.route("/greet")
@auth_required
def greet():
    name = request.args.get("name")
    # Safe: HTML escaped
    safe_name = html.escape(name)
    return f"<h1>Hello {safe_name}</h1>"
