"""Test fixture: Vulnerable Flask application for testing SAST detection."""

import sqlite3
import subprocess

from flask import Flask, render_template_string, request

app = Flask(__name__)


@app.route("/users")
def get_user():
    user_id = request.args.get("id")
    conn = sqlite3.connect("app.db")
    cursor = conn.cursor()
    # SQL Injection: string concatenation
    cursor.execute("SELECT * FROM users WHERE id = " + user_id)
    return cursor.fetchone()


@app.route("/search")
def search():
    query = request.args.get("q")
    conn = sqlite3.connect("app.db")
    cursor = conn.cursor()
    # SQL Injection: f-string
    cursor.execute(f"SELECT * FROM products WHERE name LIKE '%{query}%'")
    return cursor.fetchall()


@app.route("/ping")
def ping():
    host = request.args.get("host")
    # Command Injection
    result = subprocess.run(f"ping -c 1 {host}", shell=True, capture_output=True)
    return result.stdout


@app.route("/render")
def render():
    name = request.args.get("name")
    # XSS via template injection
    return render_template_string(f"<h1>Hello {name}</h1>")


@app.route("/file")
def read_file():
    filename = request.args.get("file")
    # Path Traversal
    with open(f"/data/{filename}") as f:
        return f.read()


@app.route("/eval")
def evaluate():
    expr = request.args.get("expr")
    # Code Execution
    result = eval(expr)
    return str(result)
