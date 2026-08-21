"""Database access functions - some vulnerable, some safe."""

import sqlite3


def get_connection():
    return sqlite3.connect("app.db")


def query_user(user_id):
    """Vulnerable: string concatenation SQL."""
    conn = get_connection()
    cursor = conn.cursor()
    cursor.execute("SELECT * FROM users WHERE id = " + user_id)
    return cursor.fetchone()


def query_products(query):
    """Safe: parameterized query."""
    conn = get_connection()
    cursor = conn.cursor()
    cursor.execute("SELECT * FROM products WHERE name LIKE ?", (f"%{query}%",))
    return cursor.fetchall()
