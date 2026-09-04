"""Owned negative controls paired with the Python positive controls."""

import shlex
import subprocess

import requests
from flask import request


def safe_sql(cursor):
    user_id = request.args.get("id")
    return cursor.execute("SELECT * FROM users WHERE id = ?", (user_id,))


def safe_command():
    host = shlex.quote(request.args.get("host"))
    return subprocess.run(["ping", "-c", "1", host], shell=False)


def safe_path():
    filename = validate_path(request.args.get("file"))
    return open("/srv/uploads/" + filename)


def safe_fixed_origin_request():
    owner = request.args.get("owner")
    return requests.get(f"https://api.github.com/repos/{owner}")
