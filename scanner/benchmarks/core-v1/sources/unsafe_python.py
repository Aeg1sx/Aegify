"""Owned positive controls for Aegify's core taint benchmark."""

import subprocess

import requests
from flask import request


def unsafe_sql(cursor):
    user_id = request.args.get("id")
    return cursor.execute("SELECT * FROM users WHERE id = " + user_id)


def unsafe_command():
    host = request.args.get("host")
    return subprocess.run("ping -c 1 " + host, shell=True)


def unsafe_path():
    filename = request.args.get("file")
    return open("/srv/uploads/" + filename)


def unsafe_code_execution():
    expression = request.args.get("expression")
    return eval(expression)


def unsafe_ssrf():
    target = request.args.get("url")
    return requests.get(target)
