"""Source-only fixtures for command argument construction."""

import subprocess

from flask import request


def built_for_platform(is_default):
    title = request.args.get("title", "")
    args = []
    if is_default:
        args.append("/bin/sh")
        args.append("-c")
    else:
        args.extend(["/bin/bash", "-lc"])
    args.append(title)
    return subprocess.run(args)


def value_at_append():
    title = request.args.get("title", "")
    args = ["sh", "-c"]
    args.append(title)
    title = "printf ready"
    return subprocess.run(args)


def value_after_append():
    title = "printf ready"
    args = ["sh", "-c"]
    args.append(title)
    title = request.args.get("title", "")
    return subprocess.run(args)


def independent_argument():
    title = request.args.get("title", "")
    args = ["sh", "-c"]
    args.append("printf ready")
    args.append(title)
    return subprocess.run(args)


def windows_command():
    title = request.args.get("title", "")
    args = ["cmd.exe", "/c", "echo"]
    args.append(title)
    return subprocess.run(args)
