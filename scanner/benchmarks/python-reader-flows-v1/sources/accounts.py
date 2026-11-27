from flask import request, session

from labels import compact


def submitted_name():
    submitted = request.query_string.decode("utf-8")
    label = compact(text=submitted, prefix="member")
    session["user_id"] = label


def default_name():
    submitted = request.args.get("name", "")
    label = compact(text="guest", prefix="member")
    session["user_id"] = label


def direct_name():
    submitted = request.args.get("name", "")
    session["user_id"] = submitted
