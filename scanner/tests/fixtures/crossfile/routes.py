"""Route handlers that call functions in db.py and utils.py."""

from db import query_products, query_user
from flask import Flask, request
from utils import validate_input

app = Flask(__name__)


@app.route("/users")
def get_user():
    user_id = request.args.get("id")
    validated = validate_input(user_id)
    result = query_user(validated)
    return str(result)


@app.route("/search")
def search():
    query = request.args.get("q")
    result = query_products(query)
    return str(result)
