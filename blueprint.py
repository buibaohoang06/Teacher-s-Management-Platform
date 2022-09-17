from re import template
from flask import Blueprint, render_template

bp = Blueprint('test', __name__, static_folder="static", template_folder="templates")

@bp.route("/test")
def test():
    return "Test"