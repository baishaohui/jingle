# -*- coding: utf-8 -*-
from flask import Blueprint
from app.api.v1 import user
from app.api.v1 import book
from app.api.v1 import client


def create_blueprint_v1():
    bp_v1 = Blueprint("v1", __name__, url_prefix="/v1")
    user.api.register_blueprint(bp_v1)
    book.api.register_blueprint(bp_v1)
    client.api.register_blueprint(bp_v1)
    return bp_v1