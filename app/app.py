# -*- coding: utf-8 -*-
from flask import Flask


def register_blueprint(app: Flask):
    from app.api.v1 import create_blueprint_v1
    bp_v1 = create_blueprint_v1()
    app.register_blueprint(bp_v1)


def register_plugins(app_):
    from app.models.base import db
    db.init_app(app_)
    with app_.app_context():
        db.create_all()


def create_app():
    app = Flask(__name__)
    app.config.from_object("app.config.secure")
    app.config.from_object("app.config.settings")
    register_blueprint(app)
    register_plugins(app)
    return app