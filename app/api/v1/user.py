# -*- coding: utf-8 -*-

from app.libs.views import ViewPrint


api = ViewPrint("user")


@api.route("/get", methods=["GET"])
def get_user():
    return "user"


@api.route("/create")
def create_user():
    return "create"