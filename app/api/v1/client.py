# -*- coding: utf-8 -*-
from flask import request

from app.libs.enums import ClientTypeEnum
from app.libs.views import ViewPrint
from app.models.user import UserModel
from app.validators.forms import ClientForm, UserEmailForm

api = ViewPrint("client")


@api.route("/register", methods=["POST"])
def register():
    form = ClientForm(data=request.json)
    if form.validate():
        promise = {
            ClientTypeEnum.USER_EMAIL: __register_user_by_email
        }
        promise[form.type.data]()
    return "success"


def __register_user_by_email():
    form = UserEmailForm(data=request.json)
    if form.validate():
        UserModel.register_by_email(
            form.nickname.data,
            form.account.data,
            form.secret.data
        )