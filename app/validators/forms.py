# -*- coding: utf-8 -*-
from wtforms import Form, StringField, IntegerField
from wtforms.validators import DataRequired, length, Email, Regexp, ValidationError

from app.libs.enums import ClientTypeEnum
from app.models.user import UserModel


class ClientForm(Form):
    account = StringField(validators=[
        DataRequired(), length(min=5, max=32)])
    secret = StringField()
    type = IntegerField(validators=[DataRequired()])

    def validate_type(self, field):
        try:
            client = ClientTypeEnum(field.data)
        except ValueError as e:
            raise e
        self.type.data = client


class UserEmailForm(Form):
    account = StringField(validators=[
        DataRequired(), length(min=5, max=32),
        Email(message="invalid email")
    ])
    secret = StringField([
        DataRequired(),
        Regexp(r"^[A-Za-z0-9_*&$#@]{6,22}")
    ])
    nickname = StringField(validators=[
        DataRequired(), length(min=2, max=22)
    ])

    def validate_account(self, field):
        if UserModel.query.filter_by(email=field.data).first():
            raise ValidationError()