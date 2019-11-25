# -*- coding: utf-8 -*-
from flask import Blueprint


class ViewPrint(object):

    def __init__(self, name, url_prefix=None):
        self.name = name
        self.url_prefix = url_prefix
        self.rules = []

    def route(self, rule, **options):
        def decorator(f):
            self.rules.append((rule, f, options))
            return f
        return decorator

    def register_blueprint(self, bp: Blueprint, url_prefix=None):
        url_prefix = url_prefix or self.url_prefix or f"/{self.name}"
        for r, f, o in self.rules:
            endpoint = o.pop("endpoint", f.__name__)
            bp.add_url_rule(url_prefix + r, endpoint, f, **o)