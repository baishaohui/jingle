# -*- coding: utf-8 -*-
from app.app import create_app

app = create_app()

app.run(debug=True)