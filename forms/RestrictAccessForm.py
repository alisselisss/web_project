from flask_wtf import FlaskForm
from wtforms import BooleanField, SubmitField
from wtforms.validators import DataRequired


class RestrictAccessForm(FlaskForm):
    restrict = BooleanField('Restrict access')
    submit = SubmitField('Submit')