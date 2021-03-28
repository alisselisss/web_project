from flask_wtf import FlaskForm
from wtforms import SubmitField, StringField
from wtforms.fields.html5 import EmailField
from wtforms.validators import DataRequired


class ForgotForm(FlaskForm):
    login = StringField('Username or email address', validators=[DataRequired()])
    search = SubmitField('Search')