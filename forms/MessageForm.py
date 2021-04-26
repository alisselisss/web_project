from flask_wtf import FlaskForm
from wtforms import SubmitField, TextAreaField, StringField
from wtforms.fields.html5 import EmailField
from wtforms.validators import DataRequired


class MessageForm(FlaskForm):
    message = StringField('')
    send = SubmitField('Send')