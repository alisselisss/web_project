from flask_wtf import FlaskForm
from wtforms import PasswordField, SubmitField
from wtforms.validators import DataRequired


class ChangePasswordOldPasswordForm(FlaskForm):
    password = PasswordField('Old password', validators=[DataRequired()])
    submit = SubmitField('Next')