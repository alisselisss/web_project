from flask_wtf import FlaskForm
from wtforms import SubmitField, IntegerField
from wtforms.validators import DataRequired


class VerificationForm(FlaskForm):
    verification = IntegerField('Verification code', validators=[DataRequired()])
    further = SubmitField('further')