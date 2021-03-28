from flask_wtf import FlaskForm
from wtforms import SubmitField, TextAreaField
from wtforms.fields.html5 import EmailField
from wtforms.validators import DataRequired


class AboutMeForm(FlaskForm):
    about = TextAreaField('Tell other users a little information about yourself')
    further = SubmitField('Further')