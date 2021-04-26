from flask_wtf import FlaskForm
from flask_wtf.file import FileRequired, FileAllowed
from wtforms import SubmitField, StringField, TextAreaField, FileField


class EditProfileForm(FlaskForm):
    username = StringField('Username')
    about = TextAreaField('About me')
    submit = SubmitField('Save')