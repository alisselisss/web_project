from flask_wtf import FlaskForm
from flask_wtf.file import FileField, FileRequired, FileAllowed
from wtforms import SubmitField


class UploadPhotoForm(FlaskForm):
    upload = FileField('image', validators=[FileRequired(), FileAllowed(['jpg', 'png'])])
    further = SubmitField('further')
