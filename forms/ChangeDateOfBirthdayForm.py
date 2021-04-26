import datetime
import requests

from flask_wtf import FlaskForm
from wtforms import SubmitField, SelectField
from wtforms.validators import DataRequired


class ChangeDateOfBirthdayForm(FlaskForm):
    list_of_months = ['January', 'February', 'March', 'April', 'May', 'June', 'July', 'August', 'September', 'October', 'November', 'December']
    list_of_years = list(map(str, range(datetime.datetime.today().year, datetime.datetime.today().year - 100, -1)))
    list_of_days = list(map(str, range(1, 32)))
    month = SelectField('Month', validators=[DataRequired()], choices=list_of_months)
    day = SelectField('Day', validators=[DataRequired()], choices=list_of_days)
    year = SelectField('Year', validators=[DataRequired()], choices=list_of_years)
    submit = SubmitField('Change')