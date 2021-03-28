import datetime
import json
import requests

from flask_wtf import FlaskForm
from wtforms import StringField, SubmitField, SelectField
from wtforms.fields.html5 import EmailField
from wtforms.validators import DataRequired


class RegisterForm(FlaskForm):
    list_of_months = ['January', 'February', 'March', 'April', 'May', 'June', 'July', 'August', 'September', 'October', 'November', 'December']
    list_of_countries = requests.get("https://api.printful.com/countries")
    json_list_of_countries = list_of_countries.json()
    list_of_countries = list(map(lambda x: x['name'], json_list_of_countries['result']))
    list_of_years = list(map(str, range(datetime.datetime.today().year, datetime.datetime.today().year - 100, -1)))
    list_of_days = list(map(str, range(1, 32)))
    email = EmailField('Email', validators=[DataRequired()])
    username = StringField('Userame', validators=[DataRequired()])
    month = SelectField('Month', validators=[DataRequired()], choices=list_of_months)
    day = SelectField('Day', validators=[DataRequired()], choices=list_of_days)
    year = SelectField('Year', validators=[DataRequired()], choices=list_of_years)
    country = SelectField('Country', validators=[DataRequired()], choices=list_of_countries)
    further = SubmitField('further')