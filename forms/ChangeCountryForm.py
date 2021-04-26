import json
import requests

from flask_wtf import FlaskForm
from wtforms import SubmitField, SelectField
from wtforms.validators import DataRequired


class ChangeCountryForm(FlaskForm):
    list_of_countries = requests.get("https://api.printful.com/countries")
    json_list_of_countries = list_of_countries.json()
    list_of_countries = list(map(lambda x: x['name'], json_list_of_countries['result']))
    country = SelectField('Country', validators=[DataRequired()], choices=list_of_countries)
    submit = SubmitField('Change')