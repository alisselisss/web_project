import datetime

import sqlalchemy as sqlalchemy
from flask_login import UserMixin
from werkzeug.security import generate_password_hash, check_password_hash

from data.db_session import SqlAlchemyBase


class User(SqlAlchemyBase, UserMixin):
    __tablename__ = 'users'

    id = sqlalchemy.Column(sqlalchemy.Integer, primary_key=True, autoincrement=True)
    username = sqlalchemy.Column(sqlalchemy.String, unique=True, nullable=True)
    year_of_birth = sqlalchemy.Column(sqlalchemy.Integer, nullable=True)
    month_of_birth = sqlalchemy.Column(sqlalchemy.Integer, nullable=True)
    day_of_birth = sqlalchemy.Column(sqlalchemy.Integer, nullable=True)
    country = sqlalchemy.Column(sqlalchemy.String, nullable=True)
    email = sqlalchemy.Column(sqlalchemy.String, unique=True, nullable=True)
    hashed_password = sqlalchemy.Column(sqlalchemy.String, nullable=True)
    modified_date = sqlalchemy.Column(sqlalchemy.DateTime, default=datetime.datetime.now())
    photo = sqlalchemy.Column(sqlalchemy.String, unique=True, nullable=True)
    about_me = sqlalchemy.Column(sqlalchemy.String, unique=True, nullable=True)
    followers = sqlalchemy.Column(sqlalchemy.String, nullable=True)
    following = sqlalchemy.Column(sqlalchemy.String, nullable=True)
    restrict = sqlalchemy.Column(sqlalchemy.Boolean, nullable=True, default=False)
    blacklist = sqlalchemy.Column(sqlalchemy.String, nullable=True, default=' ')

    def set_password(self, password):
        self.hashed_password = generate_password_hash(password)

    def check_password(self, password):
        return check_password_hash(self.hashed_password, password)
