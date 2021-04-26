import datetime
import sqlalchemy as sqlalchemy

from data.db_session import SqlAlchemyBase


class News(SqlAlchemyBase):
    __tablename__ = 'news'

    id = sqlalchemy.Column(sqlalchemy.Integer, primary_key=True, autoincrement=True)
    user_id = sqlalchemy.Column(sqlalchemy.Integer, sqlalchemy.ForeignKey("users.id"))
    news_text = sqlalchemy.Column(sqlalchemy.String, nullable=True)
    creation_time = sqlalchemy.Column(sqlalchemy.DateTime, default=datetime.datetime.now())
    likes = sqlalchemy.Column(sqlalchemy.String, nullable=True, default=' ')
    dislikes = sqlalchemy.Column(sqlalchemy.String, nullable=True, default=' ')