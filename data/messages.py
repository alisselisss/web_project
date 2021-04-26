import datetime
import sqlalchemy as sqlalchemy

from data.db_session import SqlAlchemyBase


class Messages(SqlAlchemyBase):
    __tablename__ = 'messages'

    id = sqlalchemy.Column(sqlalchemy.Integer, primary_key=True, autoincrement=True)
    from_id = sqlalchemy.Column(sqlalchemy.Integer, sqlalchemy.ForeignKey("users.id"))
    to_id = sqlalchemy.Column(sqlalchemy.Integer, sqlalchemy.ForeignKey("users.id"))
    message_text = sqlalchemy.Column(sqlalchemy.String, nullable=True)
    sending_time = sqlalchemy.Column(sqlalchemy.DateTime, default=datetime.datetime.now())