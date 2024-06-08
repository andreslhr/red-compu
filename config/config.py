import os

DB_URI = "mysql+mysqlconnector://{username}:{password}@{hostname}/{databasename}". format(
    username="redcompu",
    password="25-dici-",
    hostname="redcompu.mysql.pythonanywhere-services.com",
    databasename="redcompu$database"

    )
class Config():

    DEBUG = False
    SQLALCHEMY_DATABASE_URI = "sqlite:///:memory:"

    SECRET_KEY = 'TBD'
    SQLALCHEMY_DATABASE_URI = DB_URI

    SQLALCHEMY_DATABASE_URI = "sqlite:///" + os.path.abspath("./database.db")

    MAIL_SERVER = 'smtp.gmail.com'
    MAIL_PORT = 587
    MAIL_USE_TLS = True
    MAIL_USE_SSL = False
    MAIL_USERNAME = 'redcompu872@gmail.com'
    MAIL_PASSWORD = 'ixwx yvjn ldir plgl'
    MAIL_DEFAULT_SENDER = 'redcompu872@gmail.com'