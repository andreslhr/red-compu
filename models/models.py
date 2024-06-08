from flask_sqlalchemy import SQLAlchemy
from flask_login import UserMixin

db = SQLAlchemy()

class User(db.Model, UserMixin):
    id = db.Column(db.Integer, primary_key=True)
    usuario = db.Column(db.String(50), unique=True, nullable=False)
    correo = db.Column(db.String(120), unique=True, nullable=False)
    nombre = db.Column(db.String(120), unique=True, nullable=False)
    contrasena = db.Column(db.String(60), nullable=False)
    perfil_details = db.Column(db.String(250))
    acercademi = db.Column(db.String(250))
    ubicacion = db.Column(db.String(250))
    pais = db.Column(db.String(250))
    fecha = db.Column(db.Date)
    telefono = db.Column(db.String(250))

    def __repr__(self):
        return f"User('{self.username}', '{self.email}')"