from flask import Blueprint, render_template, request, flash, url_for, redirect
from flask_login import login_user, current_user
from werkzeug.security import check_password_hash, generate_password_hash
from models.models import db, User
from flask_bcrypt import Bcrypt

auth_bp = Blueprint('auth', __name__)
bcrypt = Bcrypt()

@auth_bp.before_request
def check_login():
    if current_user.is_authenticated and request.endpoint == 'auth.login':
        return redirect(url_for('routes.home'))

@auth_bp.route('/login', methods=["GET", "POST"])
def login():
    if current_user.is_authenticated:
        return redirect(url_for('routes.home'))  # Redirige a la página de inicio si ya está autenticado

    if request.method == "POST":
        user = User.query.filter_by(usuario=request.form["username"]).first()
        
        if user and check_password_hash(user.contraseña, request.form["password"]):

            login_user(user)
            flash("Has iniciado sesión correctamente", "success")
            return redirect(url_for('routes.home'))  # Redirige a la página de inicio después de iniciar sesión
        
        flash("Usuario o contraseña incorrecta, intente nuevamente", "danger")

    return render_template("login.html")

@auth_bp.route('/registro', methods=["GET", "POST"]) 
def registro():
    if request.method == "POST":
        usuario = request.form["username"]
        correo = request.form["email"]
        nombre = request.form["nombre"]
        contraseña = request.form["password"]
        repet_password = request.form["repetPassword"]

        if contraseña != repet_password:
            flash("Las contraseñas no coinciden, por favor intentar nuevamente", "danger")
            return redirect(url_for('auth.registro'))
        
        # Verificar si el correo ya está registrado
        user_exists = User.query.filter_by(correo=correo).first()
        if user_exists:
            flash("El correo ya está registrado, por favor usa uno diferente", "danger")
            return redirect(url_for('auth.registro'))

        # Verificar si el usuario ya está registrado
        user_exists = User.query.filter_by(usuario=usuario).first()
        if user_exists:
            flash("El nombre de usuario ya está registrado, por favor usa uno diferente", "danger")
            return redirect(url_for('auth.registro'))
        

        hashed_pw = generate_password_hash(contraseña)
        new_user = User(usuario=usuario, correo=correo, nombre=nombre, contraseña=hashed_pw)
        db.session.add(new_user)
        db.session.commit()

        # Iniciar sesión automáticamente al usuario recién registrado
        login_user(new_user)

        flash("Usuario registrado exitosamente", "success")
        return redirect(url_for('auth.login'))

    return render_template("register.html")

