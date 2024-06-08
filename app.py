from flask import Flask, flash, redirect, url_for, request, render_template, current_app
from flask_login import LoginManager, logout_user, login_required, current_user
from flask_mail import Mail, Message
from itsdangerous import TimedSerializer, SignatureExpired, BadSignature
from flask_bcrypt import Bcrypt
from datetime import datetime


from routes.routes import routes_bp
from models.models import db, User
from routes.AuthRoutes import auth_bp
from config.config import Config


def create_app():

    app = Flask(__name__)
    app.config.from_object(Config)
    app.config["SQLALCHEMY_TRACK_MODIFICATIONS"] = False
    bcrypt = Bcrypt(app)

    db.init_app(app)

    # Configurar Flask-Login
    login_manager = LoginManager(app)
    login_manager.login_view = 'auth.login'
    login_manager.login_message = "Debes iniciar sesión para acceder a este contenido."
    login_manager.login_message_category = "danger"

    @login_manager.user_loader
    def load_user(user_id):
        return User.query.get(int(user_id))

    mail = Mail(app)

    app.register_blueprint(auth_bp)
    app.register_blueprint(routes_bp)


    #DEF RECUPERACION DE CLAVE POR CORREO
    def generate_token(email):
        s = TimedSerializer(current_app.config['SECRET_KEY'])  # No se especifica la expiración aquí
        token = s.dumps({'email': email})
        return token

    def send_reset_email(email, token):
        reset_link = url_for('reset_password', token=token, _external=True)
        subject = 'Restablecer Contraseña'
        body_html = render_template('recuperacion_de_clave_email.html', reset_link=reset_link)

        msg = Message(subject, sender='redcompu872@gmail.com', recipients=[email])
        msg.html = body_html
        mail.send(msg)

    def send_password_changed_email(email):
        subject = 'Contraseña Cambiada'
        body_html = """
        <p>Tu contraseña ha sido cambiada correctamente. ¡Gracias por utilizar nuestros servicios!</p>
        """
        msg = Message(subject, sender='redcompu872@gmail.com', recipients=[email])
        msg.html = body_html
        mail.send(msg)

    def verify_token(token):
        s = TimedSerializer(current_app.config['SECRET_KEY'])
        try:
            data = s.loads(token)
            return data['email']
        except SignatureExpired:
            # Token expirado
            return None
        except BadSignature:
            # Token inválido
            return None


    #ENVIO DE CORREO ELECTRONICO
    @app.route('/enviar_correo_web', methods=["GET", "POST"])
    def enviar_correo_web():
        if request.method == 'POST':

            correo_usuario = request.form['correo']
            print(f"Correo del usuario: {correo_usuario}")

            cedula = request.form['cedula']
            nombre = request.form['nombre']
            telefono = request.form['telefono']
            pais = request.form['pais']
            direccion = request.form['direccion']
            mensaje = request.form['mensaje']

        # Crear el mensaje de correo
            msg = Message(subject="Solicitud de servicio de Desarrollo Web",
                          sender='toexample@gmail.com',
                        recipients=['redcompu872@gmail.com'])


        # Agregar el contenido del mensaje con el número de referencia
            msg.body = f"Los siguientes datos fueron enviados:\n\nTelefono: {telefono}\nCédula: {cedula}\nNombre: {nombre}\nTelefono:  {telefono}\nPais: {pais}\nCorreo: {correo_usuario}\nDireccion: {direccion}\nMensaje: {mensaje}"

            try:

        # Enviar el correo
                 mail.send(msg)
        # Agregar mensaje flash de confirmación
                 flash("Solicitud enviada exitosamente", "success")
        # Redirigir a una plantilla de confirmación
                 return redirect(url_for('routes.desarrollo_web'))

            except Exception as e:
                flash(f"Error al enviar la solicitud: {str(e)}", "danger")
                return redirect(url_for('routes.desarrollo_web'))


    #ENVIO DE CORREO ELECTRONICO
    @app.route('/enviar_correo_grafico', methods=["GET", "POST"])
    def enviar_correo_grafico():
        if request.method == 'POST':

            correo_usuario = request.form['correo']
            print(f"Correo del usuario: {correo_usuario}")

            cedula = request.form['cedula']
            nombre = request.form['nombre']
            telefono = request.form['telefono']
            pais = request.form['pais']
            direccion = request.form['direccion']
            mensaje = request.form['mensaje']

        # Crear el mensaje de correo
            msg = Message(subject="Solicitud de servicio de Diseño Grafico",
                          sender='toexample@gmail.com',
                        recipients=['redcompu872@gmail.com'])


        # Agregar el contenido del mensaje con el número de referencia
            msg.body = f"Los siguientes datos fueron enviados:\n\nTelefono: {telefono}\nCédula: {cedula}\nNombre: {nombre}\nTelefono:  {telefono}\nPais: {pais}\nCorreo: {correo_usuario}\nDireccion: {direccion}\nMensaje: {mensaje}"

            try:

        # Enviar el correo
                 mail.send(msg)
        # Agregar mensaje flash de confirmación
                 flash("Solicitud enviada exitosamente", "success")
        # Redirigir a una plantilla de confirmación
                 return redirect(url_for('routes.diseño_grafico'))

            except Exception as e:
                flash(f"Error al enviar la solicitud: {str(e)}", "danger")
                return redirect(url_for('routes.diseño_grafico'))


    @app.route('/enlace-send', methods=['GET', 'POST'])
    def send_link():
        if request.method == 'POST':
            email = request.form['email']
            user = User.query.filter_by(correo=email).first()

            if user:
                # Supongamos que ya tienes definidas tus funciones para generar el token y enviar el correo
                token = generate_token(email)
                send_reset_email(email, token)
                flash('Se ha enviado un enlace de recuperación a tu correo electrónico.', 'success')
                return redirect(url_for('auth.login'))
            else:
                flash('Correo electrónico no registrado.', 'danger')

        return render_template('login.html')


    @app.route('/reset_password/<token>', methods=['GET', 'POST'])
    def reset_password(token):
        if request.method == 'POST':
            password = request.form['new_password']
            confirm_password = request.form['confirm_password']

            if password == confirm_password:
                email = verify_token(token)
                if email:
                    hashed_password = bcrypt.generate_password_hash(password).decode('utf-8')
                    user = User.query.filter_by(correo=email).first()
                    if user:
                        user.contrasena = hashed_password
                        db.session.commit()
                        send_password_changed_email(email)
                        flash('Contraseña actualizada correctamente.', 'success')
                        return redirect(url_for('routes.home'))
                    else:
                        flash('Usuario no encontrado.', 'danger')
                else:
                    flash('Token no válido o expirado.', 'danger')
            else:
                flash('Las contraseñas no coinciden.', 'danger')

        return render_template('reset_password.html', token=token)

    @app.route('/actualizar_datos', methods=['GET', 'POST'])
    @login_required
    def actualizar_datos():
        if request.method == 'POST':
            correo = request.form['correo']
            acercademi = request.form['acercademi']
            perfil = request.form['miperfil']
            ubicacion = request.form['direccion']
            pais = request.form['pais']
            telefono = request.form['telefono']
            fecha_str  = request.form['fecha']

            # Convertir la cadena de fecha a un objeto datetime.date
            if fecha_str:
                try:
                    fecha = datetime.strptime(fecha_str, '%Y-%m-%d').date()
                except ValueError:
                    flash('Formato de fecha incorrecto. Utilice YYYY-MM-DD.', 'danger')
                    return redirect(url_for('actualizar_datos'))
            else:
                fecha = None

            # Actualizar los datos del usuario actual solo si los campos no están vacíos
            if correo:
                current_user.correo = correo
            if acercademi:
                current_user.acercademi = acercademi
            if perfil:
                current_user.perfil_details = perfil
            if ubicacion:
                current_user.ubicacion = ubicacion
            if pais:
                current_user.pais = pais
            if telefono:
                current_user.telefono = telefono
            if fecha:
                current_user.fecha = fecha

            try:
                db.session.commit()
                flash('Perfil actualizado correctamente.', 'success')
            except Exception as e:
                db.session.rollback()
                flash('Hubo un error al actualizar el perfil.', 'danger')
                print(f'Error: {e}')

            return redirect(url_for('actualizar_datos'))

        return render_template('actualizar_datos.html')
        
    #ACTUALIZAR CLAVE
    @app.route('/actualizar_contraseña', methods=['GET', 'POST'])
    @login_required
    def actualizar_contrasena():
        if request.method == 'POST':
            password = request.form['password']
            new_password = request.form['newpassword']
            rep_password = request.form['repPassword']

        # Verificar que la contraseña actual sea correcta
            if not bcrypt.check_password_hash(current_user.contrasena, password):
                flash('Contraseña actual incorrecta.', 'danger')
                return redirect(url_for('actualizar_contrasena'))

        # Verificar que la nueva contraseña coincida con la repetida
            if new_password != rep_password:
                flash('Las nuevas contraseñas no coinciden.', 'danger')
                return redirect(url_for('actualizar_contrasena'))

        # Actualizar la contraseña en la base de datos
            current_user.contrasena = bcrypt.generate_password_hash(new_password).decode('utf-8')

            try:
                db.session.commit()
                flash('Contraseña actualizada correctamente.', 'success')
            except Exception as e:
                db.session.rollback()
                flash('Hubo un error al actualizar la contraseña.', 'danger')
                print(f'Error: {e}')

            return redirect(url_for('actualizar_contrasena'))

        return render_template('actualizar_contraseña.html')
    

    @app.route('/eliminar_cuenta', methods=['POST'])
    @login_required
    def eliminar_cuenta():
        user = User.query.get(current_user.id)  # Obtener el objeto User real desde la base de datos
        if user:
            logout_user()
            db.session.delete(user)
            db.session.commit()
            flash('Tu cuenta ha sido eliminada.', 'success')
            return redirect(url_for('routes.home'))
        else:
            flash('Error al eliminar la cuenta. Usuario no encontrado.', 'danger')
            return redirect(url_for('routes.home'))


    #CERRAR SESION
    @app.route('/logout')
    def logout():
         logout_user()
         flash("Has cerrado sesión", "success")
         return redirect(url_for('routes.home'))


    return app

app = create_app()


if __name__ == "__main__":
    with app.app_context():
        db.create_all()
        app.run(debug=True)