from flask import render_template, Blueprint
from flask_login import login_required, current_user

routes_bp = Blueprint('routes', __name__)
#RUTAS  


@routes_bp.route('/')
def home():
     return render_template('index.html')

@routes_bp.route('/nosotros')
def nosotros():
     return render_template('nosotros.html')


@routes_bp.route('/descargas_programas')
def descargas_programas():
     return render_template('descargas_programas.html')

@routes_bp.route('/descargas_sistemas_operativos')
def descargas_sistemas_operativos():
     return render_template('descargas_sistemas_operativos.html')
  
@routes_bp.route('/desarrollo_web')
@login_required
def desarrollo_web():
     return render_template('servicies/desarrollo_web.html')


@routes_bp.route('/diseño_grafico')
@login_required
def diseño_grafico():
     return render_template('servicies/diseño_grafico.html')


@routes_bp.route('/debian')
def debian():
     return render_template('sistemas_operativos/debian.html')

@routes_bp.route('/linux_mint')
def linux_mint():
     return render_template('sistemas_operativos/linux_mint.html')

@routes_bp.route('/ubuntu')
def ubuntu():
     return render_template('sistemas_operativos/ubuntu.html')

@routes_bp.route('/windows_7')
def windows_7():
     return render_template('sistemas_operativos/windows_7.html')

@routes_bp.route('/windows_10')
def windows_10():
     return render_template('sistemas_operativos/windows_10.html')

@routes_bp.route('/windows_11')
def windows_11():
     return render_template('sistemas_operativos/windows_11.html')


@routes_bp.route('/chat_gpt')
def chat_gpt():
     return render_template('destacados/chat_gpt.html')

@routes_bp.route('/kits_ai')
def kits_ai():
     return render_template('destacados/kits_ai.html')

@routes_bp.route('/computacion_cuantica')
def computacion_cuantica():
     return render_template('destacados/computacion_cuantica.html')

@routes_bp.route('/Platform_Engineering')
def Platform_Engineering():
     return render_template('destacados/Platform_Engineering.html')

@routes_bp.route('/recuperacion_de_clave_email')
def recuperacion_de_clave_email():
     return render_template('recuperacion_de_clave_email.html')

@routes_bp.route('/miPerfil')
@login_required
def miPerfil():
     return render_template('miPerfil.html', current_user=current_user)














