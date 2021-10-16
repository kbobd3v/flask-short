import functools
from _curses import flash

from werkzeug.security import generate_password_hash, check_password_hash

import db
from forms import ContactUs
from message import mensajes
from db import get_db

from flask import Flask, render_template, request, flash, jsonify, redirect, url_for, session, g, send_file, \
    make_response

import yagmail as yagmail
import os
import utils

app = Flask(__name__)
app.debug = True
app.secret_key = os.urandom(12)


# El decorador @app.route define la dirección donde se ejecutará la función de ese directorio
@app.route("/")
def index():
    # Render_template te permite visualizar un html con la información que requieres
    # Puedes pasar parametros a la url para que sean tenidos en cuenta dentro del html
    if g.user:
        return redirect(url_for('send'))
    return render_template('login.html')


# En la ruta /login desde el navegador se renderizará el html de login
@app.route("/login", methods=('GET', 'POST'))
def login():
    try:
        if request.method == 'POST':
            username = request.form['username']
            password = request.form['password']

            # Siempre abrir la conexion
            db = get_db()
            error = None

            if not username:
                error = 'Debes ingresar un usuario'
                flash(error)
                return render_template('login.html')

            if not password:
                error = 'Debes ingresar una contraseña'
                flash(error)
                return render_template('login.html')

            user = db.execute('SELECT * FROM usuario WHERE usuario = ?',
                              (username, )).fetchone()

            if user is None:
                error = 'Usuario o contraseña invalidos'
                flash(error)
            else:
                store_password = user[4]
                result = check_password_hash(store_password, password)

                if result is False:
                    error = 'Usuario o contraseña invalidos'
                else:
                    session.clear()
                    session['user_id'] = user[0]
                    resp = make_response(redirect(url_for('send')))
                    resp.set_cookie('username', username)
                    return resp
            flash(error)
        return render_template('login.html')
    except Exception as ex:
        print(ex)
        return render_template('login.html')


# En este decorador de ruta, le pasamos como parametros lo que queremos que sea tenido en cuenta
# en la ruta
@app.route('/register', methods=('GET', 'POST'))
def register():
    try:
        # Si el metodo de request es POST
        if request.method == 'POST':
            name = request.form['name']
            username = request.form['username']
            password = request.form['password']
            email = request.form['email']

            if not utils.isEmailValid(email):
                error = "El email no es valido"
                flash(error)
                return render_template('register.html')

            if not utils.isUsernameValid(username):
                error = "El usuario no es valido"
                flash(error)
                return render_template('register.html')

            if not utils.isPasswordValid(password):
                error = "El password no es valido"
                flash(error)
                return render_template('register.html')

            db = get_db()

            #generate_password_hash

            #verificamos si el correo ya existe en la base de datos

            user = db.execute('SELECT id_usuario FROM usuario WHERE correo=?', (email,)).fetchone()

            # Si el correo existe entonces lanza un error y direcciona a registro
            if user is not None:
                error ='el correo ya existe'.format(email)
                flash(error)
                return render_template('register.html')

            db.execute('INSERT INTO usuario (nombre, usuario, correo, contraseña) VALUES (?,?,?,?)',(name, username, email, password))

            error = None
            db.executescript('INSERT INTO usuario (nombre, usuario, correo, contraseña) VALUES ("%s","%s","%s","%s")' %
                             (name, username, email, generate_password_hash(password)))

            db.commit()
            # db.close()

            # yag = yagmail.SMTP('mintic202221@gmail.com','Mintic2022')
            # yag.send(to=email, subject= 'Activa tu cuenta',
            #          contents='Bievenido al portal de Registro de Vacunación  usa este link '
            #                   'para activar tu cuenta')
            #
            # flash("Revisa tu correo para activar tu cuenta")
            # return render_template('register.html')

            return render_template('login.html')
        return render_template('register.html')
    except Exception as e:
        print(e)
        return render_template('register.html')


@app.route('/contactUs', methods=['GET', 'POST'])
def contactUs():
    form = ContactUs()
    return render_template('contactus.html', form=form)

def login_required(view):
    @functools.wraps(view)
    def wrapped_view(**kwargs):
        if g.user is None:
            return redirect(url_for('login'))
        return view(**kwargs)
    return wrapped_view


@app.route('/mensaje')
def message():
    return jsonify({'mensaje': 'Mensajes', 'usuario': mensajes})


@app.route('/logout')
def logout():
    session.clear()
    return redirect(url_for('login'))

@app.route('/send', methods=('GET', 'POST'))
@login_required
def send():
    try:
        if request.method == 'POST':
            from_id = g.user[0]
            to_username = request.form['para']
            subject = request.form['asunto']
            body = request.form['mensaje']

            username = request.cookies.get('username')
            if not to_username:
                flash(username + ' Para es un campo requerido')
                return render_template('send.html')

            if not subject:
                flash(username + ' El asunto es un campo requerido')
                return render_template('send.html')

            if not body:
                flash(username + ' El mensaje es un campo requerido')
                return render_template('send.html')

            db = get_db()
            user_to = db.execute('SELECT * FROM usuario WHERE usuario = ?', (to_username,)).fetchone()

            if user_to is None:
                error = 'No existe el usuario ingresado'
                flash(error)
            else:
                db = get_db()
                db.execute('INSERT INTO mensajes (from_id, to_id, asunto, mensaje) VALUES (?,?,?,?)',
                           (from_id, user_to[0], subject, body))
                db.commit()
                flash("Mensaje Enviado")
        return render_template('send.html')
    except Exception as e:
        print(e)

@app.before_request
def load_logged_in_user():
    user_id = session.get('user_id')
    if user_id is None:
        g.user = None
    else:
        db = get_db()
        g.user = db.execute('SELECT * FROM usuario WHERE id_usuario = ?', (user_id, )).fetchone()

@app.route('/downloadpdf', methods=('GET', 'POST'))
@login_required
def download_pdf():
    try:
        return send_file("static/resources/doc.pdf", as_attachment=True)
    except Exception as e:
        print(e)


@app.route('/downloadimage', methods=('GET', 'POST'))
@login_required
def download_image():
    try:
        return send_file("static/resources/image.png", as_attachment=True)
    except Exception as e:
        print(e)

if __name__ == '__main__':
    app.run(host='0.0.0.0', port=4443, ssl_context=('micertificado.pem', 'llaveprivada.pem'))
