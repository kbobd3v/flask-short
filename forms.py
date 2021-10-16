from flask_wtf import FlaskForm

from wtforms import StringField, TextAreaField, SubmitField
from wtforms.fields.html5 import EmailField
from wtforms.validators import DataRequired


class ContactUs(FlaskForm):
    name = StringField('Nombre', validators=[DataRequired(message='Este campo es obligatorio')])
    email = EmailField('Email', validators=[DataRequired(message='Este campo es obligatorio')])
    message = StringField('Mensaje', validators=[DataRequired(message='Este campo es obligatorio')])
    send = SubmitField('Enviar mensaje')
