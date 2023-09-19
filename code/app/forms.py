from flask_wtf import FlaskForm, RecaptchaField
from wtforms import IntegerField, StringField, DateTimeField, TextAreaField, SubmitField, PasswordField, BooleanField, RadioField, DateField, SelectField, HiddenField,TelField
from wtforms_components import TimeField
from wtforms.validators import DataRequired, EqualTo, NumberRange, ValidationError, Length, Email
from app import db, models, app
from .models import Facility, Activity
import datetime
from datetime import date


#Form to handle user account login process in flask
class LoginForm(FlaskForm):
    userName = StringField('User Name', validators=[DataRequired()])
    userPassword = PasswordField('passwords', validators=[DataRequired()])
    remember = BooleanField('Remember Me')

#FOrm to handle user account signups in flask
class SignupForm(FlaskForm):
    userName = StringField('User Name', validators=[DataRequired()])
    userEmail = StringField('User Email', validators=[DataRequired()])
    userPassword = PasswordField('passwords', validators=[DataRequired()])
    userVerifyPassword = PasswordField('confirm password', validators=[DataRequired(),
                        EqualTo('userPassword')])
    CountryCode = HiddenField('Country Code', validators=[DataRequired()])
    Mobile = StringField('Mobile Number', validators=[DataRequired()])

#Form that submits mobile number information to twilio for Two-Factor Authentication
class Auth2FaForm(FlaskForm):
    email = StringField('User Email', validators=[DataRequired()])
    CountryCode = HiddenField('Country Code', validators=[DataRequired()])
    pno = StringField('User Mobile', validators=[DataRequired()])

#Form that accepts Two-Factor Token To complete login process
class Verify2FA(FlaskForm):
    token = email = StringField('Token')
  
#Form that takes in user account info to help reset password
class ForgetPassword(FlaskForm):
    userEmail = StringField('User Email', validators=[DataRequired()])

#Form that accepts new password for user account.
class ResetPassword(FlaskForm):
    userPassword = PasswordField('passwords', validators=[DataRequired()])
    userVerifyPassword = PasswordField('confirm password', validators=[DataRequired(),
                        EqualTo('userPassword')])

#Form to facilitate employee login.
class EmpLoginForm(FlaskForm):
    userName = StringField('Employee Username', validators=[DataRequired()])
    userPassword = PasswordField('passwords', validators=[DataRequired()])
    remember = BooleanField('Remember Me')


#Form that takes employee details which is used by the manager to create employee accounts
class EmpSignupForm(FlaskForm):
    userName = StringField('User Name', validators=[DataRequired()])
    userEmail = StringField('User Email', validators=[DataRequired()])
    userPassword = PasswordField('passwords', validators=[DataRequired()])
    userVerifyPassword = PasswordField('confirm password', validators=[DataRequired(),
                        EqualTo('userPassword')])
    CountryCode = HiddenField('Country Code', validators=[DataRequired()])
    Mobile = StringField('Mobile Number', validators=[DataRequired()])
    role = SelectField('Role', choices=[('Employee', 'Employee'), ('Manager', 'Manager')], validators=[DataRequired()])

#Form to handle contact us feature
class ContactUsForm(FlaskForm):
  name = StringField("Name",  validators=[DataRequired()])
  email = StringField("Email",validators = [DataRequired()])
  address = StringField("Address",validators = [DataRequired()])
  message = TextAreaField("Message",validators = [DataRequired()])
  submit = SubmitField("Send")

