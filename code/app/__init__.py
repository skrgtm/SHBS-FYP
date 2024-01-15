from flask import Flask
from flask_sqlalchemy import SQLAlchemy
from flask_migrate import Migrate
from flask_login import LoginManager
from flask_admin import Admin
from flask_mail import Mail
from flask import Flask, render_template
import logging
from google.oauth2 import id_token
from google.auth.transport import requests
import stripe 
import os

from flask_login import LoginManager





#creates the flask app and configuration is retireved from config.py
app = Flask(__name__)
app.config.from_object('config')


app.config['RECAPTCHA_USE_SSL']= False
app.config['RECAPTCHA_PUBLIC_KEY']='6LfIW4UkAAAAACk9Wog68aHpKSpvUHSjmvXOAo_p'
app.config['RECAPTCHA_PRIVATE_KEY']='6LfIW4UkAAAAADqnSWXE-h6dlvd96D7saDY3X4ua'
app.config['RECAPTCHA_OPTIONS']= {'theme':'black'}

#srtipe key
stripe.api_key = 'sk_test_51Mii9fBqkMuCWI2NQ26DYOhEa34sJkp1Z55KZvEi5LwiQdltDi1hhMSSi54aRRohIItyssYimBg0iWkaiiuL1DdK00aUnCdyDv'

#configuration for email
app.config['MAIL_SERVER']='smtp.gmail.com'
app.config['MAIL_PORT'] = 465
app.config['MAIL_USERNAME'] = 'skrgtm2059@gmail.com'
app.config['MAIL_PASSWORD'] = 'igatzyfmajkjfyun'

app.config['MAIL_USE_TLS'] = False
app.config['MAIL_USE_SSL'] = True

app.config['UPLOAD_FOLDER'] = os.path.join(app.root_path, 'static', 'profile')

# app.config['UPLOAD_FOLDER'] = 'profile_pictures'
app.config['ALLOWED_EXTENSIONS'] = {'png', 'jpg', 'jpeg', 'gif'}





mail = Mail(app)



# logging.basicConfig(filename='record.log',level=logging.DEBUG, format='%(asctime)s %(levelname)s %(name)s %(threadName)s : %(message)s')

db = SQLAlchemy(app)
login_manager = LoginManager(app)
login_manager.init_app(app)
login_manager.login_view = 'login'


migrate = Migrate(app, db)
admin = Admin(app,template_mode='bootstrap4')

from app import views,models



