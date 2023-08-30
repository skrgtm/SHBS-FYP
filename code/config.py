import os
SRF_ENABLED = True
SECRET_KEY = 'a-very-secret-secret'
os.environ["OAUTHLIB_INSECURE_TRANSPORT"] = "1"

basedir = os.path.abspath(os.path.dirname(__file__))
SQLALCHEMY_DATABASE_URI = 'sqlite:///' + os.path.join(basedir, 'app.db')
SQLALCHEMY_TRACK_MODIFICATIONS = True



