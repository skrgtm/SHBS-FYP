#Relevant modules for the project.
from flask import Flask, render_template, flash, redirect, request,make_response,url_for,current_app, abort,session,jsonify
from app import app , models,db,admin,login_manager,mail
from flask_admin.contrib.sqla import ModelView
from flask_sqlalchemy import SQLAlchemy
from .forms import LoginForm,SignupForm,Auth2FaForm,Verify2FA,EmpLoginForm,EmpSignupForm,ForgetPassword,ContactUsForm
# from .forms import LoginForm,SignupForm,Auth2FaForm,Verify2FA,EmpLoginForm,EmpSignupForm,ForgetPassword,FacilityActivityForm,CreateFacilityForm,CreateActivityForm,UpdateActivityForm,UpdateFacilityForm,ResetPassword,ViewBookings,EditBookingForm, UpdateUserForm,UserMember,CreateBookings,BookingDetailsForm,RefundForm
from .models import UserAccount, Role, Booking, Facility, Receipt, Sessions,Activity, session_activity_association
from functools import wraps
from flask_login import LoginManager,login_required,logout_user,login_user,current_user
from werkzeug.security import generate_password_hash, check_password_hash
from flask_mail import Mail, Message
from twilio.rest import Client,TwilioException
from twilio.base.exceptions import TwilioRestException, TwilioException

from itsdangerous import TimedJSONWebSignatureSerializer as Serializer
from itsdangerous import URLSafeTimedSerializer
from google.oauth2 import id_token
from google_auth_oauthlib.flow import Flow
from pip._vendor import cachecontrol
import google.auth.transport.requests
import requests
import os
import pathlib
from datetime import datetime, time, timedelta
from dateutil.relativedelta import relativedelta
# from add_dynamic import dynamic_sessions,append_to_session
from datetime import datetime
import stripe
from collections import defaultdict
from sqlalchemy import desc, extract
from sqlalchemy.sql import func
import phonenumbers
from phonenumbers import NumberParseException
from flask import make_response
from reportlab.pdfgen import canvas
from reportlab.lib.pagesizes import letter
from io import BytesIO
from reportlab.platypus import Image


#Setup for twilio and Google SSO.
# client = Client('AC6ad80acd35f02624971ed118dbc6ee3f', '75edf39774229fd85fd949e357190863')
# GOOGLE_CLIENT_ID = '907426758204-iag4jlaj2j25u5cakobi2dual5806gn7.apps.googleusercontent.com'
# client_secrets_file = os.path.join(pathlib.Path(__file__).parent, "client_secret.json")

# flow = Flow.from_client_secrets_file(
#     client_secrets_file=client_secrets_file,
#     scopes=["https://www.googleapis.com/auth/userinfo.profile", "https://www.googleapis.com/auth/userinfo.email", "openid"],
#     redirect_uri="http://127.0.0.1:5000/callback"
# )

# Loads the required Role
#Redirects user to homepage if they access restricted content.
def require_role(role):
    """make sure user has this role"""
    def decorator(func):
        @wraps(func)
        def wrapped_function(*args, **kwargs):
            if not current_user.has_role(role):
                return redirect("/")
            else:
                return func(*args, **kwargs)
        return wrapped_function
    return decorator

#method to validate phone numbers. Helps reduce Twilio Errors.
# def is_valid_phone_number(number):
#     try:
#         parsed_number = phonenumbers.parse(number, None)
#         return phonenumbers.is_valid_number(parsed_number)
#     except phonenumbers.NumberParseException:
#         return False


#************************* Admin View ******************************************
#Disabled For Submission.
admin.add_view(ModelView(UserAccount, db.session))
admin.add_view(ModelView(Role, db.session))
admin.add_view(ModelView(Facility, db.session))
admin.add_view(ModelView(Activity, db.session))
admin.add_view(ModelView(Sessions, db.session))
admin.add_view(ModelView(Booking, db.session))
admin.add_view(ModelView(Receipt, db.session))

@login_manager.user_loader
def load_user(user_id):
    # Replace this with your actual user loading logic
    user = User.query.get(int(user_id))  # Example assuming you have a User model
    return user
#**************************** HomePage *************************************************

#Route for the homepage
#Also handles the Contact us Info by sending users verification emails on submission.
@app.route('/', methods=['GET','POST'])
def Homepage():
    form = ContactUsForm()
    if request.method == 'POST':
        if form.validate() == False:
            flash('All fields are required.')
            return render_template('homepage.html', form=form)
        else:
            subject = 'Message Recieved'

            body = render_template('contact_us_email.html', user_email = form.email.data)
            message = Message(subject, recipients=[form.email.data], html=body,sender = 'skrgtm2059@gmail.com')

            mail.send(message)
            return redirect('/')
    elif request.method == 'GET':
        return render_template('homepage.html', title='HomePage',form = form)


#Getter to get the information of upcoming activites using facility id.
@app.route('/facility/<int:facility_id>/activities')
def get_upcomming_activities(facility_id):
    activities = Activity.query.filter_by(facility_id=facility_id).all()
    return jsonify([activity.activity_to_dict() for activity in activities])


#**** User Create Account and Login: Reset Password, 2FA & Google Login ***********************

#******************* Route for Login ****************************************

#Handles user authentication and checks if the account has the 'User' role
#If the user logs in but has the wrong role, It results in user being redirected to homepage
#On successful login it redirects to user page
@app.route('/login', methods=['GET', 'POST'])
def login():
    form = LoginForm()
    if form.validate_on_submit():
        user = UserAccount.query.filter_by(User=form.userName.data).first()
        if user is None or not user.check_password(form.userPassword.data):
            flash('Invalid username or password')
            return redirect(url_for('login'))
        if not user.verified:
            flash('Please verify your email before logging in.')
            return redirect(url_for('login'))
        login_user(user, remember=form.remember.data)
        if user.has_role("User"):
            return redirect("/user")
        else:
            return redirect('/')
    return render_template('login_page.html', title='Login', form=form)

#******************* Route for Create Account ****************************************
#Creates a user account.
#Checks if the username and email already exists, preventing duplicate information from being used.
#On success the user account is created and user activiation process begins
#Else page is reloaded.
@app.route('/create_account', methods=['GET','POST'])
def signup():
    form = SignupForm()
    user_name = form.userName.data
    user_email = form.userEmail.data
    user_password = form.userPassword.data
    user_Role = Role.query.filter_by(name="User").first() 
    user_number = form.Mobile.data

    if form.validate_on_submit():
        user_n = UserAccount.query.filter_by(User=user_name).first()
        user_e = UserAccount.query.filter_by(Email=user_email).first()
        if user_n is not None:
            flash('User already exists')
            app.logger.error('Error: Create Account Failed')
            return redirect('/create_account')
        if user_e is not None:
            flash('email ID already exists')
            app.logger.error('Error: Create Account Failed')
            return redirect('/create_account')
        userData = UserAccount(User=user_name, Email=user_email, Password=form.userPassword.data,Mobile = form.CountryCode.data+form.Mobile.data)
        userData.roles.append(user_Role)
        verification_token = generate_verification_token(user_email)
        userData.verification_token = verification_token 
        db.session.add(userData)
        db.session.commit()

        return redirect(url_for('send_verification_email', user_email=user_email, verification_token=verification_token))
    return render_template('signup.html', title='signup', form=form)

#******************* Route for Login with Phone ****************************************

#Route to handle Two-Factor authentication.
#validate mobile number information.
#if mobile is validated verification token is generated by twilio.
#If numnber is not validated, error message is displayed.
@app.route('/2FA', methods=['GET', 'POST'])
def Auth2Fa():
    f1 = Auth2FaForm()
    email = f1.email.data
    userAcc = UserAccount.query.filter_by(Email=email).first()

    if f1.validate_on_submit():
        print(f1.CountryCode.data)
        mob = f1.CountryCode.data + str(f1.pno.data)

        # Validate the phone number
        if is_valid_phone_number(mob):
            request_verification_token(mob)
            return redirect(url_for('ec', mob=mob, email=email))
        else:
            flash('Invalid phone number format. Please enter a valid number.', 'error')


    return render_template('login2fa.html', title='2FA', form=f1)

#Route to verify the generated code is entered.
#Twilio checks if the token is correct.
#If correct the user logs in.
@app.route('/ec', methods=['GET', 'POST'])
def ec():
    mobil = request.args.get('mob')
    print(mobil)
    eml = request.args.get('email')
    f2 = Verify2FA()
    tok = f2.token.data
    userAcc = UserAccount.query.filter_by(Email=eml).first()
    if request.method == 'POST':
        login = check_verification_token(mobil, tok)
        print("Verification check result:", login)
        if login == True:
            login_user(userAcc)
            return redirect('/user')
    return render_template('verify.html', title='2FA', form2=f2)


#Method to generate the verification token for email validation
def generate_verification_token(user_email):
    s = Serializer(current_app.config['SECRET_KEY'])
    return s.dumps({'email': user_email}).decode('utf-8')

#Twilio method to check verification toekn.
#If Handles any exceptions raised by twilio for errors.
def check_verification_token(phone, token):
    print("Phone:", phone)
    print("Token:", token)
    verify = client.verify.services('VA3aca3bf651a0ca9bcb349309b4737dc4')
    try:
        result = verify.verification_checks.create(to=phone, code=token)
    except TwilioException as e:
        print("Twilio exception:", e)
        return False
    return True

#Twilio method to generate token given the users mobile number.
#Handles Any exceptions by twilio. Preventing user login if False is returned.
def request_verification_token(phone):
    verify = client.verify.services('VA3aca3bf651a0ca9bcb349309b4737dc4')
    try:
        verify.verifications.create(to=phone, channel='sms')
    except TwilioException:
       return False


#******************* Sending Account Verification Link ****************************************
@app.route('/send-verification-email')
def send_verification_email():
    # Get the current user's email and verification token
    user_email = request.args.get('user_email')
    verification_token = request.args.get('verification_token')

    # Generate the verification URL using Flask-URL-Generator
    verification_url = url_for('verify_email', token = verification_token, _external=True)
    flash('The verification link is sent to your email address.')
    # Create the email message
    subject = 'Verify Your Email'

    body = render_template('send_verify_email.html', verification_url=verification_url)
    message = Message(subject, recipients=[user_email], html=body,sender = 'arjun.krishnan0033@gmail.com')

    mail.send(message)

    # Return a message to the user
    flash('A verification email has been sent to your email address.')
    return redirect(url_for('login'))

@app.route('/verify-email/<token>')
def verify_email(token):
    # Find the user with the given verification token
    user = UserAccount.query.filter_by(verification_token=token).first()

    if user:
        # Verify the user's email and remove the verification token
        user.verified = True
        user.verification_token = None
        db.session.commit()
        # Return a message to the user
        flash('Your email has been verified.')
        msg = Message('Account Created', sender = 'arjun.krishnan0033@gmail.com', recipients = [user.Email])
        msg.html = render_template('mail.html', User=user.User)     #
        mail.send(msg)
    else:
        # Return a message to the user
        flash('The verification link is invalid.')

    return redirect(url_for('login'))

#******************* Resetting Password ****************************************

# Route for resetting the password

@app.route('/reset', methods=["GET", "POST"])
def reset():
    form = ForgetPassword()
    user_email = form.userEmail.data
    if form.validate_on_submit():
        user = UserAccount.query.filter_by(Email=form.userEmail.data).first()

        if user:
            # Generate a token that is valid for 1 hour
            s = Serializer(current_app.config['SECRET_KEY'])
            token = s.dumps(user_email, salt='recover-key')
            
            # Construct the password reset link
            reset_url = url_for('reset_password', token=token, _external=True)

            # Send an email to the user with the password reset link
            subject = 'Password reset request'

            body = render_template('password_reset_email.html', reset_url=reset_url, user_email = user_email)
            message = Message(subject, recipients=[user_email], html=body,sender = 'arjun.krishnan0033@gmail.com')

            mail.send(message)

            flash('An email has been sent with instructions to reset your password', 'success')
            return redirect(url_for('login'))

        flash('Email address not found', 'danger')

    return render_template('recover.html', title='Reset Password', form=form)

#route to validate the reset password.
#Only allows password to be reset if the toek is validate.
#Chceks if the user email also exists before resetting the password.
#If all checks are passed. User password is reset with success prompt.
@app.route('/reset_password/<token>', methods=["GET", "POST"])
def reset_password(token):
    try:
        s = Serializer(current_app.config['SECRET_KEY'])
        email = s.loads(token, salt='recover-key')
    except:
        flash('The password reset link is invalid or has expired', 'danger')
        return redirect(url_for('reset'))

    user = UserAccount.query.filter_by(Email=email).first()
    if not user:
        flash('Email address not found', 'danger')
        return redirect(url_for('reset'))

    form = ResetPassword()
    if form.validate_on_submit():
        user.Password= generate_password_hash(form.userPassword.data)
        db.session.commit()
        flash('Your password has been reset', 'success')
        return redirect(url_for('login'))

    return render_template('reset_password.html', title='Reset Password', form=form)

# Route for Login with Google Account

@app.route("/google_login")
def google_login():
    authorization_url, state = flow.authorization_url()
    session["state"] = state
    return redirect(authorization_url)

@app.route("/callback")
def callback():
    flow.fetch_token(authorization_response=request.url)
    if not session["state"] == request.args["state"]:
        abort(500)
    credentials = flow.credentials
    request_session = requests.session()
    cached_session = cachecontrol.CacheControl(request_session)
    token_request = google.auth.transport.requests.Request(session=cached_session)

    id_info = id_token.verify_oauth2_token(
        id_token=credentials._id_token,
        request=token_request,
        audience=GOOGLE_CLIENT_ID
    )

    google_id = id_info.get("sub")
    email = id_info.get("email")

    # Check if the user's email exists in the database
    user = UserAccount.query.filter_by(Email=email).first()
    if user:
        session["google_id"] = google_id
        session["email"] = email
        login_user(user)
        print("Success")
        return redirect("/user")
    else:
        # Redirect the user to an unauthorized page
        print("Failed!")
        flash('Invalid Credentials')
        return redirect("/login")