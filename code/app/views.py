# Relevant modules for the project.
from .models import Membership  # Import the Membership model
# Import your AddMembershipForm from forms.py
from .forms import AddMembershipForm
from app import app, db  # Update with your Flask app instance and db object
from flask import render_template, redirect, url_for, flash
from flask import Flask, render_template, flash, redirect, request, make_response, url_for, current_app, abort, session, jsonify
from app import app, models, db, admin, login_manager, mail
from flask_admin.contrib.sqla import ModelView
from flask import redirect, url_for
from flask import render_template_string
from reportlab.lib.pagesizes import letter
from reportlab.pdfgen import canvas
from reportlab.lib import colors
from reportlab.lib.styles import getSampleStyleSheet, ParagraphStyle
from reportlab.lib.units import inch
from reportlab.platypus import Table, TableStyle, Paragraph
from reportlab.lib.pagesizes import letter
from reportlab.pdfgen import canvas
from reportlab.lib.colors import HexColor
from reportlab.lib.styles import getSampleStyleSheet, ParagraphStyle
from reportlab.platypus import Paragraph, Table, TableStyle
from reportlab.lib.units import inch
import os
from werkzeug.utils import secure_filename
from io import BytesIO
from PIL import Image as PILImage
from reportlab.lib.utils import ImageReader
from datetime import datetime
from flask_sqlalchemy import SQLAlchemy
from .forms import LoginForm, SignupForm, EmpLoginForm, EmpSignupForm, ForgetPassword, ContactUsForm, ResetPassword, CreateFacilityForm, CreateActivityForm, UpdateFacilityForm, UpdateActivityForm, ViewBookings, EditBookingForm, UserMember, CreateBookings, FacilityActivityForm, UpdateUserForm, BookingDetailsForm, AddMembershipForm, empcheckout
from reportlab.lib.pagesizes import letter
from reportlab.lib.utils import ImageReader
from .models import UserAccount, Role, Booking, Facility, Receipt, Sessions, Activity, session_activity_association
from functools import wraps
from reportlab.lib.styles import getSampleStyleSheet
from reportlab.lib import colors
from flask_login import LoginManager, login_required, logout_user, login_user, current_user
from werkzeug.security import generate_password_hash, check_password_hash
from flask_mail import Mail, Message
from twilio.rest import Client, TwilioException
from twilio.base.exceptions import TwilioRestException, TwilioException
import json
from reportlab.platypus import SimpleDocTemplate, Table, TableStyle, Paragraph
from itsdangerous import TimedJSONWebSignatureSerializer as Serializer
from itsdangerous import URLSafeTimedSerializer
from google.oauth2 import id_token
from google_auth_oauthlib.flow import Flow
from pip._vendor import cachecontrol
import google.auth.transport.requests
import requests
from reportlab.lib.pagesizes import letter
from reportlab.lib.utils import ImageReader
from datetime import datetime
from reportlab.lib.pagesizes import letter
from PIL import Image as PILImage
from io import BytesIO
from reportlab.lib.utils import ImageReader

import os
import pathlib
from datetime import datetime, time, timedelta
from dateutil.relativedelta import relativedelta
from add_dynamic import dynamic_sessions, append_to_session
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


# Setup for twilio and Google SSO.
# client = Client('AC6ad80acd35f02624971ed118dbc6ee3f', '75edf39774229fd85fd949e357190863')
# GOOGLE_CLIENT_ID = '907426758204-iag4jlaj2j25u5cakobi2dual5806gn7.apps.googleusercontent.com'
# client_secrets_file = os.path.join(pathlib.Path(__file__).parent, "client_secret.json")

# flow = Flow.from_client_secrets_file(
#     client_secrets_file=client_secrets_file,
#     scopes=["https://www.googleapis.com/auth/userinfo.profile", "https://www.googleapis.com/auth/userinfo.email", "openid"],
#     redirect_uri="http://127.0.0.1:5000/callback"
# )

# Loads the required Role
# Redirects user to homepage if they access restricted content.
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

# method to validate phone numbers. Helps reduce Twilio Errors.
# def is_valid_phone_number(number):
#     try:
#         parsed_number = phonenumbers.parse(number, None)
#         return phonenumbers.is_valid_number(parsed_number)
#     except phonenumbers.NumberParseException:
#         return False


# ************************* Admin View ******************************************
# Disabled For Submission.
admin.add_view(ModelView(UserAccount, db.session))
admin.add_view(ModelView(Role, db.session))
admin.add_view(ModelView(Facility, db.session))
admin.add_view(ModelView(Activity, db.session))
admin.add_view(ModelView(Sessions, db.session))
admin.add_view(ModelView(Booking, db.session))
admin.add_view(ModelView(Receipt, db.session))
admin.add_view(ModelView(Membership, db.session))
# *******************************************************************************


@login_manager.user_loader
def load_user(user_id):
    # Replace this with your actual user loading logic
    # Example assuming you have a User model
    user = UserAccount.query.get(int(user_id))
    return user
# **************************** HomePage *************************************************

# Route for the homepage
# Also handles the Contact us Info by sending users verification emails on submission.


# @app.route('/', methods=['GET', 'POST'])
# def Homepage():
#     form = ContactUsForm()
#     if request.method == 'POST':
#         if form.validate() == False:
#             flash('All fields are required.')
#             return render_template('homepage.html', form=form)
#         else:
#         #     # Send email to recipient
#         #     msg = Message(subject,
#         #                   sender='your_email@example.com',
#         #                   recipients=['recipient_email@example.com'])  # Replace with the recipient's email address
#         #     msg.body = f'Name: {form.name.data}\nEmail: {form.email.data}\nMessage: {form.message.data}'
#         #     mail.send(msg)
#             subject = 'Message Recieved'
#             body = render_template('contact_us_email.html', user_email = form.email.data)
#             message = Message(subject, recipients=[form.email.data], html=body,sender = 'skrgtm2059@gmail.com')
#             mail.send(message)
#             return redirect('/')
#     elif request.method == 'GET':
#         return render_template('homepage.html', title='HomePage',form = form)
# #Route that handles the contact requests
# #Sends the acknowledgement to the user via email if the data entered is valid.
# @app.route('/contact_us', methods=['GET', 'POST'])
# def contact_us():
#   form = ContactUsForm()
#   if request.method == 'POST':
#     if form.validate() == False:
#       flash('All fields are required.')
#       return render_template('contact_us.html', form=form)
#     else:
#         subject = 'Message Recieved'
#         body = render_template('contact_us_email.html', user_email = form.email.data)
#         message = Message(subject, recipients=[form.email.data], html=body,sender = 'skrgtm2059@gmail.com')
#         mail.send(message)
#         return redirect('/')
#   elif request.method == 'GET':
#     return render_template('contact_us.html', form=form)
@app.route('/', methods=['GET', 'POST'])
def Homepage():
    form = ContactUsForm()
    if request.method == 'POST':
        if not form.validate():
            flash('All fields are required.')
            return render_template('homepage.html', form=form)
        else:
            # Send email to the website owner (recipient)
            # Replace with the recipient's email address
            recipient_email = 'skrgtm2059@gmail.com'
            subject = 'New Contact Form Submission'
            body = f'Name: {form.name.data}\nEmail: {form.email.data}\nMessage: {form.message.data}'
            message = Message(subject, recipients=[
                              recipient_email], body=body, sender='skrgtm2059@gmail.com')

            # Send confirmation email to the user
            user_subject = 'Message Received'
            user_body = render_template(
                'contact_us_email.html', user_email=form.email.data)
            user_message = Message(user_subject, recipients=[
                                   form.email.data], html=user_body, sender='skrgtm2059@gmail.com')

            mail.send(message)
            mail.send(user_message)

            return redirect('/')
    elif request.method == 'GET':
        return render_template('homepage.html', title='HomePage', form=form)

# Getter to get the information of upcoming activites using facility id.


@app.route('/facility/<int:facility_id>/activities')
def get_upcomming_activities(facility_id):
    activities = Activity.query.filter_by(facility_id=facility_id).all()
    return jsonify([activity.activity_to_dict() for activity in activities])


# **** User Create Account and Login: Reset Password, 2FA & Google Login ***********************

# ******************* Route for Login ****************************************

# Handles user authentication and checks if the account has the 'User' role
# If the user logs in but has the wrong role, It results in user being redirected to homepage
# On successful login it redirects to user page
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
        remember = form.remember.data

        login_user(user, remember=remember, duration=timedelta(days=10))
        if user.has_role("User"):
            return redirect("/user")
        else:
            return redirect('/')
    return render_template('login_page.html', title='Login', form=form)

# ******************* Route for Create Account ****************************************
# Creates a user account.
# Checks if the username and email already exists, preventing duplicate information from being used.
# On success the user account is created and user activiation process begins
# Else page is reloaded.


@app.route('/create_account', methods=['GET', 'POST'])
def signup():
    form = SignupForm()
    user_name = form.userName.data
    user_email = form.userEmail.data
    user_password = form.userPassword.data
    user_confirm_password = form.userVerifyPassword.data
    user_Role = Role.query.filter_by(name="User").first()
    user_number = form.Mobile.data

    if form.validate_on_submit():
        # Check if the username already exists
        user_n = UserAccount.query.filter_by(User=user_name).first()
        if user_n is not None:
            flash('User already exists', 'user_exists')
            app.logger.error('Error: Create Account Failed')
            return redirect('/create_account')

        # Check if the email already exists
        user_e = UserAccount.query.filter_by(Email=user_email).first()
        if user_e is not None:
            flash('Email ID already exists', 'email_exists')
            app.logger.error('Error: Create Account Failed')
            return redirect('/create_account')

        # Check if the phone number already exists
        user_phone = UserAccount.query.filter_by(
            Mobile=form.CountryCode.data + user_number).first()
        if user_phone is not None:
            flash('Phone number already registered', 'phone_exists')
            app.logger.error('Error: Create Account Failed')
            return redirect('/create_account')

        # Check if passwords match
        if user_password != user_confirm_password:
            flash('Passwords do not match', 'password_mismatch')
            app.logger.error('Error: Passwords do not match')
            return redirect('/create_account')

        # If all checks pass, create the user account
        userData = UserAccount(User=user_name, Email=user_email,
                               Password=user_password, Mobile=form.CountryCode.data + user_number)
        userData.roles.append(user_Role)
        verification_token = generate_verification_token(user_email)
        userData.verification_token = verification_token
        db.session.add(userData)
        db.session.commit()
        # flash('New Employee account created successfully!', 'success')

        return redirect(url_for('send_verification_email', user_email=user_email, verification_token=verification_token))

    # If the form didn't validate, or it's a GET request, render the form again
    return render_template('signup.html', title='Signup', form=form)


# # ******************* Route for Login with Phone ****************************************

# Route to handle Two-Factor authentication.
# validate mobile number information.
# if mobile is validated verification token is generated by twilio.
# If numnber is not validated, error message is displayed.
# @app.route('/2FA', methods=['GET', 'POST'])
# def Auth2Fa():
#     f1 = Auth2FaForm()
#     email = f1.email.data
#     userAcc = UserAccount.query.filter_by(Email=email).first()

#     if f1.validate_on_submit():
#         print(f1.CountryCode.data)
#         mob = f1.CountryCode.data + str(f1.pno.data)

#         # Validate the phone number
#         if is_valid_phone_number(mob):
#             request_verification_token(mob)
#             return redirect(url_for('ec', mob=mob, email=email))
#         else:
#             flash('Invalid phone number format. Please enter a valid number.', 'error')

#     return render_template('login2fa.html', title='2FA', form=f1)

# # Route to verify the generated code is entered.
# # Twilio checks if the token is correct.
# # If correct the user logs in.


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


# Method to generate the verification token for email validation
def generate_verification_token(user_email):
    s = Serializer(current_app.config['SECRET_KEY'])
    return s.dumps({'email': user_email}).decode('utf-8')

# # Twilio method to check verification toekn.
# # If Handles any exceptions raised by twilio for errors.


# # def check_verification_token(phone, token):
# #     print("Phone:", phone)
# #     print("Token:", token)
# #     verify = client.verify.services('VA3aca3bf651a0ca9bcb349309b4737dc4')
# #     try:
# #         result = verify.verification_checks.create(to=phone, code=token)
# #     except TwilioException as e:
# #         print("Twilio exception:", e)
# #         return False
# #     return True

# # Twilio method to generate token given the users mobile number.
# # Handles Any exceptions by twilio. Preventing user login if False is returned.


# # def request_verification_token(phone):
# #     verify = client.verify.services('VA3aca3bf651a0ca9bcb349309b4737dc4')
# #     try:
# #         verify.verifications.create(to=phone, channel='sms')
# #     except TwilioException:
# #         return False


# ******************* Sending Account Verification Link ****************************************
@app.route('/send-verification-email')
def send_verification_email():
    # Get the current user's email and verification token
    user_email = request.args.get('user_email')
    verification_token = request.args.get('verification_token')

    # Generate the verification URL using Flask-URL-Generator
    verification_url = url_for(
        'verify_email', token=verification_token, _external=True)
    flash('The verification link is sent to your email address.Make sure you have entered the valid email address.')
    # Create the email message
    subject = 'Verify Your Email'

    body = render_template('send_verify_email.html',
                           verification_url=verification_url)
    message = Message(subject, recipients=[
                      user_email], html=body, sender='skrgtm2059@gmail.com')

    mail.send(message)

    # Return a message to the user
    # flash('A verification email has been sent to your email address.')
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
        msg = Message('Account Created',
                      sender='skrgtm2059@gmail.com', recipients=[user.Email])
        msg.html = render_template('mail.html', User=user.User)
        mail.send(msg)
    else:
        # Return a message to the user
        flash('The verification link is invalid.')

    return redirect(url_for('login'))

# ******************* Resetting Password ****************************************

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

            body = render_template(
                'password_reset_email.html', reset_url=reset_url, user_email=user_email)
            message = Message(subject, recipients=[
                              user_email], html=body, sender='skrgtm2059@gmail.com')

            mail.send(message)

            flash(
                'An email has been sent with instructions to reset your password', 'success')
            return redirect(url_for('login'))

        flash('Email address not found', 'danger')

    return render_template('recover.html', title='Reset Password', form=form)

# route to validate the reset password.
# Only allows password to be reset if the toek is validate.
# Chceks if the user email also exists before resetting the password.
# If all checks are passed. User password is reset with success prompt.


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
        user.Password = generate_password_hash(form.userPassword.data)
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
    token_request = google.auth.transport.requests.Request(
        session=cached_session)

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


@app.route("/protected_area")
@login_required
def protected_area():
    return f"Hello {session['name']}! <br/> <a href='/logout'><button>Logout</button></a>"


# ************** End of User Login, Creat Account: Reset, 2FA, Google Login, Logout *******************


# #Manager Homepage
# @app.route('/mgr_homepage')
# @login_required
# @require_role(role="Manager")
# def MgrHomepage():
#     #redirects user to landing page
#     return render_template('yt.html',
#                            title='Home',User = current_user)

# ********************************* Route to Redirect User After they Login ************************

# User homepage
@app.route('/user', methods=['GET', 'POST'])
@login_required
@require_role(role="User")
def user():
    return render_template('user.html', title='User', User=current_user)

# Flask defualt logout handler.


@app.route("/logout")
@login_required
def logout():
    for key in list(session.keys()):
        session.pop(key)
    logout_user()
    return redirect('/')

# ************** End of User Login, Creat Account: Reset, 2FA, Google Login, Logout *******************


# khalti payment gateway
@app.route('/order_products', methods=['GET', 'POST'])
@login_required
@require_role(role="User")
def order_products():
    total_amount = request.form.get(
        'total_amount') or request.json.get('total_amount')
    total_amount_paisa = int(float(total_amount) * 100)

    payload = json.dumps({
        # This will be the URL Khalti redirects to after payment
        # "return_url": "http://localhost:5000/payment_success",

        "return_url": url_for('payment_success', _external=True),
        "website_url": "http://localhost:5000",  # Your website's URL
        "amount": total_amount_paisa,  # The amount in paisa
        "purchase_order_id": "Order01",  # Unique ID for the order
        "purchase_order_name": "test",  # Name or description of the order
        "customer_info": {
            "name": "Test",
            "email": "test@khalti.com",
            "phone": "9800000005"
        }


    })
    headers = {
        # Ensure the 'Key' prefix is included
        # test key
        # 'Authorization': 'key b42caed1ffbd4202b41b700a32e3a237',
        # my key
        'Authorization': 'key a0021f9f714144c5bc2b0dffb56f2c5b',
        'Content-Type': 'application/json',
    }

    # Send the request to Khalti's API
    response = requests.post(
        "https://a.khalti.com/api/v2/epayment/initiate/", headers=headers, data=payload)
    print(response.text)
    if response.status_code == 200:
        # If the response is successful, get the payment URL and redirect the user to it
        response_data = response.json()

        return redirect(response_data['payment_url'])
    else:
        # If there was an error, log it and return a JSON response with the error
        app.logger.error(f"Failed to initiate payment: {response.text}")
        return jsonify({'error': 'Payment initiation failed', 'message': response.text}), response.status_code


# Define the validate_session function
# def validate_session():
#     if current_user.is_authenticated:
#         # User is logged in, session is active
#         return True
#     else:
#         # User is not logged in or session expired
#         return False

# khalti payment success
# Handles success for user bookings.
# Sets the booking status form 'Saved' to 'Paid'.
# Recipt is now generated and a pdf version is sent to the users Email.


@app.route('/payment_success', methods=['GET'], strict_slashes=False)
@login_required
@require_role(role="User")
def payment_success():
    # if validate_session():

    user_bookings = Booking.query.filter_by(
        user_id=current_user.id, Status="Saved").all()

    if not user_bookings:
        flash('No bookings found with the "Saved" status. Please try again.')
        return redirect(url_for('my_bookings'))

    total_amount = sum(
        [booking.Size * booking.activity.Amount for booking in user_bookings])

    new_receipt = Receipt(
        user_id=current_user.id,
        Amount=total_amount
    )

    db.session.add(new_receipt)
    db.session.commit()
    receipt_id = new_receipt.id

    for booking in user_bookings:
        booking.Status = 'Booked'
        booking.receipt_id = receipt_id

    db.session.commit()
    flash('Payment successful! "Booked" Please check e-mail for booking receipt')

    static_folder = os.path.join(app.root_path, 'static')
    image_path = os.path.join(static_folder, 'images', 'nb.png')

    buffer = BytesIO()
    p = canvas.Canvas(buffer, pagesize=letter)

    # Load image
    static_folder = os.path.join(app.root_path, 'static')
    image_path = os.path.join(static_folder, 'images', 'nb.png')

    # Drawing image on canvas
    x = 50
    y = 700
    with PILImage.open(image_path) as pil_image:
        # Resize the image
        max_image_width = 500
        max_image_height = 200
        pil_image.thumbnail((max_image_width, max_image_height))

        # Convert the image to ReportLab's ImageReader format
        img = ImageReader(pil_image)
        img_width, img_height = pil_image.size

        p.drawImage(img, x, y, width=img_width, height=img_height)

    # Define styles
    styles = getSampleStyleSheet()
    style_title = styles['Title']
    style_body = styles['Normal']

    # Create a title
    p.setFont("Helvetica-Bold", 20)
    p.drawCentredString(
        300, 650, "----------------Booking Receipt----------------")

    # Other receipt details
    p.setFont("Helvetica", 12)
    y_start = 600
    line_height = 20

    # if current_user.Member:
    #     discount = int(total_amount * 0.5)  # 50% discount for members
    #     total_amount = total_amount - discount  # Apply the member discount

    receipt_bookings = Booking.query.filter_by(
        receipt_id=new_receipt.id).all()

    # Creating a table for booking details
    table_data = [
        ['Facility', 'Activity', 'Start Time', 'End Time', 'Number']
    ]

    for booking in receipt_bookings:
        facility_name = booking.session.facility.Name
        activity_name = booking.activity.Activity_Name
        start_time = booking.session.Start_time
        end_time = booking.session.End_time
        num_people = booking.Size
        table_data.append([facility_name,
                          activity_name, str(start_time), str(end_time), str(num_people)])

    table = Table(table_data, colWidths=[100, 100, 100, 100, 100])
    table.setStyle(TableStyle([
        ('BACKGROUND', (0, 0), (-1, 0), colors.gray),
        ('TEXTCOLOR', (0, 0), (-1, 0), colors.whitesmoke),
        ('ALIGN', (0, 0), (-1, -1), 'CENTER'),
        ('FONTNAME', (0, 0), (-1, 0), 'Helvetica-Bold'),
        ('BOTTOMPADDING', (0, 0), (-1, 0), 12),
        ('BACKGROUND', (0, 1), (-1, -1), colors.beige),
    ]))

    table.wrapOn(p, 400, 200)
    table.drawOn(p, x, y - img_height - 50)

    print("\n")
    print("\n")
    print("\n")
    print("\n")
    print("\n")
    print("\n")

    p.drawString(450, 200, f"Name: {current_user.User}")
    p.drawString(450, 200 - line_height, f"Date: {datetime.now().date()}")
    p.drawString(450, 200 - 2 * line_height,
                 f"Time: {datetime.now().time()}")
    p.drawString(450, 200 - 3 * line_height,
                 f"Total Amount: {total_amount}")

    # Save the PDF buffer
    p.save()
    buffer.seek(0)

    # Send the email with the PDF attachment
    msg = Message('Booking Receipt', sender='skrgtm2059@gmail.com',
                  recipients=[current_user.Email])
    msg.attach('receipt.pdf', 'application/pdf', buffer.read())
    mail.send(msg)

    return redirect(url_for('my_bookings'))

    # else:
    #     # Session expired or user not logged in
    #     # Redirect the user to the login page or handle re-authentication as needed
    #     return redirect(url_for('login'))  # Redirect to the login page


# ******************************* When User Purchases Membership ************************
# ************************************************************************************************************
# Membership Prices For Monthly and annual memberships.
plans = {
    'monthly': {
        'name': 'Club Membership',
        'price_id': 150,
        'interval': 'month',
        'currency': 'Rs'
    },
    '3_months': {
        'name': 'Gym Membership',
        'price_id': 250,
        'interval': '3 months',
        'currency': 'Rs'
    },
    '6_months': {
        'name': 'Club Membership',
        'price_id': 350,
        'interval': '6 months',
        'currency': 'Rs'
    },
    'yearly': {
        'name': 'Club Membership',
        'price_id': 500,
        'interval': 'year',
        'currency': 'Rs'
    },
}

# Route to handle the user orders.
# Users can cancel their orders redirecting them to cancel page.
# Else to the success url which activates user membership.

# Khalti payment gateway for subscription


@app.route('/subscription_success', methods=['GET'], strict_slashes=False)
@login_required
@require_role(role="User")
def subscription_success():
    user_id = current_user.id
    user_subscription = UserAccount.query.filter_by(id=user_id).first()

    if not user_subscription:
        return redirect(url_for('user'))

    # Extract membership_type from the query parameters
    membership_type = request.args.get('membership_type')

    if membership_type:
        membership_type = membership_type.split('?')[0]

        selected_plan = plans.get(membership_type)
        if selected_plan:
            user_subscription.Member = True
            # Store membership name
            user_subscription.member_type = selected_plan['name']
            user_subscription.start_date = datetime.now().date()

        if membership_type.startswith('yearly'):
            user_subscription.end_date = user_subscription.start_date + \
                timedelta(days=365)
        elif membership_type.startswith('monthly'):
            user_subscription.end_date = user_subscription.start_date + \
                timedelta(days=30)
        elif membership_type.startswith('3_months'):
            user_subscription.end_date = user_subscription.start_date + \
                timedelta(days=90)
        elif membership_type.startswith('6_months'):
            user_subscription.end_date = user_subscription.start_date + \
                timedelta(days=180)

        db.session.commit()
        msg = Message('Membership Subscription Confirmation',
                      sender='skrgtm2059@gmail.com',
                      recipients=[current_user.Email])
        msg.html = render_template(
            'membership_email.html', membership_type=membership_type)
        mail.send(msg)
        return redirect(url_for('user'))

    return 'Membership type not specified', 400


@app.route('/order_subscription/<string:username>', methods=['GET', 'POST'])
@login_required
@require_role(role="User")
def order_subscription(username):
    user = UserAccount.query.filter_by(User=username).first()

    plan_id = request.form.get('plan_id')
    memberships = Membership.query.all()

    if user is None:
        abort(404, f"No user found with username: {username}")

    if request.method == 'POST':
        plan_id = request.form.get('plan_id')
        selected_plan = plans.get(plan_id)

        if selected_plan:
            amount = selected_plan.get('price_id')
            amount_paisa = int(amount * 100)

            # Modify the return_url to include the membership_type as a query parameter
            return_url = url_for('subscription_success',
                                 _external=True) + f"?membership_type={plan_id}"

            payload = json.dumps({
                "return_url": return_url,
                "website_url": "http://localhost:5000",
                "amount": amount_paisa,
                "purchase_order_id": "Order01",
                "purchase_order_name": selected_plan['name']
                # Add other fields as needed
            })

            headers = {

                # test key
                # 'Authorization': 'key b42caed1ffbd4202b41b700a32e3a237',
                # my key
                'Authorization': 'key a0021f9f714144c5bc2b0dffb56f2c5b',
                'Content-Type': 'application/json',
            }

            response = requests.post(
                "https://a.khalti.com/api/v2/epayment/initiate/", headers=headers, data=payload)

            if response.status_code == 200:
                response_data = response.json()
                return redirect(response_data['payment_url'])
            else:
                app.logger.error(
                    f"Failed to initiate payment: {response.text}")
                return jsonify({'error': 'Payment initiation failed', 'message': response.text}), response.status_code

    return render_template('all_subscriptions.html', username=username, plans=plans, current_user=user, memberships=memberships)

# ************************************************************************************
# @app.route('/manorder_subscription/<string:username>', methods=['GET', 'POST'])
# @login_required
# @require_role(role="User")
# def manorder_subscription(username):
#     user = UserAccount.query.filter_by(User=username).first()
#     c_user = user.User

#     if (user.Member == True):
#         print("Is a member")
#     else:
#         print("Nope")

#     if user is None:
#         abort(404, f"No user found with username: {username}")

#     if request.method == 'POST':

#         plan_id = request.form.get('plan_id')

#         selected_plan = Membership.query.filter_by(id=plan_id).first()

#         if selected_plan:
#             amount = selected_plan.price
#             amount_paisa = int(amount * 100)

#             # Modify the return_url to include the membership_type as a query parameter
#             return_url = url_for('subscription_success',
#                                  _external=True) + f"?membership_type={plan_id}"

#             payload = json.dumps({
#                 "return_url": return_url,
#                 "website_url": "http://localhost:5000",
#                 "amount": amount_paisa,
#                 "purchase_order_id": "Order01",
#                 "purchase_order_name": "Member"
#                 # Add other fields as needed
#             })

#             headers = {
#                 'Authorization': 'key b42caed1ffbd4202b41b700a32e3a237',
#                 'Content-Type': 'application/json',
#             }

#             response = requests.post(
#                 "https://a.khalti.com/api/v2/epayment/initiate/", headers=headers, data=payload)

#             if response.status_code == 200:
#                 response_data = response.json()
#                 return redirect(response_data['payment_url'])
#             else:
#                 app.logger.error(
#                     f"Failed to initiate payment: {response.text}")
#                 return jsonify({'error': 'Payment initiation failed', 'message': response.text}), response.status_code

#     # Fetch all available membership plans from the database
#     memberships = Membership.query.all()

#     return render_template('all_subscriptions.html', username=username, memberships=memberships, current_user=c_user)


# **********************************************************************************

# Route to display all membership types
@app.route('/display_memberships')
def display_memberships():
    # Retrieve all memberships from the database
    memberships = Membership.query.all()
    # print(memberships)
    return render_template('all_subscriptions.html', memberships=memberships)

# *************************************************************************************************************
# Route to allow users to cancel their membership
# Cchecks if the user account exists and if the user is a member before cancelling.
# If user is not member the user is redirected to homepage
# If user is a member the membership is revoked and memebrship information is erased.


@app.route('/cancel_usermembership/<int:user_id>', methods=['POST'])
@login_required
@require_role(role="User")
def cancel_usermembership(user_id):
    user = UserAccount.query.filter_by(id=user_id).first()
    # print(user)
    if user:
        user.Member = False
        user.member_type = None
        user.start_date = None
        user.end_date = None
        db.session.commit()
        # flash('Membership canceled successfully')
        return redirect(url_for('user'))
    else:
        flash('User not found')
        return redirect(url_for('user'))

# ******************************* When User Purchases Membership ************************


# @login_required
# route to handle the successful payment
# Makes the user a member and sets info based on the length of the subscription.
@app.route('/success')
@login_required
@require_role(role="User")
def success():
    payment_type = request.args.get('payment_type')

    if payment_type == 'booking':
        booking_id = request.args.get('booking_id')
        booking = Booking.query.get(booking_id)
        if booking:
            booking.Status = "Paid"
            db.session.commit()

    elif payment_type == 'subscription':
        username = request.args.get('username')
        user = UserAccount.query.filter_by(User=username).first()
        if user:
            plan_id = request.args.get('plan_id')
            plan = plans.get(plan_id)

            if plan:
                # Set membership start and end dates based on the subscription plan
                start_date = datetime.utcnow().date()
                if plan['interval'] == 'month':
                    end_date = start_date + relativedelta(months=1)
                elif plan['interval'] == 'year':
                    end_date = start_date + relativedelta(years=1)
                else:
                    end_date = None

                # Update the user's membership information in the database
                user.Member = True
                user.start_date = start_date
                user.end_date = end_date
                user.Membership_Type = plan['name']
                db.session.commit()

    return redirect(url_for('user'))


# **************************************** Manager Role **********************************************

# route for Employee & Manager login
# Redirects the user to Employee/Manager Homepage depending on the role of the account.
# PRecents login if account does not exist, Password is incorrect or if the account type is User.
@app.route('/emp_login', methods=['GET', 'POST'])
def employee_login():
    form = EmpLoginForm()
    usr = form.userName.data
    if form.validate_on_submit():
        user = UserAccount.query.filter_by(User=usr).first()
        if user is None or not user.check_password(form.userPassword.data):
            flash('Invalid username or password for employees!', 'error')
            app.logger.warning('Invalid Login')
            return redirect('/emp_login')
        if not user.has_role("Employee") and not user.has_role("Manager"):
            flash('This login is for employees and managers only!', 'error')
            app.logger.warning('Not an Employee')
            return redirect('/emp_login')
        if user.has_role("Employee"):
            login_user(user)
            return redirect("/emp_homepage")
        if user.has_role("Manager"):
            login_user(user)
            return redirect("/mgr_homepage")
    return render_template('emplogin_page.html',
                           title='Login', form=form)


# Manager Homepage
@app.route('/mgr_homepage')
@login_required
@require_role(role="Manager")
def MgrHomepage():
    # redirects user to landing page
    return render_template('yt.html',
                           title='Home', User=current_user)

# Route to handle Employee Creation.
# Employee/Manager accounts can be created.
# Route accessible by managers only as per spec
# Checks if the Email and username are existing, preventing account creation if so
# Else account is created, Bypassing verification process.


@app.route('/create_emp', methods=['GET', 'POST'])
@require_role(role="Manager")
@login_required
def newemp():
    form = EmpSignupForm()
    usr = form.userName.data
    email = form.userEmail.data
    paswrd = form.userPassword.data
    if form.validate_on_submit():
        usern = UserAccount.query.filter_by(User=usr).first()
        emailn = UserAccount.query.filter_by(Email=email).first()
        if usern is not None:
            flash('User already exists')
            app.logger.warning('Invalid Account Creation')
            return redirect('/create_emp')
        if emailn is not None:
            app.logger.warning('Invalid Account Creation')
            flash('email ID already exists')
            return redirect('/create_emp')
        # Check if the passwords match
        if form.userPassword.data != form.userVerifyPassword.data:
            flash('Passwords must match', 'userVerifyPassword')
            app.logger.warning(
                'Invalid Account Creation: Passwords do not match')
            return redirect('/create_emp')
        # Password complexity check (you can define your own criteria)
        import re
        pattern = re.compile(
            r'^(?=.*[a-z])(?=.*[A-Z])(?=.*\d)(?=.*[@$!%*?&])[A-Za-z\d@$!%*?&]+$')
        if not re.match(pattern, form.userPassword.data):
            flash('Password must contain at least one uppercase letter, one lowercase letter, one number, and one special character', 'userPassword')
            app.logger.warning('Invalid Account Creation: Weak password')
            return redirect('/create_emp')
        userData = UserAccount(User=usr, Email=email, Password=form.userPassword.data,
                               Mobile=form.CountryCode.data+form.Mobile.data)
        db.session.add(userData)
        role = Role.query.filter_by(name=form.role.data).first()
        userData.verified = True
        userData.roles.append(role)
        db.session.commit()
        flash('New Employee created successfully!', 'success')
        return redirect('/create_emp')
    # redirects user to landing page
    return render_template('newemp.html', title='Home', form=form)

# Route to handle Facility Creation.
# Facility with a default activity 'General Usr' is created
# Route accessible by managers only as per spec
# Checks if the Facility exists, preventing Facility creation if so
# If checks are passed, 2 Weeks worth of sessions is generated using the dynamic sessions script.


@app.route('/create_facility', methods=['GET', 'POST'])
@require_role(role="Manager")
@login_required
def new_facility():
    form = CreateFacilityForm()
    if form.validate_on_submit():

        # if form.Start_time.data > form.End_time.data:
        #     flash('Start time cannot be after end time', 'Start_time')
        #     return redirect('/create_facility')

        checkfacility = Facility.query.filter_by(Name=form.Name.data).first()
        if checkfacility is not None:
            flash('Facility already exists')
            return redirect('/create_facility')

        if form.Capacity.data <= 0:
            flash('Capacity should be a positive number', 'Capacity')
            return redirect('/create_facility')
        facility = Facility(Name=form.Name.data, Capacity=form.Capacity.data,
                            Start_Facility=form.Start_time.data, End_Facility=form.End_time.data)
        activity = Activity(Activity_Name="General use",
                            Amount=form.Amount.data)
        db.session.add(activity)
        facility.activities.append(activity)
        db.session.add(facility)
        db.session.commit()
        flash('New Facility created successfully', 'success')
        dynamic_sessions(facility.id, form.Start_time.data,
                         form.End_time.data, form.Capacity.data, activity.id)
        return redirect('/create_facility')
    return render_template('createfacility.html', form=form)


# Route to handle Activity Creation.
# Activity with entered information is created
# Route accessible by managers only as per spec
# Checks if the Activity exists, preventing Activity creation if so
# If checks are passed, Activity is added to all existing sessions that have the same facility as this activity.
@app.route('/create_activity', methods=['GET', 'POST'])
@require_role(role="Manager")
@login_required
def new_activity():
    facilities = Facility.query.all()
    facility_choices = [(f.id, f.Name) for f in facilities]
    form = CreateActivityForm()
    form.Facility_Name.choices = facility_choices

    if form.validate_on_submit():
        facility = Facility.query.filter_by(id=form.Facility_Name.data).first()

        if not facility:
            flash('Facility not found', 'error')
            return redirect('/create_activity')

        check_activity = Activity.query.filter_by(
            Activity_Name=form.Activity_Name.data, facility_id=form.Facility_Name.data).first()

        if check_activity and check_activity in facility.activities:
            flash('Activity already exists for this facility', 'error')
            return redirect('/create_activity')

        activity = Activity(
            Activity_Name=form.Activity_Name.data, Amount=form.Amount.data)
        if check_activity in facility.activities:
            flash('Activity already exists')
            return redirect('/create_activity')
        facility.activities.append(activity)
        db.session.add(activity)
        try:
            db.session.commit()
            flash('New Activity created successfully!', 'success')
            # Assuming this function exists
            append_to_session(facility.id, activity.id)
            return redirect('/create_activity')
        except Exception as e:
            db.session.rollback()
            flash('Error creating activity. Please try again.', 'error')
            app.logger.error(f'Error creating activity: {str(e)}')
            return redirect('/create_activity')

    return render_template('createactivity.html', form=form)

# Route to update facility information
# Route accessible to managers only as per spec
# Allows user to select the facility from the dropdown.
# The activity Facilty is then updated if form is valid.


@app.route('/update_facility', methods=['GET', 'POST'])
@require_role(role="Manager")
@login_required
def update_facility():
    form = UpdateFacilityForm()
    facilities = Facility.query.all()
    facility_choices = [(f.id, f.Name) for f in facilities]
    form.Facility_Namez.choices = facility_choices

    if request.method == "POST" and form.validate_on_submit():
        try:
            facility = Facility.query.filter_by(
                id=int(form.Facility_Namez.data)).first()

            if not facility:
                flash('Facility not found', 'error')
                return redirect('/update_facility')

            facility.Name = form.Name.data
            facility.Capacity = form.Capacity.data
            facility.Start_Facility = form.Start_time.data
            facility.End_Facility = form.End_time.data
            db.session.commit()
            flash('Facility updated successfully!', 'success')
            return redirect('/update_facility')
        except Exception as e:
            db.session.rollback()
            flash('Error updating facility. Please try again.', 'error')
            app.logger.error(f'Error updating facility: {str(e)}')
            return redirect('/update_facility')

    return render_template('updatefacility.html', form=form)

# Route to update activity information
# Route accessible to managers only as per spec
# Allows user to select the facility, then displays all activites linked to the facility in a select dropdown
# The activity information is then updated.


@app.route('/update_Activity', methods=['GET', 'POST'])
@require_role(role="Manager")
@login_required
def update_activity():
    facilities = Facility.query.all()
    facility_choices = [(f.id, f.Name) for f in facilities]

    activities = Activity.query.all()
    activity_choices = [(a.id, a.Activity_Name) for a in activities]

    form = UpdateActivityForm()
    form.New_Facility_Name.choices = facility_choices
    form.Activity_Selector.choices = activity_choices
    if request.method == "POST" and form.validate_on_submit():
        activity = Activity.query.filter_by(
            id=int(form.Activity_Selector.data)).first()
        activity.Activity_Name = form.New_Activity_Name.data
        activity.Amount = form.New_Amount.data
        # facilityz = Facility.query.filter_by(id = int(form.New_Facility_Name.data)).first()
        # activity.facility_id = facilityz.id
        db.session.commit()
        flash('New Activity updated successfully!', 'success')
        return redirect('/update_Activity')
    return render_template('updateactivity.html', form=form)


# getter to get the facility information and converts data to JSON form.
@app.route('/facility_data/<string:facility_name>')
@require_role(role="Manager")
@login_required
def facility_data(facility_name):
    facility = Facility.query.filter_by(id=int(facility_name)).first()
    if not facility:
        return jsonify({'error': 'Facility not found'})
    data = {
        'name': facility.Name,
        'capacity': facility.Capacity,
        'start_time': facility.Start_Facility,
        'end_time': facility.End_Facility
    }

    return jsonify(data)


# getter to retrieve activity information and converts data to JSON form.
# requires the activity name as a string.
@app.route('/activity_data/<string:activity_name>')
@require_role(role="Manager")
@login_required
def activity_data(activity_name):
    activity = Activity.query.filter_by(id=int(activity_name)).first()
    if not activity:
        return jsonify({'error': 'Activity not found'})
    data = {
        'name': activity.Activity_Name,
        'amount': activity.Amount,
        'facility_id': activity.facility_id,
    }
    return jsonify(data)

# Getter to get facility and all activities linked to that facility
# Converts this data into JSON form
# Requires the facility id as a paramenter.


@app.route('/facility_activities/<int:facility_id>')
@require_role(role="Manager")
@login_required
def extractactivites(facility_id):
    facility = Facility.query.get_or_404(facility_id)
    activities = facility.activities.all()
    activity_names = [(activity.id, activity.Activity_Name)
                      for activity in activities]
    return jsonify(activity_names)

# Page that lists all Facility Activity Prices
# This was impelemented to allow info to be viewed and updated


@app.route('/pricing', methods=["GET", "POST"])
@require_role(role="Manager")
@login_required
def pricing():
    activity = Activity.query.all()
    return render_template('pricing.html', activity=activity)


# Your route for manager membership addition

# Route to add a new membership type

@app.route('/mgr_membership', methods=['GET', 'POST'])
def add_membership():
    form = AddMembershipForm()
    if form.validate_on_submit():
        new_membership = Membership(
            name=form.name.data,
            price=form.price.data,
            interval=form.interval.data,
            currency=form.currency.data
        )

        db.session.add(new_membership)
        db.session.commit()

        flash('New membership type added successfully!', 'success')
        # Update with your manager dashboard route
        return redirect(url_for('add_membership'))

    return render_template('add_membership.html', form=form)


# Route to view all membership types
@app.route('/mgr_edit_membership')
def view_memberships():
    memberships = Membership.query.all()
    return render_template('view_memtype.html', memberships=memberships)


# Route to delete a membership
@app.route('/delete_membership/<int:membership_id>', methods=['GET', 'POST'])
def delete_membership(membership_id):
    # Find the membership by its ID
    membership = Membership.query.get_or_404(membership_id)

    # Delete the membership
    db.session.delete(membership)
    db.session.commit()

    return redirect(url_for('view_memberships'))


# @app.route('/delete_membership/<int:membership_id>', methods=['GET', 'POST'])
# def delete_membership(id):
#     membership = Membership.query.get(id)
#     if membership:
#         db.session.delete(membership)
#         db.session.commit()
#     return render_template('view_memtype.html')

# # Route to delete a membership type
# @app.route('/delete_membership/<int:membership_id>', methods=['POST'])
# def delete_membership(membership_id):
#     membership = Membership.query.get_or_404(membership_id)
#     db.session.delete(membership)
#     db.session.commit()
#     flash('Membership type deleted successfully!', 'success')
#     return redirect(url_for('view_memberships'))  # Redirect to view memberships page

# # Route to update a membership type (optional)
# @app.route('/edit_membership/<int:membership_id>', methods=['GET', 'POST'])
# def edit_membership(membership_id):
#     membership = Membership.query.get_or_404(membership_id)
#     form = AddMembershipForm(obj=membership)
#     if form.validate_on_submit():
#         membership.name = form.name.data
#         membership.price = form.price.data
#         membership.interval = form.interval.data
#         membership.currency = form.currency.data

#         db.session.commit()
#         flash('Membership type updated successfully!', 'success')
#         return redirect(url_for('view_memberships'))  # Redirect to view memberships page

#     return render_template('edit_membership.html', form=form)


# ****************************************** End of Manager Roles *****************************************

# ************************************ Employee Roles ********************************************

# Route for employee homepage
@app.route('/emp_homepage')
@require_role(role="Employee")
@login_required
def EmpHomepage():
    # redirects user to landing page
    return render_template('employeefp.html', title='Home', User=current_user)


# Rote that allows employees to amend bookings on behalf of the user.
# Validates the email entered exists.
# On success retrieves all the bookinngs which are Paid by the user.
# Only accessible by employees based on spec
@app.route('/lookup_bookings', methods=['GET', 'POST'])
@require_role(role="Employee")
@login_required
def look_bookings():
    form = ViewBookings()
    bookings = None
    form_submitted = None
    if request.method == 'POST' and form.validate_on_submit():
        form_submitted = True
        user_email = form.userEmail.data
        user = UserAccount.query.filter_by(Email=user_email).first()
        if user is not None:
            bookings = Booking.query.filter_by(
                user_id=user.id, Status="Booked").all()
        else:
            flash('User not found', 'danger')
    return render_template('view_bookingsEmp.html', bookings=bookings, form=form, form_submitted=form_submitted)


# Route which handle booking modification
# The booking id is taken in as a parameter.

@app.route('/edit_booking/<int:booking_id>', methods=['GET', 'POST'])
@require_role(role="Employee")
@login_required
def edit_booking(booking_id):
    booking = Booking.query.get(booking_id)
    print(booking)  # Get the booking by its ID

    if not booking:
        flash('Booking not found', 'danger')
        return redirect(url_for('look_bookings'))

    if booking.Status != "Booked":
        flash('Booking cannot be edited because it has already occurred', 'danger')
        return redirect(url_for('look_bookings'))

    form = EditBookingForm(obj=booking)

    if request.method == 'POST' and form.validate_on_submit():
        if form.cancel.data:  # Check if the cancel button was clicked
            booking_sessionFilter = Sessions.query.filter_by(
                Start_time=form.start_time.data, End_time=form.end_time.data).first()
            print(booking_sessionFilter)
            booking_filter = Booking.query.filter_by(
                Book_Time=form.date.data, session=booking_sessionFilter.id).first()
            if not booking_filter and booking_sessionFilter:
                flash('No Booking Found to Cancel.')
            else:
                booking.Status = "Cancelled"
                booking.session.Remaining_Cap += booking.Size  # Increase the remaining capacity
                flash('Booking cancelled successfully', 'success')
        else:
            old_session = booking.session
            new_session = Sessions.query.filter_by(
                Date=form.date.data, Start_time=form.start_time.data, End_time=form.end_time.data).first()
            print(new_session)

            if not new_session:
                flash('No session found for the new date and time', 'danger')
                return render_template('edit_booking.html', form=form, booking_id=booking_id)

            if new_session.Remaining_Cap < booking.Size:
                flash('Not enough capacity for the new session', 'danger')
                return render_template('edit_booking.html', form=form, booking_id=booking_id)

            # Update the remaining capacities
            old_session.Remaining_Cap += booking.Size
            new_session.Remaining_Cap -= booking.Size

            # Update the booking
            booking.session_id = new_session.id
            booking.session = new_session
            db.session.add(old_session)
            db.session.add(new_session)
            flash('Booking updated successfully', 'success')

        db.session.commit()
        return redirect(url_for('look_bookings'))

    return render_template('edit_booking.html', form=form, booking_id=booking_id, booking=booking)


# Route that takes in the user account to check membership information
# Only allows member details to be accessed if the account is a User account
# Else respective errors are displayed
@app.route('/view_userMembership', methods=['GET', 'POST'])
@require_role(role="Employee")
@login_required
def create_userMembership():
    form = UserMember()
    form_submitted = False
    member = None
    if request.method == 'POST' and form.validate_on_submit():
        form_submitted = True
        user_email = form.userEmail.data

        isuser = UserAccount.query.filter_by(Email=user_email).all()

        if not isuser:
            flash('Not a User')

        else:
            verifyuser = UserAccount.query.filter_by(Email=user_email).first()

            if verifyuser.has_role("User"):
                ismember = UserAccount.query.filter_by(
                    Email=user_email).first()
                if ismember.Member:
                    member = verifyuser
                else:
                    flash('Not a Member')
            else:
                flash('Not a User')
    return render_template('view_userMembership.html', form=form, form_submitted=form_submitted, member=member)


# route that cancels users membership
# Requires user id as a parameter.
# Deletes all membership information and revokes membership on successful identification of account
# Else error message is displayed.
@app.route('/cancel_membership/<int:user_id>', methods=['POST'])
@require_role(role="Employee")
@login_required
def cancel_membership(user_id):
    user = UserAccount.query.get(user_id)
    if user:
        user.Member = False
        user.member_type = None
        user.start_date = None
        user.end_date = None
        db.session.commit()
        flash('Membership canceled successfully')
        return redirect(url_for('create_userMembership'))
    else:
        flash('User not found')
        return redirect(url_for('create_userMembership'))


# Route that creates bookings for a user by the employee
# Checks if the user account existis, returning appropriate error messages if account does not exist.
# IF account exists a booking can be made on behalf of the user
@app.route('/create_bookings', methods=['GET', 'POST'])
@require_role(role="Employee")
@login_required
def create_bookings():
    form = CreateBookings()
    bookings = None
    form_submitted = None
    user = None
    if request.method == 'POST' and form.validate_on_submit():
        form_submitted = True
        user_email = form.userEmail.data

        isuser = UserAccount.query.filter_by(Email=user_email).all()

        if not isuser:
            print(" ")

        else:
            verifyuser = UserAccount.query.filter_by(Email=user_email).first()

            if verifyuser.has_role("User"):
                bookings = UserAccount.query.filter_by(Email=user_email).all()
                flash('User')

    return render_template('create_bookings.html', bookings=bookings, form=form, form_submitted=form_submitted)


# Route to handle the booking information
# Taking in facility and activity information, Date and party size to get the number of sessions that match the criteria.
@app.route('/booking_details', methods=['GET', 'POST'])
@login_required
@require_role(role="Employee")
def booking_details():
    form = BookingDetailsForm()
    sessions = None
    data = None  # Initialize selected_activity_id here
    user_id = request.args.get('user_id')
    print(user_id)
    form.facility.choices = [(facility.id, facility.Name)
                             for facility in Facility.query.all()]
    form.activity.choices = [(activity.id, activity.Activity_Name)
                             for activity in Activity.query.all()]

    group_size = None
    activity_price = None
    activity_id = None

    if request.method == 'POST':
        activity_id1 = form.activity.data
        print(activity_id1)
        data_price = Activity.query.filter_by(id=activity_id1).first()
        activity_price = int(data_price.Amount)
        group_size = int(form.capacity.data)
        print(activity_price)
        print(group_size)
        print("Form submitted")

        if form.validate_on_submit():
            facility_id = form.facility.data
            activity_id = form.activity.data
            date = form.date.data
            capacity = form.capacity.data

            data = Activity.query.filter_by(id=activity_id).first()
            venue = Facility.query.get(facility_id)

            if form.date.data == datetime.now().date():
                current_time = datetime.now().time()
                sessions = Sessions.query.filter(
                    Sessions.facility_id == facility_id,
                    Sessions.activities.any(id=activity_id),
                    Sessions.Date == form.date.data,
                    Sessions.Start_time >= current_time,
                    Sessions.Remaining_Cap >= capacity
                ).all()
            else:
                sessions = Sessions.query.filter(
                    Sessions.facility_id == facility_id,
                    Sessions.activities.any(id=activity_id),
                    Sessions.Date == form.date.data,
                    Sessions.Start_time >= venue.Start_Facility,
                    Sessions.Remaining_Cap >= capacity
                ).all()

        else:
            print("Form validation failed")
            print(form.errors)

    return render_template('booking_details.html', form=form, sessions=sessions, data=data, group_size=group_size, activity_price=activity_price, activity_id=activity_id, user_id=user_id)

# **********************************************************************************************

# Gets all the information from the route above and displays all the possible sessions.


@app.route('/book_session_emp', methods=['POST'])
@login_required
# @require_role(role="User")
def book_session_emp():
    session_id = request.form.get('session_id')
    activity_id = int(request.args.get('activity_id'))
    user_id = int(request.form.get('user_id'))
    print("User ID:", user_id)
    group_size = int(request.args.get('group_size'))
    activity_price = int(request.args.get('activity_price'))
    booking_Price = int(group_size * activity_price)
    session = Sessions.query.get(session_id)
    # Check if there's enough remaining capacity for the booking
    if session.Remaining_Cap >= group_size:
        booking = Booking(
            user_id=user_id,
            session_id=session_id,
            activity_id=activity_id,
            Book_Time=session.Date,
            Status="employeeDiscount",
            Size=group_size,
            Amount=booking_Price
        )
        booking.user_id = user_id

        # Reduce the session's remaining capacity by the group size
        session.Remaining_Cap -= group_size

        db.session.add(booking)
        db.session.commit()

        # Add a message to notify the user that the booking was successful.
        flash('Booking successfully!', 'success')
        return redirect(url_for('create_booking'))
    else:
        flash('Not enough remaining capacity for the booking.')

    return redirect(url_for('booking_details'))


@app.route('/empcheckout_page', methods=['POST', 'GET'])
@login_required
@require_role(role="Employee")
def empcheckout_page():

    form = CreateBookings()
    form1 = empcheckout()
    total_amount = 0
    discount_amount = 0
    final_amount = 0

    aggregated_data = []
    if request.method == 'POST' and form.validate_on_submit():
        form_submitted = True
        user_email = form.userEmail.data

        isuser = UserAccount.query.filter_by(Email=user_email).first()
        print(isuser.id)
        if isuser:

            data = Booking.query.filter_by(
                user_id=isuser.id, Status="employeeDiscount").all()
            print(data)

            grouped_data = defaultdict(list)

            for item in data:
                grouped_data[item.session_id].append(item)
            total_amount = sum(
                [item.Size * item.activity.Amount for item in data])

            for session_id, items in grouped_data.items():
                total_size = sum(item.Size for item in items)
                aggregated_data.append({
                    'item': items[0],
                    'quantity': len(items),
                    'total_size': total_size
                })
            print(aggregated_data)

            if request.method == 'POST' and form1.validate_on_submit():
                discount = form.discount.data
                discount_amount = total_amount * (discount / 100)
                final_amount = total_amount - discount_amount

        else:
            print("Not a user")

    else:
        print("form error")

    return render_template('empcheckout_page.html', data=aggregated_data, form=form, form1=form1, discount_amount=discount_amount, final_amount=final_amount)


# Getter that displays activity id and activity name for a given facility
# requires facility id as a parameter
@app.route('/get_activities/<facility_id>', methods=['GET'])
@login_required
@require_role(role="Employee")
def get_activities_createBooking(facility_id):
    facility = Facility.query.get(facility_id)
    activities = [{'id': activity.id, 'Name': activity.Name}
                  for activity in facility.activities]
    return jsonify(activities)


# ****************************************** End of Employee ******************************************************


@login_manager.user_loader
def load_user(id):
    return UserAccount.query.get(int(id))


# ****************************************** User: After Login ******************************************************
# Route to allow users to select the activity , Facility ,Date and party size to
@app.route('/lookup_venue', methods=['POST', 'GET'])
@login_required
@require_role(role="User")
def view_venue():
    form = FacilityActivityForm()

    form.facility_name.choices = [(facility.id, facility.Name)
                                  for facility in Facility.query.all()]
    form.activity_name.choices = [
        (activity.id, activity.Activity_Name) for activity in Activity.query.all()]

    # Update the activity_name choices here
    all_activities = Activity.query.all()
    # form.activity_name.choices = [(a.Activity_Name, a.Activity_Name) for a in all_activities]

    available_sessions = []
    activities = Activity.query.all()
    activities_dict = [activity.activity_to_dict() for activity in activities]

    if form.validate_on_submit():
        facility_id = int(form.facility_name.data)
        venue = Facility.query.get(facility_id)
        activity_id = Activity.query.filter_by(
            id=form.activity_name.data).first()
        venue_activity = Activity.query.filter_by(
            Activity_Name=activity_id.Activity_Name, facility_id=venue.id).first()
        if venue_activity:  # Check if venue_activity is not None
            group_size = form.size.data
            activity_price = venue_activity.Amount

            if venue:
                query = Sessions.query.filter(
                    Sessions.facility_id == venue.id,
                    Sessions.Date == form.date.data,
                    Sessions.activities.any(
                        Activity.Activity_Name == activity_id.Activity_Name),
                    Sessions.Remaining_Cap >= form.size.data
                )

                if form.date.data == datetime.now().date():
                    current_time = datetime.now().time()
                    query = query.filter(Sessions.Start_time >= current_time)
                else:
                    query = query.filter(
                        Sessions.Start_time >= venue.Start_Facility)

                print(f"Query: {query}")  # Debug print
                query_result = query.all()
                print(f"Query result: {query_result}")  # Debug print

                available_sessions = [
                    {'session': session, 'activity_name': activity_id.Activity_Name} for session in query.all()]
                print(available_sessions)
                session_ids = [
                    session['session'].id for session in available_sessions]
                session['available_session_ids'] = session_ids
                session['selected_activity_name'] = activity_id.Activity_Name
                return redirect(url_for('view_sessions', group_size=group_size, activity_price=activity_price))
            else:
                print("No activity found with the given name and facility")
    else:
        print("Form errors:", form.errors)

    return render_template('search_results.html', title='Search Venue', form=form, sessions=available_sessions, activities=activities_dict)


# page that displays all sessions that the user can book
# takes all the data previously filled by the user such as activity, facility ,date and group size to display all sessions in a tabular form

@app.route('/view_sessions', methods=['POST', 'GET'])
@login_required
@require_role(role="User")
def view_sessions():
    available_sessions = session.get('available_session_ids', [])
    selected_activity_name = session.get('selected_activity_name', None)
    group_size = request.args.get('group_size')
    activity_price = request.args.get('activity_price')
    print(activity_price)
    sessions_with_data = []

    for s in Sessions.query.filter(Sessions.id.in_(available_sessions)).all():
        for activity in s.facility.activities:
            if activity.Activity_Name == selected_activity_name:
                sessions_with_data.append(
                    {'session': s, 'activity_name': activity.Activity_Name, 'activity_id': activity.id})

    return render_template('sessions.html', sessions=sessions_with_data, group_size=group_size, activity_price=activity_price)


@app.route('/book_session', methods=['POST'])
@login_required
# @require_role(role="User")
def book_session():
    session_id = request.form.get('session_id')
    activity_id = request.form.get('activity_id')
    user_id = current_user.id
    group_size = int(request.args.get('group_size'))
    activity_price = int(request.args.get('activity_price'))
    booking_Price = int(group_size * activity_price)
    # Get the session object
    session = Sessions.query.get(session_id)

    # Check if there's enough remaining capacity for the booking
    if session.Remaining_Cap >= group_size:
        booking = Booking(
            user_id=user_id,
            session_id=session_id,
            activity_id=activity_id,
            Book_Time=session.Date,
            Status="Saved",
            Size=group_size,
            Amount=booking_Price
        )

        # Reduce the session's remaining capacity by the group size
        session.Remaining_Cap -= group_size

        db.session.add(booking)
        db.session.commit()

        # Add a message to notify the user that the booking was successful.
        flash('Booking successful!')
    else:
        flash('Not enough remaining capacity for the booking.')

    return redirect(url_for('checkout_page'))

# route that displays booking info in the cart
# Cart can be modified dynamically using ajax
# Discount amount of 15% is also passed in if the number of bookings is more that 3


@app.route('/checkout_page', methods=['POST', 'GET'])
@login_required
@require_role(role="User")
def checkout_page():
    data = Booking.query.filter_by(
        user_id=current_user.id, Status="Saved").all()
    total_amount = sum([item.Size * item.activity.Amount for item in data])
    grouped_data = defaultdict(list)

    for item in data:
        grouped_data[item.session_id].append(item)

    aggregated_data = []
    for session_id, items in grouped_data.items():
        total_size = sum(item.Size for item in items)
        aggregated_data.append({
            'item': items[0],
            'quantity': len(items),
            'total_size': total_size
        })
    discount = 0
    if len(aggregated_data) >= 3:
        # 15% discount for 3 or more sessions
        discount = int(total_amount * 0.15)
    if current_user.Member:
        discount = int(total_amount * 0.5)  # 50% discount for members
        total_amount = total_amount - discount  # Apply the member discount

    return render_template('checkout_page.html', data=aggregated_data, total_amount=total_amount, discount=discount)


# Removes all expired bookings
@app.route('/delete_expired_booking', methods=['GET', 'POST'])
@login_required
@require_role(role="User")
def delete_expired_booking():
    print("Deleting expired bookings on the server...")
    user_bookings = Booking.query.filter_by(
        user_id=current_user.id, Status="Saved").all()

    for booking in user_bookings:
        session = Sessions.query.get(booking.session_id)
        session.Remaining_Cap += booking.Size
        db.session.delete(booking)

    db.session.commit()
    print("Deleted!")
    return {'status': 'success'}

# Route that deletes user booking
# Requires booking id
# Does not allow users to cancel bookings thaat were not made by them, Returning a 403 status code if the user tries to do so
# Else the booking is cancelled, The session remaining capacity is updated accordingly and success message is displayed


@app.route('/delete_booking/<int:booking_id>', methods=['GET', 'POST'])
@login_required
@require_role(role="User")
def delete_booking(booking_id):
    booking = Booking.query.get_or_404(booking_id)
    if booking.user_id != current_user.id:
        abort(403)

    session_id = booking.session_id
    bookings_to_delete = Booking.query.filter_by(
        session_id=session_id, user_id=current_user.id).all()

    total_size = 0
    for b in bookings_to_delete:
        total_size += b.Size
        db.session.delete(b)

    session = Sessions.query.get(session_id)
    session.Remaining_Cap += total_size
    db.session.commit()

    flash('Booking has been deleted!', 'success')
    return redirect(url_for('checkout_page'))


# increase the booking size
# only bookings made by the user can be amended, else the 403 status code is returned
# If the booking was made by the user, Booking size increases and session capacity decreases
# If there are no more spaces left in the facility an appropriate error message is returned
# response is sent as JSON
@app.route('/increase_quantity/<int:booking_id>', methods=['POST'])
@login_required
@require_role(role="User")
def increase_quantity(booking_id):
    booking = Booking.query.get_or_404(booking_id)
    if booking.user_id != current_user.id:
        abort(403)

    session = Sessions.query.get(booking.session_id)
    if session.Remaining_Cap > 0:
        booking.Size += 1
        booking.Amount = booking.Size * booking.activity.Amount
        session.Remaining_Cap -= 1
        db.session.commit()

        response = {
            'total_size': booking.Size,
            'amount': booking.Size * booking.activity.Amount,
            'status': 'success'
        }
    else:
        response = {
            'status': 'error',
            'message': 'No more available spots'
        }

    return jsonify(response)

# decrease the booking size
# only bookings made by the user can be amended, else the 403 status code is returned
# If the booking was made by the user, Booking size decreases and session capacity increases
# If there are no more spaces left in the facility an appropriate error message is returned
# response is sent as JSON


@app.route('/decrease_quantity/<int:booking_id>', methods=['POST'])
@login_required
@require_role(role="User")
def decrease_quantity(booking_id):
    booking = Booking.query.get_or_404(booking_id)
    if booking.user_id != current_user.id:
        abort(403)

    if booking.Size > 1:
        session = Sessions.query.get(booking.session_id)
        booking.Size -= 1
        booking.Amount = booking.Size * booking.activity.Amount
        session.Remaining_Cap += 1
        db.session.commit()

        response = {
            'total_size': booking.Size,
            'amount': booking.Size * booking.activity.Amount,
            'status': 'success'
        }
    else:
        response = {
            'status': 'error',
            'message': 'No more available spots'
        }

    return jsonify(response)

# route to see all user bookings That are Booked


@app.route('/my_bookings')
@login_required
@require_role(role="User")
def my_bookings():
    bookings = Booking.query.filter_by(
        user_id=current_user.id, Status="Booked").all()
    current_time = datetime.now().date()
    return render_template('my_bookings.html', bookings=bookings, current_time=current_time)


# Route that cancels the user booking
# Does not allow users to cancel bookings not made by them , returning status code 403 if the user tries to
# IF the booking was made by the user, the booking is cancelled and the remaining capacity of the session is updated
@app.route('/cancel_booking/<int:booking_id>')
@login_required
@require_role(role="User")
def cancel_booking(booking_id):
    booking = Booking.query.get_or_404(booking_id)
    if booking.user_id != current_user.id:
        abort(403)
    session = Sessions.query.get(booking.session_id)
    session.Remaining_Cap += booking.Size
    booking.Status = "Cancelled"
    db.session.commit()
    flash("Booking has been cancelled successfully", "success")
    return redirect(url_for('my_bookings'))


@app.route('/get_activities/<int:facility_id>')
def get_activities(facility_id):
    facility = Facility.query.get(facility_id)
    activities = Activity.query.filter_by(facility_id=facility_id).all()
    activities_dict = [activity.activity_to_dict() for activity in activities]
    return jsonify(activities_dict)


@app.route('/get_activity_id/<activity_name>')
def get_activity_id(activity_name):
    activity = Activity.query.filter_by(Activity_Name=activity_name).first()
    if activity:
        return jsonify(activity.id)
    else:
        return jsonify(None)


@app.route('/facilities')
def facilities():
    facilities = Facility.query.all()
    return render_template('upcoming_sessions.html', facilities=facilities)


@app.route('/facility/<int:facility_id>/activity/<int:activity_id>/sessions')
def get_sessions_for_activity(facility_id, activity_id):
    sessions = Sessions.query.filter_by(facility_id=facility_id).join(
        session_activity_association).filter_by(activity_id=activity_id).all()
    session_dicts = [session.to_dict() for session in sessions]
    return jsonify(session_dicts)

# *********************************** End of User: After Login *****************************************

# ************************************ Update User Information ********************************************
# Route that allows the user to update their personal information
# Displays the existing information


@app.route('/update_user', methods=['GET', 'POST'])
@login_required
@require_role(role="User")
def update_user():
    form = UpdateUserForm()
    if form.validate_on_submit():
        current_user.User = form.User.data
        current_user.set_password(form.password.data)
        # current_user.Email = form.email.data
        current_user.Mobile = form.mobile.data

        db.session.commit()
        flash('Your personal information has been updated', 'success')
        return redirect(url_for('update_user'))
    elif request.method == 'GET':
        form.User.data = current_user.User
        form.email.data = current_user.Email
        form.mobile.data = current_user.Mobile

    return render_template('update_user.html', title='Update Personal Information', form=form)

# Route to display user information


@app.route('/user_information')
@login_required
def user_information():
    return render_template('user_information.html', title='User Account')


# ************************************ End of User Information ********************************************


# **********************************************ANALYTICS**********************************************************

# Loads the analytics page and the selectors required for retrieving relevant datta
@app.route('/analytics', methods=["GET", "POST"])
@require_role(role="Manager")
@login_required
def analytics():
    activityset = Activity.query.all()
    facilityset = Facility.query.all()
    current_year = datetime.utcnow().year
    current_year = datetime.utcnow().year
    start_of_year = datetime(current_year, 1, 1)
    end_of_year = datetime(current_year, 12, 31)
    next_year_start = datetime(current_year + 1, 1, 1)

    last_week_of_year = end_of_year - timedelta(days=end_of_year.weekday())
    next_year_first_week = next_year_start - \
        timedelta(days=next_year_start.weekday())

    weeks_in_current_year = last_week_of_year.isocalendar(
    )[1] + 1 if next_year_first_week.year != current_year else last_week_of_year.isocalendar()[1]

    week_data = []

    for week_number in range(1, weeks_in_current_year + 1):
        start_date = datetime.strptime(
            f"{current_year}-W{week_number-1}-1", "%Y-W%W-%w")
        end_date = start_date + timedelta(days=6)
        week_data.append((week_number, start_date.date(), end_date.date()))
    return render_template('analytics.html', title="Analytics", data=activityset, data1=facilityset, week=week_data)

# Getter that retrieves the count of members and non members
# Sends this data in JSON form
# This data is passed on to google charts and displayed in the analytics page as a pie chart


@app.route('/analyzemember', methods=["GET", "POST"])
@require_role(role="Manager")
@login_required
def analyze_members():
    total_users = UserAccount.query.count()
    member_users = UserAccount.query.filter_by(Member=True).count()
    non_member_users = UserAccount.query.filter_by(Member=False).count()
    data = {
        'members': member_users,
        'nonmembers': non_member_users,
    }
    return jsonify(data)


# Getter that calculated the average booking size.
# Take the total number of bookings, total size, average size and converts this data to JSON
# This data is displayed as a Table in the analytics page
@app.route('/analyzebookings', methods=["GET", "POST"])
@require_role(role="Manager")
@login_required
def bookingstats():
    total_bookings = Booking.query.count()
    total_size = Booking.query.with_entities(
        db.func.sum(Booking.Size)).scalar()
    if total_size is None:
        total_size = 0
    if total_bookings > 0:
        avg_booking_size = int(total_size / total_bookings)
    else:
        avg_booking_size = 0
    data = {
        'totalbookings': total_bookings,
        'totalsize': total_size,
        'avgsize': avg_booking_size
    }
    return jsonify(data)

# **************************************************************************************************


@app.route('/book', methods=['POST'])
def book():
    booking_data = request.json

    # Extract details from the POST request sent by the modal
    facility = booking_data.get('facility')
    activity = booking_data.get('activity')
    date = booking_data.get('date')
    start_time = booking_data.get('startTime')
    end_time = booking_data.get('endTime')
    amount = booking_data.get('amount')
    discount = booking_data.get('discount')
    total_amount_after_discount = booking_data.get('totalAmount')

    # Generate PDF receipt
    buffer = BytesIO()
    p = canvas.Canvas(buffer, pagesize=letter)

    # Load image
    # Load image
    static_folder = os.path.join(app.root_path, 'static')
    image_path = os.path.join(static_folder, 'images', 'nb.png')

    # Drawing image on canvas
    x = 50
    y = 700
    with PILImage.open(image_path) as pil_image:
        # Resize the image
        max_image_width = 500
        max_image_height = 200
        pil_image.thumbnail((max_image_width, max_image_height))

        # Convert the image to ReportLab's ImageReader format
        img = ImageReader(pil_image)
        img_width, img_height = pil_image.size

        p.drawImage(img, x, y, width=img_width, height=img_height)

    y -= img_height + 30

    # Set fonts and colors
    header_font = "Helvetica-Bold"
    content_font = "Helvetica"
    header_font_size = 20
    content_font_size = 12
    header_color = ('#336699')

    # Drawing the receipt content
    x = 50
    # y = 750

    # Header
    p.setFont(header_font, header_font_size)
    p.setFillColor(header_color)
    p.drawCentredString(300, y, "Booking Receipt")
    y -= 50

    # Receipt details
    p.setFont(content_font, content_font_size)
    p.setFillColor(header_color)  # Black color for content
    p.drawString(x, y, f"Facility ID: {facility}")
    y -= 20
    p.drawString(x, y, f"Activity ID: {activity}")
    y -= 20
    p.drawString(x, y, f"Date: {date}")
    y -= 20
    p.drawString(x, y, f"Start Time: {start_time}")
    y -= 20
    p.drawString(x, y, f"End Time: {end_time}")
    y -= 20
    p.drawString(x, y, f"Amount: {amount}")
    y -= 20
    p.drawString(x, y, f"Discount: {discount}%")
    y -= 20
    p.drawString(
        x, y, f"Total Amount after discount: {total_amount_after_discount}")

    # Save the PDF
    p.save()
    buffer.seek(0)

    # Compose email message
    msg = Message('Booking Receipt',
                  sender='skrgtm2059@gmail.com',
                  recipients=['skrgtm2059@gmail.com'])

    # Attach PDF to email
    msg.attach('receipt.pdf', 'application/pdf', buffer.getvalue())

    # HTML content for the email body resembling a receipt
    email_content = render_template_string('''
        <html>
            <head>
                <style>
                    /* Add CSS for styling */
                    /* Example: */
                    body {
                        font-family: Arial, sans-serif;
                        background-color: #f4f4f4;
                        padding: 20px;
                    }
                    .receipt {
                        background-color: #fff;
                        border-radius: 5px;
                        padding: 20px;
                        box-shadow: 0 0 10px rgba(0,0,0,0.1);
                    }
                    /* Add more styles as needed */
                </style>
            </head>
            <body>
                <div class="receipt">
                    <h1>Booking Receipt</h1>
                    
                    <!-- Add other details in a similar manner -->
                    <p>Thank you for choosing our services!</p>
                </div>
            </body>
        </html>
    ''', facility=facility, activity=activity, date=date, start_time=start_time, end_time=end_time, amount=amount, discount=discount, total_amount_after_discount=total_amount_after_discount)

    # Set email content as HTML
    msg.html = email_content

    # Send the email
    mail.send(msg)

    flash('Booking successful!', 'success')

    return redirect(url_for('create_bookings'))
