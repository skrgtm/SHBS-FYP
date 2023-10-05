#Relevant modules for the project.
from flask import Flask, render_template, flash, redirect, request,make_response,url_for,current_app, abort,session,jsonify
from app import app , models,db,admin,login_manager,mail
from flask_admin.contrib.sqla import ModelView
from flask_sqlalchemy import SQLAlchemy
from .forms import LoginForm,SignupForm,Auth2FaForm,Verify2FA,EmpLoginForm,EmpSignupForm,ForgetPassword,ContactUsForm,ResetPassword, CreateFacilityForm, CreateActivityForm, UpdateFacilityForm, UpdateActivityForm, ViewBookings, EditBookingForm, UserMember, CreateBookings, FacilityActivityForm, UpdateUserForm

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
from add_dynamic import dynamic_sessions,append_to_session
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
    user = UserAccount.query.get(int(user_id))  # Example assuming you have a User model
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

@app.route("/protected_area")
@login_required
def protected_area():
    return f"Hello {session['name']}! <br/> <a href='/logout'><button>Logout</button></a>"



#************** End of User Login, Creat Account: Reset, 2FA, Google Login, Logout *******************



# #Manager Homepage
# @app.route('/mgr_homepage')
# @login_required
# @require_role(role="Manager")
# def MgrHomepage():
#     #redirects user to landing page
#     return render_template('yt.html',
#                            title='Home',User = current_user)

#********************************* Route to Redirect User After they Login ************************

#User homepage
@app.route('/user', methods=['GET','POST'])
@login_required
@require_role(role="User")
def user():
    return render_template('user.html',title= 'User', User = current_user)

#Flask defualt logout handler.
@app.route("/logout")
@login_required
def logout():
    for key in list(session.keys()):
        session.pop(key)
    logout_user()
    return redirect('/')

#************** End of User Login, Creat Account: Reset, 2FA, Google Login, Logout *******************


#**************************************** Manager Role **********************************************

#route for Employee & Manager login
#Redirects the user to Employee/Manager Homepage depending on the role of the account.
#PRecents login if account does not exist, Password is incorrect or if the account type is User.
@app.route('/emp_login', methods=['GET','POST'])
def employee_login():
    form = EmpLoginForm()
    usr = form.userName.data
    if form.validate_on_submit():
        user = UserAccount.query.filter_by(User=usr).first()
        if user is None or not user.check_password(form.userPassword.data):
            flash('Invalid Login')
            app.logger.warning('Invalid Login')
            return redirect('/emp_login')
        if not user.has_role("Employee") and not user.has_role("Manager"):
            app.logger.warning('Not an Employee')
            return redirect('/emp_login')
        if user.has_role("Employee"):
            login_user(user)
            return redirect("/emp_homepage")
        if user.has_role("Manager"):
            login_user(user)
            return redirect("/mgr_homepage")
    return render_template('emplogin_page.html',
                        title='Login',form = form)

#Manager Homepage
@app.route('/mgr_homepage')
@login_required
@require_role(role="Manager")
def MgrHomepage():
    #redirects user to landing page
    return render_template('yt.html',
                           title='Home',User = current_user)

#Route to handle Employee Creation.
#Employee/Manager accounts can be created.
#Route accessible by managers only as per spec
#Checks if the Email and username are existing, preventing account creation if so
#Else account is created, Bypassing verification process.
@app.route('/create_emp',methods=['GET','POST'])
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
        userData = UserAccount(User=usr, Email=email, Password=form.userPassword.data,Mobile = form.CountryCode.data+form.Mobile.data)
        db.session.add(userData)
        role = Role.query.filter_by(name=form.role.data).first()
        userData.verified=True
        userData.roles.append(role)
        db.session.commit()
        return redirect('/mgr_homepage')
    #redirects user to landing page
    return render_template('newemp.html',title='Home',form = form)

#Route to handle Facility Creation.
#Facility with a default activity 'General Usr' is created
#Route accessible by managers only as per spec
#Checks if the Facility exists, preventing Facility creation if so
#If checks are passed, 2 Weeks worth of sessions is generated using the dynamic sessions script.
@app.route('/create_facility',methods=['GET','POST'])
@require_role(role="Manager")
@login_required
def new_facility():
    form = CreateFacilityForm()
    if form.validate_on_submit():
        checkfacility =Facility.query.filter_by(Name = form.Name.data).first()
        if checkfacility is not None:
            flash('Facility already exists')
            return redirect('/create_facility')
        facility = Facility(Name=form.Name.data, Capacity=form.Capacity.data, Start_Facility=form.Start_time.data, End_Facility=form.End_time.data)
        activity = Activity(Activity_Name="General use", Amount=form.Amount.data)
        db.session.add(activity)
        facility.activities.append(activity)
        db.session.add(facility)
        db.session.commit()
        dynamic_sessions(facility.id, form.Start_time.data, form.End_time.data, form.Capacity.data,activity.id)
        return redirect('/mgr_homepage')
    return render_template('createfacility.html',form=form)


#Route to handle Activity Creation.
#Activity with entered information is created
#Route accessible by managers only as per spec
#Checks if the Activity exists, preventing Activity creation if so
#If checks are passed, Activity is added to all existing sessions that have the same facility as this activity.
@app.route('/create_activity',methods=['GET','POST'])
@require_role(role="Manager")
@login_required
def new_activity():
    facilities = Facility.query.all()
    facility_choices = [(f.id, f.Name) for f in facilities]
    form = CreateActivityForm()
    form.Facility_Name.choices = facility_choices

    if form.validate_on_submit():
        facility = Facility.query.filter_by(id = form.Facility_Name.data).first()
        check_activity = Activity.query.filter_by(Activity_Name = form.Activity_Name.data , facility_id = form.Facility_Name.data).first()
        activity = Activity(Activity_Name=form.Activity_Name.data, Amount=form.Amount.data)
        if check_activity in facility.activities:
            flash('Activity already exists')
            return redirect('/create_activity')
        facility.activities.append(activity)
        db.session.add(activity)
        db.session.commit()
        append_to_session(facility.id,activity.id)
        return redirect('/mgr_homepage')
    return render_template('createactivity.html',form=form)

#Route to update facility information
#Route accessible to managers only as per spec
#Allows user to select the facility from the dropdown.
#The activity Facilty is then updated if form is valid.
@app.route('/update_facility',methods=['GET','POST'])
@require_role(role="Manager")
@login_required
def update_facility():
    form = UpdateFacilityForm()
    facilities = Facility.query.all()
    facility_choices = [(f.id, f.Name) for f in facilities]
    form = UpdateFacilityForm()
    form.Facility_Namez.choices = facility_choices
    
    if request.method == "POST" and form.validate_on_submit():
        
        facility = Facility.query.filter_by(id=int(form.Facility_Namez.data)).first()
        facility.Name = form.Name.data 
        facility.Capacity = form.Capacity.data
        facility.Start_Facility = form.Start_time.data
        facility.End_Facility = form.End_time.data
        db.session.commit()
        return redirect('/mgr_homepage')
    if not form.validate_on_submit():
        print(form.errors)
    return render_template('updatefacility.html',form=form)

#Route to update activity information
#Route accessible to managers only as per spec
#Allows user to select the facility, then displays all activites linked to the facility in a select dropdown
#The activity information is then updated.
@app.route('/update_Activity',methods=['GET','POST'])
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
        activity = Activity.query.filter_by(id=int(form.Activity_Selector.data)).first()
        activity.Activity_Name = form.New_Activity_Name.data
        activity.Amount = form.New_Amount.data
        # facilityz = Facility.query.filter_by(id = int(form.New_Facility_Name.data)).first()
        # activity.facility_id = facilityz.id
        db.session.commit()
        return redirect('/mgr_homepage')
    return render_template('updateactivity.html',form=form)


#getter to get the facility information and converts data to JSON form.
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


#getter to retrieve activity information and converts data to JSON form.
#requires the activity name as a string.
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

#Getter to get facility and all activities linked to that facility
#Converts this data into JSON form
#Requires the facility id as a paramenter.
@app.route('/facility_activities/<int:facility_id>')
@require_role(role="Manager")
@login_required
def extractactivites(facility_id):
    facility = Facility.query.get_or_404(facility_id)
    activities = facility.activities.all()
    activity_names = [(activity.id, activity.Activity_Name) for activity in activities]
    return jsonify(activity_names)

#Page that lists all Facility Activity Prices
#This was impelemented to allow info to be viewed and updated
@app.route('/pricing', methods =["GET","POST"])
@require_role(role="Manager")
@login_required
def pricing():
    activity = Activity.query.all()
    return render_template('pricing.html', activity = activity)


#****************************************** End of Manager Roles *****************************************

#************************************ Employee Roles ********************************************

#Route for employee homepage
@app.route('/emp_homepage')
@require_role(role="Employee")
@login_required
def EmpHomepage():
    #redirects user to landing page
    return render_template('employeefp.html', title='Home',User = current_user)


#Rote that allows employees to amend bookings on behalf of the user.
#Validates the email entered exists.
#On success retrieves all the bookinngs which are Paid by the user.
#Only accessible by employees based on spec
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
        user = UserAccount.query.filter_by(Email = user_email).first()
        if user is not None:
            bookings = Booking.query.filter_by(user_id=user.id, Status="Booked").all()
        else:
            flash('User not found', 'danger')
    return render_template('view_bookingsEmp.html',bookings = bookings, form = form, form_submitted= form_submitted)


#Route which handle booking modification
#The booking id is taken in as a parameter.

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
            booking_sessionFilter = Sessions.query.filter_by(Start_time=form.start_time.data, End_time=form.end_time.data).first()
            print(booking_sessionFilter)
            booking_filter = Booking.query.filter_by(Book_Time = form.date.data,session = booking_sessionFilter.id).first()
            if not booking_filter and booking_sessionFilter:
                flash('No Booking Found to Cancel.')
            else:
                booking.Status = "Cancelled"
                booking.session.Remaining_Cap += booking.Size  # Increase the remaining capacity
                flash('Booking cancelled successfully', 'success')
        else:
            old_session = booking.session
            new_session = Sessions.query.filter_by(Date=form.date.data, Start_time=form.start_time.data, End_time=form.end_time.data).first()
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

    return render_template('edit_booking.html', form=form, booking_id=booking_id, booking = booking)


#Route that takes in the user account to check membership information
#Only allows member details to be accessed if the account is a User account
#Else respective errors are displayed
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

        isuser = UserAccount.query.filter_by(Email = user_email).all()

        if not isuser:
            flash('Not a User')
        
        else:
            verifyuser = UserAccount.query.filter_by(Email = user_email).first()

            if verifyuser.has_role("User"):
                ismember = UserAccount.query.filter_by(Email = user_email).first()
                if ismember.Member:
                    member = verifyuser
                else:
                    flash('Not a Member')
            else:
                flash('Not a User')
    return render_template('view_userMembership.html',form = form, form_submitted = form_submitted, member = member)


#route that cancels users membership
#Requires user id as a parameter.
#Deletes all membership information and revokes membership on successful identification of account
#Else error message is displayed.
@app.route('/cancel_membership/<int:user_id>', methods=['POST'])
@require_role(role="Employee")
@login_required
def cancel_membership(user_id):
    user = UserAccount.query.get(user_id)
    if user:
        user.Member = False
        user.Membership_Type = None
        user.start_date = None
        user.end_date = None
        db.session.commit()
        flash('Membership canceled successfully')
        return redirect(url_for('create_userMembership'))
    else:
        flash('User not found')
        return redirect(url_for('create_userMembership'))


#Route that creates bookings for a user by the employee
#Checks if the user account existis, returning appropriate error messages if account does not exist.
#IF account exists a booking can be made on behalf of the user
@app.route('/create_bookings', methods=['GET', 'POST'])
@require_role(role="Employee")
@login_required
def create_booking():
    form = CreateBookings()
    bookings = None
    form_submitted = None
    user = None
    if request.method == 'POST' and form.validate_on_submit():
        form_submitted = True
        user_email = form.userEmail.data

        isuser = UserAccount.query.filter_by(Email = user_email).all()

        if not isuser:
            flash('Not a User')
        
        else:
            verifyuser = UserAccount.query.filter_by(Email = user_email).first()

            if verifyuser.has_role("User"):
                bookings = UserAccount.query.filter_by(Email = user_email).all()
                flash('Not a User')
            else:
                flash('Not a User')

    return render_template('create_bookings.html',bookings = bookings, form = form, form_submitted= form_submitted)

# **********************************************************************************************


#****************************************** User: After Login ******************************************************
#Route to allow users to select the activity , Facility ,Date and party size to 
@app.route('/lookup_venue', methods=['POST', 'GET'])
@login_required
@require_role(role="User")
def view_venue():
    form = FacilityActivityForm()

    form.facility_name.choices = [(facility.id, facility.Name) for facility in Facility.query.all()]
    form.activity_name.choices = [(activity.id, activity.Activity_Name) for activity in Activity.query.all()]

    # Update the activity_name choices here
    all_activities = Activity.query.all()
    # form.activity_name.choices = [(a.Activity_Name, a.Activity_Name) for a in all_activities]

    available_sessions = []
    activities = Activity.query.all()
    activities_dict = [activity.activity_to_dict() for activity in activities]

    if form.validate_on_submit():
        facility_id = int(form.facility_name.data)
        venue = Facility.query.get(facility_id)
        activity_id = Activity.query.filter_by(id = form.activity_name.data).first()
        venue_activity = Activity.query.filter_by(Activity_Name=activity_id.Activity_Name, facility_id=venue.id).first()
        if venue_activity:  # Check if venue_activity is not None
            group_size = form.size.data
            activity_price = venue_activity.Amount
            
            if venue:
                query = Sessions.query.filter(
                    Sessions.facility_id == venue.id,
                    Sessions.Date == form.date.data,
                    Sessions.activities.any(Activity.Activity_Name == activity_id.Activity_Name),
                    Sessions.Remaining_Cap >= form.size.data
                )

                if form.date.data == datetime.now().date():
                    current_time = datetime.now().time()
                    query = query.filter(Sessions.Start_time >= current_time)
                else:
                    query = query.filter(Sessions.Start_time >= venue.Start_Facility)
                
                print(f"Query: {query}")  # Debug print
                query_result = query.all()
                print(f"Query result: {query_result}")  # Debug print

                available_sessions = [{'session': session, 'activity_name': activity_id.Activity_Name} for session in query.all()]
                print(available_sessions)
                session_ids = [session['session'].id for session in available_sessions]
                session['available_session_ids'] = session_ids
                session['selected_activity_name'] = activity_id.Activity_Name
                return redirect(url_for('view_sessions', group_size=group_size, activity_price=activity_price))
            else:
                print("No activity found with the given name and facility")
    else:
        print("Form errors:", form.errors)

    return render_template('search_results.html', title='Search Venue', form=form, sessions=available_sessions, activities=activities_dict)


#************************************ Update User Information ********************************************
#Route that allows the user to update their personal information
#Displays the existing information
@app.route('/update_user', methods=['GET', 'POST'])
@login_required
def update_user():
    form = UpdateUserForm()
    if form.validate_on_submit():
        current_user.User = form.User.data
        current_user.set_password(form.password.data)
        current_user.Email = form.email.data
        current_user.Mobile = form.mobile.data
        db.session.commit()
        flash('Your personal information has been updated!', 'success')
        return redirect(url_for('user'))
    elif request.method == 'GET':
        form.User.data = current_user.User
        form.email.data = current_user.Email
        form.mobile.data = current_user.Mobile
    return render_template('update_user.html', title='Update Personal Information', form=form)

#Route to display user information
@app.route('/user_information')
@login_required
def user_information():
    return render_template('user_information.html', title='User Account')


#************************************ End of User Information ********************************************