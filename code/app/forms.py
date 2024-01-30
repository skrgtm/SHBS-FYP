from flask_wtf import FlaskForm, RecaptchaField
from wtforms import IntegerField, StringField, DateTimeField, TextAreaField, SubmitField, PasswordField, BooleanField, RadioField, DateField, SelectField, HiddenField, TelField
from wtforms_components import TimeField
from wtforms.validators import DataRequired, EqualTo, NumberRange, ValidationError, Length, Email
from app import db, models, app
from .models import Facility, Activity
import datetime
from datetime import date
from flask_wtf.file import FileField, FileAllowed

# ************************************ Login Form*************************************************
# Form to handle user account login process in flask


class LoginForm(FlaskForm):
    userName = StringField('User Name', validators=[DataRequired()])
    userPassword = PasswordField('passwords', validators=[DataRequired()])
    remember = BooleanField('Remember Me')


# ************************************** Signup Form***********************************************
# FOrm to handle user account signups in flask

class SignupForm(FlaskForm):
    userName = StringField('User Name', validators=[DataRequired()])
    userEmail = StringField('User Email', validators=[DataRequired()])
    userPassword = PasswordField('passwords', validators=[DataRequired()])
    userVerifyPassword = PasswordField('confirm password', validators=[DataRequired(),
                                                                       EqualTo('userPassword')])
    CountryCode = HiddenField('Country Code', validators=[DataRequired()])
    Mobile = StringField('Mobile Number', validators=[DataRequired()])


# ************************************** Forget password Form***********************************************

# Form that takes in user account info to help reset password


class ForgetPassword(FlaskForm):
    userEmail = StringField('User Email', validators=[DataRequired()])


# ************************************** Reset password Form***********************************************
# Form that accepts new password for user account.


class ResetPassword(FlaskForm):
    userPassword = PasswordField('passwords', validators=[DataRequired()])
    userVerifyPassword = PasswordField('confirm password', validators=[DataRequired(),
                                                                       EqualTo('userPassword')])


# ************************************** Employee Login Form***********************************************
# Form to facilitate employee login.


class EmpLoginForm(FlaskForm):
    userName = StringField('Employee Username', validators=[DataRequired()])
    userPassword = PasswordField('passwords', validators=[DataRequired()])
    remember = BooleanField('Remember Me')


# ************************************** Create employee Form***********************************************
# Form that takes employee details which is used by the manager to create employee accounts
class EmpSignupForm(FlaskForm):
    userName = StringField('User Name', validators=[DataRequired()])
    userEmail = StringField('User Email', validators=[DataRequired()])
    userPassword = PasswordField('passwords', validators=[DataRequired()])
    userVerifyPassword = PasswordField('confirm password', validators=[DataRequired(),
                                                                       EqualTo('userPassword')])
    CountryCode = HiddenField('Country Code', validators=[DataRequired()])
    Mobile = StringField('Mobile Number', validators=[DataRequired()])
    role = SelectField('Role', choices=[
                       ('Employee', 'Employee'), ('Manager', 'Manager')], validators=[DataRequired()])


# ************************************** Contactus Form***********************************************
# Form to handle contact us feature


class ContactUsForm(FlaskForm):
    name = StringField("Name",  validators=[DataRequired()])
    email = StringField("Email", validators=[DataRequired()])
    address = StringField("Address", validators=[DataRequired()])
    message = TextAreaField("Message", validators=[DataRequired()])
    submit = SubmitField("Send")


# ************************************** Create facility Form***********************************************
# Form used to create a new facility. Also asks amount information to set a value for a default activity.


class CreateFacilityForm(FlaskForm):
    Name = StringField('Venue Name', validators=[DataRequired()])
    Capacity = IntegerField('Maximum Capacity', validators=[DataRequired()])
    Start_time = StringField('Start Time', validators=[DataRequired()])
    End_time = StringField('End Time', validators=[DataRequired()])
    Amount = IntegerField('Cost', validators=[DataRequired()])

# ************************************** Create Activity Form***********************************************
# Form to create new activity.


class CreateActivityForm(FlaskForm):
    Activity_Name = StringField('Acivity Name', validators=[DataRequired()])
    Amount = IntegerField('Cost', validators=[DataRequired()])
    Facility_Name = SelectField('Facility Name', validators=[
                                DataRequired()], choices=[])


# ************************************** Update facility Form***********************************************
# Form that takes in the new facility information to update the facility.

class UpdateFacilityForm(FlaskForm):
    Facility_Namez = SelectField('Facility Name', validators=[
                                 DataRequired()], choices=["Name", "Name"])
    Name = StringField('Venue Name', validators=[DataRequired()])
    Capacity = IntegerField('Maximum Capacity', validators=[DataRequired()])
    Start_time = StringField('Start Time', validators=[DataRequired()])
    End_time = StringField('End Time', validators=[DataRequired()])


# ************************************** Update activity Form***********************************************
# Form that takes in the new activity information to update the activity.

class UpdateActivityForm(FlaskForm):
    New_Facility_Name = SelectField('Facility Name', validators=[
                                    DataRequired()], choices=[])
    Activity_Selector = SelectField(
        'Activity Name', validators=[DataRequired()])
    New_Activity_Name = StringField(
        'Acivity Name', validators=[DataRequired()])
    New_Amount = IntegerField('Cost', validators=[DataRequired()])

# ************************************** View bookings Form***********************************************
# form that takes users email data to find bookings linked to the account


class ViewBookings(FlaskForm):
    userEmail = StringField('User Email', validators=[DataRequired()])


def empty_activity_choices():
    return [("", "Select an activity")]

# ************************************** method validate***********************************************
# method to validate date.


def validate_date(form, field):
    if field.data < date.today():
        raise ValidationError(
            "Please select a date that has not already occurred.")


# ************************************** Booking details Form***********************************************
# Form that takes booking information to return available sessions.


class BookingDetailsForm(FlaskForm):
    facility = SelectField('Facility', choices=[], validators=[DataRequired()])
    activity = SelectField('Activity', choices=[], validators=[DataRequired()])
    date = DateField('Date', validators=[DataRequired(
    ), validate_date], format='%Y-%m-%d', render_kw={"min": date.today().isoformat(), "id": "date"})
    capacity = IntegerField('Capacity', validators=[DataRequired()])
    submit = SubmitField('Get Sessions')


# ************************************** Edit booking Form***********************************************
# Form to edit booking information.

class EditBookingForm(FlaskForm):
    date = DateField('Date', validators=[DataRequired(
    )], format='%Y-%m-%d', render_kw={"min": date.today().isoformat(), "id": "date"})
    start_time = TimeField('Start Time', validators=[DataRequired()])
    end_time = TimeField('End Time', validators=[DataRequired()])
    save = SubmitField('Save')
    cancel = SubmitField('Cancel')

# method to handle empty choices for activity. used to initialize it before it gets populated with list of activities

# ************************************** Add facility activity Form***********************************************
# Form  That adds Facility and default activity


class FacilityActivityForm(FlaskForm):
    facility_name = SelectField('Facility Name', validators=[
                                DataRequired()], choices=[])
    activity_id = HiddenField()
    activity_name = SelectField('Activity Name', validators=[
                                DataRequired()], choices=[])
    date = DateField('Date', validators=[DataRequired(
    ), validate_date], format='%Y-%m-%d', render_kw={"min": date.today().isoformat(), "id": "date"})
    size = IntegerField('size', validators=[DataRequired()])
    submit = SubmitField('Add Facility and Activity')


# ************************************** Check user membership Form***********************************************
# From that takes user email data to check if the user is a member.


class UserMember(FlaskForm):
    userEmail = StringField('User Email', validators=[DataRequired()])

# ************************************** Booking Form***********************************************
# Form to handle Bookings.


class BookingForm(FlaskForm):
    num_people = IntegerField('Number of People', validators=[
                              DataRequired(), NumberRange(min=1, max=10)])
    submit = SubmitField('Book Now')


# ************************************** Create booking(employee) Form***********************************************
# From that takes user email data to create bookings on the users behalf.

class CreateBookings(FlaskForm):
    userEmail = StringField('User Email', validators=[DataRequired()])


# ***************************    Update User Form        *******************************
class UpdateUserForm(FlaskForm):
    User = StringField('Username', validators=[
                       DataRequired(), Length(min=2, max=20)])
    password = PasswordField('Password', validators=[
                             DataRequired(), Length(min=6)])
    confirm_password = PasswordField('Confirm Password', validators=[
                                     DataRequired(), EqualTo('password')])
    email = StringField('Email', validators=[DataRequired(), Email()])
    mobile = StringField('Mobile', validators=[
                         DataRequired(), Length(min=10, max=15)])
    profile_picture = FileField('Profile Picture', validators=[
                                FileAllowed(['jpg', 'png', 'jpeg'])])
    submit = SubmitField('Update')


def get_id(self):
    return self.userName

# ********************************* Add membership form ******************************************************
# add membership form


class AddMembershipForm(FlaskForm):
    name = StringField('Name', validators=[DataRequired()])
    price = IntegerField('Price', validators=[
                         DataRequired(), NumberRange(min=0)])
    interval = StringField('Interval', validators=[DataRequired()])
    currency = StringField('Currency', default='Rs',
                           render_kw={'readonly': True})
    submit = SubmitField('Submit')


class empcheckout(FlaskForm):
    discount = IntegerField('Discount', validators=[
        DataRequired(), NumberRange(min=0)])


# ************************************** End of Form***********************************************

#Form to handle refunds
class RefundForm(FlaskForm):
  name = StringField("Name",  validators=[DataRequired()])
  email = StringField("Email",validators = [DataRequired()])
  details = TextAreaField("Booking Details",validators = [DataRequired()])
  reason = TextAreaField("Reason",validators = [DataRequired()])
  submit = SubmitField("Send")