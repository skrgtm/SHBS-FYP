from app import db
from sqlalchemy import CheckConstraint,UniqueConstraint
from sqlalchemy.orm import validates
from flask_login import UserMixin
from datetime import datetime
from werkzeug.security import generate_password_hash, check_password_hash
import secrets

#association table between UserAccount and Role Models.
user_role = db.Table('user_role', db.Model.metadata,
    db.Column('user_id', db.Integer, db.ForeignKey('UserAccount.id')),
    db.Column('role_id', db.Integer, db.ForeignKey('Role.id'))
)

#Contains All Required information about user accounts.
#Roles are used here to create priority levels as per backlog requuirements.
class UserAccount(UserMixin, db.Model):
    __tablename__ = 'UserAccount'
    id = db.Column(db.Integer, primary_key=True)
    User = db.Column(db.String(500), index=True)
    Email = db.Column(db.String(500), index=True, unique=True)
    Password = db.Column(db.String(500), index=True)
    Mobile = db.Column(db.String(120), index=True)
    verification_token = db.Column(db.String(1120), unique=True)
    verified = db.Column(db.Boolean, default=False)
    start_date = db.Column(db.Date, nullable=True)
    end_date = db.Column(db.Date, nullable=True)
    Member = db.Column(db.Boolean, default=False)
    Membership_Type = db.Column(db.String(50), nullable=True)
    roles = db.relationship("Role", secondary=user_role,
                            backref=db.backref("users", lazy="dynamic"))
    #bookings = db.relationship("Booking", backref = 'Users')
    
    #method to generate verification token
    def generate_verification_token(self):
        self.verification_token = secrets.token_urlsafe()
        
    #method to set password which is used when user account is created
    def set_password(self, Password):
        self.Password = generate_password_hash(Password)
        
    #method to set password which is used when user tries to login
    def check_password(self, Password):
        return check_password_hash(self.Password, Password)

    def is_active(self):
        return True
    
    def __init__(self, User, Email, Password,Mobile):
        self.User = User
        self.Email = Email
        self.set_password(Password)
        self.Mobile = Mobile
        self.generate_verification_token()
        
    #method used to verify if the user has a paticular role. used to restrict users to access pages depending on role.
    def has_role(self, role_name):
        """Does this user have this permission?"""
        my_role = Role.query.filter_by(name=role_name).first()
        if my_role in self.roles:
            return True
        else:
            return False

#Role Model. Takes in Role id and Role Name
class Role(db.Model):
    __tablename__ = "Role"
    id = db.Column(db.Integer, primary_key=True)
    name = db.Column(db.String(80), unique=True)
    
    def __init__(self,name):
        self.name = name


# Association table between Sessions and Activity Model.
session_activity_association = db.Table(
    "session_activity",
    db.Column("session_id", db.Integer, db.ForeignKey("Sessions.id")),
    db.Column("activity_id", db.Integer, db.ForeignKey("activity.id")),
    UniqueConstraint("session_id", "activity_id")
)

#Sessions Model.
#Sessions Are Split into 1 hour blocks. Each session has a remaining Capacity which varies by facility.
#Linked To activity as a many-to-many relationship.
#Linked to Facilty as a one-many as one facility can have many sessions.
class Sessions(db.Model):
    __tablename__ = "Sessions"
    id = db.Column(db.Integer, primary_key=True)
    Date = db.Column(db.Date, index=True)
    Start_time = db.Column(db.Time, index=True)
    End_time = db.Column(db.Time, index=True)
    Remaining_Cap = db.Column(db.Integer, index=True)
    facility_id = db.Column(db.Integer, db.ForeignKey("facility.id"))

    facility = db.relationship("Facility", backref=db.backref("sessions", lazy="dynamic"))
    activities = db.relationship("Activity", secondary=session_activity_association, backref=db.backref("sessions", lazy="dynamic"))

    def __init__(self, Date, Start_time, End_time, Remaining_Cap, facility_id):
        self.Date = Date
        self.Start_time = Start_time
        self.End_time = End_time
        self.Remaining_Cap = Remaining_Cap
        self.facility_id = facility_id
        
    #method to convert to dictionary 
    def to_dict(self):
        return {
            'id': self.id,
            'facility_id': self.facility_id,
            'Date': self.Date,
            'Start_time': self.Start_time.strftime('%H:%M:%S'),
            'End_time': self.End_time.strftime('%H:%M:%S'),
            'Remaining_Cap': self.Remaining_Cap,
            'activites':[activity.activity_to_dict() for activity in self.activities]
        }

# Keep the Facility and Activity models as they are

#Facitlity model to store information of the facility
class Facility(db.Model):
    # __tablename__ = "Facilities"
    id = db.Column(db.Integer, primary_key=True)
    Name = db.Column(db.String(500), index=True)
    Capacity = db.Column(db.Integer, index=True)
    Start_Facility = db.Column(db.String(500), index=True)
    End_Facility = db.Column(db.String(500), index=True)

    def __init__(self, Name, Capacity, Start_Facility, End_Facility):
        self.Name = Name
        self.Capacity = Capacity
        self.Start_Facility = Start_Facility
        self.End_Facility = End_Facility

#Activity model to store information of the activity.
class Activity(db.Model):
    id = db.Column(db.Integer, primary_key=True)
    facility_id = db.Column(db.Integer, db.ForeignKey('facility.id'))
    Activity_Name = db.Column(db.String(500), index=True)
    Amount = db.Column(db.Integer, index=True)
    facility = db.relationship("Facility", backref=db.backref("activities", lazy="dynamic"))
    
    def __init__(self,Activity_Name,Amount):
        self.Activity_Name = Activity_Name
        self.Amount = Amount

    def activity_to_dict(self):
        return {
            'id': self.id,
            'facility_id': self.facility_id,
            'Activity_Name': self.Activity_Name,
            'Amount': self.Amount
        }


#Booking model. Holds all information of the booking made by the user.
#Linked to Facility,Activity,Reciept and UserAccount models.
class Booking(db.Model):
    __tablename__ = "Booking"
    id = db.Column(db.Integer, primary_key=True)
    user_id = db.Column(db.Integer, db.ForeignKey('UserAccount.id'))
    Book_Time = db.Column(db.Date, index=True)
    Status = db.Column(db.String(500), index=True)
    session_id = db.Column(db.Integer, db.ForeignKey('Sessions.id'))
    Size = db.Column(db.Integer, index=True)
    Amount = db.Column(db.Integer, index=True)

    activity_id = db.Column(db.Integer, db.ForeignKey('activity.id'))
    activity = db.relationship("Activity", backref=db.backref("bookings", lazy="dynamic"))

    user = db.relationship("UserAccount", backref=db.backref("bookings", lazy="dynamic"))
    session = db.relationship("Sessions", backref=db.backref("bookings", lazy="dynamic"))

    receipt_id = db.Column(db.Integer, db.ForeignKey('receipt.id'))  # New column for receipt_id foreign key
    receipt = db.relationship("Receipt", backref=db.backref("bookings", lazy="dynamic"), foreign_keys=[receipt_id])  # Update relationship attribute for Receipt

    def __init__(self, user_id, session_id, activity_id, Book_Time, Status, Size, Amount):
        self.user_id = user_id
        self.session_id = session_id
        self.activity_id = activity_id
        self.Book_Time = Book_Time
        self.Status = Status
        self.Size = Size
        self.Amount = Amount

#Stores receipt information for each booking that has been paid for.
#linked to the UserAccount model.
class Receipt(db.Model):
    id = db.Column(db.Integer, primary_key=True)
    user_id = db.Column(db.Integer, db.ForeignKey('UserAccount.id'))
    Amount = db.Column(db.String(500), index=True)
    timestamp = db.Column(db.DateTime, default=datetime.utcnow)

    user = db.relationship("UserAccount", backref=db.backref("receipts", lazy="dynamic"))

    def __init__(self, user_id, Amount):
        self.user_id = user_id
        self.Amount = Amount

