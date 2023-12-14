from flask import Flask
from app import app, db
from app.models import Role, UserAccount

# This is a script to create user roles

# Method used to create predefined roles


def create_roles():
    user_Role = Role(name="User")
    employee_Role = Role(name="Employee")
    manager_Role = Role(name="Manager")
    db.session.add(user_Role)
    db.session.add(employee_Role)
    db.session.add(manager_Role)
    db.session.commit()

# Method used to create test users of each role type


def create_user():
    user = UserAccount(User="test", Email="test.01@gmail.com",
                       Password="123", Mobile="9849517152")
    user.verified = True
    role = Role.query.filter_by(name="User").first()
    user.roles.append(role)
    admin = UserAccount(User="Admin", Email="skrgtm@gmail.com",
                        Password="1234", Mobile="9841227895")
    employee = UserAccount(
        User="Employee", Email="sakar.gautam@gmail.com", Password="1234", Mobile="9863031152")
    emp_role = Role.query.filter_by(name="Employee").first()
    employee.roles.append(emp_role)
    employee.verified = True
    admin_role = Role.query.filter_by(name="Manager").first()
    admin.roles.append(admin_role)
    admin.verified = True
    db.session.add(user)
    db.session.add(employee)
    db.session.add(admin)
    db.session.commit()


if __name__ == '__main__':
    with app.app_context():
        create_roles()
        create_user()
