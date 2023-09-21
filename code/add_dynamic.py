from app import app,db
from app.models import Facility, Activity, Sessions
from datetime import date,time,timedelta,datetime

def dynamic_sessions(facility_id, start_time, end_time, remaining_cap, activity_id):
    start_time = datetime.strptime(start_time, '%H:%M').time()
    end_time = datetime.strptime(end_time, '%H:%M').time()
    current_date = date.today()
    end_date = current_date + timedelta(days=14)
    activity = Activity.query.filter_by(id=activity_id).first()
    while current_date < end_date:
        current_time = datetime.combine(current_date, start_time)
        end_datetime = datetime.combine(current_date, end_time)
        while current_time < end_datetime:
            session_start_time = datetime.combine(current_time.date(), time(current_time.hour, 0))
            session_end_time = session_start_time + timedelta(hours=1)
            sessionz= Sessions(Date=current_date,
                               Start_time=session_start_time.time(),
                               End_time=session_end_time.time(),
                               Remaining_Cap=remaining_cap,
                               facility_id=facility_id)
            sessionz.activities.append(activity)
            db.session.add(sessionz)
            current_time += timedelta(hours=1)
        current_date += timedelta(days=1)
    db.session.commit()


def append_to_session(facility_id, new_activity_id):
    facility = Facility.query.get(facility_id)
    activity = Activity.query.filter_by(id = new_activity_id).first()
    sessions = Sessions.query.filter_by(facility=facility).all()
    for session in sessions:
        session.activities.append(activity)
    db.session.commit()
