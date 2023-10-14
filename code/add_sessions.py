from datetime import datetime, time, timedelta, date
import pytz
from app import app,db
from app.models import Facility, Activity, Sessions


#Script that generates the facilites and activites for up to 2 weeks
def create_activities():
    # Create activities for each facility
    swimming_activities = ["General use", "Lane swimming", "Lessons", "Team events"]
    fitness_activities = ["General use"]
    squash_activities = ["1-hour sessions"]
    sports_hall_activities = ["1-hour sessions", "Team events"]
    climbing_activities = ["General use"]
    studio_activities = ["Pilates", "Aerobics", "Yoga"]

    activities_data = [
        (swimming_pool, swimming_activities),
        (fitness_room, fitness_activities),
        (squash_court1, squash_activities),
        (squash_court2, squash_activities),
        (sports_hall, sports_hall_activities),
        (climbing_wall, climbing_activities),
        (studio, studio_activities)
    ]

    for facility, activities in activities_data:
        for activity_name in activities:
            activity = Activity(Activity_Name=activity_name, Amount=15)
            facility.activities.append(activity)
            db.session.add(activity)
    db.session.commit()

def create_sessions():
    # Pilates: Monday 6-7pm
    pilates_start_time = time(18, 0)
    pilates_end_time = time(19, 0)
    create_session(studio, pilates_start_time, pilates_end_time, ["Pilates"])

    # Aerobics: Tuesday 10-11am, Thursday 7-8pm, Saturday 10-11am
    aerobics_start_times = [time(10, 0), time(19, 0), time(10, 0)]
    aerobics_end_times = [time(11, 0), time(20, 0), time(11, 0)]
    aerobics_days = [1, 3, 5]  # Tuesday, Thursday, Saturday
    for start_time, end_time, day in zip(aerobics_start_times, aerobics_end_times, aerobics_days):
        create_session(studio, start_time, end_time, ["Aerobics"], day)

    # Yoga: Friday 7-8pm, Sunday 9-10am
    yoga_start_times = [time(19, 0), time(9, 0)]
    yoga_end_times = [time(20, 0), time(10, 0)]
    yoga_days = [4, 6]  # Friday, Sunday
    for start_time, end_time, day in zip(yoga_start_times, yoga_end_times, yoga_days):
        create_session(studio, start_time, end_time, ["Yoga"], day)

    # Swimming: Friday 8-10am, Sunday 8-10am
    swimming_start_time = time(8, 0)
    swimming_end_time = time(10, 0)
    swimming_days = [4, 6]  # Friday, Sunday
    for day in swimming_days:
        create_session(swimming_pool, swimming_start_time, swimming_end_time, ["Team events"], day)

    # Sports hall: Thursday 7-9pm, Saturday 9-11am
    sports_hall_start_times = [time(19, 0), time(9, 0)]
    sports_hall_end_times = [time(21, 0), time(11, 0)]
    sports_hall_days = [3, 5]  # Thursday, Saturday
    for start_time, end_time, day in zip(sports_hall_start_times, sports_hall_end_times, sports_hall_days):
        create_session(sports_hall, start_time, end_time, ["Team events"], day)
    
    # Swimming pool: General use, Lane swimming, Lessons
    swimming_activities = ["General use", "Lane swimming", "Lessons"]
    swimming_pool_hours = [(time(hour), time(hour+1)) for hour in range(8, 20)]

    for day in range(7):  # Every day of the week
        for start_time, end_time in swimming_pool_hours:
            if not ((day == 4 and start_time >= time(8, 0) and start_time < time(10, 0)) or
                    (day == 6 and start_time >= time(8, 0) and start_time < time(10, 0))):
                create_session(swimming_pool, start_time, end_time, swimming_activities, day)

    # Fitness room: General use
    fitness_activity = ["General use"]
    fitness_room_hours = [(time(hour), time(hour + 1)) for hour in range(8, 22)]

    for day in range(7):  # Every day of the week
        for start_time, end_time in fitness_room_hours:
            create_session(fitness_room, start_time, end_time, fitness_activity, day)
    
    # Climbing Wall: General Use
    climbing_activity = ["General use"]
    climbing_room_hours = [(time(hour), time(hour + 1)) for hour in range(8, 22)]
    for day in range(7):  # Every day of the week
        for start_time, end_time in climbing_room_hours:
            create_session(climbing_wall, start_time, end_time, climbing_activity, day)


    # Squash Court 1: 1:hr session
    fitness_activity = ["1-hour sessions"]
    fitness_room_hours = [(time(hour), time(hour + 1)) for hour in range(8, 22)]

    for day in range(7):  # Every day of the week
        for start_time, end_time in fitness_room_hours:
            create_session(squash_court1, start_time, end_time, fitness_activity, day)
            create_session(squash_court2, start_time, end_time, fitness_activity, day)

    # Sports Hall: General use
    sports_hall_activity = ["1-hour sessions"]
    sports_hall_hours = [(time(hour), time(hour + 1)) for hour in range(8, 21)]

    for day in range(7):  # Every day of the week
        for start_time, end_time in sports_hall_hours:
            if not ((day == 3 and start_time >= time(19, 0) and start_time < time(21, 0)) or 
                    (day == 5 and start_time >= time(9, 0) and start_time < time(11, 0))):
                create_session(sports_hall, start_time, end_time, sports_hall_activity, day)


def create_session(facility, start_time, end_time, activity_names, day=None, weeks=2):
    for week in range(weeks):
        if day is not None:
            now = datetime.utcnow().date()
            next_day = now + timedelta(days=((day - now.weekday()) % 7) + 7 * week)
            date = next_day
        else:
            date = datetime.utcnow().date() + timedelta(days=7 * week)

        session = Sessions(Date=date, Start_time=start_time, End_time=end_time, Remaining_Cap=facility.Capacity, facility_id=facility.id)
        
        for activity_name in activity_names:
            activity = Activity.query.filter_by(Activity_Name=activity_name, facility_id=facility.id).first()
            if activity is not None:
                session.activities.append(activity)
            else:
                print(f"Activity not found: {activity_name}")
        
        db.session.add(session)
    db.session.commit()

def create_facilities():
    facilities_data = [
        ("Swimming Pool", 30, "08:00", "20:00"),
        ("Fitness Room", 35, "08:00", "22:00"),
        ("Squash Court 1", 4, "08:00", "22:00"),
        ("Squash Court 2", 4, "08:00", "22:00"),
        ("Sports Hall", 45, "08:00", "22:00"),
        ("Climbing Wall", 22, "10:00", "20:00"),
        ("Studio", 25, "08:00", "22:00"),
    ]

    facilities = []
    for name, capacity, start_facility, end_facility in facilities_data:
        facility = Facility(Name=name, Capacity=capacity, Start_Facility=start_facility, End_Facility=end_facility)
        db.session.add(facility)
        facilities.append(facility)
    db.session.commit()

    return facilities

(swimming_pool, fitness_room, squash_court1, squash_court2, sports_hall, climbing_wall, studio) = create_facilities()
create_activities()
create_sessions()
