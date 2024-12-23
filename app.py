from flask import Flask, render_template, request, redirect, url_for, flash
from flask_sqlalchemy import SQLAlchemy
from flask_bcrypt import Bcrypt
from flask_login import UserMixin, LoginManager, login_user, logout_user, login_required, current_user
from datetime import datetime, timedelta

app = Flask(__name__)
app.config['SQLALCHEMY_DATABASE_URI'] = 'sqlite:///site.db'
app.config['SECRET_KEY'] = 'your_secret_key'

db = SQLAlchemy(app)
bcrypt = Bcrypt(app)

login_manager = LoginManager(app)
login_manager.login_view = 'login'
login_manager.login_message_category = 'info'

class User(db.Model, UserMixin):
    id = db.Column(db.Integer, primary_key=True)
    username = db.Column(db.String(150), unique=True, nullable=False)
    email = db.Column(db.String(150), unique=True, nullable=False)
    password = db.Column(db.String(150), nullable=False)

class Appointment(db.Model):
    id = db.Column(db.Integer, primary_key=True)
    date = db.Column(db.Date, nullable=False)
    time = db.Column(db.String(5), nullable=False)  # HH:MM format
    booked = db.Column(db.Boolean, default=False)
    name = db.Column(db.String(100), nullable=True)

@login_manager.user_loader
def load_user(user_id):
    return User.query.get(int(user_id))

@app.route('/')
def home():
    return render_template('home.html')

@app.route('/signup', methods=['GET', 'POST'])
def signup():
    if request.method == 'POST':
        username = request.form['username']
        email = request.form['email']
        password = request.form['password']
        hashed_password = bcrypt.generate_password_hash(password).decode('utf-8')

        user = User.query.filter((User.username == username) | (User.email == email)).first()
        if user:
            flash('Username or email already exists.', 'danger')
        else:
            new_user = User(username=username, email=email, password=hashed_password)
            db.session.add(new_user)
            db.session.commit()
            flash('Account created successfully! Please log in.', 'success')
            return redirect(url_for('login'))
    return render_template('signup.html')

@app.route('/login', methods=['GET', 'POST'])
def login():
    if request.method == 'POST':
        email = request.form['email']
        password = request.form['password']
        user = User.query.filter_by(email=email).first()
        if user and bcrypt.check_password_hash(user.password, password):
            login_user(user)
            flash('Login successful!', 'success')
            return redirect(url_for('calendar'))
        else:
            flash('Login failed. Check email and password.', 'danger')
    return render_template('login.html')

@app.route('/logout')
def logout():
    logout_user()
    flash('You have been logged out.', 'info')
    return redirect(url_for('login'))

def generate_week():
    today = datetime.now().date()
    week_days = [today + timedelta(days=i) for i in range(7)]  # Current day + next 6 days
    hours = [f"{hour:02}:00" for hour in range(9, 18)]  # Hours from 9:00 to 17:00
    return week_days, hours

@app.route('/calendar')
@login_required
def calendar():
    week_days, hours = generate_week()
    appointments = Appointment.query.all()
    booked_slots = {(a.date, a.time): a for a in appointments}
    return render_template('calendar.html', week_days=week_days, hours=hours, booked_slots=booked_slots)

@app.route('/book', methods=['POST'])
def book():
    try:
        date_str = request.form.get('date')
        time = request.form.get('time')
        name = request.form.get('name')

        if not date_str or not time or not name:
            return "Missing form data! Please go back and fill all fields."

        date = datetime.strptime(date_str, '%Y-%m-%d').date()

        today = datetime.now().date()
        start_of_week = today - timedelta(days=today.weekday())  # Monday
        end_of_week = start_of_week + timedelta(days=6)  # Sunday

        # Check total bookings for this name in the current week
        total_bookings = Appointment.query.filter(
            Appointment.name == name,
            Appointment.date >= start_of_week,
            Appointment.date <= end_of_week
        ).count()

        if total_bookings >= 2:  # Enforce limit of 2 hours
            return render_template("error.html", error="You can only book up to 2 hours per week.")

        existing_appointment = Appointment.query.filter_by(date=date, time=time).first()
        if existing_appointment:
            return "This slot is already booked! <a href='/calendar'>Go Back</a>"

        new_appointment = Appointment(date=date, time=time, booked=True, name=name)
        db.session.add(new_appointment)
        db.session.commit()

        return redirect(url_for('success'))
    except Exception as e:
        app.logger.error(f"Error in /book: {str(e)}")
        return render_template("error.html", error="An error occurred. Please try again.")

@app.route('/success')
def success():
    return render_template('success.html')

with app.app_context():
    db.create_all()

if __name__ == "__main__":
    app.run(debug=True)
