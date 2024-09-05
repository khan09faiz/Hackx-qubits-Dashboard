from flask import Flask, render_template, request, jsonify, redirect, url_for, flash, session
from flask_sqlalchemy import SQLAlchemy
from werkzeug.security import generate_password_hash, check_password_hash
from datetime import datetime
import uuid
from functools import wraps
from faker import Faker
import random

# Initialize the Flask application
app = Flask(__name__)

# Configuration for SQLite database and secret key for session management
app.config['SQLALCHEMY_DATABASE_URI'] = 'sqlite:///scooter_tracking.db'
app.config['SECRET_KEY'] = 'your_secret_key_here'

# Initialize SQLAlchemy for database management
db = SQLAlchemy(app)
fake = Faker()

# Database Models
class Scooter(db.Model):
    """
    Represents the scooter being tracked.
    Fields:
        - barcode: Unique identifier for the scooter.
        - current_stage: Current stage of the scooter in the tracking process.
        - current_location: Current fixed location of the scooter.
        - timestamp: Last updated timestamp.
    """
    id = db.Column(db.Integer, primary_key=True)
    barcode = db.Column(db.String(20), unique=True, nullable=False)
    current_stage = db.Column(db.String(50), nullable=False)
    current_location = db.Column(db.String(100), nullable=False)
    timestamp = db.Column(db.DateTime, nullable=False, default=datetime.utcnow)

class TrackingHistory(db.Model):
    """
    Represents the history of the scooter's journey.
    Fields:
        - scooter_id: Reference to the associated scooter.
        - stage: The stage of the journey (e.g., Manufacturer, Yard).
        - location: Fixed location corresponding to the stage.
        - timestamp: When the scooter reached this stage.
    """
    id = db.Column(db.Integer, primary_key=True)
    scooter_id = db.Column(db.Integer, db.ForeignKey('scooter.id'), nullable=False)
    stage = db.Column(db.String(50), nullable=False)
    location = db.Column(db.String(100), nullable=False)
    timestamp = db.Column(db.DateTime, nullable=False, default=datetime.utcnow)

class User(db.Model):
    """
    Represents a user of the system.
    Fields:
        - username: Unique username for login.
        - password_hash: Hashed password for security.
    """
    id = db.Column(db.Integer, primary_key=True)
    username = db.Column(db.String(80), unique=True, nullable=False)
    password_hash = db.Column(db.String(120), nullable=False)

    def set_password(self, password):
        """
        Hashes and stores the user's password.
        """
        self.password_hash = generate_password_hash(password)

    def check_password(self, password):
        """
        Checks if the provided password matches the stored hash.
        """
        return check_password_hash(self.password_hash, password)

# Create all the database tables (if not already created)
with app.app_context():
    db.create_all()

# Wrapper to ensure a user is logged in before accessing certain routes
def login_required(f):
    @wraps(f)
    def decorated_function(*args, **kwargs):
        if 'user_id' not in session:  # If no user is logged in, redirect to login page
            return redirect(url_for('login'))
        return f(*args, **kwargs)
    return decorated_function

# Dictionary to store fixed locations for each checkpoint stage
CHECKPOINTS = {
    "Manufacturer": "Factory Location",
    "BIKESETU Yard": "Warehouse Location",
    "Franchise": "Franchise Store Location",
    "Customer": "Customer's Location"
}

@app.route('/')
def index():
    """
    Route for the home page.
    """
    return render_template('index.html')

@app.route('/login', methods=['GET', 'POST'])
def login():
    """
    Route for user login.
    If a POST request is made, check the user's credentials and log them in.
    Otherwise, render the login page.
    """
    if request.method == 'POST':
        username = request.form['username']
        password = request.form['password']
        user = User.query.filter_by(username=username).first()
        if user and user.check_password(password):  # Check credentials
            session['user_id'] = user.id  # Set session for logged-in user
            return redirect(url_for('dashboard'))
        else:
            flash('Invalid username or password')  # Display error message
    return render_template('login.html')

@app.route('/logout')
def logout():
    """
    Route to log out the user by clearing the session.
    """
    session.pop('user_id', None)
    return redirect(url_for('index'))

@app.route('/dashboard')
@login_required
def dashboard():
    """
    Route to display the dashboard with a list of all scooters.
    Accessible only to logged-in users.
    """
    scooters = Scooter.query.all()
    return render_template('dashboard.html', scooters=scooters)

@app.route('/scan', methods=['POST'])
@login_required
def scan():
    """
    Route to generate a new scooter barcode upon scanning.
    Simulates RFID scanning by creating a unique scooter ID.
    """
    barcode = f"SCOOTER-{uuid.uuid4().hex[:8].upper()}"  # Generate unique barcode
    return jsonify({"barcode": barcode})

@app.route('/update', methods=['POST'])
@login_required
def update_status():
    """
    Route to update the status of the scooter when it reaches a checkpoint.
    The user provides the scooter's barcode and current stage (checkpoint).
    The database is updated accordingly.
    """
    data = request.form
    barcode = data['barcode']
    stage = data['stage']

    # Get fixed location for the checkpoint stage
    location = CHECKPOINTS.get(stage, "Unknown Location")

    # Find the scooter by its barcode
    scooter = Scooter.query.filter_by(barcode=barcode).first()
    
    # If the scooter does not exist, create a new entry
    if not scooter:
        scooter = Scooter(barcode=barcode, current_stage=stage, current_location=location)
        db.session.add(scooter)
    else:
        # Update the scooter's current stage and location
        scooter.current_stage = stage
        scooter.current_location = location
        scooter.timestamp = datetime.utcnow()
    
    # Record the scooter's tracking history
    tracking_history = TrackingHistory(scooter_id=scooter.id, stage=stage, location=location)
    db.session.add(tracking_history)
    
    # Save changes to the database
    db.session.commit()
    
    # Simulate notifications with print statements
    if stage == "Manufacturer":
        print("Your order has been dispatched from the manufacturer.")
    elif stage == "Customer":
        print("Your order has been received by the customer.")

    # Flash a message to notify the user of successful update
    flash('Status updated successfully')
    return redirect(url_for('dashboard'))

@app.route('/tracking', methods=['GET', 'POST'])
def tracking():
    """
    Route for customers to track their scooter by its barcode.
    Displays the scooter's journey timeline.
    """
    if request.method == 'POST':
        barcode = request.form['barcode']
        scooter = Scooter.query.filter_by(barcode=barcode).first()
        if not scooter:
            flash('Scooter not found')  # If barcode is invalid, show error message
            return redirect(url_for('tracking'))
        
        # List of all stages (in order)
        stages = ["Manufacturer", "BIKESETU Yard", "Franchise", "Customer"]
        # Fetch tracking history of the scooter
        history = TrackingHistory.query.filter_by(scooter_id=scooter.id).order_by(TrackingHistory.timestamp).all()
        
        # Generate timeline with stage details
        timeline = []
        for stage in stages:
            # Find if the scooter has reached the given stage
            entry = next((h for h in history if h.stage == stage), None)
            if entry:
                timeline.append({
                    "stage": entry.stage,
                    "location": entry.location,
                    "timestamp": entry.timestamp.strftime("%Y-%m-%d %H:%M:%S")
                })
            else:
                timeline.append({
                    "stage": stage,
                    "location": "Not reached yet",
                    "timestamp": "N/A"
                })
        
        # Render the tracking result page with timeline details
        return render_template('tracking_result.html', scooter=scooter, timeline=timeline)
    
    return render_template('tracking.html')


@app.route('/add_random_data')
def add_random_data():
    """
    Route to add random user IDs, product IDs, and locations for testing.
    """
    warehouse_locations = ["Warehouse A", "Warehouse B", "Warehouse C", "Warehouse D"]

    try:
        # Insert 10 random users with the password "12345"
        for _ in range(10):
            username = fake.user_name()
            user = User(username=username)
            user.set_password('12345')  # Set a fixed password for all users
            db.session.add(user)

        db.session.commit()  # Commit after adding all users

        # Insert 10 random scooters with random IDs
        for _ in range(10):
            barcode = f"SCOOTER-{uuid.uuid4().hex[:8].upper()}"
            stage = random.choice(list(CHECKPOINTS.keys()))
            location = CHECKPOINTS[stage]
            scooter = Scooter(barcode=barcode, current_stage=stage, current_location=location)
            db.session.add(scooter)
            db.session.commit()  # Commit to get the scooter ID

            # Insert random tracking history for each scooter
            for _ in range(3):  # Three stages for each scooter
                history_stage = random.choice(list(CHECKPOINTS.keys()))
                history_location = CHECKPOINTS[history_stage]
                tracking_history = TrackingHistory(scooter_id=scooter.id, stage=history_stage, location=history_location)
                db.session.add(tracking_history)
        db.session.commit()  # Commit all tracking history

        flash('Random data added successfully')
    except Exception as e:
        db.session.rollback()  # Rollback in case of error
        flash(f'Error adding random data: {str(e)}')

    return redirect(url_for('dashboard'))


@app.route('/view_scooters')
def view_scooters():
    """
    Route to view all scooters in the database.
    """
    scooters = Scooter.query.all()
    return render_template('view_scooters.html', scooters=scooters)

@app.route('/view_users')
@login_required
def view_users():
    """
    Route to view all users in the database.
    """
    users = User.query.all()
    return render_template('view_users.html', users=users)


@app.route('/view_tracking')
def view_tracking():
    """
    Route to view all tracking history entries in the database.
    """
    tracking_history = TrackingHistory.query.all()
    return render_template('view_tracking.html', tracking_history=tracking_history)


# Entry point for running the Flask application
if __name__ == '__main__':
    app.run(debug=True)
