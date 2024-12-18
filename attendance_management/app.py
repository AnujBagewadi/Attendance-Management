import os
import re
import secrets
import random
import logging
import smtplib
import traceback
from datetime import datetime, timedelta
from flask import Flask, render_template, request, redirect, url_for, flash, session, jsonify
from flask_pymongo import PyMongo
from werkzeug.security import generate_password_hash, check_password_hash
from email.mime.text import MIMEText
from email.mime.multipart import MIMEMultipart

# Initialize Flask app
app = Flask(__name__)

# Secure secret key generation
app.secret_key = secrets.token_hex(16)

# MongoDB Configuration
app.config["MONGO_URI"] = "mongodb://localhost:27017/attendance_system"
mongo = PyMongo(app)

# Logging configuration
logging.basicConfig(
    level=logging.INFO,
    format='%(asctime)s - %(name)s - %(levelname)s - %(message)s',
    filename='attendance_system.log'
)
logger = logging.getLogger(__name__)

# Ensure unique indexes
mongo.db.faculty.create_index("email", unique=True)
mongo.db.students.create_index("email", unique=True)

# Helper Functions
def validate_college_email(email, user_type):
    """Validate college email domain"""
    if user_type == 'faculty':
        return email.endswith('@git.edu')
    elif user_type == 'student':
        return email.endswith('@students.git.edu')

def generate_otp(length=5):
    """Generate OTP of specified length"""
    return ''.join([str(random.randint(0, 9)) for _ in range(length)])

def send_otp_email(to_email, otp):
    """Send OTP to email"""
    from_email = "your_email@gmail.com"  # Replace with your email
    from_password = "your_app_password"  # Replace with your app password
    
    subject = "OTP for Attendance System"
    body = f"Your OTP is: {otp}. It will expire in 5 minutes."

    msg = MIMEMultipart()
    msg['From'] = from_email
    msg['To'] = to_email
    msg['Subject'] = subject
    msg.attach(MIMEText(body, 'plain'))

    try:
        server = smtplib.SMTP('smtp.gmail.com', 587)
        server.starttls()
        server.login(from_email, from_password)
        text = msg.as_string()
        server.sendmail(from_email, to_email, text)
        server.quit()
        logger.info(f"OTP sent to {to_email}")
        return True
    except Exception as e:
        logger.error(f"Error sending OTP email: {e}")
        return False

# Routes
@app.route('/')
def home():
    """Home page route with login options"""
    return render_template('home.html', title='Home')

@app.route('/register-faculty', methods=['GET', 'POST'])
def register_faculty():
    try:
        if request.method == 'POST':
            # Collect form data
            email = request.form.get('email', '').strip()
            name = request.form.get('name', '').strip()
            contact = request.form.get('contact', '').strip()
            course = request.form.get('course', '').strip()
            password = request.form.get('password', '')
            confirm_password = request.form.get('confirm_password', '')

            # Comprehensive input validation
            if not all([email, name, contact, course, password, confirm_password]):
                flash("All fields are required", 'danger')
                return render_template('register_faculty.html', title='Register Faculty')

            # Validate email format
            if not re.match(r'^[a-zA-Z0-9._%+-]+@git\.edu$', email):
                flash("Invalid email format. Must be @git.edu", 'danger')
                return render_template('register_faculty.html', title='Register Faculty')

            # Validate contact number (assuming 10 digit number)
            if not re.match(r'^\d{10}$', contact):
                flash("Invalid contact number. Must be 10 digits.", 'danger')
                return render_template('register_faculty.html', title='Register Faculty')

            # Password validation
            if len(password) < 8:
                flash("Password must be at least 8 characters long", 'danger')
                return render_template('register_faculty.html', title='Register Faculty')

            # Validate password confirmation
            if password != confirm_password:
                flash("Passwords do not match", 'danger')
                return render_template('register_faculty.html', title='Register Faculty')

            # Check if faculty already exists
            existing_faculty = mongo.db.faculty.find_one({"email": email})
            if existing_faculty:
                flash("Faculty with this email already exists", 'danger')
                return render_template('register_faculty.html', title='Register Faculty')

            # Hash the password
            hashed_password = generate_password_hash(password)

            # Insert faculty data
            faculty_data = {
                "email": email,
                "name": name,
                "contact": contact,
                "course": course,
                "password": hashed_password,
                "registration_date": datetime.now(),
                "is_active": True
            }

            # Insert into database
            mongo.db.faculty.insert_one(faculty_data)

            # Log successful registration
            logger.info(f"Faculty registered: {email}")

            # Flash success message and redirect
            flash("Registration successful! Please login.", "success")
            return redirect(url_for('login_faculty'))

    except Exception as e:
        # Global error handling
        logger.error(f"Unexpected registration error: {e}")
        logger.error(f"Full traceback: {traceback.format_exc()}")
        flash(f"An unexpected error occurred: {str(e)}", "danger")
        return render_template('register_faculty.html', title='Register Faculty')

    # GET request
    return render_template('register_faculty.html', title='Register Faculty')

@app.route('/login-faculty', methods=['GET', 'POST'])
def login_faculty():
    if request.method == 'POST':
        email = request.form['email']
        password = request.form['password']

        # Find faculty
        faculty = mongo.db.faculty.find_one({"email": email})
        if not faculty:
            flash("No faculty found with this email", "danger")
            return render_template('login_faculty.html', title='Faculty Login')

        # Verify password
        if check_password_hash(faculty['password'], password):
            session['faculty_email'] = email
            flash("Login successful!", "success")
            return redirect(url_for('dashboard_faculty'))
        else:
            flash("Invalid password", "danger")

    return render_template('login_faculty.html', title='Faculty Login')

@app.route('/dashboard-faculty')
def dashboard_faculty():
    if 'faculty_email' not in session:
        flash("Please login first", "danger")
        return redirect(url_for('login_faculty'))

    faculty = mongo.db.faculty.find_one({"email": session['faculty_email']})
    return render_template('dashboard_faculty.html', faculty=faculty, title='Faculty Dashboard')

@app.route('/register-student', methods=['GET', 'POST'])
def register_student():
    if request.method == 'POST':
        email = request.form['email']
        name = request.form['name']
        course = request.form['course']
        password = request.form['password']

        # Validate email domain
        if not validate_college_email(email, 'student'):
            flash("Email must end with '@students.git.edu'", 'danger')
            return render_template('register_student.html', title='Register Student')

        # Check if student already exists
        existing_student = mongo.db.students.find_one({"email": email})
        if existing_student:
            flash("Student with this email already exists", 'danger')
            return render_template('register_student.html', title='Register Student')

        # Hash the password
        hashed_password = generate_password_hash(password)

        # Store student in MongoDB
        mongo.db.students.insert_one({
            "email": email,
            "name": name,
            "course": course,
            "password": hashed_password
        })

        flash("Registration successful! Please login.", "success")
        return redirect(url_for('login_student'))

    return render_template('register_student.html', title='Register Student')

@app.route('/login-student', methods=['GET', 'POST'])
def login_student():
    if request.method == 'POST':
        email = request.form['email']
        password = request.form['password']

        # Find student
        student = mongo.db.students.find_one({"email": email})
        if not student:
            flash("No student found with this email", "danger")
            return render_template('login_student.html', title='Student Login')

        # Verify password
        if check_password_hash(student['password'], password):
            session['student_email'] = email
            flash("Login successful!", "success")
            return redirect(url_for('student_dashboard'))
        else:
            flash("Invalid password", "danger")

    return render_template('login_student.html', title='Student Login')

@app.route('/student-dashboard')
def student_dashboard():
    if 'student_email' not in session:
        flash("Please login first", "danger")
        return redirect(url_for('login_student'))

    student = mongo.db.students.find_one({"email": session['student_email']})
    
    # Fetch attendance records for this student
    attendance_records = list(mongo.db.attendance.find({"student_email": student['email']}).sort("date", -1))
    
    # Get all courses for faculty selection
    courses = mongo.db.faculty.distinct("course")

    # Calculate attendance statistics
    total_classes = len(attendance_records)
    present_classes = len([record for record in attendance_records if record['status'] == 'present'])
    attendance_percentage = (present_classes / total_classes * 100) if total_classes > 0 else 0

    return render_template('dashboard_student.html', 
                           student=student, 
                           attendance_records=attendance_records,
                           courses=courses,
                           total_classes=total_classes,
                           present_classes=present_classes,
                           attendance_percentage=round(attendance_percentage, 2))

@app.route('/scan-faculty-face', methods=['GET', 'POST'])
def scan_faculty_face():
    if 'student_email' not in session:
        flash("Please login first", "danger")
        return redirect(url_for('login_student'))

    if request.method == 'POST':
        course = request.form.get('course')

        if not course:
            flash('Please select a course', 'danger')
            return redirect(url_for('student_dashboard'))

        # Find faculty with matching course
        faculty_list = list(mongo.db.faculty.find({"course": course}))
        
        if not faculty_list:
            flash("No faculty found for the selected course", "danger")
            return redirect(url_for('student_dashboard'))

        # Generate OTP
        student = mongo.db.students.find_one({"email": session['student_email']})
        otp = generate_otp()
        
        # Store OTP in session with expiry
        session['otp'] = {
            'value': otp,
            'expiry': datetime.now().isoformat(),
            'course': course
        }
        
        # Send OTP via email
        if send_otp_email(student['email'], otp):
            return redirect(url_for('verify_otp_attendance'))
        else:
            flash("Failed to send OTP", "danger")

    return redirect(url_for('student_dashboard'))

@app.route('/verify-otp-attendance', methods=['GET', 'POST'])
def verify_otp_attendance():
    if 'student_email' not in session:
        flash("Please login first", "danger")
        return redirect(url_for('login_student'))

    if 'otp' not in session:
        flash("No OTP generated", "danger")
        return redirect(url_for('student_dashboard'))

    if request.method == 'POST':
        user_otp = request.form['otp']
        stored_otp = session['otp']

        # Check OTP expiry (5 minutes)
        if datetime.now() > datetime.fromisoformat(stored_otp['expiry']) + timedelta(minutes=5):
            flash("OTP has expired", "danger")
            session.pop('otp', None)
            return redirect(url_for('student_dashboard'))

        # Verify OTP
        if user_otp == stored_otp['value']:
            # Mark attendance
            student = mongo.db.students.find_one({"email": session['student_email']})
            mongo.db.attendance.insert_one({
                "student_email": student['email'],
                "student_name": student['name'],
                "course": stored_otp['course'],
                "date": datetime.now(),
                "timestamp": datetime.now(),
                "status": "present"
            })

            # Clear OTP session
            session.pop('otp', None)
            flash("Attendance marked successfully!", "success")
            return redirect(url_for('student_dashboard'))
        else:
            flash("Invalid OTP", "danger")

    return render_template('otp_attendance.html', title='Verify OTP for Attendance')

@app.route('/logout')
def logout():
    session.clear()
    flash("Logged out successfully", "success")
    return redirect(url_for('home'))

if __name__ == '__main__':
    app.run(
        host='127.0.0.1', 
        port=5000, 
        debug=True, 
        threaded=True,
        use_reloader=False
    )