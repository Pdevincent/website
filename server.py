from flask import Flask, render_template, request, redirect, url_for, flash, jsonify, session
from datetime import timedelta
from functools import wraps
from werkzeug.utils import secure_filename
from zeroconf import ServiceInfo, Zeroconf
import logging
import json
import socket
import sqlite3
import os
import uuid

app = Flask(__name__)
app.secret_key = 'your_secret_key'  # Used for flash messages and session management
app.permanent_session_lifetime = timedelta(minutes=10)

logging.basicConfig(level=logging.INFO, format='%(asctime)s - %(levelname)s - %(message)s')
logger = logging.getLogger(__name__)

# Define the database path
DB_PATH = "students.db"
UPLOAD_FOLDER = 'uploads'
SERVICE_NAME = "myschool.local"  # Custom phrase for browser access
PORT = 5000
app.config['UPLOAD_FOLDER'] = UPLOAD_FOLDER

# Ensure the 'uploads' folder exists
if not os.path.exists(app.config['UPLOAD_FOLDER']):
    os.makedirs(app.config['UPLOAD_FOLDER'])

def init_db():
    """Create tables for classes, subjects, enrollments, and levels."""
    try:
        conn = sqlite3.connect(DB_PATH)
        cursor = conn.cursor()
        


        # Add the 'balance' column to the 'students' table if it doesn't exist
        cursor.execute("PRAGMA table_info(students)")
        columns = [col[1] for col in cursor.fetchall()]
        if "balance" not in columns:
            cursor.execute("ALTER TABLE students ADD COLUMN balance INTEGER DEFAULT 0")
            print("Column 'balance' added to students table.")
        
        # Students Table (revised)
        cursor.execute('''CREATE TABLE IF NOT EXISTS students (
                            id TEXT PRIMARY KEY,
                            first_name TEXT NOT NULL,
                            last_name TEXT NOT NULL,
                            dob TEXT NOT NULL,
                            age INTEGER NOT NULL,
                            gender TEXT,
                            disabled TEXT,
                            religion TEXT NOT NULL,
                            next_of_kin TEXT NOT NULL,
                            relationship TEXT NOT NULL,
                            contact TEXT NOT NULL,
                            level TEXT NOT NULL,
                            student_class TEXT NOT NULL,
                            balance INTEGER DEFAULT 0)''')
        # Classes Table
        cursor.execute('''CREATE TABLE IF NOT EXISTS classes (
                            id INTEGER PRIMARY KEY AUTOINCREMENT,
                            class_name TEXT NOT NULL)''')

        # Subjects Table
        cursor.execute('''CREATE TABLE IF NOT EXISTS subjects (
                            id INTEGER PRIMARY KEY AUTOINCREMENT,
                            subject_name TEXT NOT NULL)''')

        # Enrollments Table
        cursor.execute('''CREATE TABLE IF NOT EXISTS enrollments (
                            id INTEGER PRIMARY KEY AUTOINCREMENT,
                            student_id TEXT NOT NULL,
                            class_id INTEGER NOT NULL,
                            FOREIGN KEY (class_id) REFERENCES classes(id),
                            FOREIGN KEY (student_id) REFERENCES students(id),
                            UNIQUE(student_id, class_id)
                        )''')

        # Marks Table
        cursor.execute('''CREATE TABLE IF NOT EXISTS marks (
                            id INTEGER PRIMARY KEY AUTOINCREMENT,
                            student_id TEXT NOT NULL,
                            subject_id INTEGER NOT NULL,
                            marks INTEGER NOT NULL,
                            FOREIGN KEY (student_id) REFERENCES students(id),
                            FOREIGN KEY (subject_id) REFERENCES subjects(id))''')

        # Levels Table
        cursor.execute('''CREATE TABLE IF NOT EXISTS levels (
                            id INTEGER PRIMARY KEY AUTOINCREMENT,
                            level_name TEXT NOT NULL)''')

        # Fee Payments Table
        cursor.execute('''CREATE TABLE IF NOT EXISTS fee_payments (
                            id INTEGER PRIMARY KEY AUTOINCREMENT,
                            student_id TEXT,
                            amount_paid INTEGER,
                            term TEXT,
                            year INTEGER,
                            payment_date TIMESTAMP DEFAULT CURRENT_TIMESTAMP,
                            FOREIGN KEY (student_id) REFERENCES students(id)
                        )''')

        # Grade Settings Table
        cursor.execute('''CREATE TABLE IF NOT EXISTS grade_settings (
                    level TEXT NOT NULL,
                    grade TEXT NOT NULL,
                    min_marks INTEGER NOT NULL,
                    PRIMARY KEY (level, grade)
                )''')
        # Fee Structure Table
        cursor.execute('''CREATE TABLE IF NOT EXISTS fee_structure (
                            term TEXT NOT NULL,
                            bursary_status TEXT NOT NULL,
                            year INTEGER NOT NULL,
                            fee_amount INTEGER NOT NULL,
                            class_name TEXT NOT NULL,
                            PRIMARY KEY (term, year, class_name)
                        )''')

        # Subject Enrollments Table
        cursor.execute('''CREATE TABLE IF NOT EXISTS subject_enrollments (
                            id INTEGER PRIMARY KEY AUTOINCREMENT,
                            student_id TEXT NOT NULL,
                            subject_id INTEGER NOT NULL,
                            FOREIGN KEY (student_id) REFERENCES students(id),
                            FOREIGN KEY (subject_id) REFERENCES subjects(id),
                            UNIQUE(student_id, subject_id)
                        )''')

        # Users Table for Login System
        cursor.execute('''CREATE TABLE IF NOT EXISTS users (
                            id INTEGER PRIMARY KEY AUTOINCREMENT,
                            username TEXT NOT NULL UNIQUE,
                            password TEXT NOT NULL,
                            role TEXT NOT NULL)''')
        
        cursor.execute('''CREATE TABLE IF NOT EXISTS institution (
                            id INTEGER PRIMARY KEY AUTOINCREMENT,
                            school_name TEXT,
                            logo_filename TEXT,
                            contact_info TEXT
                        )''')
        
        cursor.execute('''CREATE TABLE IF NOT EXISTS fee_adjustments (
                            id INTEGER PRIMARY KEY AUTOINCREMENT,
                            student_id TEXT NOT NULL,
                            adjustment_type TEXT NOT NULL CHECK (adjustment_type IN ('add', 'reduce')),
                            amount INTEGER NOT NULL,
                            term TEXT NOT NULL,
                            year INTEGER NOT NULL,
                            reason TEXT NOT NULL,
                            FOREIGN KEY (student_id) REFERENCES students(id)
                        );
                        ''')
        
        cursor.execute('''CREATE TABLE IF NOT EXISTS performance_record (
                            id INTEGER PRIMARY KEY AUTOINCREMENT,
                            student_id TEXT NOT NULL,
                            term TEXT NOT NULL,
                            year INTEGER NOT NULL,
                            marks_data TEXT NOT NULL,  -- JSON data
                            created_at TIMESTAMP DEFAULT CURRENT_TIMESTAMP,
                            UNIQUE(student_id, term, year),
                            FOREIGN KEY (student_id) REFERENCES students(id)
                        )''')
                
        

        # Check if 'class_id' column already exists in users table
        cursor.execute("PRAGMA table_info(users)")
        columns = [col[1] for col in cursor.fetchall()]
        if "class_id" not in columns:
            cursor.execute('''ALTER TABLE users ADD COLUMN class_id INTEGER''')
            print("Column 'class_id' added to users table.")

        # Create a default admin/developer account if it doesn't exist
        cursor.execute("SELECT * FROM users WHERE username = 'admin'")
        admin_user = cursor.fetchone()
        if not admin_user:
            cursor.execute("INSERT INTO users (username, password, role) VALUES (?, ?, ?)",
                           ('admin', 'admin123', 'admin'))  # Default admin account
            print("Default admin account created.")

        # Fetch and print levels from the database
        cursor.execute("SELECT * FROM levels")
        levels = cursor.fetchall()
        print("Levels Table Content:", levels)

        conn.commit()
        print("Database tables created successfully.")
    except sqlite3.Error as e:
        print(f"Error creating tables: {e}")
    finally:
        if conn:
            conn.close()



def get_local_ip():
    """Get the local IP address of the machine for LAN access."""
    try:
        # Create a socket to find the LAN IP
        s = socket.socket(socket.AF_INET, socket.SOCK_DGRAM)
        # Use a local broadcast address to avoid external dependency
        s.connect(("192.168.1.255", 80))  # Common LAN subnet broadcast address
        local_ip = s.getsockname()[0]
        s.close()
        logger.info(f"Detected local IP: {local_ip}")
        return local_ip
    except Exception as e:
        logger.warning(f"Error detecting IP, falling back to 0.0.0.0: {e}")
        return "0.0.0.0"  # Bind to all interfaces if detection fails

# Advertise service via mDNS
def advertise_service(ip, port):
    """Advertise the Flask app on the LAN using mDNS."""
    try:
        zeroconf = Zeroconf()
        service_name = f"{SERVICE_NAME}._http._tcp.local."
        service_info = ServiceInfo(
            "_http._tcp.local.",
            service_name,
            addresses=[socket.inet_aton(ip)],
            port=port,
            properties={"path": "/"},
        )
        zeroconf.register_service(service_info)
        logger.info(f"Service advertised as http://{SERVICE_NAME}.local:{port}")
        return zeroconf
    except Exception as e:
        logger.error(f"Error advertising service: {e}")
        return None

def role_required(required_role):
    def decorator(func):
        @wraps(func)
        def wrapped(*args, **kwargs):
            if 'role' not in session or session['role'].lower() != required_role.lower():
                flash("Access denied: Insufficient permissions.", "error")
                return redirect(url_for('index'))
            return func(*args, **kwargs)
        return wrapped
    return decorator

# Login Route
@app.route('/login', methods=['GET', 'POST'])
def login():
    if request.method == 'POST':
        username = request.form['username']
        password = request.form['password']

        try:
            conn = sqlite3.connect(DB_PATH)
            cursor = conn.cursor()
            cursor.execute("SELECT * FROM users WHERE username = ? AND password = ?", (username, password))
            user = cursor.fetchone()

            if user:
                session['user_id'] = user[0]
                session['username'] = user[1]
                session['role'] = user[3]
                return redirect(url_for('index'))
            else:
                flash("Invalid username or password", "error")
        except sqlite3.Error as e:
            flash(f"Database error: {e}", "error")
        finally:
            if conn:
                conn.close()
    session.permanent = True

    # Fetch institution data
    try:
        conn = sqlite3.connect(DB_PATH)
        cursor = conn.cursor()
        cursor.execute("SELECT school_name, logo_filename FROM institution LIMIT 1")
        institution = cursor.fetchone()
    except sqlite3.Error as e:
        institution = None
    finally:
        if conn:
            conn.close()

    return render_template('login.html', institution=institution)

@app.route('/logout')
def logout():
    session.clear()
    session.modified = True  # Ensure session is invalidated
    return redirect(url_for('login'))

# User Management Route (Protected)
@app.route('/user', methods=['GET', 'POST'])
def user_login():
    if 'user_id' not in session or session.get('role') != 'admin':
        flash("You do not have permission to access this page.", "error")
        return redirect(url_for('index'))

    try:
        conn = sqlite3.connect(DB_PATH)
        cursor = conn.cursor()

        if request.method == 'POST':
            username = request.form['username']
            password = request.form['password']
            role = request.form['role']

            cursor.execute("INSERT INTO users (username, password, role) VALUES (?, ?, ?)", (username, password, role))
            conn.commit()
            flash("User created successfully!", "success")
            return redirect(url_for('user'))

        cursor.execute("SELECT * FROM users")
        users = cursor.fetchall()
        return render_template("user.html", users=users)
    except sqlite3.Error as e:
        flash(f"Database error: {e}", "error")
        return render_template("user.html", users=[])
    finally:
        if conn:
            conn.close()


def generate_unique_student_id():
    """Generates a unique 10-digit student ID."""
    return str(uuid.uuid4().int)[:10]

@app.route('/get_student_name', methods=['GET'])
def get_student_name():
    student_id = request.args.get('student_id')
    if not student_id:
        return jsonify({"error": "Student ID is required"}), 400

    try:
        conn = sqlite3.connect(DB_PATH)
        cursor = conn.cursor()
        # Modify the query to use student_class instead of class
        cursor.execute("SELECT first_name, last_name, student_class FROM students WHERE id = ?", (student_id,))
        student = cursor.fetchone()
        conn.close()

        if student:
            # Return both the name and class
            return jsonify({"name": f"{student[0]} {student[1]}", "class": student[2]})
        else:
            return jsonify({"error": "Student not found"}), 404
    except sqlite3.Error as e:
        return jsonify({"error": f"Database error: {e}"}), 500

@app.route('/adjust_fees', methods=['POST'])
def adjust_fees():
    data = request.json
    try:
        conn = sqlite3.connect(DB_PATH)
        cursor = conn.cursor()

        # Validate student exists
        cursor.execute("SELECT id, balance FROM students WHERE id = ?", (data['student_id'],))
        student = cursor.fetchone()
        if not student:
            return jsonify({"success": False, "error": "Student not found"})

        # Determine adjustment amount
        amount = int(data['amount'])
        if data['type'] == 'reduce':
            amount = -amount

        # Update the student's balance
        new_balance = student[1] + amount  # Assuming balance is stored in the student record
        cursor.execute("UPDATE students SET balance = ? WHERE id = ?", (new_balance, data['student_id']))

        # Record the adjustment in the fee_adjustments table
        cursor.execute('''INSERT INTO fee_adjustments 
                        (student_id, adjustment_type, amount, term, year, reason)
                        VALUES (?, ?, ?, ?, ?, ?)''',
                     (data['student_id'], data['type'], amount, data['term'], data['year'], data['reason']))

        conn.commit()
        return jsonify({"success": True, "new_balance": new_balance})
    
    except sqlite3.Error as e:
        return jsonify({"success": False, "error": str(e)})
    finally:
        if conn:
            conn.close()


@app.route('/', methods=['GET', 'POST'])
def index():
    # Check if user is logged in
    if 'user_id' not in session:
        return redirect(url_for('login'))

    try:
        conn = sqlite3.connect(DB_PATH)
        cursor = conn.cursor()

        query = "SELECT * FROM students WHERE 1=1"
        params = []

        if request.method == 'POST':
            student_id = request.form.get('student_id', '').strip()
            name = request.form.get('name', '').strip()
            level = request.form.get('level', '').strip()
            class_name = request.form.get('student_class', '').strip()

            if student_id:
                query += " AND id LIKE ?"
                params.append(f"%{student_id}%")
            if name:
                query += " AND (first_name LIKE ? OR last_name LIKE ?)"
                params.append(f"%{name}%")
                params.append(f"%{name}%")
            if level:
                query += " AND level LIKE ?"
                params.append(f"%{level}%")
            if class_name:
                query += " AND student_class LIKE ?"
                params.append(f"%{class_name}%")

        cursor.execute(query, params)
        students = cursor.fetchall()
    except sqlite3.Error as e:
        flash(f"Database error: {e}", "error")
        students = []
    finally:
        if conn:
            conn.close()

    return render_template("index.html", students=students)

@app.route('/update_marks', methods=['POST'])
def update_marks():
    data = request.get_json()
    student_id = data.get('student_id')
    subject_id = data.get('subject_id')
    marks = data.get('marks')

    print(f"🛠️ Received Data - student_id: {student_id}, subject_id: {subject_id}, marks: {marks}")  

    if not student_id or not subject_id or marks is None:
        print("⚠️ Missing required fields!")
        return jsonify(success=False, error="Missing required fields"), 400

    try:
        conn = sqlite3.connect(DB_PATH)
        cursor = conn.cursor()

        # Ensure student and subject exist
        cursor.execute("SELECT id FROM students WHERE id = ?", (student_id,))
        student_exists = cursor.fetchone()
        cursor.execute("SELECT id FROM subjects WHERE id = ?", (subject_id,))
        subject_exists = cursor.fetchone()

        if not student_exists:
            print(f"❌ Error: Student ID {student_id} not found in database")
            return jsonify(success=False, error="Student not found"), 400
        if not subject_exists:
            print(f"❌ Error: Subject ID {subject_id} not found in database")
            return jsonify(success=False, error="Subject not found"), 400

        # Check if marks already exist
        cursor.execute("SELECT id FROM marks WHERE student_id = ? AND subject_id = ?", (student_id, subject_id))
        existing = cursor.fetchone()

        if existing:
            # Update marks
            cursor.execute("UPDATE marks SET marks = ? WHERE student_id = ? AND subject_id = ?", 
                           (marks, student_id, subject_id))
            print(f"✅ Updated marks for Student {student_id}, Subject {subject_id} to {marks}")
        else:
            # Insert new marks
            cursor.execute("INSERT INTO marks (student_id, subject_id, marks) VALUES (?, ?, ?)", 
                           (student_id, subject_id, marks))
            print(f"✅ Inserted marks for Student {student_id}, Subject {subject_id} - Marks: {marks}")

        conn.commit()
        return jsonify(success=True)
    except sqlite3.Error as e:
        print(f"🔥 Database error: {e}")
        return jsonify(success=False, error=str(e)), 500
    finally:
        conn.close()

@app.route('/bulk_enrollment', methods=['GET', 'POST'])
def bulk_enrollment():
    class_name = request.args.get('class_name')
    if not class_name:
        flash("Class not specified", "error")
        return redirect(url_for('index'))

    try:
        conn = sqlite3.connect(DB_PATH)
        cursor = conn.cursor()
        
        # Get students in class
        cursor.execute("SELECT id, first_name, last_name FROM students WHERE student_class = ?", (class_name,))
        students = cursor.fetchall()
        
        # Get all subjects
        cursor.execute("SELECT id, subject_name FROM subjects")
        subjects = cursor.fetchall()

        return render_template("bulk_enrollment.html", 
                             students=students, 
                             subjects=subjects,
                             class_name=class_name)
    
    except sqlite3.Error as e:
        flash(f"Database error: {e}", "error")
        return redirect(url_for('index'))
    
@app.route('/enroll_bulk', methods=['POST'])
def enroll_bulk():
    data = request.get_json()
    student_ids = data.get('student_ids', [])
    subject_ids = data.get('subject_ids', [])
    class_name = data.get('class_name')

    if not student_ids or not subject_ids:
        return jsonify(success=False, error="No students or subjects selected")

    try:
        conn = sqlite3.connect(DB_PATH)
        cursor = conn.cursor()

        # Validate all students belong to the specified class
        cursor.execute("SELECT id FROM students WHERE student_class = ?", (class_name,))
        valid_students = [row[0] for row in cursor.fetchall()]
        
        for student_id in student_ids:
            if student_id not in valid_students:
                return jsonify(success=False, error=f"Student {student_id} not in {class_name}"), 400

        # Insert enrollments
        for student_id in student_ids:
            for subject_id in subject_ids:
                try:
                    cursor.execute('''INSERT INTO subject_enrollments 
                                   (student_id, subject_id)
                                   VALUES (?, ?)''', 
                                   (student_id, subject_id))
                except sqlite3.IntegrityError:
                    conn.rollback()  # Ignore duplicate entries
                    continue

        conn.commit()
        return jsonify(success=True)
    
    except sqlite3.Error as e:
        return jsonify(success=False, error=str(e)), 500
    finally:
        if conn:
            conn.close()

@app.route('/academics', methods=['GET', 'POST'])
def academics():
    conn = sqlite3.connect(DB_PATH)
    cursor = conn.cursor()

    # ✅ Fetch levels for the dropdown
    cursor.execute("SELECT level_name FROM levels")  
    levels = [row[0] for row in cursor.fetchall()]  # Extract level names from tuples
    conn.close()  

    if request.method == 'POST':
        try:
            if 'create_class' in request.form:
                class_name = request.form['class_name']
                level = request.form['level']

                # Ensure level exists
                cursor.execute("SELECT level_name FROM levels WHERE level_name = ?", (level,))
                if not cursor.fetchone():
                    flash("Error: Selected level does not exist!", "error")
                else:
                    cursor.execute("INSERT INTO classes (class_name, level) VALUES (?, ?)", (class_name, level))
                    conn.commit()
                    flash("Class created successfully!", "success")

            if 'create_subject' in request.form:
                subject_name = request.form['subject_name']
                paper = request.form['paper']
                cursor.execute("INSERT INTO subjects (subject_name, paper) VALUES (?, ?)", (subject_name, paper))
                conn.commit()
                flash("Subject created successfully!", "success")

            if 'enroll_student' in request.form:
                student_id = request.form['student_id']
                class_id = request.form['class_id']
                cursor.execute("INSERT INTO enrollments (student_id, class_id) VALUES (?, ?)", (student_id, class_id))
                conn.commit()
                flash("Student enrolled successfully!", "success")

        except sqlite3.Error as e:
            flash(f"Database error: {e}", "error")

    conn.close()  # ✅ Ensure the database connection is closed

    return render_template('academics.html', levels=levels) # ✅ Pass levels to the template


@app.route('/submit_fee_payment', methods=['POST'])
def submit_fee_payment():
    student_id = request.form['student_id']
    amount_paid = request.form['amount_paid']
    term = request.form['term']
    year = request.form['year']

    # Save fee payment with term and year
    try:
        conn = sqlite3.connect(DB_PATH)
        cursor = conn.cursor()
        cursor.execute('''INSERT INTO fee_payments (student_id, amount_paid, term, year) 
                          VALUES (?, ?, ?, ?)''', 
                       (student_id, amount_paid, term, year))
        conn.commit()
        flash('Fee payment successfully recorded!', 'success')
    except sqlite3.Error as e:
        flash(f'Error recording fee payment: {e}', 'error')
    finally:
        if conn:
            conn.close()

    return redirect(url_for('finance'))

@app.route('/save_performance', methods=['POST'])
def save_performance():
    data = request.get_json()
    student_id = data['student_id']
    term = data['term']
    year = data['year']
    marks_data = json.dumps(data['marks_data'])

    try:
        conn = sqlite3.connect(DB_PATH)
        cursor = conn.cursor()
        
        # Check for existing record
        cursor.execute('''SELECT id FROM performance_record 
                        WHERE student_id = ? AND term = ? AND year = ?''',
                       (student_id, term, year))
        if cursor.fetchone():
            return jsonify(success=False, error="Performance for this term already exists"), 400

        # Insert new record
        cursor.execute('''INSERT INTO performance_record 
                        (student_id, term, year, marks_data)
                        VALUES (?, ?, ?, ?)''',
                       (student_id, term, year, marks_data))
        conn.commit()
        return jsonify(success=True)
    
    except sqlite3.IntegrityError:
        return jsonify(success=False, error="Duplicate entry"), 400
    except Exception as e:
        return jsonify(success=False, error=str(e)), 500
    finally:
        if conn:
            conn.close()


@app.route('/add_student', methods=['GET', 'POST'])
def add_student():
    if request.method == 'POST':
        student_id = generate_unique_student_id()  
        first_name = request.form['first_name']
        last_name = request.form['last_name']
        dob = request.form['dob']
        age = int(request.form['age'])
        gender = request.form['gender']
        disabled = request.form['disabled']
        religion = request.form['religion']
        next_of_kin = request.form['next_of_kin']
        relationship = request.form['relationship']
        contact = request.form['contact']
        level = request.form['level']
        student_class = request.form['student_class']

        try:
            conn = sqlite3.connect(DB_PATH)
            cursor = conn.cursor()

            cursor.execute('''INSERT INTO students (id, first_name, last_name, dob, age, gender, disabled, religion, 
                         next_of_kin, relationship, contact, level, student_class) 
                         VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?)''', 
                      (student_id, first_name, last_name, dob, age, gender, disabled, religion, next_of_kin, 
                       relationship, contact, level, student_class))

            conn.commit()
            flash("Student added successfully!", "success")
        except sqlite3.Error as e:
            flash(f"Database error: {e}", "error")
        finally:
            if conn:
                conn.close()
        return redirect(url_for('index'))

    # Fetch classes and levels from the database when rendering the form
    conn = sqlite3.connect(DB_PATH)
    cursor = conn.cursor()

    cursor.execute("SELECT class_name FROM classes")
    classes = cursor.fetchall()  # This returns a list of tuples

    cursor.execute("SELECT level_name FROM levels")
    levels = cursor.fetchall()  # This returns a list of tuples

    conn.close()

    # Pass classes and levels to the template
    return render_template("add_student.html", classes=classes, levels=levels)


@app.route('/view_student/<id>')
def view_student(id):
    try:
        conn = sqlite3.connect(DB_PATH)
        cursor = conn.cursor()

        cursor.execute("SELECT * FROM students WHERE id = ?", (id,))
        student = cursor.fetchone()

        if student:
            return render_template("view_student.html", student=student)
        else:
            return "Student not found", 404
    except sqlite3.Error as e:
        flash(f"Database error: {e}", "error")
        return "An error occurred while fetching student data.", 500
    finally:
        if conn:
            conn.close()

@app.route('/edit_student/<id>', methods=['GET', 'POST'])
def edit_student(id):
    student = get_student_by_id(id)

    if request.method == 'POST':
        update_student_data(id, request.form)
        flash("Student record updated successfully!", "success")
        return redirect(url_for('index'))

    return render_template('edit_student.html', student=student)

def get_student_by_id(id):
    try:
        conn = sqlite3.connect(DB_PATH)
        cursor = conn.cursor()
        cursor.execute("SELECT * FROM students WHERE id = ?", (id,))
        student = cursor.fetchone()
        return student
    except sqlite3.Error as e:
        flash(f"Database error: {e}", "error")
        return None
    finally:
        if conn:
            conn.close()
def get_levels_from_db():
    conn = sqlite3.connect(DB_PATH)
    cursor = conn.cursor()
    cursor.execute("SELECT id, level_name FROM levels")
    levels = cursor.fetchall()
    return levels

def update_student_data(id, data):
    try:
        conn = sqlite3.connect(DB_PATH)
        cursor = conn.cursor()

        cursor.execute('''UPDATE students
                          SET first_name = ?, last_name = ?, dob = ?, age = ?, gender = ?, disabled = ?, religion = ?, 
                              next_of_kin = ?, relationship = ?, contact = ?, level = ?, 
                              student_class = ?
                          WHERE id = ?''', 
                       (data['first_name'], data['last_name'], data['dob'], int(data['age']), data['gender'], data['disabled'], data['religion'], 
                        data['next_of_kin'], data['relationship'], data['contact'], data['level'], 
                        data['student_class'], id))
        
        conn.commit()
    except sqlite3.Error as e:
        flash(f"Database error: {e}", "error")
    finally:
        if conn:
            conn.close()


@app.route('/set_fee_structure', methods=['GET', 'POST'])
def set_fee_structure():
    if request.method == 'POST':
        term = request.form['term']
        bursary_status = request.form['bursary_status']
        year = int(request.form['year'])
        fee_amount = int(request.form['fee_amount'])
        class_name = request.form['student_class']  # Get class from form

        try:
            conn = sqlite3.connect(DB_PATH)
            cursor = conn.cursor()
            cursor.execute('''INSERT INTO fee_structure (term, bursary_status, year, fee_amount, class_name) 
                              VALUES (?, ?, ?, ?, ?)''', 
                           (term, bursary_status, year, fee_amount, class_name))
            conn.commit()
            flash("Fee structure set successfully!", "success")
        except sqlite3.Error as e:
            flash(f"Database error: {e}", "error")
        finally:
            if conn:
                conn.close()
        return redirect(url_for('finance'))

    # Fetch classes from the database when rendering the form
    try:
        conn = sqlite3.connect(DB_PATH)
        cursor = conn.cursor()
        cursor.execute("SELECT class_name FROM classes")
        classes = cursor.fetchall()
    except sqlite3.Error as e:
        flash(f"Database error: {e}", "error")
        classes = []
    finally:
        if conn:
            conn.close()

    return render_template('set_fee_structure.html', classes=classes)
@app.route('/create_requirements', methods=['GET', 'POST'])
def create_requirements():
    if request.method == 'POST':
        term = request.form['term']
        class_name = request.form['class_name']
        requirements = request.form['requirements']
        quantity = int(request.form['quantity'])  # Convert quantity to integer

        # Save the requirements and quantity to the database
        try:
            conn = sqlite3.connect(DB_PATH)
            cursor = conn.cursor()

            cursor.execute('''INSERT INTO requirements (term, class_name, requirements, quantity) 
                            VALUES (?, ?, ?, ?)''', 
                            (term, class_name, requirements, quantity))
            
            conn.commit()
            flash("Requirements saved successfully!", "success")
        except sqlite3.Error as e:
            flash(f"Database error: {e}", "error")
        finally:
            if conn:
                conn.close()

        return redirect(url_for('finance'))  # Redirect back to the finance page or success page
    
    return render_template('create_requirements.html')

@app.route('/get_fees_defaulters')
def get_fees_defaulters():
    try:
        conn = sqlite3.connect(DB_PATH)
        cursor = conn.cursor()

        # Query to fetch defaulters grouped by class
        cursor.execute('''
            SELECT 
                s.student_class AS class_name,
                s.id AS student_id,
                s.first_name || ' ' || s.last_name AS student_name,
                SUM(fs.fee_amount - COALESCE(fp.total_paid, 0)) AS total_due
            FROM students s
            JOIN fee_structure fs ON s.student_class = fs.class_name
            LEFT JOIN (
                SELECT student_id, term, year, SUM(amount_paid) AS total_paid
                FROM fee_payments
                GROUP BY student_id, term, year
            ) fp ON s.id = fp.student_id AND fs.term = fp.term AND fs.year = fp.year
            GROUP BY s.student_class, s.id
            HAVING total_due > 0
            ORDER BY s.student_class, s.id
        ''')

        defaulters = cursor.fetchall()

        # Organize defaulters by class
        classes = {}
        for row in defaulters:
            class_name = row[0]
            student_id = row[1]
            student_name = row[2]
            amount_due = row[3]

            if class_name not in classes:
                classes[class_name] = []
            classes[class_name].append({
                "student_id": student_id,
                "name": student_name,
                "amount_due": amount_due
            })

        # Convert to the required format
        result = []
        for class_name, students in classes.items():
            result.append({
                "name": class_name,
                "defaulters": students
            })

        return jsonify({"success": True, "classes": result})
    except sqlite3.Error as e:
        return jsonify({"success": False, "error": str(e)}), 500
    finally:
        if conn:
            conn.close()

@app.route('/get_students', methods=['GET'])
def get_students():
    try:
        conn = sqlite3.connect(DB_PATH)
        cursor = conn.cursor()
        cursor.execute("SELECT id, name FROM students")
        students = cursor.fetchall()
        conn.close()

        # Return the list of students as JSON
        return jsonify(students)
    except sqlite3.Error as e:
        return jsonify({"error": f"Database error: {e}"})



@app.route('/student_data')
def student_data():
    conn = sqlite3.connect(DB_PATH)
    cursor = conn.cursor()

    # Fetch all classes with student count
    cursor.execute("""
        SELECT c.class_name, COUNT(s.id) 
        FROM classes c 
        LEFT JOIN students s ON c.class_name = s.student_class 
        GROUP BY c.class_name
    """)
    classes = cursor.fetchall()

    # Get student statistics
    cursor.execute("SELECT COUNT(*) FROM students")  # Total students
    total_students = cursor.fetchone()[0]

    cursor.execute("SELECT COUNT(*) FROM students WHERE gender = 'Male'")  # Male students
    male_students = cursor.fetchone()[0]

    cursor.execute("SELECT COUNT(*) FROM students WHERE gender = 'Female'")  # Female students
    female_students = cursor.fetchone()[0]

    conn.close()

    return render_template("student_data.html", 
                           classes=classes, 
                           total_students=total_students, 
                           male_students=male_students, 
                           female_students=female_students)


@app.route('/report_cards')
def report_cards():
    return "Report Cards Page (To be implemented)"

@app.route('/finance')
def finance():
    return render_template("finance.html")

@app.route('/create_class', methods=['POST'])
def create_class():
    class_name = request.form.get('class_name')
    level = request.form.get('level')

    if not class_name or not level:
        flash("Class name and level are required", "error")
        return redirect(url_for('academics'))

    try:
        conn = sqlite3.connect(DB_PATH)
        cursor = conn.cursor()

        # Ensure the level is stored in the levels table
        cursor.execute("SELECT id FROM levels WHERE level_name = ?", (level,))
        existing_level = cursor.fetchone()

        if not existing_level:
            cursor.execute("INSERT INTO levels (level_name) VALUES (?)", (level,))
            conn.commit()
            print(f"New level '{level}' inserted into levels table.")

        # Insert the class into the classes table
        cursor.execute("INSERT INTO classes (class_name) VALUES (?)", (class_name,))
        conn.commit()

        flash(f"Class '{class_name}' created successfully under level '{level}'!", "success")
        print(f"Class '{class_name}' inserted successfully.")

    except sqlite3.Error as e:
        flash(f"Error creating class: {e}", "error")
        print(f"Error inserting class: {e}")
    finally:
        if conn:
            conn.close()

    return redirect(url_for('academics'))


@app.route('/class_students/<class_name>')
def class_students(class_name):
    if 'user_id' not in session:
        flash("You need to login to access this page.", "error")
        return redirect(url_for('login'))

    try:
        conn = sqlite3.connect(DB_PATH)
        cursor = conn.cursor()

        # Fetch the user's role and assigned class (if any)
        cursor.execute("SELECT role, class_id FROM users WHERE id = ?", (session['user_id'],))
        user = cursor.fetchone()

        if not user:
            flash("User not found.", "error")
            return redirect(url_for('index'))

        role, user_class_id = user

        # If the user is a Class Teacher, ensure they can only access their assigned class
        if role == "Class Teacher":
            cursor.execute("SELECT id FROM classes WHERE class_name = ?", (class_name,))
            class_id = cursor.fetchone()[0]

            if user_class_id != class_id:
                flash("You do not have permission to access this class.", "error")
                return redirect(url_for('index'))

        # Fetch students belonging to the selected class
        cursor.execute("SELECT id, first_name, last_name FROM students WHERE student_class = ?", (class_name,))
        students = cursor.fetchall()

    except sqlite3.Error as e:
        flash(f"Database error: {e}", "error")
        students = []
    finally:
        if conn:
            conn.close()

    # Render the template with the list of students
    return render_template("class_students.html", students=students, class_name=class_name)

@app.route('/create_subject', methods=['POST'])
def create_subject():
    subject_name = request.form.get('subject_name')
    paper = request.form.get('paper')

    if not subject_name:
        flash("Subject name is required", "error")
        return redirect(url_for('academics'))

    try:
        conn = sqlite3.connect(DB_PATH)
        cursor = conn.cursor()

        # Insert new subject into the subjects table
        cursor.execute('''INSERT INTO subjects (subject_name) VALUES (?)''', (subject_name,))
        
        conn.commit()
        flash(f"Subject '{subject_name}' created successfully!", "success")
    except sqlite3.Error as e:
        flash(f"Error creating subject: {e}", "error")
    finally:
        if conn:
            conn.close()

    return redirect(url_for('academics'))

@app.route('/get_payment_history', methods=['GET'])
def get_payment_history():
    student_id = request.args.get('student_id')

    if not student_id:
        return jsonify({"success": False, "message": "Student ID is required"}), 400

    try:
        conn = sqlite3.connect(DB_PATH)
        cursor = conn.cursor()

        # Fetch student details (name and class)
        cursor.execute("SELECT first_name, last_name, student_class FROM students WHERE id = ?", (student_id,))
        student = cursor.fetchone()
        if not student:
            return jsonify({"success": False, "message": "Student not found"}), 404
        student_name = f"{student[0]} {student[1]}"
        student_class = student[2]

        # Fetch total fees for the student's class
        cursor.execute("SELECT fee_amount FROM fee_structure WHERE class_name = ?", (student_class,))
        fee_data = cursor.fetchone()
        total_fee = fee_data[0] if fee_data else 0  # Default to 0 if no fee structure exists

        # Fetch payment history with date
        cursor.execute('''SELECT term, year, amount_paid, date(payment_date) 
                          FROM fee_payments 
                          WHERE student_id = ? 
                          ORDER BY year DESC, term DESC''', (student_id,))
        payment_records = cursor.fetchall()

        # Calculate total amount paid
        total_paid = sum([record[2] for record in payment_records])
        fee_balance = total_fee - total_paid

        conn.close()

        # Format payment history for JSON response
        payment_history = [
            {
                "term": record[0],
                "year": record[1],
                "amount_paid": record[2],
                "payment_date": record[3]
            }
            for record in payment_records
        ]

        return jsonify({
            "success": True,
            "student_name": student_name,
            "student_class": student_class,
            "payment_history": payment_history,
            "fee_balance": fee_balance
        })
    except sqlite3.Error as e:
        return jsonify({"success": False, "error": str(e)}), 500

@app.route('/view_class')
def view_classes():
    try:
        conn = sqlite3.connect(DB_PATH)
        cursor = conn.cursor()
        cursor.execute("SELECT * FROM classes")  # Assuming you have a 'classes' table
        classes = cursor.fetchall()
    except sqlite3.Error as e:
        flash(f"Database error: {e}", "error")
        classes = []
    finally:
        if conn:
            conn.close()

    return render_template('view_classes.html', classes=classes)

@app.route('/set_grades', methods=['GET', 'POST'])
def set_grades():
    if request.method == 'POST':
        grade_names = request.form.getlist('grade_name[]')
        grade_marks = request.form.getlist('grade_marks[]')
        level = request.form.get('level')  # Get the level from the form

        if not grade_names or not grade_marks or len(grade_names) != len(grade_marks) or not level:
            flash("All fields are required!", "error")
            return redirect(url_for('academics'))

        try:
            print("Connecting to database...")
            conn = sqlite3.connect(DB_PATH)
            cursor = conn.cursor()
            print("Database connection successful!")

            # Clear previous settings for this level
            cursor.execute("DELETE FROM grade_settings WHERE level = ?", (level,))

            # Insert new grade boundaries dynamically
            for name, mark in zip(grade_names, grade_marks):
                cursor.execute("INSERT INTO grade_settings (grade, min_marks, level) VALUES (?, ?, ?)", 
                               (name, int(mark), level))

            conn.commit()
            print(f"Grades set successfully for level: {level}")
            flash(f"Grade boundaries for {level} set successfully!", "success")
        except sqlite3.Error as e:
            print(f"Database error: {e}")  # Debugging statement
            flash(f"Database error: {e}", "error")
        finally:
            if conn:
                conn.close()
                print("Database connection closed.")

        return redirect(url_for('academics'))

    # Fetch available levels from the database
    try:
        print("Fetching available levels...")
        conn = sqlite3.connect(DB_PATH)
        cursor = conn.cursor()
        
        cursor.execute("SELECT level_name FROM levels")  # Fetch all levels
        raw_levels = cursor.fetchall()
        
        print("Raw data fetched:", raw_levels)  # Debugging statement
        
        levels = [row[0] for row in raw_levels]  # Extract level names
        print("Extracted levels:", levels)  # Debugging statement
        
        conn.close()
        print("Database connection closed after fetching levels.")

        # Check if levels is empty and print an exception message
        if not levels:
            print("Exception: No levels found in the database!")  # Debugging statement
            flash("No levels found in the database. Please add levels first.", "error")
    except sqlite3.Error as e:
        print(f"Database error while fetching levels: {e}")  # Debugging statement
        flash(f"Database error: {e}", "error")
        levels = []

    # Pass levels to the template
    return render_template('academics.html', levels=levels)



def get_grade_boundaries():
    """Fetch grade boundaries from the database."""
    conn = sqlite3.connect(DB_PATH)
    cursor = conn.cursor()
    cursor.execute("SELECT grade, min_marks FROM grade_settings")
    grade_data = cursor.fetchall()
    conn.close()

    # Convert to dictionary {Grade: Min Marks}
    grade_boundaries = {row[0]: int(row[1]) for row in grade_data}
    return grade_boundaries

def calculate_grade(marks, level):
    """Determine grade based on dynamically set grade boundaries for a specific level."""
    try:
        conn = sqlite3.connect(DB_PATH)
        cursor = conn.cursor()

        # Fetch grade boundaries for the specified level
        cursor.execute("SELECT grade, min_marks FROM grade_settings WHERE level = ? ORDER BY min_marks DESC", (level,))
        grade_data = cursor.fetchall()

        # Convert to dictionary {Grade: Min Marks}
        grade_boundaries = {row[0]: int(row[1]) for row in grade_data}

        # Determine the grade based on marks
        marks = float(marks)
        for grade, min_marks in grade_boundaries.items():
            if marks >= min_marks:
                return grade  # Return the first matching grade

        return "F"  # Default to "F" if marks are below all set boundaries
    except sqlite3.Error as e:
        print(f"Database error: {e}")
        return "N/A"  # Return "N/A" if there's an error
    finally:
        if conn:
            conn.close()



# Modified view_student route
@app.route('/personal_page/<id>')
def personal_page(id):
    try:
        conn = sqlite3.connect(DB_PATH)
        cursor = conn.cursor()

        # Get student details
        cursor.execute("SELECT * FROM students WHERE id = ?", (id,))
        student = cursor.fetchone()

        # Get all available subjects
        cursor.execute("SELECT * FROM subjects")
        subjects = cursor.fetchall()

        # Get enrolled subjects and their marks
        cursor.execute('''SELECT s.id, s.subject_name, COALESCE(m.marks, 'N/A') 
                        FROM subjects s
                        LEFT JOIN marks m ON s.id = m.subject_id AND m.student_id = ?
                        WHERE s.id IN (
                            SELECT subject_id FROM enrollments WHERE student_id = ?
                        )''', (id, id))
        enrolled_subjects = cursor.fetchall()

        conn.close()

        if student:
            return render_template("view_student.html", 
                                 student=student, 
                                 subjects=subjects,
                                 enrolled_subjects=enrolled_subjects)
        else:
            return "Student not found", 404
    except sqlite3.Error as e:
        flash(f"Database error: {e}", "error")
        return "An error occurred while fetching student data.", 500

# New routes for student actions
@app.route('/enroll_student_subject/<student_id>', methods=['POST'])
def enroll_student_subject(student_id):
    subject_ids = request.form.getlist('subject_id')  # This ensures multiple subjects are fetched
    try:
        conn = sqlite3.connect(DB_PATH)
        cursor = conn.cursor()

        for subject_id in subject_ids:
            cursor.execute("SELECT id FROM subjects WHERE id = ?", (subject_id,))
            if not cursor.fetchone():
                return jsonify({"success": False, "message": f"Subject ID {subject_id} does not exist"}), 400

            cursor.execute("SELECT id FROM students WHERE id = ?", (student_id,))
            if not cursor.fetchone():
                return jsonify({"success": False, "message": "Student ID does not exist"}), 400

            # Check if the student is already enrolled in the subject
            cursor.execute("SELECT * FROM subject_enrollments WHERE student_id = ? AND subject_id = ?", (student_id, subject_id))
            if cursor.fetchone():
                continue  # Skip already enrolled subjects

            # Enroll the student
            cursor.execute("INSERT INTO subject_enrollments (student_id, subject_id) VALUES (?, ?)", (student_id, subject_id))

        conn.commit()
        return jsonify({"success": True, "message": "Enrollment successful!"})
    except sqlite3.Error as e:
        return jsonify({"success": False, "message": f"Database error: {e}"}), 500
    finally:
        conn.close()


@app.route('/student_details/<id>')
def student_details(id):
    try:
        conn = sqlite3.connect(DB_PATH)
        cursor = conn.cursor()

        # Fetch student details
        cursor.execute("SELECT * FROM students WHERE id = ?", (id,))
        student = cursor.fetchone()

        if not student:
            flash(f"Student ID {id} not found!", "error")
            return "Student not found", 404

        # Fetch enrolled subjects
        cursor.execute('''SELECT subjects.id, subjects.subject_name 
                          FROM subjects
                          INNER JOIN subject_enrollments 
                          ON subjects.id = subject_enrollments.subject_id
                          WHERE subject_enrollments.student_id = ?''', (id,))
        enrolled_subjects = cursor.fetchall()

        # Fetch student marks and calculate grades based on the student's level
        cursor.execute('''SELECT subjects.id, subjects.subject_name, COALESCE(marks.marks, NULL)
                          FROM subjects
                          LEFT JOIN marks ON marks.subject_id = subjects.id AND marks.student_id = ?
                          WHERE subjects.id IN (
                              SELECT subject_id FROM subject_enrollments WHERE student_id = ?
                          )''', (id, id))
        raw_marks = cursor.fetchall()

        # Process marks to include grades
        student_marks = []
        for mark in raw_marks:
            subject_id, subject_name, marks_value = mark
            if marks_value is not None:
                grade = calculate_grade(marks_value, student[11])  # Pass the student's level
            else:
                grade = 'N/A'
            student_marks.append((subject_id, subject_name, marks_value, grade))

        # Fetch financial records
        cursor.execute("SELECT amount_paid, term, year FROM fee_payments WHERE student_id = ?", (id,))
        fee_payments = cursor.fetchall()

        # Fetch fee adjustments
        cursor.execute("SELECT adjustment_type, amount, term, year, reason FROM fee_adjustments WHERE student_id = ?", (id,))
        fee_adjustments = cursor.fetchall()

        # Calculate total adjustments
        total_adjustments = sum(adj[1] for adj in fee_adjustments)

        # Fetch total fees for the student's class
        cursor.execute("SELECT fee_amount FROM fee_structure WHERE class_name = ?", (student[12],))  # Assuming class_name is at index 12
        fee_data = cursor.fetchone()
        total_fee = fee_data[0] if fee_data else 0

        # Calculate total amount paid
        total_paid = sum(payment[0] for payment in fee_payments)

        # Calculate remaining balance
        remaining_balance = total_fee - total_paid + total_adjustments

        # Fetch all available subjects
        cursor.execute("SELECT id, subject_name FROM subjects")
        available_subjects = cursor.fetchall()

        conn.close()

        return render_template("student_details.html", 
                               student=student, 
                               enrolled_subjects=enrolled_subjects,  
                               student_marks=student_marks,
                               fee_payments=fee_payments,
                               remaining_balance=remaining_balance,
                               available_subjects=available_subjects)
    except sqlite3.Error as e:
        flash(f"Database error: {e}", "error")
        return "An error occurred while fetching student data.", 500

# Institution Route
@app.route('/institution', methods=['GET', 'POST'])
def institution():
    conn = sqlite3.connect("database.db")
    cursor = conn.cursor()

    # Create table if it doesn't exist
    cursor.execute('''CREATE TABLE IF NOT EXISTS institution (
                        id INTEGER PRIMARY KEY AUTOINCREMENT,
                        name TEXT NOT NULL,
                        logo TEXT,
                        contact TEXT
                    )''')

    # Fetch existing institution data
    cursor.execute("SELECT name, logo, contact FROM institution LIMIT 1")
    institution = cursor.fetchone()

    if request.method == 'POST':
        school_name = request.form['school_name']
        contact_info = request.form['contact_info']
        logo_file = request.files['logo']

        logo_filename = institution[1] if institution else 'default_logo.png'

        if logo_file and logo_file.filename != '':
            filename = secure_filename(logo_file.filename)
            logo_path = os.path.join(app.config['UPLOAD_FOLDER'], filename)
            logo_file.save(logo_path)
            logo_filename = filename  # Store the new logo file name

        if institution:
            cursor.execute("UPDATE institution SET name = ?, logo = ?, contact = ? WHERE rowid = 1",
                           (school_name, logo_filename, contact_info))
        else:
            cursor.execute("INSERT INTO institution (name, logo, contact) VALUES (?, ?, ?)",
                           (school_name, logo_filename, contact_info))

        conn.commit()
        conn.close()

        return redirect(url_for('institution'))

    conn.close()
    return render_template('institution.html', institution=institution)

@app.route('/enter_marks/<student_id>', methods=['POST'])
def enter_marks(student_id):
    subject_id = request.form['subject_id']
    marks = request.form['marks']
    try:
        conn = sqlite3.connect(DB_PATH)
        cursor = conn.cursor()
        
        # Verify student and subject exist
        cursor.execute("SELECT id FROM students WHERE id = ?", (student_id,))
        if not cursor.fetchone():
            flash("Student not found", "error")
            return redirect(url_for('view_student', id=student_id))

        cursor.execute("SELECT id FROM subjects WHERE id = ?", (subject_id,))
        if not cursor.fetchone():
            flash("Subject not found", "error")
            return redirect(url_for('view_student', id=student_id))

        # Update or insert marks
        cursor.execute('''INSERT OR REPLACE INTO marks 
                        (student_id, subject_id, marks) 
                        VALUES (?, ?, ?)''',
                      (student_id, subject_id, marks))
        
        conn.commit()
        flash("Marks updated successfully!", "success")
    except sqlite3.Error as e:
        flash(f"Database error: {e}", "error")
    finally:
        if conn:
            conn.close()
    return redirect(url_for('view_student', id=student_id))

@app.route('/promote_students', methods=['GET', 'POST'])
def promote_students():
    if request.method == 'GET':
        current_class = request.args.get('class_name')
        if not current_class:
            flash("Class not specified", "error")
            return redirect(url_for('index'))

        try:
            conn = sqlite3.connect(DB_PATH)
            cursor = conn.cursor()

            # Get students in current class
            cursor.execute("SELECT id, first_name, last_name FROM students WHERE student_class = ?", (current_class,))
            students = cursor.fetchall()

            # Get all available classes except current class
            cursor.execute("SELECT class_name FROM classes WHERE class_name != ?", (current_class,))
            available_classes = cursor.fetchall()

            return render_template("promote_students.html", 
                                current_class=current_class,
                                students=students,
                                available_classes=available_classes)

        except sqlite3.Error as e:
            flash(f"Database error: {e}", "error")
            return redirect(url_for('index'))

    elif request.method == 'POST':
        current_class = request.form.get('current_class')
        target_class = request.form.get('target_class')
        student_ids = request.form.getlist('student_ids')

        if not student_ids:
            flash("No students selected", "error")
            return redirect(url_for('class_students', class_name=current_class))

        try:
            conn = sqlite3.connect(DB_PATH)
            cursor = conn.cursor()

            # Update selected students' class
            for student_id in student_ids:
                cursor.execute("UPDATE students SET student_class = ? WHERE id = ?", 
                             (target_class, student_id))
            
            conn.commit()
            flash(f"Successfully promoted {len(student_ids)} student(s) to {target_class}!", "success")

        except sqlite3.Error as e:
            flash(f"Database error: {e}", "error")
        finally:
            if conn:
                conn.close()

        return redirect(url_for('class_students', class_name=current_class))

# ✅ USER MANAGEMENT ROUTE
@app.route('/user', methods=['GET', 'POST'])
def user():
    try:
        conn = sqlite3.connect(DB_PATH)
        cursor = conn.cursor()

        if request.method == 'POST':
            username = request.form['username']
            password = request.form['password']
            role = request.form['role']
            class_id = request.form.get('class') if role == "Class Teacher" else None  # Only store class_id for Class Teachers

            cursor.execute("INSERT INTO users (username, password, role, class_id) VALUES (?, ?, ?, ?)",
                           (username, password, role, class_id))
            conn.commit()
            flash("User created successfully!", "success")
            return redirect(url_for('user'))

        # Fetch all users
        cursor.execute("SELECT * FROM users")
        users = cursor.fetchall()

        # Fetch available classes from the database
        cursor.execute("SELECT id, class_name FROM classes")
        classes = cursor.fetchall()  # List of (id, class_name)

       


        return render_template("user.html", users=users, classes=classes)

    except sqlite3.Error as e:
        flash(f"Database error: {e}", "error")
        return render_template("user.html", users=[], classes=[])
    
    finally:
        if conn:
            conn.close()

if __name__ == "__main__":
    local_ip = get_local_ip()
    zeroconf = advertise_service(local_ip, PORT)
    try:
        logger.info(f"Starting server on http://{local_ip}:{PORT}")
        app.run(host=local_ip, port=PORT, debug=False, use_reloader=False)
    finally:
        if zeroconf is not None:  # Fix applied here
            zeroconf.unregister_all_services()
            zeroconf.close()
            logger.info("Service unregistered and Zeroconf closed.")
        else:
            logger.warning("No Zeroconf service to unregister (advertisement failed).")