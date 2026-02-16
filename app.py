
"""
Title: Health Companion - B.Tech CSE Major Project
Author: Aman Yadav
Email: aman.yadav.ten@gmail.com
Description: A web application for health risk prediction using machine learning.
"""



# =====================================================
# SECTION 1: IMPORT REQUIRED LIBRARIES
# =====================================================

from flask import Flask, render_template, request, redirect, url_for, session, abort, send_file
import sqlite3
import json
import re
import numpy as np
import pandas as pd
import os
import time
import warnings
from io import BytesIO
from functools import wraps
from dotenv import load_dotenv
from health_report_generator import HealthReportGenerator
from werkzeug.security import generate_password_hash, check_password_hash

try:
    from sklearn.exceptions import InconsistentVersionWarning
except Exception:  # pragma: no cover - fallback for older sklearn variants
    InconsistentVersionWarning = Warning

# =====================================================
# SECTION 2: APPLICATION CONFIGURATION & LOGGING
# =====================================================

load_dotenv()

app = Flask(__name__)
_secret_key = os.getenv('SECRET_KEY')
_app_env = (os.getenv('APP_ENV') or os.getenv('FLASK_ENV') or 'development').strip().lower()
if not _secret_key:
    if _app_env in ('production', 'prod'):
        raise RuntimeError('SECRET_KEY must be set in production environment.')
    _secret_key = 'health-companion-dev-secret-change-me'
app.secret_key = _secret_key
app.config.update(
    SESSION_COOKIE_HTTPONLY=True,
    SESSION_COOKIE_SAMESITE='Lax',
    SESSION_COOKIE_SECURE=str(os.getenv('SESSION_COOKIE_SECURE', '0')).lower() in ('1', 'true', 'yes'),
)

import logging

logging.basicConfig(level=logging.INFO)


# =====================================================
# SECTION 3: DATABASE CONNECTION & INITIALIZATION
# =====================================================

def get_db_connection():
    # Timeout + WAL reduce "database is locked" errors under concurrent admin writes.
    conn = sqlite3.connect('health_companion.db', timeout=30.0)
    conn.row_factory = sqlite3.Row
    conn.execute('PRAGMA foreign_keys = ON')
    conn.execute('PRAGMA busy_timeout = 30000')
    conn.execute('PRAGMA journal_mode = WAL')
    conn.execute('PRAGMA synchronous = NORMAL')
    return conn


def init_db():
    conn = get_db_connection()
    cursor = conn.cursor()

    cursor.execute('''
        CREATE TABLE IF NOT EXISTS users (
            id INTEGER PRIMARY KEY AUTOINCREMENT,
            username TEXT NOT NULL UNIQUE,
            email TEXT NOT NULL UNIQUE,
            password_hash TEXT NOT NULL,
            role TEXT NOT NULL DEFAULT 'user',
            is_active INTEGER NOT NULL DEFAULT 1,
            created_at TIMESTAMP DEFAULT CURRENT_TIMESTAMP
        )
    ''')

    cursor.execute('''
        CREATE TABLE IF NOT EXISTS accounts (
            id INTEGER PRIMARY KEY AUTOINCREMENT,
            username TEXT NOT NULL,
            password TEXT NOT NULL,
            email TEXT NOT NULL
        )
    ''')

    cursor.execute('''
        CREATE TABLE IF NOT EXISTS account_stroke (
            id INTEGER PRIMARY KEY AUTOINCREMENT,
            username TEXT,
            gender INTEGER,
            age INTEGER,
            hypertension INTEGER,
            heart_disease INTEGER,
            ever_married INTEGER,
            work_type INTEGER,
            residence_type INTEGER,
            avg_glucose_level REAL,
            bmi REAL,
            smoking_status INTEGER,
            stroke INTEGER
        )
    ''')

    cursor.execute('''
        CREATE TABLE IF NOT EXISTS account_dia (
            id INTEGER PRIMARY KEY AUTOINCREMENT,
            username TEXT,
            pregnancies INTEGER,
            glucose INTEGER,
            bloodpressure INTEGER,
            skinthickness INTEGER,
            insulin INTEGER,
            bmi_dia REAL,
            diabetes_pedigree_fnc REAL,
            age_dia INTEGER,
            outcome INTEGER
        )
    ''')

    cursor.execute('''
        CREATE TABLE IF NOT EXISTS account_cardiovascular (
            id INTEGER PRIMARY KEY AUTOINCREMENT,
            username TEXT,
            age1 INTEGER,
            gender1 INTEGER,
            height REAL,
            weight REAL,
            ap_hi INTEGER,
            ap_lo INTEGER,
            cholesterol INTEGER,
            glu INTEGER,
            smoke INTEGER,
            alco INTEGER,
            active INTEGER,
            cardio_disease INTEGER
        )
    ''')

    cursor.execute('''
        CREATE TABLE IF NOT EXISTS account_bmi (
            id INTEGER PRIMARY KEY AUTOINCREMENT,
            username TEXT,
            weight REAL,
            height REAL,
            bmi REAL
        )
    ''')

    # User profile table keyed by users.id (single source of truth for model input)
    cursor.execute('''
        CREATE TABLE IF NOT EXISTS user_profile (
            id INTEGER PRIMARY KEY AUTOINCREMENT,
            user_id INTEGER NOT NULL UNIQUE,
            age INTEGER,
            gender INTEGER,
            height REAL,
            weight REAL,
            bmi REAL,
            blood_pressure_systolic INTEGER,
            blood_pressure_diastolic INTEGER,
            glucose_level INTEGER,
            cholesterol INTEGER,
            smoking_status INTEGER,
            hypertension INTEGER,
            heart_disease INTEGER,
            ever_married INTEGER,
            work_type INTEGER,
            residence_type INTEGER,
            pregnancies INTEGER,
            insulin INTEGER,
            skin_thickness INTEGER,
            diabetes_pedigree_function REAL,
            alcohol_consumption INTEGER,
            physical_activity INTEGER,
            profile_complete INTEGER DEFAULT 0,
            last_updated TIMESTAMP DEFAULT CURRENT_TIMESTAMP,
            FOREIGN KEY (user_id) REFERENCES users(id) ON DELETE CASCADE
        )
    ''')

    cursor.execute('''
        CREATE TABLE IF NOT EXISTS prediction_results (
            id INTEGER PRIMARY KEY AUTOINCREMENT,
            user_id INTEGER NOT NULL,
            model_type TEXT NOT NULL,
            result INTEGER NOT NULL,
            probability REAL,
            risk_level TEXT,
            created_at TIMESTAMP DEFAULT CURRENT_TIMESTAMP,
            FOREIGN KEY (user_id) REFERENCES users(id) ON DELETE CASCADE
        )
    ''')

    cursor.execute('''
        CREATE TABLE IF NOT EXISTS system_logs (
            id INTEGER PRIMARY KEY AUTOINCREMENT,
            admin_user_id INTEGER NOT NULL,
            target_user_id INTEGER,
            action TEXT NOT NULL,
            details TEXT,
            created_at TIMESTAMP DEFAULT CURRENT_TIMESTAMP,
            FOREIGN KEY (admin_user_id) REFERENCES users(id) ON DELETE CASCADE,
            FOREIGN KEY (target_user_id) REFERENCES users(id) ON DELETE SET NULL
        )
    ''')

    # Assessment History Tables for Reports
    cursor.execute('''
        CREATE TABLE IF NOT EXISTS assessment_cardiovascular (
            id INTEGER PRIMARY KEY AUTOINCREMENT,
            username TEXT NOT NULL,
            assessment_date TIMESTAMP DEFAULT CURRENT_TIMESTAMP,
            patient_data TEXT,
            prediction_result TEXT,
            risk_level TEXT,
            probability REAL,
            report_text TEXT
        )
    ''')

    cursor.execute('''
        CREATE TABLE IF NOT EXISTS assessment_diabetes (
            id INTEGER PRIMARY KEY AUTOINCREMENT,
            username TEXT NOT NULL,
            assessment_date TIMESTAMP DEFAULT CURRENT_TIMESTAMP,
            patient_data TEXT,
            prediction_result TEXT,
            risk_level TEXT,
            probability REAL,
            report_text TEXT
        )
    ''')

    cursor.execute('''
        CREATE TABLE IF NOT EXISTS assessment_stroke (
            id INTEGER PRIMARY KEY AUTOINCREMENT,
            username TEXT NOT NULL,
            assessment_date TIMESTAMP DEFAULT CURRENT_TIMESTAMP,
            patient_data TEXT,
            prediction_result TEXT,
            risk_level TEXT,
            probability REAL,
            report_text TEXT
        )
    ''')

    conn.commit()
    conn.close()


def run_db_migrations():
    """
    Backward-compatible schema/data migration for existing deployments:
    - accounts(username,password,email) -> users(username,email,password_hash)
    - user_profile(username-based) -> user_profile(user_id-based)
    """
    conn = get_db_connection()
    cursor = conn.cursor()

    cursor.execute('''
        CREATE TABLE IF NOT EXISTS users (
            id INTEGER PRIMARY KEY AUTOINCREMENT,
            username TEXT NOT NULL UNIQUE,
            email TEXT NOT NULL UNIQUE,
            password_hash TEXT NOT NULL,
            role TEXT NOT NULL DEFAULT 'user',
            is_active INTEGER NOT NULL DEFAULT 1,
            created_at TIMESTAMP DEFAULT CURRENT_TIMESTAMP
        )
    ''')

    # Add role column for existing deployments where users table already exists.
    cursor.execute('PRAGMA table_info(users)')
    user_cols = [row['name'] for row in cursor.fetchall()]
    if 'role' not in user_cols:
        cursor.execute("ALTER TABLE users ADD COLUMN role TEXT NOT NULL DEFAULT 'user'")
    if 'is_active' not in user_cols:
        cursor.execute("ALTER TABLE users ADD COLUMN is_active INTEGER NOT NULL DEFAULT 1")
    cursor.execute("UPDATE users SET role = 'user' WHERE role IS NULL OR role = ''")
    cursor.execute("UPDATE users SET is_active = 1 WHERE is_active IS NULL")

    cursor.execute('''
        CREATE TABLE IF NOT EXISTS system_logs (
            id INTEGER PRIMARY KEY AUTOINCREMENT,
            admin_user_id INTEGER NOT NULL,
            target_user_id INTEGER,
            action TEXT NOT NULL,
            details TEXT,
            created_at TIMESTAMP DEFAULT CURRENT_TIMESTAMP,
            FOREIGN KEY (admin_user_id) REFERENCES users(id) ON DELETE CASCADE,
            FOREIGN KEY (target_user_id) REFERENCES users(id) ON DELETE SET NULL
        )
    ''')

    cursor.execute('CREATE UNIQUE INDEX IF NOT EXISTS idx_users_username_unique ON users(username)')
    cursor.execute('CREATE UNIQUE INDEX IF NOT EXISTS idx_users_email_unique ON users(email)')

    # Migrate existing plaintext accounts into users with hashed passwords.
    cursor.execute("SELECT name FROM sqlite_master WHERE type='table' AND name='accounts'")
    if cursor.fetchone():
        cursor.execute('SELECT username, email, password FROM accounts')
        for row in cursor.fetchall():
            username = (row['username'] or '').strip()
            email = (row['email'] or '').strip().lower()
            raw_password = row['password'] or ''
            if not username or not email or not raw_password:
                continue

            cursor.execute('SELECT id FROM users WHERE username = ? OR email = ?', (username, email))
            if cursor.fetchone():
                continue

            cursor.execute(
                'INSERT INTO users (username, email, password_hash, role, is_active) VALUES (?, ?, ?, ?, 1)',
                (username, email, generate_password_hash(raw_password, method='pbkdf2:sha256'), 'user')
            )

    # Optional admin bootstrap via environment variables.
    admin_username = (os.getenv('ADMIN_USERNAME') or '').strip()
    admin_email = (os.getenv('ADMIN_EMAIL') or '').strip().lower()
    admin_password = os.getenv('ADMIN_PASSWORD') or ''
    if admin_username and admin_email and admin_password:
        cursor.execute('SELECT id FROM users WHERE username = ? OR email = ?', (admin_username, admin_email))
        admin = cursor.fetchone()
        if admin:
            cursor.execute('UPDATE users SET role = ? WHERE id = ?', ('admin', admin['id']))
        else:
            cursor.execute(
                'INSERT INTO users (username, email, password_hash, role, is_active) VALUES (?, ?, ?, ?, 1)',
                (
                    admin_username,
                    admin_email,
                    generate_password_hash(admin_password, method='pbkdf2:sha256'),
                    'admin'
                )
            )

    # If old profile schema exists (username column), rebuild it to FK user_id schema.
    cursor.execute("SELECT name FROM sqlite_master WHERE type='table' AND name='user_profile'")
    if cursor.fetchone():
        cursor.execute('PRAGMA table_info(user_profile)')
        columns = [row['name'] for row in cursor.fetchall()]

        if 'user_id' not in columns and 'username' in columns:
            cursor.execute('''
                CREATE TABLE IF NOT EXISTS user_profile_new (
                    id INTEGER PRIMARY KEY AUTOINCREMENT,
                    user_id INTEGER NOT NULL UNIQUE,
                    age INTEGER,
                    gender INTEGER,
                    height REAL,
                    weight REAL,
                    bmi REAL,
                    blood_pressure_systolic INTEGER,
                    blood_pressure_diastolic INTEGER,
                    glucose_level INTEGER,
                    cholesterol INTEGER,
                    smoking_status INTEGER,
                    hypertension INTEGER,
                    heart_disease INTEGER,
                    ever_married INTEGER,
                    work_type INTEGER,
                    residence_type INTEGER,
                    pregnancies INTEGER,
                    insulin INTEGER,
                    skin_thickness INTEGER,
                    diabetes_pedigree_function REAL,
                    alcohol_consumption INTEGER,
                    physical_activity INTEGER,
                    profile_complete INTEGER DEFAULT 0,
                    last_updated TIMESTAMP DEFAULT CURRENT_TIMESTAMP,
                    FOREIGN KEY (user_id) REFERENCES users(id) ON DELETE CASCADE
                )
            ''')

            cursor.execute('''
                INSERT OR REPLACE INTO user_profile_new (
                    user_id, age, gender, height, weight, bmi,
                    blood_pressure_systolic, blood_pressure_diastolic,
                    glucose_level, cholesterol, smoking_status, hypertension,
                    heart_disease, ever_married, work_type, residence_type,
                    pregnancies, insulin, skin_thickness, diabetes_pedigree_function,
                    alcohol_consumption, physical_activity, profile_complete, last_updated
                )
                SELECT
                    u.id, p.age, p.gender, p.height, p.weight, p.bmi,
                    p.blood_pressure_systolic, p.blood_pressure_diastolic,
                    p.glucose_level, p.cholesterol, p.smoking_status, p.hypertension,
                    p.heart_disease, p.ever_married, p.work_type, p.residence_type,
                    p.pregnancies, p.insulin, p.skin_thickness, p.diabetes_pedigree_function,
                    p.alcohol_consumption, p.physical_activity, p.profile_complete, p.last_updated
                FROM user_profile p
                JOIN users u ON u.username = p.username
            ''')

            cursor.execute('DROP TABLE user_profile')
            cursor.execute('ALTER TABLE user_profile_new RENAME TO user_profile')

    conn.commit()
    conn.close()


# Initialize database tables
init_db()
run_db_migrations()


# =====================================================
# SECTION 3B: USER PROFILE MANAGEMENT HELPERS
# =====================================================

def get_user_profile(user_id):
    """Retrieve user's health profile from database"""
    conn = get_db_connection()
    cursor = conn.cursor()
    cursor.execute('SELECT * FROM user_profile WHERE user_id = ?', (user_id,))
    profile = cursor.fetchone()
    conn.close()
    return dict(profile) if profile else None


def profile_exists(user_id):
    """Check if user has a completed profile"""
    profile = get_user_profile(user_id)
    return profile is not None and profile.get('profile_complete') == 1


def save_user_profile(user_id, profile_data):
    """Save or update user's health profile"""
    conn = get_db_connection()
    cursor = conn.cursor()
    
    # Check if profile exists
    cursor.execute('SELECT id FROM user_profile WHERE user_id = ?', (user_id,))
    existing = cursor.fetchone()
    
    if existing:
        # Update existing profile
        cursor.execute('''
            UPDATE user_profile 
            SET age=?, gender=?, height=?, weight=?, bmi=?, 
                blood_pressure_systolic=?, blood_pressure_diastolic=?, 
                glucose_level=?, cholesterol=?, smoking_status=?, 
                hypertension=?, heart_disease=?, ever_married=?, 
                work_type=?, residence_type=?, pregnancies=?, 
                insulin=?, skin_thickness=?, diabetes_pedigree_function=?,
                alcohol_consumption=?, physical_activity=?, profile_complete=1,
                last_updated=CURRENT_TIMESTAMP
            WHERE user_id = ?
        ''', (
            profile_data.get('age'),
            profile_data.get('gender'),
            profile_data.get('height'),
            profile_data.get('weight'),
            profile_data.get('bmi'),
            profile_data.get('blood_pressure_systolic'),
            profile_data.get('blood_pressure_diastolic'),
            profile_data.get('glucose_level'),
            profile_data.get('cholesterol'),
            profile_data.get('smoking_status'),
            profile_data.get('hypertension'),
            profile_data.get('heart_disease'),
            profile_data.get('ever_married'),
            profile_data.get('work_type'),
            profile_data.get('residence_type'),
            profile_data.get('pregnancies'),
            profile_data.get('insulin'),
            profile_data.get('skin_thickness'),
            profile_data.get('diabetes_pedigree_function'),
            profile_data.get('alcohol_consumption'),
            profile_data.get('physical_activity'),
            user_id
        ))
    else:
        # Create new profile
        cursor.execute('''
            INSERT INTO user_profile 
            (user_id, age, gender, height, weight, bmi,
             blood_pressure_systolic, blood_pressure_diastolic, 
             glucose_level, cholesterol, smoking_status, 
             hypertension, heart_disease, ever_married, 
             work_type, residence_type, pregnancies, 
             insulin, skin_thickness, diabetes_pedigree_function,
             alcohol_consumption, physical_activity, profile_complete)
            VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, 1)
        ''', (
            user_id,
            profile_data.get('age'),
            profile_data.get('gender'),
            profile_data.get('height'),
            profile_data.get('weight'),
            profile_data.get('bmi'),
            profile_data.get('blood_pressure_systolic'),
            profile_data.get('blood_pressure_diastolic'),
            profile_data.get('glucose_level'),
            profile_data.get('cholesterol'),
            profile_data.get('smoking_status'),
            profile_data.get('hypertension'),
            profile_data.get('heart_disease'),
            profile_data.get('ever_married'),
            profile_data.get('work_type'),
            profile_data.get('residence_type'),
            profile_data.get('pregnancies'),
            profile_data.get('insulin'),
            profile_data.get('skin_thickness'),
            profile_data.get('diabetes_pedigree_function'),
            profile_data.get('alcohol_consumption'),
            profile_data.get('physical_activity')
        ))
    
    conn.commit()
    conn.close()


def get_current_user_id():
    """Return current authenticated user id with backward compatibility for old sessions."""
    user_id = session.get('user_id') or session.get('id')
    if user_id:
        session['user_id'] = user_id
    return user_id


def get_current_user_account():
    """
    Return the current user account row (id, role, is_active), or None if missing.
    Centralizes session-to-database validation for protected routes.
    """
    user_id = get_current_user_id()
    if not user_id:
        return None
    conn = get_db_connection()
    cursor = conn.cursor()
    cursor.execute('SELECT id, role, is_active FROM users WHERE id = ?', (user_id,))
    account = cursor.fetchone()
    conn.close()
    return account


def get_current_user_role():
    """Return current session role and lazy-load from DB if missing."""
    account = get_current_user_account()
    if not account:
        return None
    role = account['role'] if account['role'] else 'user'
    session['role'] = role
    return role


def log_admin_action(action, target_user_id=None, details=None):
    """Persist admin actions for traceability and safety audits."""
    admin_user_id = get_current_user_id()
    if not admin_user_id:
        return
    for _ in range(3):
        conn = None
        try:
            conn = get_db_connection()
            cursor = conn.cursor()
            cursor.execute(
                '''
                INSERT INTO system_logs (admin_user_id, target_user_id, action, details)
                VALUES (?, ?, ?, ?)
                ''',
                (admin_user_id, target_user_id, action, details)
            )
            conn.commit()
            return
        except sqlite3.OperationalError as exc:
            if 'locked' in str(exc).lower():
                time.sleep(0.15)
                continue
            return
        finally:
            if conn:
                conn.close()


def is_admin():
    return get_current_user_role() == 'admin'


def login_required(view_func):
    @wraps(view_func)
    def wrapper(*args, **kwargs):
        if 'loggedin' not in session:
            return redirect(url_for('login'))
        account = get_current_user_account()
        if not account:
            return redirect(url_for('logout'))
        if int(account['is_active']) != 1:
            return redirect(url_for('logout'))
        session['role'] = account['role'] if account['role'] else 'user'
        return view_func(*args, **kwargs)
    return wrapper


def admin_required(view_func):
    @wraps(view_func)
    def wrapper(*args, **kwargs):
        if 'loggedin' not in session:
            return redirect('/admin-login?msg=Please+sign+in+as+admin')
        account = get_current_user_account()
        if not account:
            return redirect(url_for('logout'))
        if int(account['is_active']) != 1:
            return redirect(url_for('logout'))
        role = account['role'] if account['role'] else 'user'
        session['role'] = role
        if role != 'admin':
            return redirect('/admin-login?msg=Admin+authorization+required')
        return view_func(*args, **kwargs)
    return wrapper


def user_required(view_func):
    """
    Restrict route to normal users.
    Admin accounts are redirected to admin dashboard by design.
    """
    @wraps(view_func)
    def wrapper(*args, **kwargs):
        if 'loggedin' not in session:
            return redirect(url_for('login'))
        account = get_current_user_account()
        if not account:
            return redirect(url_for('logout'))
        if int(account['is_active']) != 1:
            return redirect(url_for('logout'))
        role = account['role'] if account['role'] else 'user'
        session['role'] = role
        if role == 'admin':
            return redirect(url_for('admin_dashboard'))
        return view_func(*args, **kwargs)
    return wrapper


@app.errorhandler(403)
def forbidden(_error):
    """Graceful fallback for unauthorized pages."""
    return redirect('/admin-login?msg=Admin+authorization+required')


@app.context_processor
def inject_auth_flags():
    """
    Template-level auth flags resolved from current session/database state.
    Prevents stale UI when role changes after a user already logged in.
    """
    account = get_current_user_account() if 'loggedin' in session else None
    loggedin = bool(account) and int(account['is_active']) == 1
    role = get_current_user_role() if loggedin else None
    return {
        'is_admin_user': role == 'admin',
        'logged_in_user_role': role
    }

# =====================================================
# SECTION 4: LANDING PAGE – PUBLIC DASHBOARD
# =====================================================

@app.route('/')
def landing():
    """
    Public landing page shown as the default app route.
    """
    return render_template('landing.html', msg='')


@app.route('/index')
@login_required
def index():
    """
    Dashboard page - accessible only to logged-in users.
    Displays health overview and prediction shortcuts.
    """
    if is_admin():
        return redirect(url_for('admin_dashboard'))
    user_id = get_current_user_id()
    if not profile_exists(user_id):
        return redirect(url_for('profile', msg='Please complete your health profile before using predictions.'))
    return render_template('index.html', msg='')


@app.route('/admin')
@admin_required
def admin_dashboard():
    """
    Admin-only dashboard with high-level system metrics.
    """
    conn = get_db_connection()
    cursor = conn.cursor()

    cursor.execute("SELECT COUNT(*) AS count FROM users")
    total_users = cursor.fetchone()['count']

    cursor.execute("SELECT COUNT(*) AS count FROM users WHERE role = 'admin'")
    total_admins = cursor.fetchone()['count']

    cursor.execute("SELECT COUNT(*) AS count FROM users WHERE is_active = 1")
    active_users = cursor.fetchone()['count']

    cursor.execute("""
        SELECT COUNT(*) AS count
        FROM user_profile
        WHERE last_updated >= datetime('now', '-30 days')
    """)
    recent_active_users = cursor.fetchone()['count']

    cursor.execute("""
        SELECT
            (SELECT COUNT(*) FROM assessment_stroke) +
            (SELECT COUNT(*) FROM assessment_diabetes) +
            (SELECT COUNT(*) FROM assessment_cardiovascular) AS count
    """)
    total_predictions = cursor.fetchone()['count']

    cursor.execute("SELECT MAX(assessment_date) AS ts FROM assessment_stroke")
    last_stroke = cursor.fetchone()['ts']
    cursor.execute("SELECT MAX(assessment_date) AS ts FROM assessment_diabetes")
    last_diabetes = cursor.fetchone()['ts']
    cursor.execute("SELECT MAX(assessment_date) AS ts FROM assessment_cardiovascular")
    last_cardio = cursor.fetchone()['ts']

    conn.close()

    model_status = [
        {'name': 'Stroke', 'loaded': os.path.exists('health-models/stroke_model.pkl'), 'last_prediction': last_stroke},
        {'name': 'Diabetes', 'loaded': os.path.exists('health-models/diabetes_model.pkl'), 'last_prediction': last_diabetes},
        {'name': 'Cardiovascular', 'loaded': os.path.exists('health-models/cardio_model.pkl'), 'last_prediction': last_cardio},
    ]

    return render_template(
        'admin_dashboard.html',
        username=session.get('username', 'Admin'),
        msg=request.args.get('msg', ''),
        status=request.args.get('status', ''),
        total_users=total_users,
        total_admins=total_admins,
        active_users=active_users,
        recent_active_users=recent_active_users,
        total_predictions=total_predictions,
        model_status=model_status
    )


@app.route('/admin/reset-password', methods=['POST'])
@admin_required
def admin_reset_password():
    """
    Allow admin to reset own password from admin dashboard.
    Requires current password verification.
    """
    current_password = request.form.get('current_password', '')
    new_password = request.form.get('new_password', '')
    confirm_password = request.form.get('confirm_password', '')

    if not current_password or not new_password or not confirm_password:
        return redirect(url_for('admin_dashboard', status='error', msg='Please fill all password fields.'))

    if len(new_password) < 8:
        return redirect(url_for('admin_dashboard', status='error', msg='New password must be at least 8 characters.'))

    if new_password != confirm_password:
        return redirect(url_for('admin_dashboard', status='error', msg='New password and confirm password do not match.'))

    user_id = get_current_user_id()
    conn = get_db_connection()
    cursor = conn.cursor()
    cursor.execute('SELECT password_hash, username FROM users WHERE id = ?', (user_id,))
    user = cursor.fetchone()

    if not user:
        conn.close()
        return redirect(url_for('logout'))

    if not check_password_hash(user['password_hash'], current_password):
        conn.close()
        return redirect(url_for('admin_dashboard', status='error', msg='Current password is incorrect.'))

    cursor.execute(
        'UPDATE users SET password_hash = ? WHERE id = ?',
        (generate_password_hash(new_password, method='pbkdf2:sha256'), user_id)
    )
    conn.commit()
    conn.close()

    log_admin_action('reset_own_admin_password', target_user_id=user_id, details=f"username={user['username']}")
    return redirect(url_for('admin_dashboard', status='success', msg='Admin password updated successfully.'))


@app.route('/admin/users')
@admin_required
def admin_users():
    """Admin user management list."""
    conn = get_db_connection()
    cursor = conn.cursor()
    cursor.execute('''
        SELECT
            u.id, u.username, u.email, u.role, u.is_active, u.created_at,
            up.profile_complete, up.last_updated
        FROM users u
        LEFT JOIN user_profile up ON up.user_id = u.id
        ORDER BY u.created_at DESC
    ''')
    users = cursor.fetchall()
    conn.close()
    return render_template(
        'admin_users.html',
        users=users,
        current_user_id=get_current_user_id(),
        msg=request.args.get('msg', ''),
        status=request.args.get('status', '')
    )


@app.route('/admin/users/<int:target_user_id>')
@admin_required
def admin_user_profile(target_user_id):
    """Read-only detail view of a user and profile."""
    conn = get_db_connection()
    cursor = conn.cursor()
    cursor.execute('SELECT id, username, email, role, is_active, created_at FROM users WHERE id = ?', (target_user_id,))
    user = cursor.fetchone()
    if not user:
        conn.close()
        return abort(404)

    cursor.execute('SELECT * FROM user_profile WHERE user_id = ?', (target_user_id,))
    profile_row = cursor.fetchone()
    profile = dict(profile_row) if profile_row else None

    cursor.execute('SELECT COUNT(*) AS count FROM assessment_stroke WHERE username = ?', (user['username'],))
    stroke_count = cursor.fetchone()['count']
    cursor.execute('SELECT COUNT(*) AS count FROM assessment_diabetes WHERE username = ?', (user['username'],))
    diabetes_count = cursor.fetchone()['count']
    cursor.execute('SELECT COUNT(*) AS count FROM assessment_cardiovascular WHERE username = ?', (user['username'],))
    cardio_count = cursor.fetchone()['count']
    conn.close()

    return render_template(
        'admin_user_profile.html',
        user=user,
        profile=profile,
        stroke_count=stroke_count,
        diabetes_count=diabetes_count,
        cardio_count=cardio_count,
        msg=request.args.get('msg', ''),
        status=request.args.get('status', '')
    )


@app.route('/admin/users/<int:target_user_id>/toggle-active', methods=['POST'])
@admin_required
def admin_toggle_user_active(target_user_id):
    """
    Toggle user active state.
    Requires explicit confirmation to prevent accidental destructive actions.
    """
    if request.form.get('confirm') != 'yes':
        return redirect(url_for('admin_user_profile', target_user_id=target_user_id))

    current_user_id = get_current_user_id()
    if target_user_id == current_user_id:
        return redirect(url_for('admin_user_profile', target_user_id=target_user_id, status='error', msg='You cannot deactivate your own account.'))

    conn = get_db_connection()
    cursor = conn.cursor()
    cursor.execute('SELECT id, username, is_active FROM users WHERE id = ?', (target_user_id,))
    user = cursor.fetchone()
    if not user:
        conn.close()
        return abort(404)

    new_state = 0 if user['is_active'] == 1 else 1
    try:
        cursor.execute('BEGIN IMMEDIATE')
        cursor.execute('UPDATE users SET is_active = ? WHERE id = ?', (new_state, target_user_id))
        conn.commit()
    except sqlite3.OperationalError as exc:
        conn.rollback()
        conn.close()
        return redirect(url_for('admin_user_profile', target_user_id=target_user_id, status='error', msg=f'Action failed: {str(exc)}'))
    conn.close()

    action = 'deactivate_user' if new_state == 0 else 'reactivate_user'
    log_admin_action(action, target_user_id, f"user={user['username']}")
    status_msg = 'User deactivated successfully.' if new_state == 0 else 'User reactivated successfully.'
    return redirect(url_for('admin_user_profile', target_user_id=target_user_id, status='success', msg=status_msg))


@app.route('/admin/users/<int:target_user_id>/delete', methods=['POST'])
@admin_required
def admin_delete_user(target_user_id):
    """
    Permanently delete user account and related data.
    Requires explicit confirmation in POST payload.
    """
    if request.form.get('confirm') != 'yes':
        return redirect(url_for('admin_user_profile', target_user_id=target_user_id))

    current_user_id = get_current_user_id()
    if target_user_id == current_user_id:
        return redirect(url_for('admin_user_profile', target_user_id=target_user_id, status='error', msg='You cannot delete your own account.'))

    last_error = None
    username = None
    for _ in range(5):
        conn = None
        try:
            conn = get_db_connection()
            cursor = conn.cursor()
            cursor.execute('BEGIN IMMEDIATE')
            cursor.execute('SELECT id, username, role FROM users WHERE id = ?', (target_user_id,))
            user = cursor.fetchone()
            if not user:
                conn.rollback()
                conn.close()
                return abort(404)

            if user['role'] == 'admin':
                cursor.execute("SELECT COUNT(*) AS count FROM users WHERE role = 'admin' AND is_active = 1")
                active_admins = cursor.fetchone()['count']
                if active_admins <= 1:
                    conn.rollback()
                    conn.close()
                    return redirect(url_for('admin_user_profile', target_user_id=target_user_id, status='error', msg='At least one active admin account is required.'))

            username = user['username']

            # Delete legacy username-keyed prediction history rows.
            cursor.execute('DELETE FROM assessment_stroke WHERE username = ?', (username,))
            cursor.execute('DELETE FROM assessment_diabetes WHERE username = ?', (username,))
            cursor.execute('DELETE FROM assessment_cardiovascular WHERE username = ?', (username,))
            cursor.execute('DELETE FROM account_stroke WHERE username = ?', (username,))
            cursor.execute('DELETE FROM account_dia WHERE username = ?', (username,))
            cursor.execute('DELETE FROM account_cardiovascular WHERE username = ?', (username,))
            cursor.execute('DELETE FROM account_bmi WHERE username = ?', (username,))

            # Cascades to user_profile/prediction_results/system_logs target reference behavior.
            cursor.execute('DELETE FROM users WHERE id = ?', (target_user_id,))
            conn.commit()
            conn.close()
            log_admin_action('delete_user', None, f"user={username}; deleted_user_id={target_user_id}")
            return redirect(url_for('admin_users', status='success', msg='User deleted successfully.'))
        except sqlite3.OperationalError as exc:
            last_error = str(exc)
            if conn:
                conn.rollback()
                conn.close()
            if 'locked' in last_error.lower():
                time.sleep(0.2)
                continue
            break
        finally:
            if conn:
                try:
                    conn.close()
                except Exception:
                    pass

    return redirect(url_for('admin_user_profile', target_user_id=target_user_id, status='error', msg=f"Delete failed: {last_error or 'database busy'}"))


@app.route('/admin/predictions')
@admin_required
def admin_predictions():
    """Admin view of prediction history across all model types."""
    conn = get_db_connection()
    cursor = conn.cursor()
    cursor.execute('''
        SELECT 'stroke' AS model_type, id, username, assessment_date, risk_level, probability
        FROM assessment_stroke
        UNION ALL
        SELECT 'diabetes' AS model_type, id, username, assessment_date, risk_level, probability
        FROM assessment_diabetes
        UNION ALL
        SELECT 'cardiovascular' AS model_type, id, username, assessment_date, risk_level, probability
        FROM assessment_cardiovascular
        ORDER BY assessment_date DESC
        LIMIT 300
    ''')
    predictions = cursor.fetchall()
    conn.close()
    return render_template(
        'admin_predictions.html',
        predictions=predictions,
        msg=request.args.get('msg', ''),
        status=request.args.get('status', '')
    )


@app.route('/admin/predictions/clear', methods=['POST'])
@admin_required
def admin_clear_predictions():
    """
    Clear prediction history by scope (all/model).
    Requires explicit POST confirmation.
    """
    if request.form.get('confirm') != 'yes':
        return redirect(url_for('admin_predictions', status='error', msg='Confirmation required to clear history.'))

    scope = (request.form.get('scope') or 'all').strip().lower()
    table_map = {
        'stroke': 'assessment_stroke',
        'diabetes': 'assessment_diabetes',
        'cardiovascular': 'assessment_cardiovascular'
    }

    last_error = None
    for _ in range(5):
        conn = None
        try:
            conn = get_db_connection()
            cursor = conn.cursor()
            cursor.execute('BEGIN IMMEDIATE')

            if scope == 'all':
                cursor.execute('DELETE FROM assessment_stroke')
                cursor.execute('DELETE FROM assessment_diabetes')
                cursor.execute('DELETE FROM assessment_cardiovascular')
                cursor.execute('DELETE FROM prediction_results')
            elif scope in table_map:
                cursor.execute(f'DELETE FROM {table_map[scope]}')
                cursor.execute('DELETE FROM prediction_results WHERE model_type = ?', (scope,))
            else:
                conn.rollback()
                conn.close()
                return redirect(url_for('admin_predictions', status='error', msg='Invalid clear scope selected.'))

            conn.commit()
            conn.close()
            log_admin_action('clear_predictions', details=f"scope={scope}")
            return redirect(url_for('admin_predictions', status='success', msg=f'Prediction history cleared for: {scope}.'))
        except sqlite3.OperationalError as exc:
            last_error = str(exc)
            if conn:
                conn.rollback()
                conn.close()
            if 'locked' in last_error.lower():
                time.sleep(0.2)
                continue
            break
        finally:
            if conn:
                try:
                    conn.close()
                except Exception:
                    pass
    return redirect(url_for('admin_predictions', status='error', msg=f"Clear failed: {last_error or 'database busy'}"))


@app.route('/admin/logs')
@admin_required
def admin_logs():
    """Admin action audit trail."""
    conn = get_db_connection()
    cursor = conn.cursor()
    cursor.execute('''
        SELECT
            l.id, l.action, l.details, l.created_at,
            a.username AS admin_username,
            t.username AS target_username
        FROM system_logs l
        LEFT JOIN users a ON a.id = l.admin_user_id
        LEFT JOIN users t ON t.id = l.target_user_id
        ORDER BY l.created_at DESC
        LIMIT 300
    ''')
    logs = cursor.fetchall()
    conn.close()
    return render_template('admin_logs.html', logs=logs)


# =====================================================
# SECTION 5: USER AUTHENTICATION – LOGIN
# =====================================================

@app.route('/login', methods=['GET', 'POST'], endpoint='login')
@app.route('/admin-login', methods=['GET', 'POST'], endpoint='admin_login')
def login():
    """
    Handle user login.
    GET: Render login form.
    POST: Authenticate user and start session.
    If user logs in for the first time, redirect to profile completion.
    """
    admin_mode = request.path == '/admin-login'
    msg = request.args.get('msg', '').strip()
    if 'loggedin' in session:
        return redirect(url_for('admin_dashboard' if is_admin() else 'profile'))
    if request.method == 'POST' and 'username' in request.form and 'password' in request.form:
        username = request.form['username'].strip()
        password = request.form['password']
        connection = get_db_connection()
        cursor = connection.cursor()
        cursor.execute('SELECT * FROM users WHERE username = ? OR email = ?', (username, username.lower()))
        account = cursor.fetchone()
        cursor.close()
        connection.close()
        if account and check_password_hash(account['password_hash'], password):
            if int(account['is_active']) != 1:
                msg = 'Account is deactivated. Contact application owner.'
                return render_template('login.html', msg=msg, admin_mode=admin_mode)
            if admin_mode and (account['role'] or 'user') != 'admin':
                msg = 'This account is not an admin account.'
                return render_template('login.html', msg=msg, admin_mode=admin_mode)
            session['loggedin'] = True
            session['user_id'] = account['id']
            session['id'] = account['id']
            session['username'] = account['username']
            session['role'] = account['role'] if account['role'] else 'user'
            session.permanent = True

            # Role-aware redirect after login.
            if session['role'] == 'admin':
                return redirect(url_for('admin_dashboard'))
            return redirect(url_for('profile', first_time=1))
        else:
            msg = 'Invalid username/email or password.'
    return render_template('login.html', msg=msg, admin_mode=admin_mode)


# =====================================================
# SECTION 5B: USER HEALTH PROFILE MANAGEMENT
# =====================================================

@app.route('/profile', methods=['GET', 'POST'])
@user_required
def profile():
    """
    User health profile management page.
    GET: Display user's current profile or profile form if incomplete
    POST: Save/update user's health profile
    """
    # Authentication check
    if 'loggedin' not in session:
        return redirect(url_for('landing'))
    user_id = get_current_user_id()
    if not user_id:
        return redirect(url_for('logout'))

    msg = request.args.get('msg', '')
    first_time = str(request.args.get('first_time', '0')).lower() in ('1', 'true', 'yes')
    
    if request.method == 'POST':
        # Collect profile data from form
        try:
            required_fields = [
                'age', 'gender', 'height', 'weight', 'blood_pressure_systolic',
                'blood_pressure_diastolic', 'glucose_level', 'cholesterol',
                'smoking_status', 'hypertension', 'heart_disease', 'ever_married',
                'work_type', 'residence_type', 'alcohol_consumption', 'physical_activity'
            ]
            missing_fields = [field for field in required_fields if request.form.get(field) in (None, '')]
            if missing_fields:
                msg = 'Please complete all required profile fields.'
                existing_profile = get_user_profile(user_id)
                return render_template('profile.html', msg=msg, profile=existing_profile, first_time=first_time)

            height = float(request.form.get('height', 0))
            weight = float(request.form.get('weight', 0))
            bmi = weight / ((height / 100) ** 2) if height > 0 else 0
            
            profile_data = {
                'age': int(request.form.get('age', 0)),
                'gender': int(request.form.get('gender', 0)),
                'height': height,
                'weight': weight,
                'bmi': round(bmi, 2),
                'blood_pressure_systolic': int(request.form.get('blood_pressure_systolic', 0)),
                'blood_pressure_diastolic': int(request.form.get('blood_pressure_diastolic', 0)),
                'glucose_level': int(request.form.get('glucose_level', 0)),
                'cholesterol': int(request.form.get('cholesterol', 0)),
                'smoking_status': int(request.form.get('smoking_status', 0)),
                'hypertension': int(request.form.get('hypertension', 0)),
                'heart_disease': int(request.form.get('heart_disease', 0)),
                'ever_married': int(request.form.get('ever_married', 0)),
                'work_type': int(request.form.get('work_type', 0)),
                'residence_type': int(request.form.get('residence_type', 0)),
                'pregnancies': int(request.form.get('pregnancies', 0)) if request.form.get('pregnancies') else 0,
                'insulin': int(request.form.get('insulin', 0)) if request.form.get('insulin') else 0,
                'skin_thickness': int(request.form.get('skin_thickness', 0)) if request.form.get('skin_thickness') else 0,
                'diabetes_pedigree_function': float(request.form.get('diabetes_pedigree_function', 0)) if request.form.get('diabetes_pedigree_function') else 0.0,
                'alcohol_consumption': int(request.form.get('alcohol_consumption', 0)),
                'physical_activity': int(request.form.get('physical_activity', 0)),
            }

            if profile_data['height'] <= 0 or profile_data['weight'] <= 0:
                msg = 'Height and weight must be greater than zero.'
                existing_profile = get_user_profile(user_id)
                return render_template('profile.html', msg=msg, profile=existing_profile, first_time=first_time)

            # Save profile and continue to dashboard.
            save_user_profile(user_id, profile_data)
            return redirect(url_for('index'))
        
        except ValueError as e:
            msg = 'Invalid input: Please check your entries'
    
    # GET request - Load existing profile
    existing_profile = get_user_profile(user_id)
    
    bmr_value = None
    if existing_profile and all(existing_profile.get(k) not in (None, '') for k in ['age', 'gender', 'height', 'weight']):
        bmr_value = calculate_bmr('male' if int(existing_profile['gender']) == 1 else 'female',
                                  float(existing_profile['weight']),
                                  float(existing_profile['height']),
                                  int(existing_profile['age']))

    return render_template('profile.html', msg=msg, profile=existing_profile, first_time=first_time, bmr_value=bmr_value)

@app.route('/output')
@user_required
def output():
    """
    Output page - show results (protected).
    """
    if 'loggedin' not in session:
        return redirect(url_for('landing'))
    msg=' '
    return render_template('output.html', msg=msg)


# =====================================================
# SECTION 6: STROKE PREDICTION – ROUTE HANDLING
# =====================================================

@app.route('/stroke', methods =['GET', 'POST'])
@user_required
def stroke():
    # Authentication check - protect this route
    if 'loggedin' not in session:
        return redirect(url_for('landing'))
    user_id = get_current_user_id()
    if not user_id:
        return redirect(url_for('logout'))
    
    # Check if user has completed profile
    if not profile_exists(user_id):
        return redirect(url_for('profile'))
    
    msg = ' '
    if request.method == 'POST':
        try:
            # Fetch user's profile data automatically
            profile = get_user_profile(user_id)
            
            if not profile:
                msg = 'Please complete your health profile first'
                return render_template('stroke.html', msg=msg, auto_fetch=True)
            
            # Extract stroke-related data from profile
            gender = profile['gender']
            age = profile['age']
            hypertension = profile['hypertension']
            heart_disease = profile['heart_disease']
            ever_married = profile['ever_married']
            work_type = profile['work_type']
            residence_type = profile['residence_type']
            avg_glucose_level = profile['glucose_level']
            bmi = profile['bmi']
            smoking_status = profile['smoking_status']
            
            # Validate profile fields without rejecting valid categorical zero values.
            required_profile_values = {
                'gender': gender,
                'age': age,
                'hypertension': hypertension,
                'heart_disease': heart_disease,
                'ever_married': ever_married,
                'work_type': work_type,
                'residence_type': residence_type,
                'avg_glucose_level': avg_glucose_level,
                'bmi': bmi,
                'smoking_status': smoking_status
            }
            if any(value is None or value == '' for value in required_profile_values.values()):
                msg = 'Your profile is incomplete. Please update it.'
                return render_template('stroke.html', msg=msg, auto_fetch=True)
            
            # Store in assessment history
            connection = get_db_connection()
            cursor = connection.cursor()
            cursor.execute('INSERT INTO account_stroke VALUES (NULL, ?,?,?,?,?,?,?,?,?,?,?,NULL)', 
                          (session['username'],gender,age,hypertension,heart_disease,
                           ever_married,work_type,residence_type,avg_glucose_level,bmi,smoking_status))
            connection.commit()
            cursor.close()
            connection.close()
            
            # Get ML prediction
            prediction_result = strokeml(gender,age,hypertension,heart_disease,ever_married,
                                        work_type,residence_type,avg_glucose_level,bmi,smoking_status)
            
            if 'error' in prediction_result:
                msg = prediction_result['error']
                return render_template('output.html', msg=msg)
            
            # Prepare patient data for report
            patient_data = {
                'name': session.get('username', 'Patient'),
                'age': int(age),
                'gender': 'Male' if int(gender) == 1 else 'Female',
                'height': profile.get('height', 'N/A'),
                'weight': profile.get('weight', 'N/A'),
                'bmi': float(bmi),
                'bmi_category': 'Normal' if 18.5 <= float(bmi) < 25 else ('Overweight' if float(bmi) < 30 else 'Obese'),
                'hypertension': int(hypertension),
                'heart_disease': int(heart_disease),
                'avg_glucose': float(avg_glucose_level),
                'smoking_status': int(smoking_status),
                'ever_married': int(ever_married),
                'work_type': work_type,
                'residence_type': int(residence_type)
            }
            
            risk_prediction = {
                'risk_level': prediction_result['risk_level'],
                'probability': prediction_result['probability'],
                'recommendation': 'Consult with a healthcare provider'
            }
            
            # Generate professional report
            generator = HealthReportGenerator()
            msg = generator.generate_stroke_report(patient_data, risk_prediction)
            
            # Store assessment in database for history
            import json
            conn = get_db_connection()
            cursor = conn.cursor()
            cursor.execute('''
                INSERT INTO assessment_stroke 
                (username, patient_data, prediction_result, risk_level, probability, report_text)
                VALUES (?, ?, ?, ?, ?, ?)
            ''', (
                session['username'],
                json.dumps(patient_data),
                json.dumps(prediction_result),
                risk_prediction['risk_level'],
                risk_prediction['probability'],
                msg
            ))
            conn.commit()
            conn.close()
            
            return render_template('output.html', msg=msg)
        except Exception as e:
            msg = f'Error processing prediction: {str(e)}'
            return render_template('stroke.html', msg=msg, auto_fetch=True)
    elif request.method == 'POST':
        msg = 'Error processing request'
    return render_template('stroke.html', msg=msg, auto_fetch=True)


# =====================================================
# SECTION 7: STROKE PREDICTION – MACHINE LEARNING LOGIC
# =====================================================

def strokeml(gender, age, hypertension, heart_disease, ever_married, work_type, residence_type, avg_glucose_level, bmi, smoking_status):
    import joblib
    import pandas as pd
    try:
        with warnings.catch_warnings():
            warnings.simplefilter("ignore", InconsistentVersionWarning)
            model = joblib.load("health-models/stroke_model.pkl")
            scaler = joblib.load("health-models/stroke_scaler.pkl")
        
        # Create a DataFrame with proper column order to match training data
        input_df = pd.DataFrame({
            'gender': [int(gender)],
            'age': [float(age)],
            'hypertension': [int(hypertension)],
            'heart_disease': [int(heart_disease)],
            'ever_married': [int(ever_married)],
            'work_type': [int(work_type)],
            'Residence_type': [int(residence_type)],
            'avg_glucose_level': [float(avg_glucose_level)],
            'bmi': [float(bmi)],
            'smoking_status': [int(smoking_status)]
        })
        
        # Scale the input data using the same scaler from training
        input_scaled = scaler.transform(input_df)
        input_scaled_df = pd.DataFrame(input_scaled, columns=input_df.columns)
        model_input = input_scaled_df if hasattr(model, 'feature_names_in_') else input_scaled
        
        prediction = model.predict(model_input)[0]
        probability = model.predict_proba(model_input)[0][1] if hasattr(model, 'predict_proba') else (1.0 if prediction == 1 else 0.0)
        
        # Convert numpy types to native Python types for JSON serialization
        prediction = int(prediction)
        probability = float(probability)
        
        if prediction == 0:
            risk_level = "Low Risk"
        elif probability > 0.7:
            risk_level = "High Risk"
        else:
            risk_level = "Moderate Risk"
        
        return {
            'prediction': prediction,
            'probability': probability,
            'risk_level': risk_level
        }
    except Exception as e:
        return {'error': str(e)}


@app.route('/diabetes', methods =['GET', 'POST'])
@user_required
def diabetes():
    # Authentication check - protect this route
    if 'loggedin' not in session:
        return redirect(url_for('landing'))
    user_id = get_current_user_id()
    if not user_id:
        return redirect(url_for('logout'))
    
    # Check if user has completed profile
    if not profile_exists(user_id):
        return redirect(url_for('profile'))
    
    msg = ''
    if request.method == 'POST':
        try:
            # Fetch user's profile data automatically
            profile = get_user_profile(user_id)
            
            if not profile:
                msg = 'Please complete your health profile first'
                return render_template('diabetes.html', msg=msg, auto_fetch=True)
            
            # Extract diabetes-related data from profile
            pregnancies = profile['pregnancies'] or 0
            glucose = profile['glucose_level']
            bloodpressure = profile['blood_pressure_diastolic']  # Using diastolic BP
            skinthickness = profile['skin_thickness'] or 0
            insulin = profile['insulin'] or 0
            bmi_dia = profile['bmi']
            diabetes_pedigree_fnc = profile['diabetes_pedigree_function'] or 0.0
            age_dia = profile['age']
            
            # Validate critical data
            if not all([glucose, bloodpressure, bmi_dia, age_dia]):
                msg = 'Your profile is incomplete. Please update it.'
                return render_template('diabetes.html', msg=msg, auto_fetch=True)
            
            # Store in assessment history
            connection = get_db_connection()
            cursor = connection.cursor()
            cursor.execute('INSERT INTO account_dia VALUES (NULL, ?, ?, ?, ?,?,?,?,?,?,NULL)', 
                          (session['username'],pregnancies,glucose,bloodpressure,skinthickness,
                           insulin,bmi_dia,diabetes_pedigree_fnc,age_dia))
            connection.commit()
            cursor.close()
            connection.close()
            
            # Get ML prediction
            prediction_result = diaml(pregnancies,glucose,bloodpressure,skinthickness,insulin,
                                     bmi_dia,diabetes_pedigree_fnc,age_dia)
            
            if 'error' in prediction_result:
                msg = prediction_result['error']
                return render_template('output.html', msg=msg)
            
            # Prepare patient data for report
            patient_data = {
                'name': session.get('username', 'Patient'),
                'age': int(age_dia),
                'gender': 'Female',
                'pregnancies': int(pregnancies),
                'weight': profile.get('weight', 'N/A'),
                'height': profile.get('height', 'N/A'),
                'bmi': float(bmi_dia),
                'bmi_category': 'Normal' if 18.5 <= float(bmi_dia) < 25 else ('Overweight' if float(bmi_dia) < 30 else 'Obese'),
                'glucose': float(glucose),
                'blood_pressure': float(bloodpressure),
                'insulin': float(insulin),
                'skin_thickness': float(skinthickness),
                'diabetes_pedigree_function': float(diabetes_pedigree_fnc)
            }
            
            risk_prediction = {
                'risk_level': prediction_result['risk_level'],
                'probability': prediction_result['probability'],
                'recommendation': 'Consult with an endocrinologist'
            }
            
            # Generate professional report
            generator = HealthReportGenerator()
            msg = generator.generate_diabetes_report(patient_data, risk_prediction)
            
            # Store assessment in database for history
            import json
            conn = get_db_connection()
            cursor = conn.cursor()
            cursor.execute('''
                INSERT INTO assessment_diabetes 
                (username, patient_data, prediction_result, risk_level, probability, report_text)
                VALUES (?, ?, ?, ?, ?, ?)
            ''', (
                session['username'],
                json.dumps(patient_data),
                json.dumps(prediction_result),
                risk_prediction['risk_level'],
                risk_prediction['probability'],
                msg
            ))
            conn.commit()
            conn.close()
            
            return render_template('output.html', msg=msg)
        except Exception as e:
            msg = f'Error processing prediction: {str(e)}'
            return render_template('diabetes.html', msg=msg, auto_fetch=True)
    elif request.method == 'POST':
        msg = 'Error processing request'
    return render_template('diabetes.html', msg=msg, auto_fetch=True)



# =====================================================
# SECTION 9: DIABETES PREDICTION – MACHINE LEARNING LOGIC
# =====================================================

def diaml(pregnancies,glucose,bloodpressure,skinthickness,insulin,bmi_dia,diabetes_pedigree_fnc,age_dia):
    import joblib
    import pandas as pd
    try:
        with warnings.catch_warnings():
            warnings.simplefilter("ignore", InconsistentVersionWarning)
            model = joblib.load("health-models/diabetes_model.pkl")
            scaler = joblib.load("health-models/diabetes_scaler.pkl")
        
        # Compatibility fix for pickled LogisticRegression objects across sklearn versions.
        if hasattr(model, '__dict__') and not hasattr(model, 'multi_class'):
            model.multi_class = 'auto'
        
        # Create a DataFrame with column names matching the training data (capitalized)
        input_df = pd.DataFrame({
            'Pregnancies': [int(pregnancies)],
            'Glucose': [float(glucose)],
            'BloodPressure': [float(bloodpressure)],
            'SkinThickness': [float(skinthickness)],
            'Insulin': [float(insulin)],
            'BMI': [float(bmi_dia)],
            'DiabetesPedigreeFunction': [float(diabetes_pedigree_fnc)],
            'Age': [int(age_dia)]
        })
        
        # Scale the input data using the same scaler from training
        input_scaled = scaler.transform(input_df)
        input_scaled_df = pd.DataFrame(input_scaled, columns=input_df.columns)
        model_input = input_scaled_df if hasattr(model, 'feature_names_in_') else input_scaled
        
        prediction = model.predict(model_input)[0]
        probability = model.predict_proba(model_input)[0][1] if hasattr(model, 'predict_proba') else (1.0 if prediction == 1 else 0.0)
        
        # Convert numpy types to native Python types for JSON serialization
        prediction = int(prediction)
        probability = float(probability)
        
        if prediction == 0:
            risk_level = "Low Risk"
        elif probability > 0.7:
            risk_level = "High Risk"
        else:
            risk_level = "Moderate Risk"
        
        return {
            'prediction': prediction,
            'probability': probability,
            'risk_level': risk_level
        }
    except Exception as e:
        return {'error': str(e)}


@app.route('/cardiovascular', methods =['GET', 'POST'])
@user_required
def cardiovascular():
    # Authentication check - protect this route
    if 'loggedin' not in session:
        return redirect(url_for('landing'))
    user_id = get_current_user_id()
    if not user_id:
        return redirect(url_for('logout'))
    
    # Check if user has completed profile
    if not profile_exists(user_id):
        return redirect(url_for('profile'))
    
    msg = ''
    if request.method == 'POST':
        try:
            # Fetch user's profile data automatically
            profile = get_user_profile(user_id)
            
            if not profile:
                msg = 'Please complete your health profile first'
                return render_template('cardiovascular.html', msg=msg, auto_fetch=True)
            
            # Extract cardiovascular-related data from profile
            age1 = profile['age']
            gender1 = profile['gender']
            height = profile['height']
            weight = profile['weight']
            ap_hi = profile['blood_pressure_systolic']
            ap_lo = profile['blood_pressure_diastolic']
            cholesterol = profile['cholesterol']
            glu = profile['glucose_level']
            smoke = profile['smoking_status']
            alco = profile['alcohol_consumption']
            active = profile['physical_activity']
            
            # Validate profile fields without rejecting valid categorical zero values.
            required_profile_values = {
                'age1': age1,
                'gender1': gender1,
                'height': height,
                'weight': weight,
                'ap_hi': ap_hi,
                'ap_lo': ap_lo,
                'cholesterol': cholesterol,
                'glu': glu,
                'smoke': smoke,
                'alco': alco,
                'active': active,
            }
            if any(value is None or value == '' for value in required_profile_values.values()):
                msg = 'Your profile is incomplete. Please update it.'
                return render_template('cardiovascular.html', msg=msg, auto_fetch=True)
            
            # Store in assessment history
            connection = get_db_connection()
            cursor = connection.cursor()
            cursor.execute('INSERT INTO account_cardiovascular VALUES (NULL, ?, ?, ?, ?,?,?,?,?,?,?,?,?,NULL)', 
                          (session['username'],age1,gender1,height,weight,ap_hi,ap_lo,cholesterol,glu,smoke,alco,active))
            connection.commit()
            cursor.close()
            connection.close()
            
            # Get ML prediction
            prediction_result = cardiovascularml(age1,gender1,height,weight,ap_hi,ap_lo,cholesterol,glu,smoke,alco,active)
            
            if 'error' in prediction_result:
                msg = prediction_result['error']
                return render_template('output.html', msg=msg)
            
            # Prepare patient data for report
            bmi = float(weight) / ((float(height) / 100) ** 2)
            patient_data = {
                'name': session.get('username', 'Patient'),
                'age': int(age1),
                'gender': 'Male' if int(gender1) == 1 else 'Female',
                'height': float(height),
                'weight': float(weight),
                'bmi': bmi,
                'bmi_category': 'Underweight' if bmi < 18.5 else ('Normal' if bmi < 25 else ('Overweight' if bmi < 30 else 'Obese')),
                'systolic_bp': int(ap_hi),
                'diastolic_bp': int(ap_lo),
                'bp_category': 'Normal' if int(ap_hi) < 120 and int(ap_lo) < 80 else ('Elevated' if int(ap_hi) < 130 else ('Stage 1 Hypertension' if int(ap_hi) < 140 else 'Stage 2 Hypertension')),
                'cholesterol': int(cholesterol),
                'glucose': int(glu),
                'smoking': int(smoke),
                'alcohol': int(alco),
                'physical_activity': int(active)
            }
            
            risk_prediction = {
                'risk_level': prediction_result['risk_level'],
                'probability': prediction_result['probability'],
                'recommendation': 'Consult with a cardiologist'
            }
            
            # Generate professional report
            generator = HealthReportGenerator()
            msg = generator.generate_cardiovascular_report(patient_data, risk_prediction)
            
            # Store assessment in database for history
            import json
            conn = get_db_connection()
            cursor = conn.cursor()
            cursor.execute('''
                INSERT INTO assessment_cardiovascular 
                (username, patient_data, prediction_result, risk_level, probability, report_text)
                VALUES (?, ?, ?, ?, ?, ?)
            ''', (
                session['username'],
                json.dumps(patient_data),
                json.dumps(prediction_result),
                risk_prediction['risk_level'],
                risk_prediction['probability'],
                msg
            ))
            conn.commit()
            conn.close()
            
            return render_template('output.html', msg=msg)
        except Exception as e:
            msg = f'Error processing prediction: {str(e)}'
            return render_template('cardiovascular.html', msg=msg, auto_fetch=True)
    elif request.method == 'POST':
        msg = 'Error processing request'
    return render_template('cardiovascular.html', msg=msg, auto_fetch=True)



# =====================================================
# SECTION 11: CARDIOVASCULAR PREDICTION – MACHINE LEARNING LOGIC
# =====================================================

def cardiovascularml(age1,gender1,height,weight,ap_hi,ap_lo,cholesterol,glu,smoke,alco,active):
    import joblib
    import pandas as pd
    try:
        with warnings.catch_warnings():
            warnings.simplefilter("ignore", InconsistentVersionWarning)
            model = joblib.load("health-models/cardio_model.pkl")
            scaler = joblib.load("health-models/cardio_scaler.pkl")
        
        # Create a DataFrame with column names matching the training data (uppercase)
        input_df = pd.DataFrame({
            'AGE': [int(age1)],
            'GENDER': [int(gender1)],
            'HEIGHT': [float(height)],
            'WEIGHT': [float(weight)],
            'AP_HIGH': [int(ap_hi)],
            'AP_LOW': [int(ap_lo)],
            'CHOLESTEROL': [int(cholesterol)],
            'GLUCOSE': [int(glu)],
            'SMOKE': [int(smoke)],
            'ALCOHOL': [int(alco)],
            'PHYSICAL_ACTIVITY': [int(active)]
        })
        
        # Scale the input data using the same scaler from training
        input_scaled = scaler.transform(input_df)
        input_scaled_df = pd.DataFrame(input_scaled, columns=input_df.columns)
        model_input = input_scaled_df if hasattr(model, 'feature_names_in_') else input_scaled
        
        prediction = model.predict(model_input)[0]
        probability = model.predict_proba(model_input)[0][1] if hasattr(model, 'predict_proba') else (1.0 if prediction == 1 else 0.0)
        
        # Convert numpy types to native Python types for JSON serialization
        prediction = int(prediction)
        probability = float(probability)
        
        if prediction == 0:
            risk_level = "Low Risk"
        elif probability > 0.7:
            risk_level = "High Risk"
        else:
            risk_level = "Moderate Risk"
        
        return {
            'prediction': prediction,
            'probability': probability,
            'risk_level': risk_level
        }
    except Exception as e:
        return {'error': str(e)}


@app.route('/calculate_bmi', methods=['GET', 'POST'])
@user_required
def calculate_bmi():
    # Authentication check - protect this route
    if 'loggedin' not in session:
        return redirect(url_for('landing'))
    
    msg = 'BMI CALCULATOR'
    if request.method == 'POST' and 'weight' in request.form and 'height' in request.form:
        weight = request.form['weight']
        height = request.form['height']

        if not weight or not height:
            msg = 'Please fill out the form!'
        else:
            try:
                weight = float(weight)
                height = float(height)
                if weight <= 0 or height <= 0:
                    msg = 'Weight and height must be greater than zero.'
                    return render_template('calculate_bmi.html', msg=msg)

                bmi = calculate_bmi_value(weight, height)
                msg = f'Your BMI is: {bmi}'

                connection = get_db_connection()
                cursor = connection.cursor()
                cursor.execute('INSERT INTO account_bmi VALUES (NULL, ?, ?,?,?)' ,(session['username'],weight,height, bmi,))
                connection.commit()
                cursor.close()
                connection.close()
                return render_template('output.html', msg = msg)
            except ValueError:
                msg = 'Invalid input. Please enter numeric values.'
    return render_template('calculate_bmi.html', msg=msg)


def calculate_bmi_value(weight, height):
    if height <= 0:
        raise ValueError('Height must be greater than zero.')
    height_in_meters = height / 100  
    bmi = weight / (height_in_meters ** 2)
    return round(bmi, 2)       




# =====================================================
# SECTION 13: CALORIE CALCULATOR – ROUTE & LOGIC
# =====================================================

@app.route('/calculate_calories', methods=['GET', 'POST'])
@user_required
def calculate_calories():
    # Authentication check - protect this route
    if 'loggedin' not in session:
        return redirect(url_for('landing'))
    
    msg = 'CALORIE CALCULATOR'
    if request.method == 'POST' and 'gender' in request.form and 'weight' in request.form and 'height' in request.form and 'age' in request.form and 'activity_level' in request.form:
        gender = request.form['gender']
        weight = request.form['weight']
        height = request.form['height']
        age = request.form['age']
        activity_level = request.form['activity_level']

        if not gender or not weight or not height or not age or not activity_level:
            msg = 'Please fill out the form!'
        else:
            weight = float(weight)
            height = float(height)
            age = int(age)
            bmr = calculate_bmr(gender, weight, height, age)
            calorie_msg = calculate_calories_based_on_activity(bmr, activity_level)
            msg = f'Your BMR is: {bmr} calories. {calorie_msg}'
            return render_template('output.html', msg = msg)
    return render_template('calculate_calories.html', msg=msg)


def calculate_bmr(gender, weight, height, age):
    if gender.lower() == 'female':
        bmr = (weight * 10) + (height * 6.25) - (age * 5) - 161
    else:
        bmr = (weight * 10) + (height * 6.25) - (age * 5) + 5
    return int(bmr)


def calculate_calories_based_on_activity(bmr, activity_level):
    activity_levels = {
        'sedentary': 1.2,
        'exercise_1_3': 1.375,
        'exercise_4_5': 1.55,
        'daily_exercise': 1.725,
        'intense_exercise': 1.9,
        'very_intense_exercise': 2.095,
    }
    calorie_multiplier = activity_levels.get(activity_level, 1.2)
    calories = int(bmr * calorie_multiplier)
    return f'Based on your activity level, you need approximately {calories} calories per day.'




# =====================================================
# SECTION 14: USER SESSION, INFO PAGES & REPORTS
# =====================================================

@app.route('/logout')
def logout():
    session.pop('loggedin', None)
    session.pop('id', None)
    session.pop('user_id', None)
    session.pop('username', None)
    session.pop('role', None)
    return redirect(url_for('login'))


@app.route('/details')
@user_required
def details():
    # Authentication check - protect this route
    if 'loggedin' not in session:
        return redirect(url_for('landing'))
    return render_template('details.html')


@app.route('/stroke_info')
@user_required
def stroke_info():
    # Authentication check - protect this route
    if 'loggedin' not in session:
        return redirect(url_for('landing'))
    return render_template('stroke_info.html')


@app.route('/diabetes_info')
@user_required
def diabetes_info():
    # Authentication check - protect this route
    if 'loggedin' not in session:
        return redirect(url_for('landing'))
    return render_template('diabetes_info.html')


@app.route('/cardiovascular_info')
@user_required
def cardiovascular_info():
    # Authentication check - protect this route
    if 'loggedin' not in session:
        return redirect(url_for('landing'))
    return render_template('cardiovascular_info.html')


@app.route('/reports')
@user_required
def reports():
    """
    Display user health reports and analytics.
    """
    if 'loggedin' not in session:
        return redirect(url_for('landing'))
    
    # Fetch all assessments for this user
    conn = get_db_connection()
    cursor = conn.cursor()
    
    # Fetch all cardiovascular assessments
    cursor.execute('''
        SELECT id, assessment_date, risk_level, probability, patient_data, report_text 
        FROM assessment_cardiovascular 
        WHERE username = ?
        ORDER BY assessment_date DESC
    ''', (session['username'],))
    cardio_assessments = cursor.fetchall()
    
    # Fetch all diabetes assessments
    cursor.execute('''
        SELECT id, assessment_date, risk_level, probability, patient_data, report_text 
        FROM assessment_diabetes 
        WHERE username = ?
        ORDER BY assessment_date DESC
    ''', (session['username'],))
    diabetes_assessments = cursor.fetchall()
    
    # Fetch all stroke assessments
    cursor.execute('''
        SELECT id, assessment_date, risk_level, probability, patient_data, report_text 
        FROM assessment_stroke 
        WHERE username = ?
        ORDER BY assessment_date DESC
    ''', (session['username'],))
    stroke_assessments = cursor.fetchall()
    
    conn.close()
    
    # Convert to dict-like structure for template and parse patient_data JSON
    def parse_assessments(rows):
        parsed = []
        for row in rows:
            assessment = dict(row)
            # Parse patient_data JSON if it's a string
            if isinstance(assessment['patient_data'], str):
                try:
                    assessment['patient_data'] = json.loads(assessment['patient_data'])
                except (json.JSONDecodeError, TypeError):
                    assessment['patient_data'] = {}
            parsed.append(assessment)
        return parsed
    
    assessments = {
        'cardiovascular': parse_assessments(cardio_assessments) if cardio_assessments else [],
        'diabetes': parse_assessments(diabetes_assessments) if diabetes_assessments else [],
        'stroke': parse_assessments(stroke_assessments) if stroke_assessments else []
    }
    
    return render_template('reports.html', username=session['username'], assessments=assessments)


# =====================================================
# SECTION 14A: PERSONALIZED HEALTH REPORT
# =====================================================

@app.route('/report')
@user_required
def report():
    """
    Display comprehensive personalized health report.
    Combines user profile data with all prediction results.
    """
    if 'loggedin' not in session:
        return redirect(url_for('landing'))
    user_id = get_current_user_id()
    if not user_id:
        return redirect(url_for('logout'))
    
    # Check if user has profile
    profile = get_user_profile(user_id)
    if not profile:
        return redirect(url_for('profile'))
    
    conn = get_db_connection()
    cursor = conn.cursor()
    
    # Fetch latest assessment from each prediction type
    cursor.execute('''
        SELECT assessment_date, risk_level, probability, patient_data, report_text
        FROM assessment_cardiovascular 
        WHERE username = ?
        ORDER BY assessment_date DESC LIMIT 1
    ''', (session['username'],))
    cardio = cursor.fetchone()
    
    cursor.execute('''
        SELECT assessment_date, risk_level, probability, patient_data, report_text
        FROM assessment_diabetes 
        WHERE username = ?
        ORDER BY assessment_date DESC LIMIT 1
    ''', (session['username'],))
    diabetes = cursor.fetchone()
    
    cursor.execute('''
        SELECT assessment_date, risk_level, probability, patient_data, report_text
        FROM assessment_stroke 
        WHERE username = ?
        ORDER BY assessment_date DESC LIMIT 1
    ''', (session['username'],))
    stroke = cursor.fetchone()
    
    conn.close()
    
    # Parse assessments
    assessments = {}
    for assessment_type, data in [('cardio', cardio), ('diabetes', diabetes), ('stroke', stroke)]:
        if data:
            assessment = dict(data)
            if isinstance(assessment['patient_data'], str):
                try:
                    assessment['patient_data'] = json.loads(assessment['patient_data'])
                except (json.JSONDecodeError, TypeError):
                    assessment['patient_data'] = {}
            assessments[assessment_type] = assessment
        else:
            assessments[assessment_type] = None
    
    # Prepare user profile data for display
    profile_data = dict(profile) if profile else {}
    
    # Calculate BMI category
    if profile_data.get('bmi'):
        bmi = profile_data['bmi']
        if bmi < 18.5:
            bmi_category = 'Underweight'
        elif bmi < 25:
            bmi_category = 'Normal Weight'
        elif bmi < 30:
            bmi_category = 'Overweight'
        else:
            bmi_category = 'Obese'
        profile_data['bmi_category'] = bmi_category
    
    # Calculate BP category
    if profile_data.get('blood_pressure_systolic') and profile_data.get('blood_pressure_diastolic'):
        systolic = profile_data['blood_pressure_systolic']
        diastolic = profile_data['blood_pressure_diastolic']
        if systolic < 120 and diastolic < 80:
            bp_category = 'Normal'
        elif systolic < 130 and diastolic < 80:
            bp_category = 'Elevated'
        elif systolic < 140 or diastolic < 90:
            bp_category = 'Stage 1 Hypertension'
        else:
            bp_category = 'Stage 2 Hypertension'
        profile_data['bp_category'] = bp_category
    
    # Generate preventive health suggestions
    suggestions = generate_health_suggestions(profile_data, assessments)
    
    return render_template('report.html', 
                         username=session['username'],
                         profile=profile_data,
                         assessments=assessments,
                         suggestions=suggestions)


def generate_health_suggestions(profile, assessments):
    """Generate personalized health suggestions based on profile and assessments"""
    suggestions = []
    
    # BMI-related suggestions
    if profile.get('bmi'):
        if profile['bmi'] >= 30:
            suggestions.append({
                'category': 'Weight Management',
                'text': 'Maintain a healthy weight through balanced diet and regular exercise.',
                'priority': 'high'
            })
        elif profile['bmi'] >= 25:
            suggestions.append({
                'category': 'Weight Management',
                'text': 'Work on gradual weight loss through lifestyle modifications.',
                'priority': 'medium'
            })
    
    # Blood Pressure-related suggestions
    if profile.get('blood_pressure_systolic', 0) >= 140 or profile.get('blood_pressure_diastolic', 0) >= 90:
        suggestions.append({
            'category': 'Blood Pressure',
            'text': 'Monitor blood pressure regularly and consult with a healthcare provider.',
            'priority': 'high'
        })
    
    # Glucose-related suggestions
    if profile.get('glucose_level', 0) > 125:
        suggestions.append({
            'category': 'Glucose Control',
            'text': 'Reduce sugar and refined carbohydrates in your diet.',
            'priority': 'high'
        })
    
    # Smoking-related suggestions
    if profile.get('smoking_status') == 1:
        suggestions.append({
            'category': 'Smoking Cessation',
            'text': 'Quit smoking to significantly reduce cardiovascular and stroke risk.',
            'priority': 'high'
        })
    
    # Physical Activity suggestions
    if profile.get('physical_activity', 0) == 0:
        suggestions.append({
            'category': 'Physical Activity',
            'text': 'Aim for at least 150 minutes of moderate-intensity exercise per week.',
            'priority': 'medium'
        })
    
    # Cholesterol-related suggestions
    if profile.get('cholesterol', 0) > 200:
        suggestions.append({
            'category': 'Cholesterol Management',
            'text': 'Monitor cholesterol levels and follow a heart-healthy diet.',
            'priority': 'medium'
        })
    
    # General health suggestions
    suggestions.append({
        'category': 'Regular Check-ups',
        'text': 'Schedule regular health check-ups and screenings with your healthcare provider.',
        'priority': 'medium'
    })
    
    suggestions.append({
        'category': 'Lifestyle',
        'text': 'Maintain stress management and ensure adequate sleep (7-9 hours per night).',
        'priority': 'medium'
    })
    
    return suggestions

@app.route('/download_report/<assessment_type>/<int:assessment_id>')
@user_required
def download_report(assessment_type, assessment_id):
    """
    Generate and download a PDF report.
    """
    if 'loggedin' not in session:
        return redirect(url_for('landing'))
    
    conn = get_db_connection()
    cursor = conn.cursor()
    
    # Map assessment type to table
    table_map = {
        'cardiovascular': 'assessment_cardiovascular',
        'diabetes': 'assessment_diabetes',
        'stroke': 'assessment_stroke'
    }
    
    if assessment_type not in table_map:
        return "Invalid assessment type", 400
    
    table = table_map[assessment_type]
    cursor.execute(f'''
        SELECT report_text, assessment_date 
        FROM {table}
        WHERE id = ? AND username = ?
    ''', (assessment_id, session['username']))
    
    result = cursor.fetchone()
    conn.close()
    
    if not result:
        return "Assessment not found", 404
    
    report_text = result['report_text']
    assessment_date = result['assessment_date']
    
    try:
        from reportlab.lib.pagesizes import letter, A4
        from reportlab.lib.styles import getSampleStyleSheet, ParagraphStyle
        from reportlab.lib.units import inch
        from reportlab.platypus import SimpleDocTemplate, Paragraph, Spacer, Table, TableStyle, PageBreak
        from reportlab.lib import colors
        
        # Create PDF
        pdf_buffer = BytesIO()
        doc = SimpleDocTemplate(pdf_buffer, pagesize=letter)
        story = []
        styles = getSampleStyleSheet()
        
        # Add title
        title_style = ParagraphStyle(
            'CustomTitle',
            parent=styles['Heading1'],
            fontSize=20,
            textColor=colors.HexColor('#0f172a'),
            spaceAfter=30,
            alignment=1  # center
        )
        story.append(Paragraph(f"{assessment_type.upper()} HEALTH REPORT", title_style))
        
        # Add date
        date_style = ParagraphStyle(
            'CustomDate',
            parent=styles['Normal'],
            fontSize=10,
            textColor=colors.HexColor('#475569'),
            spaceAfter=20,
            alignment=1  # center
        )
        story.append(Paragraph(f"Generated: {assessment_date}", date_style))
        story.append(Spacer(1, 0.3*inch))
        
        # Add report text as preformatted (preserve formatting)
        report_style = ParagraphStyle(
            'ReportText',
            parent=styles['Normal'],
            fontSize=9,
            leftIndent=20,
            rightIndent=20,
            spaceAfter=10,
            fontName='Courier'
        )
        
        # Split report into lines to preserve structure
        for line in report_text.split('\n'):
            if line.strip():
                story.append(Paragraph(line.replace('<', '&lt;').replace('>', '&gt;'), report_style))
            else:
                story.append(Spacer(1, 0.1*inch))
        
        # Build PDF
        doc.build(story)
        pdf_buffer.seek(0)
        
        # Return PDF
        filename = f"{assessment_type}_report_{assessment_id}.pdf"
        return send_file(
            pdf_buffer,
            mimetype='application/pdf',
            as_attachment=True,
            download_name=filename
        )
    
    except ImportError:
        # Fallback: return text file
        return send_file(
            BytesIO(report_text.encode('utf-8')),
            mimetype='text/plain',
            as_attachment=True,
            download_name=f"{assessment_type}_report_{assessment_id}.txt"
        )


# =====================================================
# SECTION 15: USER REGISTRATION
# =====================================================

@app.route('/register', methods =['GET', 'POST'])
@app.route('/signup', methods =['GET', 'POST'])
def register():
    msg = ''
    if request.method == 'POST' and 'username' in request.form and 'password' in request.form and 'email' in request.form :
        username = request.form['username'].strip()
        password = request.form['password']
        email = request.form['email'].strip().lower()
        connection = get_db_connection()
        cursor = connection.cursor()
        cursor.execute('SELECT id FROM users WHERE username = ? OR email = ?', (username, email))
        account = cursor.fetchone()
        if account:
            msg = 'Account already exists !'
            connection.close()
        elif not re.match(r'[^@]+@[^@]+\.[^@]+', email):
            msg = 'Invalid email address !'
            connection.close()
        elif not re.match(r'^[A-Za-z0-9_]{3,30}$', username):
            msg = 'Username must be 3-30 chars and use letters, numbers, or underscore!'
            connection.close()
        elif len(password) < 8:
            msg = 'Password must be at least 8 characters long!'
            connection.close()
        elif not username or not password or not email:
            msg = 'Please fill out the form !'
            connection.close()
        else:
            cursor.execute(
                'INSERT INTO users (username, email, password_hash, role, is_active) VALUES (?, ?, ?, ?, 1)',
                (username, email, generate_password_hash(password, method='pbkdf2:sha256'), 'user')
            )
            connection.commit()
            cursor.close()
            connection.close()
            msg = 'You have successfully registered! Please sign in.'
            return redirect(url_for('login', msg=msg))
    elif request.method == 'POST':
        msg = 'Please fill out the form !'
    return render_template('register.html', msg = msg)




# =====================================================
# SECTION 16: APPLICATION ENTRY POINT
# =====================================================

if __name__ == '__main__':
    debug_enabled = str(os.getenv('FLASK_DEBUG', '0')).lower() in ('1', 'true', 'yes')
    app.run(
        host=os.getenv('FLASK_HOST', '127.0.0.1'),
        port=int(os.getenv('FLASK_PORT', '5001')),
        debug=debug_enabled
    )

