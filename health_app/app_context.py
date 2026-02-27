
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
import smtplib
import secrets
from io import BytesIO
from datetime import datetime
from functools import wraps
from email.mime.text import MIMEText
from email.mime.multipart import MIMEMultipart
from dotenv import load_dotenv
from .health_report_generator import HealthReportGenerator
from werkzeug.security import generate_password_hash, check_password_hash

try:
    from sklearn.exceptions import InconsistentVersionWarning
except Exception:  # pragma: no cover - fallback for older sklearn variants
    InconsistentVersionWarning = Warning

# =====================================================
# SECTION 2: APPLICATION CONFIGURATION & LOGGING
# =====================================================

load_dotenv()

_BASE_DIR = os.path.abspath(os.path.join(os.path.dirname(__file__), '..'))
app = Flask(
    __name__,
    template_folder=os.path.join(_BASE_DIR, 'templates'),
    static_folder=os.path.join(_BASE_DIR, 'static'),
)
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

    cursor.execute('''
        CREATE TABLE IF NOT EXISTS password_reset_otp (
            id INTEGER PRIMARY KEY AUTOINCREMENT,
            user_id INTEGER NOT NULL,
            email TEXT NOT NULL,
            otp_hash TEXT NOT NULL,
            expires_at INTEGER NOT NULL,
            consumed INTEGER NOT NULL DEFAULT 0,
            created_at TIMESTAMP DEFAULT CURRENT_TIMESTAMP,
            FOREIGN KEY (user_id) REFERENCES users(id) ON DELETE CASCADE
        )
    ''')

    cursor.execute('''
        CREATE TABLE IF NOT EXISTS registration_otp (
            id INTEGER PRIMARY KEY AUTOINCREMENT,
            username TEXT NOT NULL,
            email TEXT NOT NULL,
            password_hash TEXT NOT NULL,
            otp_hash TEXT NOT NULL,
            expires_at INTEGER NOT NULL,
            consumed INTEGER NOT NULL DEFAULT 0,
            created_at TIMESTAMP DEFAULT CURRENT_TIMESTAMP
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

    cursor.execute('''
        CREATE TABLE IF NOT EXISTS password_reset_otp (
            id INTEGER PRIMARY KEY AUTOINCREMENT,
            user_id INTEGER NOT NULL,
            email TEXT NOT NULL,
            otp_hash TEXT NOT NULL,
            expires_at INTEGER NOT NULL,
            consumed INTEGER NOT NULL DEFAULT 0,
            created_at TIMESTAMP DEFAULT CURRENT_TIMESTAMP,
            FOREIGN KEY (user_id) REFERENCES users(id) ON DELETE CASCADE
        )
    ''')

    cursor.execute('''
        CREATE TABLE IF NOT EXISTS registration_otp (
            id INTEGER PRIMARY KEY AUTOINCREMENT,
            username TEXT NOT NULL,
            email TEXT NOT NULL,
            password_hash TEXT NOT NULL,
            otp_hash TEXT NOT NULL,
            expires_at INTEGER NOT NULL,
            consumed INTEGER NOT NULL DEFAULT 0,
            created_at TIMESTAMP DEFAULT CURRENT_TIMESTAMP
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


def has_user_assessment(username, table_name):
    """Return True if user has at least one assessment row in the given model table."""
    allowed_tables = {
        'assessment_stroke',
        'assessment_diabetes',
        'assessment_cardiovascular',
    }
    if not username or table_name not in allowed_tables:
        return False

    conn = get_db_connection()
    cursor = conn.cursor()
    cursor.execute(f'SELECT 1 FROM {table_name} WHERE username = ? LIMIT 1', (username,))
    exists = cursor.fetchone() is not None
    conn.close()
    return exists


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


def send_password_reset_otp_email(to_email, username, otp_code):
    """
    Send password reset OTP email using SMTP env configuration.
    Returns True on success, False on failure.
    """
    smtp_host = (os.getenv('SMTP_HOST') or '').strip()
    smtp_port = int(os.getenv('SMTP_PORT') or '587')
    smtp_username = (os.getenv('SMTP_USERNAME') or '').strip()
    smtp_password = os.getenv('SMTP_PASSWORD') or ''
    from_email = (os.getenv('FROM_EMAIL') or smtp_username or '').strip()

    if not smtp_host or not from_email:
        logging.warning("SMTP not configured. Cannot send OTP email to %s", to_email)
        return False

    msg = MIMEMultipart('alternative')
    msg['Subject'] = 'Health Companion Password Reset OTP'
    msg['From'] = from_email
    msg['To'] = to_email

    now_str = datetime.now().strftime('%Y-%m-%d %H:%M:%S')
    text_body = (
        f"Hello {username},\n\n"
        f"Your OTP for password reset is: {otp_code}\n"
        "This OTP is valid for 10 minutes.\n\n"
        f"Requested at: {now_str}\n"
        "If you did not request this, please ignore this email."
    )
    html_body = (
        f"<p>Hello <strong>{username}</strong>,</p>"
        f"<p>Your OTP for password reset is:</p>"
        f"<h2 style='letter-spacing:3px'>{otp_code}</h2>"
        "<p>This OTP is valid for <strong>10 minutes</strong>.</p>"
        f"<p style='color:#6b7280'>Requested at: {now_str}</p>"
        "<p>If you did not request this, you can ignore this email.</p>"
    )

    msg.attach(MIMEText(text_body, 'plain'))
    msg.attach(MIMEText(html_body, 'html'))

    try:
        with smtplib.SMTP(smtp_host, smtp_port, timeout=20) as server:
            server.ehlo()
            if str(os.getenv('SMTP_USE_TLS', '1')).lower() in ('1', 'true', 'yes'):
                server.starttls()
                server.ehlo()
            if smtp_username:
                server.login(smtp_username, smtp_password)
            server.sendmail(from_email, [to_email], msg.as_string())
        return True
    except Exception as exc:
        logging.exception("Failed to send OTP email to %s: %s", to_email, str(exc))
        return False


def issue_password_reset_otp(user_id, email):
    """Create and persist a 6-digit OTP for password reset."""
    otp_code = f"{secrets.randbelow(900000) + 100000}"
    otp_hash = generate_password_hash(otp_code, method='pbkdf2:sha256')
    now_ts = int(time.time())
    expires_ts = now_ts + 600  # 10 minutes

    conn = get_db_connection()
    cursor = conn.cursor()
    cursor.execute('DELETE FROM password_reset_otp WHERE expires_at < ? OR consumed = 1', (now_ts,))
    cursor.execute(
        'INSERT INTO password_reset_otp (user_id, email, otp_hash, expires_at, consumed) VALUES (?, ?, ?, ?, 0)',
        (user_id, email, otp_hash, expires_ts)
    )
    conn.commit()
    conn.close()
    return otp_code


def verify_password_reset_otp(user_id, otp_code):
    """Validate latest non-consumed OTP for a user."""
    now_ts = int(time.time())
    conn = get_db_connection()
    cursor = conn.cursor()
    cursor.execute(
        '''
        SELECT id, otp_hash, expires_at
        FROM password_reset_otp
        WHERE user_id = ? AND consumed = 0
        ORDER BY id DESC
        LIMIT 1
        ''',
        (user_id,)
    )
    otp_record = cursor.fetchone()
    if not otp_record:
        conn.close()
        return False, "No OTP found. Request a new one."
    if int(otp_record['expires_at']) < now_ts:
        conn.close()
        return False, "OTP has expired. Request a new one."
    if not check_password_hash(otp_record['otp_hash'], otp_code):
        conn.close()
        return False, "Invalid OTP."

    cursor.execute('UPDATE password_reset_otp SET consumed = 1 WHERE id = ?', (otp_record['id'],))
    conn.commit()
    conn.close()
    return True, ''


def send_registration_otp_email(to_email, username, otp_code):
    """
    Send registration OTP email using SMTP env configuration.
    Returns True on success, False on failure.
    """
    smtp_host = (os.getenv('SMTP_HOST') or '').strip()
    smtp_port = int(os.getenv('SMTP_PORT') or '587')
    smtp_username = (os.getenv('SMTP_USERNAME') or '').strip()
    smtp_password = os.getenv('SMTP_PASSWORD') or ''
    from_email = (os.getenv('FROM_EMAIL') or smtp_username or '').strip()

    if not smtp_host or not from_email:
        logging.warning("SMTP not configured. Cannot send registration OTP email to %s", to_email)
        return False

    msg = MIMEMultipart('alternative')
    msg['Subject'] = 'Health Companion Registration OTP'
    msg['From'] = from_email
    msg['To'] = to_email

    now_str = datetime.now().strftime('%Y-%m-%d %H:%M:%S')
    text_body = (
        f"Hello {username},\n\n"
        f"Your OTP for account registration is: {otp_code}\n"
        "This OTP is valid for 10 minutes.\n\n"
        f"Requested at: {now_str}\n"
        "If you did not request this, please ignore this email."
    )
    html_body = (
        f"<p>Hello <strong>{username}</strong>,</p>"
        "<p>Your OTP for account registration is:</p>"
        f"<h2 style='letter-spacing:3px'>{otp_code}</h2>"
        "<p>This OTP is valid for <strong>10 minutes</strong>.</p>"
        f"<p style='color:#6b7280'>Requested at: {now_str}</p>"
        "<p>If you did not request this, you can ignore this email.</p>"
    )

    msg.attach(MIMEText(text_body, 'plain'))
    msg.attach(MIMEText(html_body, 'html'))

    try:
        with smtplib.SMTP(smtp_host, smtp_port, timeout=20) as server:
            server.ehlo()
            if str(os.getenv('SMTP_USE_TLS', '1')).lower() in ('1', 'true', 'yes'):
                server.starttls()
                server.ehlo()
            if smtp_username:
                server.login(smtp_username, smtp_password)
            server.sendmail(from_email, [to_email], msg.as_string())
        return True
    except Exception as exc:
        logging.exception("Failed to send registration OTP email to %s: %s", to_email, str(exc))
        return False


def send_smtp_test_email(to_email):
    """
    Send a simple SMTP test email using current environment configuration.
    Returns (success: bool, message: str).
    """
    smtp_host = (os.getenv('SMTP_HOST') or '').strip()
    smtp_port = int(os.getenv('SMTP_PORT') or '587')
    smtp_username = (os.getenv('SMTP_USERNAME') or '').strip()
    smtp_password = os.getenv('SMTP_PASSWORD') or ''
    from_email = (os.getenv('FROM_EMAIL') or smtp_username or '').strip()

    if not smtp_host or not from_email:
        return False, 'SMTP_HOST or FROM_EMAIL is missing.'

    msg = MIMEMultipart('alternative')
    msg['Subject'] = 'Health Companion SMTP Test'
    msg['From'] = from_email
    msg['To'] = to_email

    now_str = datetime.now().strftime('%Y-%m-%d %H:%M:%S')
    text_body = (
        "SMTP test successful.\n\n"
        f"Sent at: {now_str}\n"
        "If you received this email, your SMTP settings are working."
    )
    html_body = (
        "<p><strong>SMTP test successful.</strong></p>"
        f"<p>Sent at: {now_str}</p>"
        "<p>If you received this email, your SMTP settings are working.</p>"
    )
    msg.attach(MIMEText(text_body, 'plain'))
    msg.attach(MIMEText(html_body, 'html'))

    try:
        with smtplib.SMTP(smtp_host, smtp_port, timeout=20) as server:
            server.ehlo()
            if str(os.getenv('SMTP_USE_TLS', '1')).lower() in ('1', 'true', 'yes'):
                server.starttls()
                server.ehlo()
            if smtp_username:
                server.login(smtp_username, smtp_password)
            server.sendmail(from_email, [to_email], msg.as_string())
        return True, f'Test email sent to {to_email}.'
    except Exception as exc:
        logging.exception("SMTP test email failed for %s: %s", to_email, str(exc))
        return False, f'Failed to send test email: {str(exc)}'


def issue_registration_otp(username, email, password):
    """Create and persist a 6-digit OTP for new-user registration."""
    otp_code = f"{secrets.randbelow(900000) + 100000}"
    otp_hash = generate_password_hash(otp_code, method='pbkdf2:sha256')
    password_hash = generate_password_hash(password, method='pbkdf2:sha256')
    now_ts = int(time.time())
    expires_ts = now_ts + 600  # 10 minutes

    conn = get_db_connection()
    cursor = conn.cursor()
    cursor.execute('DELETE FROM registration_otp WHERE expires_at < ? OR consumed = 1', (now_ts,))
    cursor.execute('DELETE FROM registration_otp WHERE username = ? OR email = ?', (username, email))
    cursor.execute(
        '''
        INSERT INTO registration_otp (username, email, password_hash, otp_hash, expires_at, consumed)
        VALUES (?, ?, ?, ?, ?, 0)
        ''',
        (username, email, password_hash, otp_hash, expires_ts)
    )
    conn.commit()
    conn.close()
    return otp_code


def verify_registration_otp(username, email, otp_code):
    """Validate latest non-consumed registration OTP by username/email."""
    now_ts = int(time.time())
    conn = get_db_connection()
    cursor = conn.cursor()
    cursor.execute(
        '''
        SELECT id, password_hash, otp_hash, expires_at
        FROM registration_otp
        WHERE username = ? AND email = ? AND consumed = 0
        ORDER BY id DESC
        LIMIT 1
        ''',
        (username, email)
    )
    otp_record = cursor.fetchone()
    if not otp_record:
        conn.close()
        return False, "No OTP found. Request a new OTP.", None
    if int(otp_record['expires_at']) < now_ts:
        conn.close()
        return False, "OTP has expired. Request a new OTP.", None
    if not check_password_hash(otp_record['otp_hash'], otp_code):
        conn.close()
        return False, "Invalid OTP.", None

    cursor.execute('UPDATE registration_otp SET consumed = 1 WHERE id = ?', (otp_record['id'],))
    conn.commit()
    password_hash = otp_record['password_hash']
    conn.close()
    return True, '', password_hash




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



# =====================================================
# SECTION 5: USER AUTHENTICATION – LOGIN
# =====================================================





# =====================================================
# SECTION 5B: USER HEALTH PROFILE MANAGEMENT
# =====================================================

# =====================================================
# SECTION 6: STROKE PREDICTION – ROUTE HANDLING
# =====================================================

# =====================================================
# SECTION 7: STROKE PREDICTION – MACHINE LEARNING LOGIC
# =====================================================

def strokeml(gender, age, hypertension, heart_disease, ever_married, work_type, residence_type, avg_glucose_level, bmi, smoking_status):
    import joblib
    import pandas as pd
    try:
        with warnings.catch_warnings():
            warnings.simplefilter("ignore", InconsistentVersionWarning)
            model = joblib.load("health-models/models/stroke_model.pkl")
            scaler = joblib.load("health-models/models/stroke_scaler.pkl")
        
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

# =====================================================
# SECTION 9: DIABETES PREDICTION – MACHINE LEARNING LOGIC
# =====================================================

def diaml(pregnancies,glucose,bloodpressure,skinthickness,insulin,bmi_dia,diabetes_pedigree_fnc,age_dia):
    import joblib
    import pandas as pd
    try:
        with warnings.catch_warnings():
            warnings.simplefilter("ignore", InconsistentVersionWarning)
            model = joblib.load("health-models/models/diabetes_model.pkl")
            scaler = joblib.load("health-models/models/diabetes_scaler.pkl")
        
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

# =====================================================
# SECTION 11: CARDIOVASCULAR PREDICTION – MACHINE LEARNING LOGIC
# =====================================================

def cardiovascularml(age1,gender1,height,weight,ap_hi,ap_lo,cholesterol,glu,smoke,alco,active):
    import joblib
    import pandas as pd
    try:
        with warnings.catch_warnings():
            warnings.simplefilter("ignore", InconsistentVersionWarning)
            model = joblib.load("health-models/models/cardio_model.pkl")
            scaler = joblib.load("health-models/models/cardio_scaler.pkl")
        
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


@user_required


def calculate_bmi_value(weight, height):
    if height <= 0:
        raise ValueError('Height must be greater than zero.')
    height_in_meters = height / 100  
    bmi = weight / (height_in_meters ** 2)
    return round(bmi, 2)       




# =====================================================
# SECTION 13: CALORIE CALCULATOR – ROUTE & LOGIC
# =====================================================

@user_required


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



@user_required


@user_required


@user_required


@user_required


@user_required


# =====================================================
# SECTION 14A: PERSONALIZED HEALTH REPORT
# =====================================================

@user_required


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



# =====================================================
# SECTION 15: USER REGISTRATION
# =====================================================
