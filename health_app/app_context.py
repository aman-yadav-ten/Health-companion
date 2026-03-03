
"""
Title: Health Companion - B.Tech CSE Major Project
Author: Aman Yadav
Email: aman.yadav.ten@gmail.com
Description: A web application for health risk prediction using machine learning.
"""



# =====================================================
# SECTION 1: IMPORT REQUIRED LIBRARIES
# =====================================================

from flask import Flask, render_template, request, redirect, url_for, session, send_file
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
_DB_PATH = os.getenv('DB_PATH', os.path.join(_BASE_DIR, 'health_companion.db'))
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
    # Timeout + WAL reduce "database is locked" errors under concurrent writes.
    db_dir = os.path.dirname(_DB_PATH)
    if db_dir:
        os.makedirs(db_dir, exist_ok=True)
    conn = sqlite3.connect(_DB_PATH, timeout=30.0)
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
            full_name TEXT NOT NULL,
            date_of_birth TEXT NOT NULL,
            username TEXT NOT NULL UNIQUE,
            password_hash TEXT NOT NULL,
            created_at TIMESTAMP DEFAULT CURRENT_TIMESTAMP
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
    """Normalize legacy auth schema to user-only, OTP-free model."""
    conn = get_db_connection()
    cursor = conn.cursor()

    # Rebuild users table if legacy columns exist (email/role/is_active) or required columns are missing.
    cursor.execute("SELECT name FROM sqlite_master WHERE type='table' AND name='users'")
    users_exists = cursor.fetchone() is not None
    rebuild_users = True
    if users_exists:
        cursor.execute('PRAGMA table_info(users)')
        cols = [row['name'] for row in cursor.fetchall()]
        required = {'id', 'full_name', 'date_of_birth', 'username', 'password_hash'}
        legacy = {'email', 'role', 'is_active'}
        rebuild_users = (not required.issubset(set(cols))) or bool(legacy.intersection(set(cols)))

    if rebuild_users:
        cursor.execute('''
            CREATE TABLE IF NOT EXISTS users_new (
                id INTEGER PRIMARY KEY AUTOINCREMENT,
                full_name TEXT NOT NULL,
                date_of_birth TEXT NOT NULL,
                username TEXT NOT NULL UNIQUE,
                password_hash TEXT NOT NULL,
                created_at TIMESTAMP DEFAULT CURRENT_TIMESTAMP
            )
        ''')

        if users_exists:
            cursor.execute('PRAGMA table_info(users)')
            old_cols = {row['name'] for row in cursor.fetchall()}
            select_full_name = "COALESCE(full_name, username, 'User')" if 'full_name' in old_cols else "COALESCE(username, 'User')"
            select_dob = "COALESCE(date_of_birth, '')" if 'date_of_birth' in old_cols else "''"
            select_username = "username" if 'username' in old_cols else "'user_' || id"
            select_password_hash = "password_hash" if 'password_hash' in old_cols else "''"
            select_created_at = "created_at" if 'created_at' in old_cols else "CURRENT_TIMESTAMP"

            cursor.execute(f'''
                INSERT OR IGNORE INTO users_new (id, full_name, date_of_birth, username, password_hash, created_at)
                SELECT id, {select_full_name}, {select_dob}, {select_username}, {select_password_hash}, {select_created_at}
                FROM users
                WHERE {select_username} IS NOT NULL AND TRIM({select_username}) <> ''
                  AND {select_password_hash} IS NOT NULL AND TRIM({select_password_hash}) <> ''
            ''')

            cursor.execute('DROP TABLE users')

        cursor.execute('ALTER TABLE users_new RENAME TO users')

    cursor.execute('CREATE UNIQUE INDEX IF NOT EXISTS idx_users_username_unique ON users(username)')
    cursor.execute("UPDATE users SET full_name = username WHERE full_name IS NULL OR TRIM(full_name) = ''")

    # Cleanup removed modules/tables.
    cursor.execute('DROP TABLE IF EXISTS system_logs')
    cursor.execute('DROP TABLE IF EXISTS password_reset_otp')
    cursor.execute('DROP TABLE IF EXISTS registration_otp')
    cursor.execute('DROP TABLE IF EXISTS accounts')

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
    """Return current user row if session maps to a valid user."""
    user_id = get_current_user_id()
    if not user_id:
        return None
    conn = get_db_connection()
    cursor = conn.cursor()
    cursor.execute('SELECT id, username FROM users WHERE id = ?', (user_id,))
    account = cursor.fetchone()
    conn.close()
    return account


def get_current_user_role():
    """Compatibility shim for templates expecting a role string."""
    return 'user' if get_current_user_account() else None


def is_admin():
    return False


def generate_captcha():
    alphabet = 'ABCDEFGHJKLMNPQRSTUVWXYZ23456789'
    captcha = ''.join(np.random.choice(list(alphabet), 5))
    session['captcha_code'] = captcha
    return captcha


def validate_captcha(user_input):
    expected = (session.get('captcha_code') or '').strip().upper()
    provided = (user_input or '').strip().upper()
    session.pop('captcha_code', None)
    return bool(expected and provided and expected == provided)




def login_required(view_func):
    @wraps(view_func)
    def wrapper(*args, **kwargs):
        if 'loggedin' not in session:
            return redirect(url_for('login'))
        account = get_current_user_account()
        if not account:
            return redirect(url_for('logout'))
        session['username'] = account['username']
        return view_func(*args, **kwargs)
    return wrapper


def user_required(view_func):
    @wraps(view_func)
    def wrapper(*args, **kwargs):
        return login_required(view_func)(*args, **kwargs)
    return wrapper


@app.errorhandler(403)
def forbidden(_error):
    return redirect(url_for('login', msg='Unauthorized access. Please sign in.'))


@app.context_processor
def inject_auth_flags():
    account = get_current_user_account() if 'loggedin' in session else None
    loggedin = bool(account)
    return {
        'is_admin_user': False,
        'logged_in_user_role': 'user' if loggedin else None
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

def _normalize_cardio_lab_category(value, lab_name):
    """
    Convert lab values into cardio training categories.
    Training data uses:
      1 = normal, 2 = above normal, 3 = well above normal.
    """
    numeric = float(value)
    if numeric in (1.0, 2.0, 3.0):
        return int(numeric)

    if lab_name == 'cholesterol':
        if numeric < 200:
            return 1
        if numeric < 240:
            return 2
        return 3

    if lab_name == 'glucose':
        if numeric < 100:
            return 1
        if numeric < 126:
            return 2
        return 3

    raise ValueError(f'Unsupported lab name: {lab_name}')


def cardiovascularml(age1,gender1,height,weight,ap_hi,ap_lo,cholesterol,glu,smoke,alco,active):
    import joblib
    import pandas as pd
    try:
        model_candidates = [
            "health-models/models/cardio_model.pkl",
            "health-models/models/cardio_random_forest_model.pkl",
        ]
        model_path = next((p for p in model_candidates if os.path.exists(p)), None)
        if not model_path:
            return {
                'error': (
                    "Missing cardiovascular model file. Expected one of: "
                    f"{', '.join(model_candidates)}"
                )
            }
        scaler_path = "health-models/models/cardio_scaler.pkl"
        if not os.path.exists(scaler_path):
            return {'error': f"Missing cardiovascular scaler file: {scaler_path}"}

        with warnings.catch_warnings():
            warnings.simplefilter("ignore", InconsistentVersionWarning)
            model = joblib.load(model_path)
            scaler = joblib.load(scaler_path)

        # Normalize profile inputs to the training schema.
        normalized_features = {
            'AGE': int(age1),
            'GENDER': int(gender1),
            'HEIGHT': float(height),
            'WEIGHT': float(weight),
            'AP_HIGH': int(ap_hi),
            'AP_LOW': int(ap_lo),
            'CHOLESTEROL': _normalize_cardio_lab_category(cholesterol, 'cholesterol'),
            'GLUCOSE': _normalize_cardio_lab_category(glu, 'glucose'),
            'SMOKE': int(smoke),
            'ALCOHOL': int(alco),
            'PHYSICAL_ACTIVITY': int(active),
        }

        expected_features = list(getattr(scaler, 'feature_names_in_', [])) or [
            'AGE',
            'GENDER',
            'HEIGHT',
            'WEIGHT',
            'AP_HIGH',
            'AP_LOW',
            'CHOLESTEROL',
            'GLUCOSE',
            'SMOKE',
            'ALCOHOL',
            'PHYSICAL_ACTIVITY',
        ]
        input_df = pd.DataFrame([{name: normalized_features[name] for name in expected_features}])
        
        # Scale the input data using the same scaler from training
        input_scaled = scaler.transform(input_df)
        input_scaled_df = pd.DataFrame(input_scaled, columns=expected_features)
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
