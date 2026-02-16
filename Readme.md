# Health Companion 🏥

**AI-Powered Health Risk Prediction Web Application**

**B.Tech CSE Major Project**  
**Author:** Aman Yadav  
**Email:** aman.yadav.ten@gmail.com  
**Institution:** United Institute of Technology, Naini, Prayagraj  
**Year:** 2026

> **✨ PHASE 3 COMPLETE: PRODUCTION READY**
> - Landing page as primary entry point ✅
> - Secure authentication with session management ✅  
> - Glassmorphic UI with modern design ✅
> - 10+ protected health prediction routes ✅
> - Fully responsive (mobile, tablet, desktop) ✅
> - 3 AI-powered ML models integrated ✅
> - SQLite database with auto-initialization ✅

---

## 🚀 Quick Start (Run from Scratch)

Follow these exact steps to run the project locally from a fresh checkout.

1) Create and activate a Python virtual environment

Windows (PowerShell):

```powershell
python -m venv .venv
.\.venv\Scripts\Activate.ps1
```

macOS / Linux (bash / zsh):

```bash
python3 -m venv .venv
source .venv/bin/activate
```

2) Upgrade pip and install dependencies

```bash
python -m pip install --upgrade pip
pip install -r requirements.txt
```

3) Create a `.env` file (required for `SECRET_KEY`)

Create a file named `.env` in the project root with at least:

```ini
SECRET_KEY=your-dev-secret
AUTHOR_NAME=Aman Yadav
AUTHOR_EMAIL=aman.yadav.ten@gmail.com
```

4) Ensure ML model files exist

Make sure the following files are present in `health-models/`:
- `cardio_model.pkl` + `cardio_scaler.pkl`
- `diabetes_model.pkl` + `diabetes_scaler.pkl`
- `stroke_model.pkl` + `stroke_scaler.pkl`

**Note:** Both model and scaler files are required for accurate predictions.

5) Run the application

```bash
# From the activated virtual environment
python app.py
# Or on Windows you can run: run_app.bat
```

6) Open the app in your browser

http://127.0.0.1:5000

Troubleshooting: if you see "Error in prediction: ..." when using prediction forms, check that the relevant `.pkl` files exist and were created with a compatible scikit-learn version.

---

## ✅ Quality & Operations (Now Enabled)

1) Install exact locked dependencies (recommended):

```bash
pip install -r requirements-lock.txt
```

2) Run regression tests before each push:

```bash
PYTHONPYCACHEPREFIX=/tmp/pycache python -m unittest discover -s tests -p 'test_*.py' -v
```

3) CI is configured via GitHub Actions:
- File: `.github/workflows/tests.yml`
- Trigger: every push + pull request
- Action: installs dependencies and runs regression suite

4) Production hardening environment variables:

```ini
APP_ENV=production
SECRET_KEY=use-a-long-random-secret
FLASK_DEBUG=0
SESSION_COOKIE_SECURE=1
```

5) Database backup script:

```bash
./scripts/backup_db.sh
```

Backups are saved under `backups/db/`.

---

## 📖 Table of Contents
1. [Project Overview](#project-overview)
2. [Problem Statement & Objectives](#problem-statement--objectives)
3. [Features](#features)
4. [Machine Learning Models](#machine-learning-models)
5. [Tech Stack](#tech-stack)
6. [Setup Instructions](#setup-instructions)
7. [Project Structure](#project-structure)
8. [Routes & Endpoints](#routes--endpoints)
9. [Database Schema](#database-schema)
10. [Usage Guide](#usage-guide)
11. [Future Enhancements](#future-enhancements)

---

## 📋 Project Overview

**Health Companion** is a comprehensive, production-ready web application that leverages machine learning and modern web technologies to provide early health risk assessments. The platform empowers users to proactively monitor their health by predicting risks for chronic diseases like stroke, diabetes, and cardiovascular conditions.

### Key Highlights
- **AI-Driven Predictions** - 3 pre-trained ML models with high accuracy
- **User-Centric Design** - Glassmorphic UI with smooth animations
- **Secure Platform** - Session-based authentication, SQLite database
- **Health Tools** - BMI and calorie calculators for wellness tracking
- **Educational Content** - Disease information pages with prevention tips
- **Cross-Device** - Fully responsive on mobile, tablet, and desktop
- **Production Ready** - Clean code, error handling, logging

---

## 🎯 Problem Statement & Objectives

### Problem
In today's fast-paced world, individuals often neglect health until symptoms become severe. There's a critical need for accessible tools that can provide **early risk assessments** for common diseases. Most people lack awareness of their health status until medical emergencies occur.

### Objectives
1. ✅ Develop an intuitive, user-friendly health risk prediction platform
2. ✅ Implement pre-trained ML models for accurate disease risk assessment
3. ✅ Provide educational resources and preventive health recommendations
4. ✅ Ensure data privacy with secure authentication
5. ✅ Create scalable, maintainable production-ready code
6. ✅ Demonstrate full-stack development capabilities (Backend, Frontend, ML, Database)

---

## ✨ Features

### 🔐 **Authentication & Security**
- User registration with email validation
- Secure login/logout with session management
- Password-protected routes (10+ protected endpoints)
- Automatic redirect for unauthorized access
- SQLite database with user account storage

### 🏥 **Disease Risk Prediction (AI-Powered)**

#### 1. **Stroke Risk Assessment**
- **Input Parameters:** Gender, Age, Hypertension, Heart Disease, Marital Status, Work Type, Residence Type, Glucose Level, BMI, Smoking Status
- **ML Model:** Logistic Regression with feature scaling
- **Output:** Risk assessment + personalized health recommendations
- **Route:** `/stroke`

#### 2. **Diabetes Risk Evaluation**
- **Input Parameters:** Pregnancies, Glucose, Blood Pressure, Skin Thickness, Insulin, BMI, Pedigree Function, Age
- **ML Model:** Logistic Regression
- **Output:** Diabetes risk prediction + lifestyle advice
- **Route:** `/diabetes`

#### 3. **Cardiovascular Disease Prediction**
- **Input Parameters:** Age, Gender, Height, Weight, Blood Pressure (Systolic/Diastolic), Cholesterol, Glucose, Smoking, Alcohol, Physical Activity
- **ML Model:** Random Forest Classifier (100 estimators)
- **Output:** Heart disease risk + preventive measures
- **Route:** `/cardiovascular`

### 🧮 **Health Calculators**
- **BMI Calculator**
  - Calculate Body Mass Index
  - Interpret results with health insights
  - Route: `/calculate_bmi`

- **Calorie Calculator**
  - Calculate Basal Metabolic Rate (BMR)
  - Estimate daily caloric needs based on activity level
  - Activity Levels: Sedentary, Light Exercise, Moderate Exercise, Active, Very Active, Intense Exercise
  - Route: `/calculate_calories`

### 📚 **Educational Resources**
- **Stroke Information Page** - Causes, symptoms, prevention
- **Diabetes Information Page** - Risk factors, management, lifestyle changes
- **Cardiovascular Information Page** - Heart health, prevention strategies
- Routes: `/stroke_info`, `/diabetes_info`, `/cardiovascular_info`

### 📊 **User Dashboard & Reports**
- Dashboard showing all available health tools
- User reports tracking prediction history
- Personal details and account information
- Routes: `/index` (dashboard), `/reports`, `/details`

### 🎨 **User Interface**
- **Glassmorphic Design** - Modern frosted glass aesthetic with blur effects
- **Dark Blue Theme** - Professional healthcare color scheme (#0f3460 primary)
- **Smooth Animations** - Enhanced transitions and hover effects
- **Responsive Layout** - Adapts to all screen sizes

### 📱 **Responsive Design**
| Device | Breakpoint | Layout |
|--------|-----------|--------|
| Desktop | 1024px+ | 2-column layout |
| Tablet | 768-1024px | 1-column layout |
| Mobile | <768px | Optimized full-width |

---

## 🤖 Machine Learning Models

All ML models are pre-trained, optimized, and saved in the `health-models/` directory.

### Model Summary Table

| Disease | Algorithm | File | Training Data | Features | Scaler |
|---------|-----------|------|---|----------|--------|
| **Cardiovascular** | Random Forest (100 estimators) | `cardio_model.pkl` | 70,000 records | 11 | `cardio_scaler.pkl` ✅ |
| **Diabetes** | Logistic Regression | `diabetes_model.pkl` | 768 records | 8 | `diabetes_scaler.pkl` ✅ |
| **Stroke** | Gaussian Naive Bayes with StandardScaler | `stroke_model.pkl` | 5,110 records | 10 | `stroke_scaler.pkl` ✅ |

### Model Details

#### 🫀 Cardiovascular Disease Model
- **Algorithm:** Random Forest (100 trees)
- **Features (11):** Age, Gender, Height, Weight, Systolic BP, Diastolic BP, Cholesterol, Glucose, Smoking, Alcohol, Physical Activity
- **File:** `cardio_model.pkl`
- **Training Data:** `cardio.csv` (70,000 records)
- **Scaler:** `cardio_scaler.pkl`

#### 🩺 Diabetes Risk Model
- **Algorithm:** Logistic Regression
- **Features (8):** Pregnancies, Glucose, Blood Pressure, Skin Thickness, Insulin, BMI, Diabetes Pedigree Function, Age
- **File:** `diabetes_model.pkl`
- **Training Data:** `diabetes.csv` (768 records)
- **Scaler:** `diabetes_scaler.pkl`

#### 🧠 Stroke Risk Model
- **Algorithm:** Gaussian Naive Bayes with StandardScaler preprocessing
- **Features (10):** Gender, Age, Hypertension, Heart Disease, Ever Married, Work Type, Residence Type, Avg Glucose Level, BMI, Smoking Status
- **File:** `stroke_model.pkl`
- **Training Data:** `Stroke.csv` (5,110 records)
- **Scaler:** `stroke_scaler.pkl` (StandardScaler - REQUIRED for predictions)
- **Preprocessing:** Categorical encoding, missing value imputation, feature scaling

### Model Training & Preprocessing
- **Data Preprocessing:** Categorical encoding, feature scaling, handling missing values
- **Train-Test Split:** 80-20 split with stratification for balanced class distribution
- **Feature Scaling:** StandardScaler applied to all features before training (critical for prediction accuracy)
- **Scaler Persistence:** Scalers saved with models using joblib for consistent preprocessing during inference
- **Performance Metrics:** Accuracy, Precision, Recall, F1-Score, ROC-AUC, Cross-Validation
- **Model Format:** Python Pickle (joblib) for efficient serialization and loading

---

## 🛠 Tech Stack

### Backend
- **Framework:** Python Flask 3.1.2
- **Language:** Python 3.8+

### Frontend
- **HTML5** - Semantic markup
- **CSS3** - Glassmorphic design, animations
- **JavaScript** - Form validation, interactivity

### Machine Learning
- **Scikit-learn 1.8.0** - ML algorithms (Random Forest, Logistic Regression)
- **Pandas 2.3.3** - Data manipulation
- **NumPy 2.4.0** - Numerical computations
- **Joblib 1.5.3** - Model serialization

### Database
- **SQLite** - Lightweight, file-based (health_companion.db)
- **No server required** - Ideal for development and small deployments

### Additional Libraries
- **python-dotenv 1.2.1** - Environment variable management
- **Werkzeug 3.1.4** - WSGI utilities
- **Jinja2 3.1.6** - Template engine
- **Matplotlib 3.10.8** - Data visualization (optional)
- **Seaborn 0.13.2** - Statistical visualization (optional)

---

## 📦 Setup Instructions

### Prerequisites
- Python 3.8 or higher
- Git (optional)
- Windows/Linux/macOS

### Step 1: Clone or Download Repository
```bash
# Clone from git (if available)
git clone <repository-url>
cd Health-Companion

# Or extract from zip file manually
```

### Step 2: Create and Activate Virtual Environment

**Windows:**
```bash
python -m venv .venv
.venv\Scripts\activate
```

**Linux/macOS:**
```bash
python3 -m venv .venv
source .venv/bin/activate
```

### Step 3: Install Dependencies
```bash
pip install -r requirements.txt
```

### Step 4: Environment Configuration
Create a `.env` file in the root directory:
```ini
SECRET_KEY=your-secret-key-here-change-in-production
AUTHOR_NAME=Aman Yadav
AUTHOR_EMAIL=aman.yadav.ten@gmail.com
```

### Step 5: Database Setup
The application automatically initializes the SQLite database on first run. No manual setup needed!

**Database file:** `health_companion.db` (created in root directory)

### Step 6: Run the Application

**Windows (Using Batch File):**
```bash
run_app.bat
```

**Windows/Linux/macOS (Using Terminal):**
```bash
python app.py
```

### Step 7: Access the Application
Open your web browser and navigate to:
```
http://127.0.0.1:5000
```

The application runs on Flask's built-in development server. For production deployment, use a WSGI server like Gunicorn or uWSGI.

---

## 📁 Project Structure

```
Health-Companion/
├── app.py                          # Main Flask application
├── run_app.bat                     # Windows batch file to run app
├── requirements.txt                # Python dependencies
├── .env                           # Environment variables (create this)
├── Readme.md                      # This file
├── health_companion.db            # SQLite database (auto-created)
│
├── health-models/                 # Machine Learning Models
│   ├── cardio_model.pkl           # Cardiovascular disease model
│   ├── cardio_scaler.pkl          # Feature scaler for cardio (REQUIRED)
│   ├── diabetes_model.pkl         # Diabetes risk model
│   ├── diabetes_scaler.pkl        # Feature scaler for diabetes (REQUIRED)
│   ├── stroke_model.pkl           # Stroke risk model
│   ├── stroke_scaler.pkl          # Feature scaler for stroke (REQUIRED)
│   ├── cardio.csv                 # Training data (70K records)
│   ├── diabetes.csv               # Training data (768 records)
│   ├── Stroke.csv                 # Training data (5,110 records)
│   ├── Cardio_Model.ipynb         # Cardio model development notebook
│   ├── Diabetes_Model.ipynb       # Diabetes model development notebook
│   └── Stroke_Model.ipynb         # Stroke model development notebook
│
├── database/                       # Database schema files (reference)
│   ├── cardiovascular_db.sql
│   ├── diabetes_db.sql
│   ├── registered_db.sql
│   └── stroke.sql
│
├── templates/                      # HTML templates
│   ├── landing.html               # Landing page (public)
│   ├── login.html                 # Login form
│   ├── register.html              # Registration form
│   ├── index.html                 # Dashboard (protected)
│   ├── details.html               # User details page
│   ├── output.html                # Results display
│   ├── stroke.html                # Stroke prediction form
│   ├── stroke_info.html           # Stroke information page
│   ├── diabetes.html              # Diabetes prediction form
│   ├── diabetes_info.html         # Diabetes information page
│   ├── cardiovascular.html        # Cardiovascular prediction form
│   ├── cardiovascular_info.html   # Cardiovascular information page
│   ├── calculate_bmi.html         # BMI calculator form
│   ├── calculate_calories.html    # Calorie calculator form
│   └── reports.html               # User health reports
│
├── static/                        # Static files
│   ├── style.css                  # Main stylesheet (glassmorphic design)
│   └── ss/                        # Screenshots and images
│
└── __pycache__/                   # Python cache (auto-generated)
```

---

## 🔗 Routes & Endpoints

### Public Routes (No Authentication Required)
| Route | Method | Purpose |
|-------|--------|---------|
| `/` | GET | Landing page (redirects to dashboard if logged in) |
| `/login` | GET, POST | User login |
| `/register` | GET, POST | User registration |

### Protected Routes (Requires Authentication)
#### Health Prediction Routes
| Route | Method | Purpose | Model |
|-------|--------|---------|-------|
| `/stroke` | GET, POST | Stroke risk prediction form & processing | Logistic Regression |
| `/diabetes` | GET, POST | Diabetes risk prediction form & processing | Logistic Regression |
| `/cardiovascular` | GET, POST | Cardiovascular risk prediction form & processing | Random Forest |

#### Information & Education Routes
| Route | Method | Purpose |
|-------|--------|---------|
| `/stroke_info` | GET | Stroke information and prevention tips |
| `/diabetes_info` | GET | Diabetes information and management |
| `/cardiovascular_info` | GET | Cardiovascular health information |

#### Health Calculator Routes
| Route | Method | Purpose |
|-------|--------|---------|
| `/calculate_bmi` | GET, POST | BMI calculator |
| `/calculate_calories` | GET, POST | Calorie requirement calculator |

#### User & Dashboard Routes
| Route | Method | Purpose |
|-------|--------|---------|
| `/index` | GET | Main dashboard |
| `/details` | GET | User profile details |
| `/reports` | GET | Health reports and history |
| `/output` | GET | Results display page |
| `/logout` | GET | User logout (clears session) |

---

## 💾 Database Schema

### Table: accounts
User authentication and profile information

| Column | Type | Constraint | Description |
|--------|------|-----------|-------------|
| id | INTEGER | PRIMARY KEY, AUTOINCREMENT | Unique user ID |
| username | TEXT | NOT NULL | Username |
| password | TEXT | NOT NULL | Password (stored as plain text - consider hashing in production) |
| email | TEXT | NOT NULL | Email address |

### Table: account_stroke
Stroke prediction data for each user

| Column | Type | Description |
|--------|------|-------------|
| id | INTEGER | Primary key |
| username | TEXT | Username reference |
| gender | INTEGER | Gender (0/1) |
| age | INTEGER | Age in years |
| hypertension | INTEGER | Hypertension status (0/1) |
| heart_disease | INTEGER | Heart disease status (0/1) |
| ever_married | INTEGER | Marital status (0/1) |
| work_type | INTEGER | Type of work (encoded) |
| residence_type | INTEGER | Residence type (0/1) |
| avg_glucose_level | REAL | Average glucose level |
| bmi | REAL | Body Mass Index |
| smoking_status | INTEGER | Smoking status (encoded) |
| stroke | INTEGER | Prediction result (0/1) |

### Table: account_dia
Diabetes prediction data for each user

| Column | Type | Description |
|--------|------|-------------|
| id | INTEGER | Primary key |
| username | TEXT | Username reference |
| pregnancies | INTEGER | Number of pregnancies |
| glucose | INTEGER | Glucose level |
| bloodpressure | INTEGER | Blood pressure |
| skinthickness | INTEGER | Skin thickness |
| insulin | INTEGER | Insulin level |
| bmi_dia | REAL | Body Mass Index |
| diabetes_pedigree_fnc | REAL | Diabetes pedigree function |
| age_dia | INTEGER | Age in years |
| outcome | INTEGER | Prediction result (0/1) |

### Table: account_cardiovascular
Cardiovascular disease prediction data for each user

| Column | Type | Description |
|--------|------|-------------|
| id | INTEGER | Primary key |
| username | TEXT | Username reference |
| age1 | INTEGER | Age in years |
| gender1 | INTEGER | Gender (0/1) |
| height | REAL | Height in cm |
| weight | REAL | Weight in kg |
| ap_hi | INTEGER | Systolic blood pressure |
| ap_lo | INTEGER | Diastolic blood pressure |
| cholesterol | INTEGER | Cholesterol level (0-3) |
| glu | INTEGER | Glucose level (0-3) |
| smoke | INTEGER | Smoking status (0/1) |
| alco | INTEGER | Alcohol consumption (0/1) |
| active | INTEGER | Physical activity (0/1) |
| cardio_disease | INTEGER | Prediction result (0/1) |

### Table: account_bmi
BMI calculation history for each user

| Column | Type | Description |
|--------|------|-------------|
| id | INTEGER | Primary key |
| username | TEXT | Username reference |
| weight | REAL | Weight in kg |
| height | REAL | Height in cm |
| bmi | REAL | Calculated BMI |

---

## 📖 Usage Guide

### 1. **First-Time User**
1. Visit http://127.0.0.1:5000
2. Click "Register" on landing page
3. Fill in username, email, password
4. Click "Register" button
5. Login with your credentials
6. You'll be redirected to dashboard

### 2. **Health Risk Prediction**
1. From dashboard, select a disease prediction tool
2. Fill in the health parameters (form validation ensures correct input)
3. Click "Predict" button
4. View your risk assessment and recommendations
5. Results are saved in database for future reference

### 3. **Using Health Calculators**
1. **BMI Calculator:** Enter weight (kg) and height (cm) → Get BMI and interpretation
2. **Calorie Calculator:** Enter gender, weight, height, age, activity level → Get BMR and daily calorie needs

### 4. **Educational Content**
1. Visit disease information pages for prevention tips
2. Understand risk factors and symptoms
3. Learn lifestyle modifications

### 5. **Viewing Reports**
1. Go to Reports section from dashboard
2. View prediction history and trends
3. Track health improvements over time

---

## 🔒 Security Considerations

### Current Implementation
- Session-based authentication
- SQLite database for user storage
- Protected routes with automatic redirects
- Input validation on forms

### Production Recommendations
1. Hash passwords using `bcrypt` or `werkzeug.security`
2. Use environment variables for SECRET_KEY
3. Enable HTTPS/SSL certificates
4. Deploy with production WSGI server (Gunicorn, uWSGI)
5. Implement rate limiting for login attempts
6. Add CSRF protection to forms
7. Regular security audits
8. Database backups and logging

---

## 🚀 Execution Steps

### Standard Workflow
1. Activate virtual environment
2. Run `python app.py`
3. Access application at `http://127.0.0.1:5000`
4. Register or login
5. Navigate to desired health tool
6. Input health parameters
7. View predictions and recommendations
8. Logout when done

### Testing the Application
```bash
# Test landing page
Visit http://127.0.0.1:5000

# Test login
Register new account, then login

# Test health predictions
Fill form and submit for each disease

# Test calculators
Enter parameters in BMI/Calorie calculators

# Test logout
Click logout button
```

---

## 🎯 Performance & Optimization

### Model Loading Optimization
- Models are loaded from `health-models/` directory
- Using joblib for efficient serialization
- Feature scalers cached alongside models

### Database Optimization
- SQLite with file-based storage
- Indexed primary keys
- Simple schema design for fast queries

### Frontend Performance
- Lightweight CSS with no heavy frameworks
- Minimal JavaScript dependencies
- Responsive images and assets
- Mobile-first design approach

---

## 📊 Model Performance Metrics

### Cardiovascular Model
- Trained on 70,000 records
- Random Forest (100 estimators)
- Features: 11 key health indicators
- High accuracy with good generalization

### Diabetes Model
- Trained on 768 records
- Logistic Regression
- Features: 8 medical parameters
- Well-calibrated predictions

### Stroke Model
- Trained on 5,110 records
- Logistic Regression with scaling
- Features: 10 demographic & health factors
- Balanced accuracy and interpretability

---

## 🔄 Future Enhancements

### Short-term (3-6 months)
- [ ] Email notifications for health alerts
- [ ] User profile picture upload
- [ ] Dark/Light theme toggle
- [ ] Multi-language support (Hindi, Spanish)
- [ ] Export reports as PDF

### Medium-term (6-12 months)
- [ ] Mobile app (React Native/Flutter)
- [ ] Wearable device integration (Apple Watch, Fitbit)
- [ ] Advanced analytics dashboard
- [ ] AI-powered personalized recommendations
- [ ] Integration with medical APIs

### Long-term (12+ months)
- [ ] Telemedicine platform integration
- [ ] Real-time health monitoring
- [ ] Insurance integration
- [ ] Clinical trial matching
- [ ] Blockchain-based medical records
- [ ] IoT health device ecosystem

---

## 🎓 Academic Value

This project demonstrates:
- ✅ **Machine Learning Application** - Real-world disease prediction
- ✅ **Full-Stack Development** - Backend, Frontend, Database
- ✅ **Software Engineering** - Clean code, modular design, documentation
- ✅ **Database Design** - Schema design, relationships, optimization
- ✅ **Web Development** - Flask, HTML, CSS, JavaScript
- ✅ **User Authentication** - Secure session management
- ✅ **Problem Solving** - Healthcare domain implementation
- ✅ **UI/UX Design** - Responsive, accessible, modern design

---

## 📞 Support & Contact

For issues, questions, or suggestions:
- **Author:** Aman Yadav
- **Email:** aman.yadav.ten@gmail.com
- **Institution:** United Institute of Technology, Naini, Prayagraj

---

## 📜 License

This project is developed as part of B.Tech CSE Major Project curriculum at United Institute of Technology, Naini, Prayagraj. All rights reserved. 

Use for educational and research purposes only.

---

## ✅ Verification Checklist

- [x] Landing page implemented with glassmorphic design
- [x] Authentication system (login/register/logout)
- [x] 3 ML models integrated and working
- [x] 2 Health calculators (BMI, Calories)
- [x] Educational information pages
- [x] User dashboard and reports
- [x] Responsive design (mobile/tablet/desktop)
- [x] Database schema created and optimized
- [x] Error handling and validation
- [x] Documentation complete

---

**Last Updated:** January 2026  
**Version:** 1.0 - Production Ready  
**Status:** ✅ Fully Functional
