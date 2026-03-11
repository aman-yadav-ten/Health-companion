# Health Companion

Health Companion is my Flask-based health risk prediction app. It collects a single health profile, runs ML models for stroke, diabetes, and cardiovascular risk, and generates clear reports you can download as PDF. It also includes BMI and calorie calculators so users can get quick basic insights in the same workflow.

## Author

Aman Yadav  
Email: aman.yadav.ten@gmail.com

## Live Application

Production app (Render):

`https://health-companion-1xb2.onrender.com`

## What It Does

- One profile for all assessments
- Stroke, diabetes, and cardiovascular risk predictions
- Clinical-style report generation + PDF export
- BMI and calorie calculators
- CAPTCHA-protected auth with hashed passwords
- SQLite storage with automatic schema migration

## How It Works

**Request flow (simplified):**

1. User registers/logs in with CAPTCHA protection
2. User completes a health profile (single source of truth for model input)
3. Assessment routes auto-fetch profile values and run ML inference
4. Prediction results + profile details are saved to history tables
5. Health report generator builds a structured narrative report
6. Reports are displayed in-app and can be exported to PDF

**Core modules:**

- `app.py`: Application entrypoint
- `health_app/route_registry.py`: Central route registration
- `health_app/auth_routes.py`: Auth and password reset flows
- `health_app/page_routes.py`: Landing, dashboard, profile, reports
- `health_app/assessment_routes.py`: Assessments and calculators
- `health_app/app_context.py`: App config, DB, model inference helpers
- `health_app/health_report_generator.py`: Report generation logic

## Features

### 1) Authentication

- Register with full name, date of birth, username, password, CAPTCHA
- Login with username, password, CAPTCHA
- OTP-free password reset flow
- Passwords hashed using `werkzeug.security.generate_password_hash`

### 2) Profile-Driven Assessments

All prediction routes use the **same profile**. Users fill it once, and the app automatically fetches values when they run assessments. I did this to avoid re-entering data and to keep model inputs consistent.

Available assessments:

- Stroke risk (`/stroke`)
- Diabetes risk (`/diabetes`)
- Cardiovascular risk (`/cardiovascular`)

### 3) Health Reports

- Per-assessment report history (`/reports`)
- Consolidated latest report (`/report`)
- PDF export (`/reports/download/<assessment_type>/<assessment_id>`)

Reports include:

- Risk summary with probability and risk band
- Key clinical inputs and computed metrics (BMI, BP category, etc.)
- Findings + recommended actions
- Medical disclaimer

### 4) Calculators

- BMI calculator (`/calculate-bmi`)
- Calorie calculator (`/calculate-calories`)

### 5) Responsive Frontend

- Mobile/tablet/desktop responsive templates
- Landing page + dashboard-style UX

## Data and Model Training

### Datasets

Datasets live in `health-models/data/` and are loaded by the training notebooks:

- `stroke.csv`
- `diabetes.csv`
- `cardio.csv`

Dataset shapes (from notebooks):

- Stroke: `120000 x 11`
- Diabetes: `120000 x 9`
- Cardiovascular: `120000 x 12`

Each dataset is preformatted so the column names match model input requirements and profile fields. The profile UI captures all features needed by each dataset (age, gender, blood pressure, glucose, BMI, etc.).

### Training Approach and Model Selection

Each disease model is trained using the same comparative workflow in its notebook:

1. Load dataset from `health-models/data/`
2. Split into train/test (`train_test_split`) with stratification
3. Scale features (`StandardScaler`)
4. Evaluate multiple supervised models
5. Compare metrics (Accuracy, Precision, Recall, F1-Score)
6. Cross-validation and ROC-AUC
7. Select the best-performing model
8. Persist model + scaler with `joblib`

Models compared:

- Logistic Regression
- Decision Tree
- Random Forest
- SVM
- KNN
- Naive Bayes

### Selected Models (Best Performance)

- **Stroke:** Random Forest (selected in `health-models/notebooks/Stroke_Model.ipynb`)
- **Diabetes:** Random Forest (selected in `health-models/notebooks/Diabetes_Model.ipynb`)
- **Cardiovascular:** Random Forest (selected in `health-models/notebooks/Cardio_Model.ipynb`)

Training report artifacts:

- `health-models/reports/cardio_training_report.json`
- `health-models/reports/latest_training_report.json`

Notes:

- `latest_training_report.json` currently contains **stroke** metrics.
- The Diabetes notebook writes to `latest_training_report.json` (this can overwrite the stroke report if re-run).

### Model Artifacts Used by the App

The Flask app loads models and scalers from `health-models/models/`:

- `stroke_model.pkl` + `stroke_scaler.pkl`
- `diabetes_model.pkl` + `diabetes_scaler.pkl`
- `cardio_model.pkl` (or `cardio_random_forest_model.pkl`) + `cardio_scaler.pkl`

Inference helpers are in `health_app/app_context.py`:

- `strokeml(...)`
- `diaml(...)`
- `cardiovascularml(...)`

Cardiovascular lab values are normalized to training categories using `_normalize_cardio_lab_category`.

## How the App Uses the Dataset

1. The health profile captures all features present in the CSV training data.
2. Assessment routes auto-fetch the profile and prepare a feature vector.
3. The same feature order and scaler used in training are applied at inference.
4. Predictions return risk levels and probabilities used by the report generator.

## Database Overview

SQLite database: `health_companion.db`

Primary tables:

- `users`: user auth credentials
- `user_profile`: single canonical profile per user
- `assessment_stroke`, `assessment_diabetes`, `assessment_cardiovascular`: report history
- `account_*` tables: raw inputs by assessment for audit/history

Schema is initialized and migrated at startup via `health_app/app_context.py`.

## Project Structure

```
Health-companion-main/
├── app.py
├── Readme.md
├── requirements.txt
├── render.yaml
├── runtime.txt
├── health_companion.db
├── database/
│   ├── registered_db.sql
│   ├── stroke.sql
│   ├── diabetes_db.sql
│   └── cardiovascular_db.sql
├── health-models/
│   ├── data/
│   │   ├── stroke.csv
│   │   ├── diabetes.csv
│   │   └── cardio.csv
│   ├── models/
│   │   ├── stroke_model.pkl
│   │   ├── stroke_random_forest_model.pkl
│   │   ├── stroke_scaler.pkl
│   │   ├── diabetes_model.pkl
│   │   ├── diabetes_random_forest_model.pkl
│   │   ├── diabetes_scaler.pkl
│   │   ├── cardio_model.pkl
│   │   ├── cardio_random_forest_model.pkl
│   │   └── cardio_scaler.pkl
│   ├── notebooks/
│   │   ├── Stroke_Model.ipynb
│   │   ├── Diabetes_Model.ipynb
│   │   └── Cardio_Model.ipynb
│   └── reports/
│       ├── cardio_training_report.json
│       └── latest_training_report.json
├── health_app/
│   ├── __init__.py
│   ├── app_context.py
│   ├── auth_routes.py
│   ├── assessment_routes.py
│   ├── page_routes.py
│   ├── route_registry.py
│   └── health_report_generator.py
├── templates/
│   ├── assessments/
│   ├── auth/
│   ├── base/
│   ├── pages/
│   ├── profile/
│   └── reports/
└── static/
    ├── style.css
    ├── bg.jpg
    └── ss/
```

## Setup Instructions (Local)

### 1) Create virtual environment

```bash
python3 -m venv .venv
source .venv/bin/activate
```

### 2) Install dependencies

```bash
pip install -r requirements.txt
```

### 3) Configure environment

Create `.env` in project root:

```ini
SECRET_KEY=change-this-in-production
FLASK_HOST=127.0.0.1
FLASK_PORT=5001
FLASK_DEBUG=0

# Optional
APP_ENV=development
DB_PATH=health_companion.db
SESSION_COOKIE_SECURE=0
```

### 4) Start app

```bash
python app.py
```

Open:

`http://127.0.0.1:5001`

## Deployment (Render)

Configured in `render.yaml`:

```bash
gunicorn app:app --bind 0.0.0.0:$PORT --workers 1 --threads 2 --timeout 180
```

## Security and Compliance Notes

- Passwords are hashed using Werkzeug
- CAPTCHA protection on auth routes
- Sessions are configured with HTTPOnly and SameSite flags
- Medical disclaimer included in generated reports

## Future Improvements (Optional)

- Add model versioning and per-model report files
- Add data provenance documentation for the CSV datasets
- Add unit tests for inference and report generation
