# Health Companion

Health Companion is a Flask-based AI health risk prediction platform that combines user health profiles, machine-learning risk models, and automated clinical-style reports. The application helps users understand potential risk levels for stroke, diabetes, and cardiovascular disease, and provides calculators (BMI and calories) plus downloadable PDF reports.

## Academic Abstract (B.Tech Format)

This project presents **Health Companion**, a web-based health risk prediction system that integrates machine learning with a patient profile-driven workflow. The system predicts risk levels for stroke, diabetes, and cardiovascular disease using supervised classification models trained on structured health datasets. A single user profile provides consistent feature inputs for all models. The application includes report generation that transforms numerical predictions into clinically styled summaries with recommendations and PDF export. The work demonstrates an end-to-end pipeline covering data preparation, comparative model training, model selection, deployment, and user-facing decision support.

## Objectives

- Build a unified health risk assessment platform using a single user profile
- Train and compare multiple supervised learning models for three health conditions
- Select the best-performing model for each condition using standard evaluation metrics
- Deploy a production-ready Flask application with report generation and history
- Provide a user-friendly UI for assessments, calculators, and downloadable reports

## Methodology

1. **Data Preparation:** Datasets are stored as CSVs in `health-models/data/` with predefined columns; each dataset aligns with corresponding profile fields (age, gender, BP, glucose, BMI, etc.).
2. **Model Training and Selection:** Train/test split with stratification (`train_test_split`), feature standardization (`StandardScaler`), comparative evaluation across Logistic Regression, Decision Tree, Random Forest, SVM, KNN, and Naive Bayes, and selection of the best-performing model per disease using Accuracy, Precision, Recall, F1-Score, cross-validation, and ROC-AUC.
3. **System Integration:** Flask app loads the trained model and scaler for each assessment, normalizes profile inputs to match the training schema, and stores predictions alongside patient data and report text.
4. **Reporting:** A clinical-style report generator produces structured narratives with risk summary, inputs, findings, recommendations, and a medical disclaimer.

## Evaluation Summary

Evaluation is performed in the notebooks under `health-models/notebooks/` and recorded in report JSONs where available.

Available report artifacts:

- `health-models/reports/cardio_training_report.json`
- `health-models/reports/latest_training_report.json` (currently stroke)

Key evaluation points:

- **Cardiovascular model:** Random Forest selected based on comparative metrics and cross-validation
- **Stroke model:** Random Forest selected based on comparative metrics and cross-validation
- **Diabetes model:** Random Forest selected (metrics and CV computed in notebook)

For detailed metric tables (Accuracy, Precision, Recall, F1-Score) and ROC-AUC values, see the notebooks and report JSON files.

## Limitations (Academic Context)

- Dataset provenance and collection pipeline are not documented in this repository
- Diabetes report JSON currently overwrites `latest_training_report.json` when re-run
- Clinical validity depends on data quality and model generalization; this tool is informational only

## Live Application

Production app (Render):

`https://health-companion-1xb2.onrender.com`

## What This Project Delivers

- Profile-first health assessment flow (single health profile reused across all models)
- Stroke, diabetes, and cardiovascular risk predictions
- Model-driven, clinical-style report generation with PDF export
- BMI and calorie calculators
- Auth system with CAPTCHA and hashed passwords
- SQLite-backed persistence with automated schema migration

## High-Level Architecture

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

All prediction routes use the **same profile**. Users fill it once, and the app automatically fetches values when they run assessments.

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

### Datasets Used (Local Assets)

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

Each disease model is trained using the **same comparative workflow** in its notebook:

1. Load dataset from `health-models/data/`
2. Split into train/test (`train_test_split`) with stratification
3. Scale features (`StandardScaler`)
4. Evaluate multiple supervised models:

- Logistic Regression
- Decision Tree
- Random Forest
- SVM
- KNN
- Naive Bayes

5. Compare metrics (Accuracy, Precision, Recall, F1-Score)
6. Cross-validation and ROC-AUC
7. Select the best-performing model
8. Persist model + scaler with `joblib`

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

---

If you want any section adjusted for academic submission (B.Tech report format), I can tailor the wording and add a formal abstract, objectives, methodology, and evaluation section.
