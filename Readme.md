# Health Companion

Health Companion is a Flask-based AI health risk prediction platform that provides:
- Stroke risk prediction
- Diabetes risk prediction
- Cardiovascular disease risk prediction
- BMI and calorie calculators
- Profile-driven assessments
- Downloadable PDF health reports

## Live Application

Production app is live at:

**https://health-companion-1xb2.onrender.com**

## Current Product Status (Important)

This repository currently uses:
- User-only authentication (no admin module)
- OTP-free authentication and password reset flow
- CAPTCHA-protected login, registration, and password reset
- SQLite database with automatic schema migration on startup
- Flask server (`app.py`) for local development
- Gunicorn via `render.yaml` for deployment

## Core Features

### 1. Authentication
- Register with:
  - Full Name
  - Date of Birth
  - Username
  - Password
  - CAPTCHA
- Login with:
  - Username
  - Password
  - CAPTCHA
- Forgot Password flow:
  - Verify identity with Full Name + DOB + Username + CAPTCHA
  - Set new password + confirm + CAPTCHA
  - Password stored as secure hash using `werkzeug.security.generate_password_hash`

### 2. Profile-Driven Health Assessments
After login, user completes one health profile. Assessment routes auto-fetch profile values.

Predictions available:
- Stroke (`/stroke`)
- Diabetes (`/diabetes`)
- Cardiovascular (`/cardiovascular`)

### 3. Health Reports
- View report summaries and history (`/reports`)
- View latest consolidated report (`/report`)
- Download PDFs (`/reports/download/<assessment_type>/<assessment_id>`)

### 4. Calculators
- BMI calculator (`/calculate-bmi`)
- Calorie calculator (`/calculate-calories`)

### 5. Responsive Frontend
- Redesigned SaaS-style landing page
- Modern report dashboard UI
- Mobile/tablet/desktop responsive templates

## Technology Stack

- **Backend:** Flask, Python
- **Database:** SQLite
- **ML/DS:** scikit-learn, pandas, numpy, scipy
- **Visualization/Reporting:** matplotlib, seaborn, reportlab
- **Model Persistence:** joblib (`.pkl` artifacts)
- **Deployment:** Render + Gunicorn

## Project Structure

```text
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
│   └── reports/
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

## Entry Point and Runtime

### Local Run
```bash
python app.py
```

Default runtime values:
- Host: `127.0.0.1`
- Port: `5001`
- Debug: disabled unless `FLASK_DEBUG=1`

### Production Run (Render)
Defined in `render.yaml`:
```bash
gunicorn app:app --bind 0.0.0.0:$PORT --workers 1 --threads 2 --timeout 180
```

## Python Version

Project target Python version:
- `.python-version` => `3.11.10`
- `render.yaml` => `PYTHON_VERSION=3.11.10`

Use Python 3.11.10 for best dependency compatibility.

## Setup Instructions (Local)

### 1) Clone repository
```bash
git clone <your-repo-url>
cd Health-companion-main
```

### 2) Create virtual environment
```bash
python3 -m venv .venv
source .venv/bin/activate
```

### 3) Install dependencies
```bash
pip install -r requirements.txt
```

### 4) Configure environment
Create `.env` in project root (minimum):

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

### 5) Start app
```bash
python app.py
```

### 6) Open in browser
```text
http://127.0.0.1:5001
```

## URL Routes (Current)

### Public
- `GET /`
- `GET /landing`

### Authentication
- `GET|POST /login`
- `GET|POST /register`
- `GET|POST /forgot-password`
- `GET /logout`

### User Pages (login required)
- `GET /index`
- `GET|POST /profile`
- `GET /output`
- `GET /details`
- `GET /stroke-info`
- `GET /diabetes-info`
- `GET /cardiovascular-info`
- `GET /reports`
- `GET /report`
- `GET /reports/download/<assessment_type>/<assessment_id>`

### Assessments & Tools (login required)
- `GET|POST /stroke`
- `GET|POST /diabetes`
- `GET|POST /cardiovascular`
- `GET|POST /calculate-bmi`
- `GET|POST /calculate-calories`

## Database Design (Current)

SQLite file:
- `health_companion.db` (local)
- `/tmp/health_companion.db` on Render free tier (ephemeral)

### Key tables
- `users`
  - `id`
  - `full_name`
  - `date_of_birth`
  - `username` (unique)
  - `password_hash`
  - `created_at`
- `user_profile`
  - health profile linked to `users.id`
- `assessment_stroke`
- `assessment_diabetes`
- `assessment_cardiovascular`
- `account_stroke`, `account_dia`, `account_cardiovascular` (assessment inputs/logging)
- `prediction_results`

### Auto-migration behavior
`run_db_migrations()` in `health_app/app_context.py`:
- Normalizes legacy user schema to current user-only auth schema
- Removes obsolete OTP/admin tables when present
- Preserves profile and assessment history tables

## ML Model Pipeline Details

### Stroke
- Model artifact: `health-models/models/stroke_model.pkl`
- Scaler: `health-models/models/stroke_scaler.pkl`

### Diabetes
- Model artifact: `health-models/models/diabetes_model.pkl`
- Scaler: `health-models/models/diabetes_scaler.pkl`

### Cardiovascular
- Model artifact preference:
  1. `health-models/models/cardio_model.pkl`
  2. fallback `health-models/models/cardio_random_forest_model.pkl`
- Scaler: `health-models/models/cardio_scaler.pkl`

#### Cardiovascular input normalization (important)
Cardio model is trained with categorical lab levels:
- `CHOLESTEROL`: 1/2/3
- `GLUCOSE`: 1/2/3

Runtime now safely normalizes profile inputs before inference:
- If already 1/2/3, used directly
- If provided as mg/dL, mapped to training categories:
  - Cholesterol: `<200 => 1`, `200-239 => 2`, `>=240 => 3`
  - Glucose: `<100 => 1`, `100-125 => 2`, `>=126 => 3`

This prevents false high-risk bias from out-of-distribution numeric lab values.

## Security Notes

- Passwords are hashed using Werkzeug (`pbkdf2:sha256`)
- SQL queries use parameterized statements
- CAPTCHA enforced for:
  - login
  - register
  - forgot-password identity verification
  - forgot-password reset step
- Session cookies configured with:
  - `SESSION_COOKIE_HTTPONLY=True`
  - `SESSION_COOKIE_SAMESITE='Lax'`
  - optional `SESSION_COOKIE_SECURE`

## Deployment (Render)

### Live URL
- https://health-companion-1xb2.onrender.com

### `render.yaml` summary
- Service name: `health-companion`
- Runtime: Python
- Build command: `pip install -r requirements.txt`
- Start command: Gunicorn
- `PYTHON_VERSION=3.11.10`
- `DB_PATH=/tmp/health_companion.db`

### Important free-tier note
`/tmp` storage is ephemeral. Data may reset after restarts/redeploys.

## Troubleshooting

### Port already in use (5001)
```bash
lsof -nP -iTCP:5001 -sTCP:LISTEN
kill <PID>
```

### Cardio model file missing
Ensure one of:
- `health-models/models/cardio_model.pkl`
- `health-models/models/cardio_random_forest_model.pkl`

And scaler:
- `health-models/models/cardio_scaler.pkl`

### Python dependency issues
Use Python `3.11.10` and recreate environment:
```bash
rm -rf .venv
python3.11 -m venv .venv
source .venv/bin/activate
pip install -r requirements.txt
```

### Force fresh DB locally
```bash
rm -f health_companion.db
python app.py
```

## Quick Smoke Test Checklist

- [ ] Landing page loads
- [ ] Register works with CAPTCHA
- [ ] Login works with CAPTCHA
- [ ] Forgot password identity verification works
- [ ] Password reset updates login credentials
- [ ] Profile save works
- [ ] Stroke assessment works
- [ ] Diabetes assessment works
- [ ] Cardiovascular assessment works
- [ ] Reports page renders and PDF download works

---

If you deploy new updates, keep this README synchronized with route, auth, and model pipeline changes.
