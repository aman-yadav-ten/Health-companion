# Health Companion

AI-powered health risk prediction web app built with Flask, SQLite, and scikit-learn models.

## What This Project Does
- Predicts risk for:
  - Stroke
  - Diabetes
  - Cardiovascular disease
- Uses profile-driven auto-analysis for logged-in users.
- Generates structured health reports per assessment.
- Includes BMI and calorie calculators.
- Supports user and admin authentication flows.

## Current Architecture
- Entry point: `app.py`
- App package: `health_app/`
  - `route_registry.py` - route registration
  - `app_context.py` - app setup, DB setup/migrations, shared helpers
  - `auth_routes.py` - login/register/forgot-password flows
  - `assessment_routes.py` - prediction endpoints
  - `page_routes.py` - landing, dashboard, reports, profile
  - `admin_routes.py` - admin dashboard/actions
  - `health_report_generator.py` - report generation engine

## Project Structure
```text
Health companion/
├── app.py
├── health_app/
├── health-models/
│   ├── models/
│   ├── data/
│   ├── notebooks/
│   ├── reports/
│   └── scripts/
├── templates/
│   ├── admin/
│   ├── assessments/
│   ├── auth/
│   ├── base/
│   ├── pages/
│   ├── profile/
│   └── reports/
├── static/
├── database/
├── requirements.txt
└── Readme.md
```

## Setup
1. Create virtual environment and activate it.

```bash
python3 -m venv .venv
source .venv/bin/activate
```

2. Install dependencies.

```bash
pip install -r requirements.txt
```

3. Create `.env` (minimum example):

```ini
SECRET_KEY=change-me
FLASK_HOST=127.0.0.1
FLASK_PORT=5001
FLASK_DEBUG=0

# SMTP (required for real OTP emails)
SMTP_HOST=smtp.example.com
SMTP_PORT=587
SMTP_USE_TLS=1
SMTP_USERNAME=your_smtp_user
SMTP_PASSWORD=your_smtp_password
FROM_EMAIL=your_from_email@example.com
```

4. Run app.

```bash
python app.py
```

5. Open:
- `http://127.0.0.1:5001`

## Authentication and Password Reset
- User routes:
  - `/login`, `/register`, `/forgot-password`
- Admin routes:
  - `/admin-login`, `/admin-register`, `/admin-forgot-password`
- Forgot-password is OTP-based.
- If SMTP is unavailable in non-production mode, local OTP fallback is enabled by default for development.
  - Optional control: `ALLOW_LOCAL_OTP_FALLBACK=true|false`

## Models
Expected model files in `health-models/models/`:
- `stroke_model.pkl`, `stroke_scaler.pkl`
- `diabetes_model.pkl`, `diabetes_scaler.pkl`
- `cardio_model.pkl`, `cardio_scaler.pkl`

## Database
- SQLite DB file: `health_companion.db`
- DB tables are auto-created on startup.
- Migrations run automatically via `run_db_migrations()`.
- Key tables:
  - `users`, `user_profile`
  - `assessment_stroke`, `assessment_diabetes`, `assessment_cardiovascular`
  - `password_reset_otp`, `registration_otp`, `system_logs`

## Quick Health Checks
- SMTP test endpoint:
  - `GET /smtp-test` (usage help)
  - `POST /smtp-test` with `to=<email>`
- SQLite integrity:

```bash
sqlite3 health_companion.db 'PRAGMA integrity_check;'
```

## Notes
- `HealthReportGenerator` is package-local at `health_app/health_report_generator.py`.
- App import path uses package-relative imports to avoid missing-module startup issues.
