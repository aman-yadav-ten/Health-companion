# Health Companion

Health Companion is a Flask-based preventive healthcare web application that helps users screen for stroke, diabetes, and cardiovascular risk from one reusable health profile. It combines authentication, profile management, machine learning inference, SQLite persistence, report generation, and a responsive web UI in a single full-stack academic project.

The app is designed around a simple user journey: create an account, log in to the dashboard, complete the health profile once, run any assessment, review report history, and download assessment reports as PDF.

## At A Glance

| Area | Details |
| --- | --- |
| Backend | Flask 3, Python 3.11 |
| Frontend | Jinja templates, HTML, CSS, light JavaScript |
| Database | SQLite with automatic initialization and migration |
| ML Runtime | scikit-learn, pandas, numpy, joblib |
| Reports | In-app text reports plus PDF export using ReportLab |
| Deployment | Gunicorn + Render configuration included |
| Auth | Session-based login, password hashing, CAPTCHA |

## Why This Project Is Useful

- One shared health profile feeds all three risk prediction modules.
- Users land on the dashboard after login instead of being forced into profile entry first.
- The landing page explains required medical inputs and exact clinical tests in a user-friendly way.
- Reports are saved for later review and can be downloaded as PDF files.
- The project is structured clearly enough for academic submission, learning, and further extension.

## Core Capabilities

### Authentication And Session Flow

- User registration with full name, date of birth, username, password, and CAPTCHA
- Login with CAPTCHA and hashed password verification
- Logout and switch-account flow
- Forgot-password flow based on identity verification
- Session-aware landing page that changes actions for logged-in users

### Dashboard And Profile

- Dashboard-first experience after login
- Central health profile stored in `user_profile`
- Profile update flow for vitals, history, lifestyle, and selected clinical values
- Profile completeness checks before running prediction modules

### Risk Prediction Modules

- Stroke risk assessment
- Diabetes risk assessment
- Cardiovascular risk assessment
- Reuse of saved profile values to avoid repeated data entry

### Reports And Utilities

- Assessment history view
- Consolidated health report page
- Downloadable PDF reports per assessment
- BMI calculator
- Calorie calculator
- Educational pages for stroke, diabetes, and cardiovascular health

## User Journey

1. Open the landing page at `/`.
2. Register an account or log in.
3. Reach the dashboard at `/index`.
4. Open the profile page and enter health data.
5. Run stroke, diabetes, or cardiovascular assessment.
6. Review the generated report.
7. Revisit saved reports from `/reports` or the consolidated overview at `/report`.
8. Download a PDF copy when needed.

## Prediction Modules And Inputs

The application stores one health profile and reuses it across different prediction modules. Each module uses a different subset of fields.

| Module | Main Inputs Used By The App | Typical Source |
| --- | --- | --- |
| Stroke | gender, age, hypertension, heart disease, marital status, work type, residence type, glucose level, BMI, smoking status | profile history, vitals, glucose test |
| Diabetes | pregnancies, glucose, diastolic blood pressure, skin thickness, insulin, BMI, diabetes pedigree score, age | profile history, vitals, fasting glucose, fasting insulin |
| Cardiovascular | age, gender, height, weight, systolic BP, diastolic BP, cholesterol, glucose, smoking, alcohol use, physical activity | vitals, lipid profile, fasting glucose, lifestyle inputs |

Clinical input guidance is also surfaced directly on the landing page so users can see which tests or measurements they need before using each module.

## Technology Stack

### Backend

- `Flask`
- `Werkzeug`
- `python-dotenv`

### Data And ML

- `sqlite3`
- `numpy`
- `pandas`
- `scikit-learn`
- `joblib`

### Reporting And Visualization

- `reportlab`
- `matplotlib`
- `seaborn`

### Deployment

- `gunicorn`
- `render.yaml`

## Architecture Overview

The project follows a server-rendered Flask architecture.

1. `app.py` starts the application.
2. `health_app/__init__.py` exposes the Flask app instance.
3. `health_app/route_registry.py` registers public, authenticated, assessment, and report routes.
4. `health_app/app_context.py` handles app configuration, database setup, migrations, shared helpers, session helpers, CAPTCHA, and ML inference.
5. Route modules process user actions and render templates.
6. `health_app/health_report_generator.py` turns patient data and prediction output into structured clinical-style reports.
7. Templates in `templates/` render the UI, while `static/style.css` handles the main visual styling.

## Repository Structure

```text
Health-companion-main/
├── app.py
├── Readme.md
├── requirements.txt
├── render.yaml
├── runtime.txt
├── run_app.bat
├── database/
│   ├── cardiovascular_db.sql
│   ├── diabetes_db.sql
│   ├── registered_db.sql
│   └── stroke.sql
├── health-models/
│   ├── data/
│   ├── models/
│   ├── notebooks/
│   └── reports/
├── health_app/
│   ├── __init__.py
│   ├── app_context.py
│   ├── assessment_routes.py
│   ├── auth_routes.py
│   ├── health_report_generator.py
│   ├── page_routes.py
│   └── route_registry.py
├── static/
│   ├── bg.jpg
│   ├── style.css
│   └── ss/
└── templates/
    ├── assessments/
    ├── auth/
    ├── base/
    ├── pages/
    ├── profile/
    └── reports/
```

## Main Application Modules

| File | Responsibility |
| --- | --- |
| `app.py` | Local development entrypoint |
| `health_app/app_context.py` | Flask app config, session setup, DB helpers, schema init, migrations, CAPTCHA, model inference, shared utilities |
| `health_app/auth_routes.py` | Login, register, forgot-password, logout, switch-account behavior |
| `health_app/page_routes.py` | Landing page, dashboard, profile, educational pages, report views, PDF downloads |
| `health_app/assessment_routes.py` | Stroke, diabetes, cardiovascular, BMI, and calorie flows |
| `health_app/health_report_generator.py` | Structured health-report formatting |
| `health_app/route_registry.py` | URL registration for the entire app |

## Route Map

### Public Routes

| Route | Purpose |
| --- | --- |
| `/` | Landing page |
| `/landing` | Alternate landing route |
| `/login` | Login page |
| `/register` | Registration page |
| `/forgot-password` | Password reset flow |
| `/logout` | Logout endpoint |

### Protected Routes

| Route | Purpose |
| --- | --- |
| `/index` | Dashboard |
| `/profile` | Create or update health profile |
| `/output` | Result display page |
| `/details` | Profile detail page |
| `/stroke-info` | Stroke education page |
| `/diabetes-info` | Diabetes education page |
| `/cardiovascular-info` | Cardiovascular education page |
| `/stroke` | Stroke risk assessment |
| `/diabetes` | Diabetes risk assessment |
| `/cardiovascular` | Cardiovascular risk assessment |
| `/calculate-bmi` | BMI calculator |
| `/calculate-calories` | Calorie calculator |
| `/reports` | Assessment history |
| `/report` | Consolidated health report |
| `/reports/download/<assessment_type>/<assessment_id>` | PDF or text report download |

## Database Design

The application uses SQLite and creates its schema automatically at startup. If legacy schema differences are detected, migration logic in `health_app/app_context.py` normalizes them.

### Main Tables

| Table | Purpose |
| --- | --- |
| `users` | Stores account identity and hashed password |
| `user_profile` | Stores the main reusable patient profile |
| `prediction_results` | Generic prediction result store |
| `assessment_stroke` | Saved stroke assessment reports |
| `assessment_diabetes` | Saved diabetes assessment reports |
| `assessment_cardiovascular` | Saved cardiovascular assessment reports |
| `account_stroke` | Historical stroke raw inputs |
| `account_dia` | Historical diabetes raw inputs |
| `account_cardiovascular` | Historical cardiovascular raw inputs |
| `account_bmi` | BMI calculator history |

### Database Notes

- SQLite WAL mode is enabled to reduce locking issues.
- `DB_PATH` can be changed through environment variables.
- The repository also includes SQL reference files in `database/`.

## Machine Learning Assets

The trained datasets, notebooks, and serialized models live under `health-models/`.

### Data

- `health-models/data/stroke.csv`
- `health-models/data/diabetes.csv`
- `health-models/data/cardio.csv`

### Model Artifacts

- `health-models/models/stroke_model.pkl`
- `health-models/models/stroke_scaler.pkl`
- `health-models/models/diabetes_model.pkl`
- `health-models/models/diabetes_scaler.pkl`
- `health-models/models/cardio_model.pkl`
- `health-models/models/cardio_scaler.pkl`

Additional random-forest model artifacts are also present for experimentation or future comparison.

### Training Assets

- `health-models/notebooks/Stroke_Model.ipynb`
- `health-models/notebooks/Diabetes_Model.ipynb`
- `health-models/notebooks/Cardio_Model.ipynb`
- `health-models/reports/latest_training_report.json`

## Local Setup

### 1. Create A Virtual Environment

macOS or Linux:

```bash
python3 -m venv .venv
source .venv/bin/activate
```

Windows:

```bat
python -m venv .venv
.venv\Scripts\activate
```

### 2. Install Dependencies

```bash
pip install -r requirements.txt
```

### 3. Create A `.env` File

Example:

```ini
SECRET_KEY=change-this-in-production
APP_ENV=development
FLASK_HOST=127.0.0.1
FLASK_PORT=5001
FLASK_DEBUG=0
DB_PATH=health_companion.db
SESSION_COOKIE_SECURE=0
```

### 4. Run The App

```bash
python app.py
```

Then open:

```text
http://127.0.0.1:5001
```

### 5. Windows Shortcut

If you prefer, `run_app.bat` activates the virtual environment, installs dependencies, and starts the app.

## Environment Variables

| Variable | Purpose | Example |
| --- | --- | --- |
| `SECRET_KEY` | Flask session signing key. Required in production. | `change-this-in-production` |
| `APP_ENV` | App environment mode | `development` or `production` |
| `FLASK_HOST` | Host for local server | `127.0.0.1` |
| `FLASK_PORT` | Port for local server | `5001` |
| `FLASK_DEBUG` | Enables Flask debug mode | `0` or `1` |
| `DB_PATH` | SQLite database file path | `health_companion.db` |
| `SESSION_COOKIE_SECURE` | Marks session cookie as secure | `0` or `1` |

## Running In Production

The repository includes Render deployment configuration in `render.yaml`.

### Current Render Setup

- Python runtime: `3.11.10`
- Build command: `pip install -r requirements.txt`
- Start command: `gunicorn app:app --bind 0.0.0.0:$PORT --workers 1 --threads 2 --timeout 180`

### Important Deployment Note

The current Render file uses:

```text
DB_PATH=/tmp/health_companion.db
```

That path is usually ephemeral on cloud platforms. It is acceptable for demos, but not for long-term persistent production data. For serious deployment, move persistence to a managed database or persistent volume strategy.

## Manual QA Checklist

This workspace does not currently include a `tests/` directory or bundled automated test suite, so the safest validation path is a focused manual smoke test:

1. Register a new user.
2. Log in and confirm the dashboard opens first.
3. Complete the health profile.
4. Run stroke, diabetes, and cardiovascular assessments.
5. Open `/reports` and confirm saved history appears.
6. Open `/report` and confirm profile values render correctly.
7. Download a PDF report from report history.
8. Use logout and switch-account to confirm session behavior is correct.
9. Check the landing page on desktop and mobile widths.

## Troubleshooting

### App Does Not Start

- Make sure the virtual environment is activated.
- Reinstall dependencies with `pip install -r requirements.txt`.
- Confirm your Python version is compatible with `runtime.txt`.

### `SECRET_KEY must be set in production environment`

- Set `SECRET_KEY` in your environment or `.env` file.
- This check is enforced when `APP_ENV` is `production`.

### Prediction Errors Or Missing Model Files

- Verify that the `.pkl` model and scaler files exist in `health-models/models/`.
- Confirm the app is being run from the project root so relative model paths resolve correctly.

### Database Locking Or Write Errors

- SQLite is file-based, so avoid multiple heavy write processes against the same DB file.
- The app already enables WAL and busy timeout, but local file contention can still happen.

### PDF Download Falls Back To Text

- If ReportLab cannot be imported, the app returns a `.txt` version of the report.
- Reinstall dependencies and ensure `reportlab` is available in the current environment.

## Security Notes

- Passwords are hashed using Werkzeug before storage.
- CAPTCHA is required for register, login, and forgot-password flows.
- Session cookies are configured with `HTTPOnly`.
- `SameSite=Lax` is enabled.
- `SESSION_COOKIE_SECURE` can be enabled for HTTPS deployments.

## Limitations

- This is an academic and educational risk-screening project, not a certified clinical product.
- The app uses SQLite, which is convenient for demos and local use but limited for larger multi-user deployments.
- Model management is file-based; there is no model registry or experiment tracking service integrated into runtime.
- The current repository does not include an automated test suite.

## Medical Disclaimer

Health Companion provides AI-assisted health risk estimation for educational and informational use only. It is not a medical diagnosis system and must not replace licensed clinical evaluation, emergency care, or treatment advice from a qualified healthcare professional.

## Author

**Aman Yadav**  
Email: `aman.yadav.ten@gmail.com`
