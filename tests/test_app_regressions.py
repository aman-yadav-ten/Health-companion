import builtins
import sqlite3
import unittest
import uuid
from unittest.mock import patch

import app as app_module


class AppRegressionTests(unittest.TestCase):
    @classmethod
    def setUpClass(cls):
        app_module.app.config["TESTING"] = True

    def setUp(self):
        self.client = app_module.app.test_client()
        self.username = f"u_{uuid.uuid4().hex[:10]}"
        self.email = f"{self.username}@example.com"
        self.password = "Password123"
        self._register_and_login(self.username, self.email, self.password)

    def _register_and_login(self, username, email, password):
        self.client.post(
            "/register",
            data={"username": username, "password": password, "email": email},
            follow_redirects=False,
        )
        self.client.post(
            "/login",
            data={"username": username, "password": password},
            follow_redirects=False,
        )

    def _create_admin_client(self):
        admin_client = app_module.app.test_client()
        admin_username = f"a_{uuid.uuid4().hex[:10]}"
        admin_email = f"{admin_username}@example.com"
        admin_client.post(
            "/register",
            data={"username": admin_username, "password": "Password123", "email": admin_email},
            follow_redirects=False,
        )

        conn = sqlite3.connect("health_companion.db")
        cur = conn.cursor()
        cur.execute("UPDATE users SET role = 'admin' WHERE username = ?", (admin_username,))
        conn.commit()
        conn.close()

        admin_client.post(
            "/admin-login",
            data={"username": admin_username, "password": "Password123"},
            follow_redirects=False,
        )
        return admin_client

    def _submit_profile(self, gender="0"):
        profile_data = {
            "age": "36",
            "gender": str(gender),
            "height": "165",
            "weight": "64",
            "blood_pressure_systolic": "118",
            "blood_pressure_diastolic": "76",
            "glucose_level": "95",
            "cholesterol": "1",
            "smoking_status": "0",
            "hypertension": "0",
            "heart_disease": "0",
            "ever_married": "0",
            "work_type": "2",
            "residence_type": "0",
            "pregnancies": "0",
            "insulin": "0",
            "skin_thickness": "0",
            "diabetes_pedigree_function": "0.2",
            "alcohol_consumption": "0",
            "physical_activity": "1",
        }
        response = self.client.post("/profile", data=profile_data, follow_redirects=False)
        self.assertEqual(response.status_code, 302)

    def _deactivate_user(self, username):
        conn = sqlite3.connect("health_companion.db")
        cur = conn.cursor()
        cur.execute("UPDATE users SET is_active = 0 WHERE username = ?", (username,))
        conn.commit()
        conn.close()

    def _latest_stroke_assessment_id(self, username):
        conn = sqlite3.connect("health_companion.db")
        cur = conn.cursor()
        cur.execute(
            "SELECT id FROM assessment_stroke WHERE username = ? ORDER BY id DESC LIMIT 1",
            (username,),
        )
        row = cur.fetchone()
        conn.close()
        return row[0] if row else None

    def test_female_user_can_run_cardiovascular_prediction(self):
        self._submit_profile(gender="0")
        response = self.client.post("/cardiovascular", data={}, follow_redirects=True)
        body = response.get_data(as_text=True).lower()
        self.assertEqual(response.status_code, 200)
        self.assertIn("risk summary", body)
        self.assertNotIn("profile is incomplete", body)

    def test_deactivated_user_is_forced_to_logout(self):
        self._submit_profile(gender="1")
        response_before = self.client.get("/details", follow_redirects=False)
        self.assertEqual(response_before.status_code, 200)

        self._deactivate_user(self.username)
        response_after = self.client.get("/details", follow_redirects=False)
        self.assertEqual(response_after.status_code, 302)
        self.assertEqual(response_after.headers.get("Location"), "/logout")

    def test_bmi_zero_height_returns_validation_not_server_error(self):
        response = self.client.post(
            "/calculate_bmi",
            data={"weight": "70", "height": "0"},
            follow_redirects=False,
        )
        body = response.get_data(as_text=True).lower()
        self.assertEqual(response.status_code, 200)
        self.assertIn("greater than zero", body)
        self.assertNotIn("internal server error", body)

    def test_download_report_falls_back_to_text_when_reportlab_missing(self):
        self._submit_profile(gender="1")
        prediction_response = self.client.post("/stroke", data={}, follow_redirects=False)
        self.assertEqual(prediction_response.status_code, 200)

        assessment_id = self._latest_stroke_assessment_id(self.username)
        self.assertIsNotNone(assessment_id)

        original_import = builtins.__import__

        def fake_import(name, globals=None, locals=None, fromlist=(), level=0):
            if name.startswith("reportlab"):
                raise ImportError("simulated missing reportlab")
            return original_import(name, globals, locals, fromlist, level)

        with patch("builtins.__import__", side_effect=fake_import):
            response = self.client.get(f"/download_report/stroke/{assessment_id}")

        self.assertEqual(response.status_code, 200)
        self.assertTrue(response.headers.get("Content-Type", "").startswith("text/plain"))
        self.assertIn("health companion", response.get_data(as_text=True).lower())

    def test_register_rejects_invalid_email(self):
        anon = app_module.app.test_client()
        response = anon.post(
            "/register",
            data={"username": f"u_{uuid.uuid4().hex[:8]}", "password": "Password123", "email": "invalid-email"},
            follow_redirects=True,
        )
        body = response.get_data(as_text=True).lower()
        self.assertEqual(response.status_code, 200)
        self.assertIn("invalid email address", body)

    def test_login_rejects_wrong_password(self):
        anon = app_module.app.test_client()
        bad_login = anon.post(
            "/login",
            data={"username": self.username, "password": "WrongPassword1"},
            follow_redirects=True,
        )
        body = bad_login.get_data(as_text=True).lower()
        self.assertEqual(bad_login.status_code, 200)
        self.assertIn("invalid username/email or password", body)

    def test_admin_can_toggle_user_active(self):
        admin_client = self._create_admin_client()

        conn = sqlite3.connect("health_companion.db")
        cur = conn.cursor()
        cur.execute("SELECT id FROM users WHERE username = ?", (self.username,))
        target_user_id = cur.fetchone()[0]
        conn.close()

        response = admin_client.post(
            f"/admin/users/{target_user_id}/toggle-active",
            data={"confirm": "yes"},
            follow_redirects=False,
        )
        self.assertEqual(response.status_code, 302)

        conn = sqlite3.connect("health_companion.db")
        cur = conn.cursor()
        cur.execute("SELECT is_active FROM users WHERE id = ?", (target_user_id,))
        state = cur.fetchone()[0]
        conn.close()
        self.assertEqual(state, 0)

    def test_admin_can_clear_stroke_predictions(self):
        self._submit_profile(gender="1")
        self.client.post("/stroke", data={}, follow_redirects=False)

        admin_client = self._create_admin_client()
        response = admin_client.post(
            "/admin/predictions/clear",
            data={"confirm": "yes", "scope": "stroke"},
            follow_redirects=False,
        )
        self.assertEqual(response.status_code, 302)
        self.assertIn("/admin/predictions", response.headers.get("Location", ""))

        conn = sqlite3.connect("health_companion.db")
        cur = conn.cursor()
        cur.execute("SELECT COUNT(*) FROM assessment_stroke")
        stroke_rows = cur.fetchone()[0]
        conn.close()
        self.assertEqual(stroke_rows, 0)

    def test_reports_and_download_work_for_all_assessment_types(self):
        self._submit_profile(gender="1")
        self.client.post("/stroke", data={}, follow_redirects=False)
        self.client.post("/diabetes", data={}, follow_redirects=False)
        self.client.post("/cardiovascular", data={}, follow_redirects=False)

        report_page = self.client.get("/report", follow_redirects=False)
        reports_page = self.client.get("/reports", follow_redirects=False)
        self.assertEqual(report_page.status_code, 200)
        self.assertEqual(reports_page.status_code, 200)

        conn = sqlite3.connect("health_companion.db")
        cur = conn.cursor()
        cur.execute("SELECT id FROM assessment_stroke WHERE username = ? ORDER BY id DESC LIMIT 1", (self.username,))
        stroke_id = cur.fetchone()[0]
        cur.execute("SELECT id FROM assessment_diabetes WHERE username = ? ORDER BY id DESC LIMIT 1", (self.username,))
        diabetes_id = cur.fetchone()[0]
        cur.execute("SELECT id FROM assessment_cardiovascular WHERE username = ? ORDER BY id DESC LIMIT 1", (self.username,))
        cardio_id = cur.fetchone()[0]
        conn.close()

        stroke_download = self.client.get(f"/download_report/stroke/{stroke_id}", follow_redirects=False)
        diabetes_download = self.client.get(f"/download_report/diabetes/{diabetes_id}", follow_redirects=False)
        cardio_download = self.client.get(f"/download_report/cardiovascular/{cardio_id}", follow_redirects=False)
        self.assertEqual(stroke_download.status_code, 200)
        self.assertEqual(diabetes_download.status_code, 200)
        self.assertEqual(cardio_download.status_code, 200)


if __name__ == "__main__":
    unittest.main()
