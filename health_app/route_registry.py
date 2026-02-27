"""Centralized Flask route registration."""

from .app_context import admin_required, app, login_required
from . import admin_routes
from . import assessment_routes
from . import auth_routes
from . import page_routes


def register_routes():
    # Public pages
    app.add_url_rule("/", endpoint="landing", view_func=page_routes.landing, methods=["GET"])
    app.add_url_rule("/landing", endpoint="landing_page", view_func=page_routes.landing, methods=["GET"])
    app.add_url_rule("/smtp-test", endpoint="smtp_test", view_func=page_routes.smtp_test, methods=["GET", "POST"])

    # Authentication
    app.add_url_rule("/login", endpoint="login", view_func=auth_routes.login, methods=["GET", "POST"])
    app.add_url_rule("/admin-login", endpoint="admin_login", view_func=auth_routes.login, methods=["GET", "POST"])
    app.add_url_rule("/register", endpoint="register", view_func=auth_routes.register, methods=["GET", "POST"])
    app.add_url_rule("/admin-register", endpoint="admin_register", view_func=auth_routes.register, methods=["GET", "POST"])
    app.add_url_rule(
        "/forgot-password",
        endpoint="forgot_password",
        view_func=auth_routes.forgot_password,
        methods=["GET", "POST"],
    )
    app.add_url_rule(
        "/admin-forgot-password",
        endpoint="admin_forgot_password",
        view_func=auth_routes.forgot_password,
        methods=["GET", "POST"],
    )
    app.add_url_rule("/logout", endpoint="logout", view_func=auth_routes.logout, methods=["GET"])

    # User app pages
    app.add_url_rule("/index", endpoint="index", view_func=login_required(page_routes.index), methods=["GET"])
    app.add_url_rule("/profile", endpoint="profile", view_func=login_required(page_routes.profile), methods=["GET", "POST"])
    app.add_url_rule("/output", endpoint="output", view_func=login_required(page_routes.output), methods=["GET"])
    app.add_url_rule("/details", endpoint="details", view_func=login_required(page_routes.details), methods=["GET"])
    app.add_url_rule("/stroke-info", endpoint="stroke_info", view_func=login_required(page_routes.stroke_info), methods=["GET"])
    app.add_url_rule("/diabetes-info", endpoint="diabetes_info", view_func=login_required(page_routes.diabetes_info), methods=["GET"])
    app.add_url_rule(
        "/cardiovascular-info",
        endpoint="cardiovascular_info",
        view_func=login_required(page_routes.cardiovascular_info),
        methods=["GET"],
    )
    app.add_url_rule("/reports", endpoint="reports", view_func=login_required(page_routes.reports), methods=["GET"])
    app.add_url_rule("/report", endpoint="report", view_func=login_required(page_routes.report), methods=["GET"])
    app.add_url_rule(
        "/reports/download/<assessment_type>/<int:assessment_id>",
        endpoint="download_report",
        view_func=login_required(page_routes.download_report),
        methods=["GET"],
    )

    # Assessments and calculators
    app.add_url_rule("/stroke", endpoint="stroke", view_func=login_required(assessment_routes.stroke), methods=["GET", "POST"])
    app.add_url_rule("/diabetes", endpoint="diabetes", view_func=login_required(assessment_routes.diabetes), methods=["GET", "POST"])
    app.add_url_rule(
        "/cardiovascular",
        endpoint="cardiovascular",
        view_func=login_required(assessment_routes.cardiovascular),
        methods=["GET", "POST"],
    )
    app.add_url_rule(
        "/calculate-bmi",
        endpoint="calculate_bmi",
        view_func=login_required(assessment_routes.calculate_bmi),
        methods=["GET", "POST"],
    )
    app.add_url_rule(
        "/calculate-calories",
        endpoint="calculate_calories",
        view_func=login_required(assessment_routes.calculate_calories),
        methods=["GET", "POST"],
    )

    # Admin routes
    app.add_url_rule("/admin", endpoint="admin_dashboard", view_func=admin_required(admin_routes.admin_dashboard), methods=["GET"])
    app.add_url_rule(
        "/admin/reset-password",
        endpoint="admin_reset_password",
        view_func=admin_required(admin_routes.admin_reset_password),
        methods=["POST"],
    )
    app.add_url_rule("/admin/users", endpoint="admin_users", view_func=admin_required(admin_routes.admin_users), methods=["GET"])
    app.add_url_rule(
        "/admin/users/<int:target_user_id>",
        endpoint="admin_user_profile",
        view_func=admin_required(admin_routes.admin_user_profile),
        methods=["GET"],
    )
    app.add_url_rule(
        "/admin/users/<int:target_user_id>/toggle-active",
        endpoint="admin_toggle_user_active",
        view_func=admin_required(admin_routes.admin_toggle_user_active),
        methods=["POST"],
    )
    app.add_url_rule(
        "/admin/users/<int:target_user_id>/delete",
        endpoint="admin_delete_user",
        view_func=admin_required(admin_routes.admin_delete_user),
        methods=["POST"],
    )
    app.add_url_rule(
        "/admin/predictions",
        endpoint="admin_predictions",
        view_func=admin_required(admin_routes.admin_predictions),
        methods=["GET"],
    )
    app.add_url_rule(
        "/admin/predictions/clear",
        endpoint="admin_clear_predictions",
        view_func=admin_required(admin_routes.admin_clear_predictions),
        methods=["POST"],
    )
    app.add_url_rule("/admin/logs", endpoint="admin_logs", view_func=admin_required(admin_routes.admin_logs), methods=["GET"])


register_routes()
