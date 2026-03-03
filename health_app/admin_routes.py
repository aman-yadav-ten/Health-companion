from .app_context import *

def admin_dashboard():
    """
    Admin-only dashboard with high-level system metrics.
    """
    conn = get_db_connection()
    cursor = conn.cursor()

    cursor.execute("SELECT COUNT(*) AS count FROM users")
    total_users = cursor.fetchone()['count']

    cursor.execute("SELECT COUNT(*) AS count FROM users WHERE role = 'admin'")
    total_admins = cursor.fetchone()['count']

    cursor.execute("SELECT COUNT(*) AS count FROM users WHERE is_active = 1")
    active_users = cursor.fetchone()['count']

    cursor.execute("""
        SELECT COUNT(*) AS count
        FROM user_profile
        WHERE last_updated >= datetime('now', '-30 days')
    """)
    recent_active_users = cursor.fetchone()['count']

    cursor.execute("""
        SELECT
            (SELECT COUNT(*) FROM assessment_stroke) +
            (SELECT COUNT(*) FROM assessment_diabetes) +
            (SELECT COUNT(*) FROM assessment_cardiovascular) AS count
    """)
    total_predictions = cursor.fetchone()['count']

    cursor.execute("SELECT MAX(assessment_date) AS ts FROM assessment_stroke")
    last_stroke = cursor.fetchone()['ts']
    cursor.execute("SELECT MAX(assessment_date) AS ts FROM assessment_diabetes")
    last_diabetes = cursor.fetchone()['ts']
    cursor.execute("SELECT MAX(assessment_date) AS ts FROM assessment_cardiovascular")
    last_cardio = cursor.fetchone()['ts']

    conn.close()

    model_status = [
        {'name': 'Stroke', 'loaded': os.path.exists('health-models/models/stroke_model.pkl'), 'last_prediction': last_stroke},
        {'name': 'Diabetes', 'loaded': os.path.exists('health-models/models/diabetes_model.pkl'), 'last_prediction': last_diabetes},
        {'name': 'Cardiovascular', 'loaded': os.path.exists('health-models/models/cardio_model.pkl'), 'last_prediction': last_cardio},
    ]

    return render_template(
        'admin/dashboard.html',
        username=session.get('username', 'Admin'),
        msg=request.args.get('msg', ''),
        status=request.args.get('status', ''),
        total_users=total_users,
        total_admins=total_admins,
        active_users=active_users,
        recent_active_users=recent_active_users,
        total_predictions=total_predictions,
        model_status=model_status
    )

def admin_reset_password():
    """
    Allow admin to reset own password from admin dashboard.
    Requires current password verification.
    """
    current_password = request.form.get('current_password', '')
    new_password = request.form.get('new_password', '')
    confirm_password = request.form.get('confirm_password', '')

    if not current_password or not new_password or not confirm_password:
        return redirect(url_for('admin_dashboard', status='error', msg='Please fill all password fields.'))

    if len(new_password) < 8:
        return redirect(url_for('admin_dashboard', status='error', msg='New password must be at least 8 characters.'))

    if new_password != confirm_password:
        return redirect(url_for('admin_dashboard', status='error', msg='New password and confirm password do not match.'))

    user_id = get_current_user_id()
    conn = get_db_connection()
    cursor = conn.cursor()
    cursor.execute('SELECT password_hash, username FROM users WHERE id = ?', (user_id,))
    user = cursor.fetchone()

    if not user:
        conn.close()
        return redirect(url_for('logout'))

    if not check_password_hash(user['password_hash'], current_password):
        conn.close()
        return redirect(url_for('admin_dashboard', status='error', msg='Current password is incorrect.'))

    cursor.execute(
        'UPDATE users SET password_hash = ? WHERE id = ?',
        (generate_password_hash(new_password, method='pbkdf2:sha256'), user_id)
    )
    conn.commit()
    conn.close()

    log_admin_action('reset_own_admin_password', target_user_id=user_id, details=f"username={user['username']}")
    return redirect(url_for('admin_dashboard', status='success', msg='Admin password updated successfully.'))

def admin_users():
    """Admin user management list."""
    conn = get_db_connection()
    cursor = conn.cursor()
    cursor.execute('''
        SELECT
            u.id, u.username, u.email, u.role, u.is_active, u.created_at,
            up.profile_complete, up.last_updated
        FROM users u
        LEFT JOIN user_profile up ON up.user_id = u.id
        ORDER BY u.created_at DESC
    ''')
    users = cursor.fetchall()
    conn.close()
    return render_template(
        'admin/users.html',
        users=users,
        current_user_id=get_current_user_id(),
        msg=request.args.get('msg', ''),
        status=request.args.get('status', '')
    )

def admin_user_profile(target_user_id):
    """Read-only detail view of a user and profile."""
    conn = get_db_connection()
    cursor = conn.cursor()
    cursor.execute('SELECT id, username, email, role, is_active, created_at FROM users WHERE id = ?', (target_user_id,))
    user = cursor.fetchone()
    if not user:
        conn.close()
        return abort(404)

    cursor.execute('SELECT * FROM user_profile WHERE user_id = ?', (target_user_id,))
    profile_row = cursor.fetchone()
    profile = dict(profile_row) if profile_row else None

    cursor.execute('SELECT COUNT(*) AS count FROM assessment_stroke WHERE username = ?', (user['username'],))
    stroke_count = cursor.fetchone()['count']
    cursor.execute('SELECT COUNT(*) AS count FROM assessment_diabetes WHERE username = ?', (user['username'],))
    diabetes_count = cursor.fetchone()['count']
    cursor.execute('SELECT COUNT(*) AS count FROM assessment_cardiovascular WHERE username = ?', (user['username'],))
    cardio_count = cursor.fetchone()['count']
    conn.close()

    return render_template(
        'admin/user_profile.html',
        user=user,
        profile=profile,
        stroke_count=stroke_count,
        diabetes_count=diabetes_count,
        cardio_count=cardio_count,
        msg=request.args.get('msg', ''),
        status=request.args.get('status', '')
    )

def admin_toggle_user_active(target_user_id):
    """
    Toggle user active state.
    Requires explicit confirmation to prevent accidental destructive actions.
    """
    if request.form.get('confirm') != 'yes':
        return redirect(url_for('admin_user_profile', target_user_id=target_user_id))

    current_user_id = get_current_user_id()
    if target_user_id == current_user_id:
        return redirect(url_for('admin_user_profile', target_user_id=target_user_id, status='error', msg='You cannot deactivate your own account.'))

    conn = get_db_connection()
    cursor = conn.cursor()
    cursor.execute('SELECT id, username, is_active FROM users WHERE id = ?', (target_user_id,))
    user = cursor.fetchone()
    if not user:
        conn.close()
        return abort(404)

    new_state = 0 if user['is_active'] == 1 else 1
    try:
        cursor.execute('BEGIN IMMEDIATE')
        cursor.execute('UPDATE users SET is_active = ? WHERE id = ?', (new_state, target_user_id))
        conn.commit()
    except sqlite3.OperationalError as exc:
        conn.rollback()
        conn.close()
        return redirect(url_for('admin_user_profile', target_user_id=target_user_id, status='error', msg=f'Action failed: {str(exc)}'))
    conn.close()

    action = 'deactivate_user' if new_state == 0 else 'reactivate_user'
    log_admin_action(action, target_user_id, f"user={user['username']}")
    status_msg = 'User deactivated successfully.' if new_state == 0 else 'User reactivated successfully.'
    return redirect(url_for('admin_user_profile', target_user_id=target_user_id, status='success', msg=status_msg))

def admin_delete_user(target_user_id):
    """
    Permanently delete user account and related data.
    Requires explicit confirmation in POST payload.
    """
    if request.form.get('confirm') != 'yes':
        return redirect(url_for('admin_user_profile', target_user_id=target_user_id))

    current_user_id = get_current_user_id()
    if target_user_id == current_user_id:
        return redirect(url_for('admin_user_profile', target_user_id=target_user_id, status='error', msg='You cannot delete your own account.'))

    last_error = None
    username = None
    for _ in range(5):
        conn = None
        try:
            conn = get_db_connection()
            cursor = conn.cursor()
            cursor.execute('BEGIN IMMEDIATE')
            cursor.execute('SELECT id, username, role FROM users WHERE id = ?', (target_user_id,))
            user = cursor.fetchone()
            if not user:
                conn.rollback()
                conn.close()
                return abort(404)

            if user['role'] == 'admin':
                cursor.execute("SELECT COUNT(*) AS count FROM users WHERE role = 'admin' AND is_active = 1")
                active_admins = cursor.fetchone()['count']
                if active_admins <= 1:
                    conn.rollback()
                    conn.close()
                    return redirect(url_for('admin_user_profile', target_user_id=target_user_id, status='error', msg='At least one active admin account is required.'))

            username = user['username']

            # Delete legacy username-keyed prediction history rows.
            cursor.execute('DELETE FROM assessment_stroke WHERE username = ?', (username,))
            cursor.execute('DELETE FROM assessment_diabetes WHERE username = ?', (username,))
            cursor.execute('DELETE FROM assessment_cardiovascular WHERE username = ?', (username,))
            cursor.execute('DELETE FROM account_stroke WHERE username = ?', (username,))
            cursor.execute('DELETE FROM account_dia WHERE username = ?', (username,))
            cursor.execute('DELETE FROM account_cardiovascular WHERE username = ?', (username,))
            cursor.execute('DELETE FROM account_bmi WHERE username = ?', (username,))

            # Cascades to user_profile/prediction_results/system_logs target reference behavior.
            cursor.execute('DELETE FROM users WHERE id = ?', (target_user_id,))
            conn.commit()
            conn.close()
            log_admin_action('delete_user', None, f"user={username}; deleted_user_id={target_user_id}")
            return redirect(url_for('admin_users', status='success', msg='User deleted successfully.'))
        except sqlite3.OperationalError as exc:
            last_error = str(exc)
            if conn:
                conn.rollback()
                conn.close()
            if 'locked' in last_error.lower():
                time.sleep(0.2)
                continue
            break
        finally:
            if conn:
                try:
                    conn.close()
                except Exception:
                    pass

    return redirect(url_for('admin_user_profile', target_user_id=target_user_id, status='error', msg=f"Delete failed: {last_error or 'database busy'}"))

def admin_predictions():
    """Admin view of prediction history across all model types."""
    conn = get_db_connection()
    cursor = conn.cursor()
    cursor.execute('''
        SELECT 'stroke' AS model_type, id, username, assessment_date, risk_level, probability
        FROM assessment_stroke
        UNION ALL
        SELECT 'diabetes' AS model_type, id, username, assessment_date, risk_level, probability
        FROM assessment_diabetes
        UNION ALL
        SELECT 'cardiovascular' AS model_type, id, username, assessment_date, risk_level, probability
        FROM assessment_cardiovascular
        ORDER BY assessment_date DESC
        LIMIT 300
    ''')
    predictions = cursor.fetchall()
    conn.close()
    return render_template(
        'admin/predictions.html',
        predictions=predictions,
        msg=request.args.get('msg', ''),
        status=request.args.get('status', '')
    )

def admin_clear_predictions():
    """
    Clear prediction history by scope (all/model).
    Requires explicit POST confirmation.
    """
    if request.form.get('confirm') != 'yes':
        return redirect(url_for('admin_predictions', status='error', msg='Confirmation required to clear history.'))

    scope = (request.form.get('scope') or 'all').strip().lower()
    table_map = {
        'stroke': 'assessment_stroke',
        'diabetes': 'assessment_diabetes',
        'cardiovascular': 'assessment_cardiovascular'
    }

    last_error = None
    for _ in range(5):
        conn = None
        try:
            conn = get_db_connection()
            cursor = conn.cursor()
            cursor.execute('BEGIN IMMEDIATE')

            if scope == 'all':
                cursor.execute('DELETE FROM assessment_stroke')
                cursor.execute('DELETE FROM assessment_diabetes')
                cursor.execute('DELETE FROM assessment_cardiovascular')
                cursor.execute('DELETE FROM prediction_results')
            elif scope in table_map:
                cursor.execute(f'DELETE FROM {table_map[scope]}')
                cursor.execute('DELETE FROM prediction_results WHERE model_type = ?', (scope,))
            else:
                conn.rollback()
                conn.close()
                return redirect(url_for('admin_predictions', status='error', msg='Invalid clear scope selected.'))

            conn.commit()
            conn.close()
            log_admin_action('clear_predictions', details=f"scope={scope}")
            return redirect(url_for('admin_predictions', status='success', msg=f'Prediction history cleared for: {scope}.'))
        except sqlite3.OperationalError as exc:
            last_error = str(exc)
            if conn:
                conn.rollback()
                conn.close()
            if 'locked' in last_error.lower():
                time.sleep(0.2)
                continue
            break
        finally:
            if conn:
                try:
                    conn.close()
                except Exception:
                    pass
    return redirect(url_for('admin_predictions', status='error', msg=f"Clear failed: {last_error or 'database busy'}"))

def admin_logs():
    """Admin action audit trail."""
    conn = get_db_connection()
    cursor = conn.cursor()
    cursor.execute('''
        SELECT
            l.id, l.action, l.details, l.created_at,
            a.username AS admin_username,
            t.username AS target_username
        FROM system_logs l
        LEFT JOIN users a ON a.id = l.admin_user_id
        LEFT JOIN users t ON t.id = l.target_user_id
        ORDER BY l.created_at DESC
        LIMIT 300
    ''')
    logs = cursor.fetchall()
    conn.close()
    return render_template('admin/logs.html', logs=logs)
