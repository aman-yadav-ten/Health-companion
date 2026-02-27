from .app_context import *


def _allow_local_otp_fallback():
    """
    Permit OTP fallback in non-production environments when SMTP delivery fails.
    This keeps forgot-password usable during local development/testing.
    """
    app_env = (os.getenv('APP_ENV') or os.getenv('FLASK_ENV') or 'development').strip().lower()
    explicit = str(os.getenv('ALLOW_LOCAL_OTP_FALLBACK', '')).strip().lower()
    if explicit in ('1', 'true', 'yes'):
        return True
    if explicit in ('0', 'false', 'no'):
        return False
    return app_env not in ('production', 'prod')


def login():
    """
    Handle user login.
    GET: Render login form.
    POST: Authenticate user and start session.
    If user logs in for the first time, redirect to profile completion.
    """
    admin_mode = request.path == '/admin-login'
    msg = request.args.get('msg', '').strip()
    if 'loggedin' in session:
        return redirect(url_for('admin_dashboard' if is_admin() else 'profile'))
    if request.method == 'POST' and 'username' in request.form and 'password' in request.form:
        username = request.form['username'].strip()
        password = request.form['password']
        connection = get_db_connection()
        cursor = connection.cursor()
        cursor.execute('SELECT * FROM users WHERE username = ? OR email = ?', (username, username.lower()))
        account = cursor.fetchone()
        cursor.close()
        connection.close()
        if account and check_password_hash(account['password_hash'], password):
            if int(account['is_active']) != 1:
                msg = 'Account is deactivated. Contact application owner.'
                return render_template('auth/login.html', msg=msg, admin_mode=admin_mode)
            if admin_mode and (account['role'] or 'user') != 'admin':
                msg = 'This account is not an admin account.'
                return render_template('auth/login.html', msg=msg, admin_mode=admin_mode)
            session['loggedin'] = True
            session['user_id'] = account['id']
            session['id'] = account['id']
            session['username'] = account['username']
            session['role'] = account['role'] if account['role'] else 'user'
            session.permanent = True

            # Role-aware redirect after login.
            if session['role'] == 'admin':
                return redirect(url_for('admin_dashboard'))
            return redirect(url_for('profile', first_time=1))
        else:
            msg = 'Invalid username/email or password.'
    return render_template('auth/login.html', msg=msg, admin_mode=admin_mode)

def forgot_password():
    """
    OTP-based forgot-password flow for both users and admins.
    """
    admin_mode = request.path == '/admin-forgot-password'
    msg = request.args.get('msg', '').strip()
    status = request.args.get('status', '').strip()
    step = request.args.get('step', 'request').strip().lower()
    email_prefill = request.args.get('email', '').strip().lower()

    if request.method == 'POST':
        action = request.form.get('action', '').strip()
        identity = request.form.get('identity', '').strip()
        email = request.form.get('email', '').strip().lower()
        otp_code = request.form.get('otp', '').strip()
        new_password = request.form.get('new_password', '')
        confirm_password = request.form.get('confirm_password', '')

        conn = get_db_connection()
        cursor = conn.cursor()

        if action == 'send_otp':
            if not identity:
                conn.close()
                return render_template(
                    'auth/forgot_password.html',
                    msg='Please enter your username or email.',
                    status='error',
                    admin_mode=admin_mode,
                    step='request',
                    email=''
                )

            cursor.execute(
                'SELECT id, username, email, role, is_active FROM users WHERE username = ? OR email = ?',
                (identity, identity.lower())
            )
            account = cursor.fetchone()
            if not account and admin_mode:
                cursor.execute("SELECT COUNT(*) AS count FROM users WHERE role = 'admin'")
                admin_count = int(cursor.fetchone()['count'])
                conn.close()
                if admin_count == 0:
                    return render_template(
                        'auth/forgot_password.html',
                        msg='No admin account found. Register an admin account first.',
                        status='error',
                        admin_mode=admin_mode,
                        step='request',
                        email=''
                    )
            else:
                conn.close()

            # Non-disclosing response for unknown identity.
            if not account:
                return render_template(
                    'auth/forgot_password.html',
                    msg='If an account exists, an OTP has been sent to its email.',
                    status='success',
                    admin_mode=admin_mode,
                    step='request',
                    email=''
                )

            if admin_mode and (account['role'] or 'user') != 'admin':
                return render_template(
                    'auth/forgot_password.html',
                    msg='This account is not an admin account.',
                    status='error',
                    admin_mode=admin_mode,
                    step='request',
                    email=''
                )
            if (not admin_mode) and (account['role'] or 'user') == 'admin':
                return render_template(
                    'auth/forgot_password.html',
                    msg='Use Admin Forgot Password for admin accounts.',
                    status='error',
                    admin_mode=admin_mode,
                    step='request',
                    email=''
                )
            if int(account['is_active']) != 1:
                return render_template(
                    'auth/forgot_password.html',
                    msg='Account is deactivated. Contact application owner.',
                    status='error',
                    admin_mode=admin_mode,
                    step='request',
                    email=''
                )

            otp_code = issue_password_reset_otp(account['id'], account['email'])
            email_sent = send_password_reset_otp_email(account['email'], account['username'], otp_code)
            if not email_sent:
                if _allow_local_otp_fallback():
                    return render_template(
                        'auth/forgot_password.html',
                        msg=f"SMTP send failed. Development OTP: {otp_code}",
                        status='success',
                        admin_mode=admin_mode,
                        step='verify',
                        email=account['email']
                    )
                return render_template(
                    'auth/forgot_password.html',
                    msg='Could not send OTP email. Check SMTP settings and try again.',
                    status='error',
                    admin_mode=admin_mode,
                    step='request',
                    email=account['email']
                )
            return render_template(
                'auth/forgot_password.html',
                msg='OTP sent to your registered email. Enter OTP to reset your password.',
                status='success',
                admin_mode=admin_mode,
                step='verify',
                email=account['email']
            )

        if action == 'verify_otp':
            if not email or not otp_code or not new_password or not confirm_password:
                conn.close()
                return render_template(
                    'auth/forgot_password.html',
                    msg='Please fill email, OTP, and both password fields.',
                    status='error',
                    admin_mode=admin_mode,
                    step='verify',
                    email=email
                )
            if len(new_password) < 8:
                conn.close()
                return render_template(
                    'auth/forgot_password.html',
                    msg='Password must be at least 8 characters.',
                    status='error',
                    admin_mode=admin_mode,
                    step='verify',
                    email=email
                )
            if new_password != confirm_password:
                conn.close()
                return render_template(
                    'auth/forgot_password.html',
                    msg='New password and confirm password do not match.',
                    status='error',
                    admin_mode=admin_mode,
                    step='verify',
                    email=email
                )

            cursor.execute('SELECT id, role, is_active FROM users WHERE email = ?', (email,))
            account = cursor.fetchone()
            if not account:
                conn.close()
                return render_template(
                    'auth/forgot_password.html',
                    msg='Invalid account details.',
                    status='error',
                    admin_mode=admin_mode,
                    step='verify',
                    email=email
                )
            if admin_mode and (account['role'] or 'user') != 'admin':
                conn.close()
                return render_template(
                    'auth/forgot_password.html',
                    msg='This account is not an admin account.',
                    status='error',
                    admin_mode=admin_mode,
                    step='verify',
                    email=email
                )
            if (not admin_mode) and (account['role'] or 'user') == 'admin':
                conn.close()
                return render_template(
                    'auth/forgot_password.html',
                    msg='Use Admin Forgot Password for admin accounts.',
                    status='error',
                    admin_mode=admin_mode,
                    step='verify',
                    email=email
                )
            if int(account['is_active']) != 1:
                conn.close()
                return render_template(
                    'auth/forgot_password.html',
                    msg='Account is deactivated. Contact application owner.',
                    status='error',
                    admin_mode=admin_mode,
                    step='verify',
                    email=email
                )

            verified, verify_msg = verify_password_reset_otp(account['id'], otp_code)
            if not verified:
                conn.close()
                return render_template(
                    'auth/forgot_password.html',
                    msg=verify_msg,
                    status='error',
                    admin_mode=admin_mode,
                    step='verify',
                    email=email
                )

            cursor.execute(
                'UPDATE users SET password_hash = ? WHERE id = ?',
                (generate_password_hash(new_password, method='pbkdf2:sha256'), account['id'])
            )
            # Invalidate leftover OTP records for the account.
            cursor.execute('UPDATE password_reset_otp SET consumed = 1 WHERE user_id = ?', (account['id'],))
            conn.commit()
            conn.close()
            login_endpoint = 'admin_login' if admin_mode else 'login'
            return redirect(url_for(login_endpoint, msg='Password reset successful. Please sign in.'))

        conn.close()

    return render_template(
        'auth/forgot_password.html',
        msg=msg,
        status=status,
        admin_mode=admin_mode,
        step=step if step in ('request', 'verify') else 'request',
        email=email_prefill
    )

def register():
    msg = ''
    admin_mode = request.path == '/admin-register'
    status = request.args.get('status', '').strip()
    step = request.args.get('step', 'request').strip().lower()
    username = request.args.get('username', '').strip()
    email = request.args.get('email', '').strip().lower()

    if request.method == 'POST':
        action = request.form.get('action', '').strip().lower()
        username = request.form.get('username', '').strip()
        email = request.form.get('email', '').strip().lower()
        password = request.form.get('password', '')
        otp_code = request.form.get('otp', '').strip()

        if action == 'send_otp':
            if not username or not password or not email:
                msg = 'Please fill out username, email, and password.'
                status = 'error'
                step = 'request'
            elif not re.match(r'[^@]+@[^@]+\.[^@]+', email):
                msg = 'Invalid email address !'
                status = 'error'
                step = 'request'
            elif not re.match(r'^[A-Za-z0-9_]{3,30}$', username):
                msg = 'Username must be 3-30 chars and use letters, numbers, or underscore!'
                status = 'error'
                step = 'request'
            elif len(password) < 8:
                msg = 'Password must be at least 8 characters long!'
                status = 'error'
                step = 'request'
            else:
                connection = get_db_connection()
                cursor = connection.cursor()
                cursor.execute('SELECT id FROM users WHERE username = ? OR email = ?', (username, email))
                account = cursor.fetchone()
                connection.close()
                if account:
                    msg = 'Account already exists !'
                    status = 'error'
                    step = 'request'
                else:
                    otp_value = issue_registration_otp(username, email, password)
                    email_sent = send_registration_otp_email(email, username, otp_value)
                    if not email_sent:
                        msg = 'Could not send OTP email. Check SMTP settings and try again.'
                        status = 'error'
                        step = 'request'
                    else:
                        msg = 'OTP sent to your email. Enter OTP to complete registration.'
                        status = 'success'
                        step = 'verify'

        elif action == 'verify_otp':
            if not username or not email or not otp_code:
                msg = 'Please provide username, email, and OTP.'
                status = 'error'
                step = 'verify'
            elif not re.match(r'[^@]+@[^@]+\.[^@]+', email):
                msg = 'Invalid email address !'
                status = 'error'
                step = 'verify'
            elif not re.match(r'^[A-Za-z0-9_]{3,30}$', username):
                msg = 'Invalid username.'
                status = 'error'
                step = 'verify'
            else:
                verified, verify_msg, password_hash = verify_registration_otp(username, email, otp_code)
                if not verified:
                    msg = verify_msg
                    status = 'error'
                    step = 'verify'
                else:
                    connection = get_db_connection()
                    cursor = connection.cursor()
                    cursor.execute('SELECT id FROM users WHERE username = ? OR email = ?', (username, email))
                    existing = cursor.fetchone()
                    if existing:
                        connection.close()
                        msg = 'Account already exists !'
                        status = 'error'
                        step = 'request'
                    else:
                        role_to_assign = 'admin' if admin_mode else 'user'

                        cursor.execute(
                            'INSERT INTO users (username, email, password_hash, role, is_active) VALUES (?, ?, ?, ?, 1)',
                            (username, email, password_hash, role_to_assign)
                        )
                        cursor.execute(
                            'UPDATE registration_otp SET consumed = 1 WHERE username = ? OR email = ?',
                            (username, email)
                        )
                        connection.commit()
                        connection.close()

                        if role_to_assign == 'admin':
                            final_msg = 'Admin account registered successfully via OTP. Please sign in.'
                            return redirect(url_for('admin_login', msg=final_msg))
                        return redirect(url_for('login', msg='You have successfully registered! Please sign in.'))
        else:
            msg = 'Invalid registration action.'
            status = 'error'
            step = 'request'

    return render_template(
        'auth/register.html',
        msg=msg,
        status=status,
        step=step if step in ('request', 'verify') else 'request',
        admin_mode=admin_mode,
        username=username,
        email=email
    )

def logout():
    session.pop('loggedin', None)
    session.pop('id', None)
    session.pop('user_id', None)
    session.pop('username', None)
    session.pop('role', None)
    return redirect(url_for('login'))
