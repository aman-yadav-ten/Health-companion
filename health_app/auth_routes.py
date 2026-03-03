from .app_context import *


def _valid_username(username):
    return bool(re.fullmatch(r'^[A-Za-z0-9_]{3,30}$', username or ''))


def _valid_dob(date_of_birth):
    return bool(re.fullmatch(r'^\d{4}-\d{2}-\d{2}$', date_of_birth or ''))


def login():
    msg = request.args.get('msg', '').strip()
    status = request.args.get('status', '').strip()

    if 'loggedin' in session:
        return redirect(url_for('profile'))

    if request.method == 'POST':
        username = request.form.get('username', '').strip()
        password = request.form.get('password', '')
        captcha = request.form.get('captcha', '').strip()

        if not username or not password or not captcha:
            msg = 'Please fill all required fields.'
            status = 'error'
        elif not validate_captcha(captcha):
            msg = 'Invalid CAPTCHA. Please try again.'
            status = 'error'
        else:
            connection = get_db_connection()
            cursor = connection.cursor()
            cursor.execute('SELECT id, username, password_hash FROM users WHERE username = ?', (username,))
            account = cursor.fetchone()
            connection.close()

            if account and check_password_hash(account['password_hash'], password):
                session['loggedin'] = True
                session['user_id'] = account['id']
                session['id'] = account['id']
                session['username'] = account['username']
                session.permanent = True
                return redirect(url_for('profile', first_time=1))

            msg = 'Invalid username or password.'
            status = 'error'

    captcha_code = generate_captcha()
    return render_template('auth/login.html', msg=msg, status=status, captcha_code=captcha_code)


def register():
    msg = request.args.get('msg', '').strip()
    status = request.args.get('status', '').strip()

    form_data = {
        'full_name': '',
        'date_of_birth': '',
        'username': '',
    }

    if request.method == 'POST':
        full_name = request.form.get('full_name', '').strip()
        date_of_birth = request.form.get('date_of_birth', '').strip()
        username = request.form.get('username', '').strip()
        password = request.form.get('password', '')
        captcha = request.form.get('captcha', '').strip()

        form_data.update({
            'full_name': full_name,
            'date_of_birth': date_of_birth,
            'username': username,
        })

        if not full_name or not date_of_birth or not username or not password or not captcha:
            msg = 'Please fill all required fields.'
            status = 'error'
        elif len(full_name) < 2:
            msg = 'Full name must be at least 2 characters.'
            status = 'error'
        elif not _valid_dob(date_of_birth):
            msg = 'Date of birth must be in YYYY-MM-DD format.'
            status = 'error'
        elif not _valid_username(username):
            msg = 'Username must be 3-30 chars using letters, numbers, or underscore.'
            status = 'error'
        elif len(password) < 8:
            msg = 'Password must be at least 8 characters long.'
            status = 'error'
        elif not validate_captcha(captcha):
            msg = 'Invalid CAPTCHA. Please try again.'
            status = 'error'
        else:
            connection = get_db_connection()
            cursor = connection.cursor()
            cursor.execute('SELECT id FROM users WHERE username = ?', (username,))
            existing = cursor.fetchone()
            if existing:
                connection.close()
                msg = 'Username already exists.'
                status = 'error'
            else:
                cursor.execute(
                    'INSERT INTO users (full_name, date_of_birth, username, password_hash) VALUES (?, ?, ?, ?)',
                    (full_name, date_of_birth, username, generate_password_hash(password, method='pbkdf2:sha256')),
                )
                connection.commit()
                connection.close()
                return redirect(url_for('login', msg='You have successfully registered! Please sign in.', status='success'))

    captcha_code = generate_captcha()
    return render_template(
        'auth/register.html',
        msg=msg,
        status=status,
        full_name=form_data['full_name'],
        date_of_birth=form_data['date_of_birth'],
        username=form_data['username'],
        captcha_code=captcha_code,
    )


def forgot_password():
    msg = request.args.get('msg', '').strip()
    status = request.args.get('status', '').strip()
    step = request.args.get('step', 'verify_identity').strip().lower()
    reset_username = request.args.get('username', '').strip()

    if step not in ('verify_identity', 'reset_password'):
        step = 'verify_identity'

    if request.method == 'POST':
        action = request.form.get('action', '').strip()

        if action == 'verify_identity':
            full_name = request.form.get('full_name', '').strip()
            date_of_birth = request.form.get('date_of_birth', '').strip()
            username = request.form.get('username', '').strip()
            captcha = request.form.get('captcha', '').strip()

            if not full_name or not date_of_birth or not username or not captcha:
                msg = 'Please fill all required fields.'
                status = 'error'
                step = 'verify_identity'
            elif not _valid_dob(date_of_birth):
                msg = 'Date of birth must be in YYYY-MM-DD format.'
                status = 'error'
                step = 'verify_identity'
            elif not _valid_username(username):
                msg = 'Invalid username format.'
                status = 'error'
                step = 'verify_identity'
            elif not validate_captcha(captcha):
                msg = 'Invalid CAPTCHA. Please try again.'
                status = 'error'
                step = 'verify_identity'
            else:
                conn = get_db_connection()
                cursor = conn.cursor()
                cursor.execute(
                    '''
                    SELECT id FROM users
                    WHERE username = ?
                      AND full_name = ?
                      AND date_of_birth = ?
                    ''',
                    (username, full_name, date_of_birth),
                )
                account = cursor.fetchone()
                conn.close()
                if not account:
                    msg = 'Provided details do not match our records.'
                    status = 'error'
                    step = 'verify_identity'
                else:
                    session['password_reset_verified_user_id'] = account['id']
                    session['password_reset_verified_username'] = username
                    msg = 'Identity verified. Set your new password.'
                    status = 'success'
                    step = 'reset_password'
                    reset_username = username

        elif action == 'reset_password':
            username = request.form.get('username', '').strip()
            new_password = request.form.get('new_password', '')
            confirm_password = request.form.get('confirm_password', '')
            captcha = request.form.get('captcha', '').strip()
            verified_user_id = session.get('password_reset_verified_user_id')
            verified_username = session.get('password_reset_verified_username')

            if not username or not new_password or not confirm_password or not captcha:
                msg = 'Please fill all required fields.'
                status = 'error'
                step = 'reset_password'
                reset_username = username
            elif not verified_user_id or not verified_username or verified_username != username:
                msg = 'Verification session expired. Please verify identity again.'
                status = 'error'
                step = 'verify_identity'
                session.pop('password_reset_verified_user_id', None)
                session.pop('password_reset_verified_username', None)
            elif len(new_password) < 8:
                msg = 'Password must be at least 8 characters.'
                status = 'error'
                step = 'reset_password'
                reset_username = username
            elif new_password != confirm_password:
                msg = 'New password and confirm password do not match.'
                status = 'error'
                step = 'reset_password'
                reset_username = username
            elif not validate_captcha(captcha):
                msg = 'Invalid CAPTCHA. Please try again.'
                status = 'error'
                step = 'reset_password'
                reset_username = username
            else:
                conn = get_db_connection()
                cursor = conn.cursor()
                cursor.execute('SELECT id FROM users WHERE id = ? AND username = ?', (verified_user_id, username))
                account = cursor.fetchone()
                if not account:
                    conn.close()
                    msg = 'Verification session expired. Please verify identity again.'
                    status = 'error'
                    step = 'verify_identity'
                    session.pop('password_reset_verified_user_id', None)
                    session.pop('password_reset_verified_username', None)
                else:
                    cursor.execute(
                        'UPDATE users SET password_hash = ? WHERE id = ?',
                        (generate_password_hash(new_password, method='pbkdf2:sha256'), verified_user_id),
                    )
                    conn.commit()
                    conn.close()
                    session.pop('password_reset_verified_user_id', None)
                    session.pop('password_reset_verified_username', None)
                    return redirect(url_for('login', msg='Password reset successful. Please sign in.', status='success'))

    captcha_code = generate_captcha()
    return render_template(
        'auth/forgot_password.html',
        msg=msg,
        status=status,
        step=step,
        username=reset_username,
        captcha_code=captcha_code,
    )


def logout():
    session.pop('loggedin', None)
    session.pop('id', None)
    session.pop('user_id', None)
    session.pop('username', None)
    session.pop('role', None)
    session.pop('password_reset_verified_user_id', None)
    session.pop('password_reset_verified_username', None)
    session.pop('captcha_code', None)
    return redirect(url_for('login'))
