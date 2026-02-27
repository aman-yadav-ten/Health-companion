from .app_context import *

def smtp_test():
    """
    Lightweight SMTP verification endpoint.
    GET: Show quick usage text.
    POST: Send test email to provided address.
    """
    if request.method == 'GET':
        return (
            "SMTP test endpoint is ready. "
            "POST form-data: to=<email> to send a test email.",
            200
        )

    to_email = request.form.get('to', '').strip().lower()
    if not to_email or not re.match(r'[^@]+@[^@]+\.[^@]+', to_email):
        return {"ok": False, "message": "Provide a valid email in form field: to"}, 400

    ok, message = send_smtp_test_email(to_email)
    status_code = 200 if ok else 500
    return {"ok": ok, "message": message}, status_code

def landing():
    """
    Public landing page shown as the default app route.
    """
    return render_template('pages/landing.html', msg='')

def index():
    """
    Dashboard page - accessible only to logged-in users.
    Displays health overview and prediction shortcuts.
    """
    if is_admin():
        return redirect(url_for('admin_dashboard'))
    user_id = get_current_user_id()
    if not profile_exists(user_id):
        return redirect(url_for('profile', msg='Please complete your health profile before using predictions.'))
    username = session.get('username')
    conn = get_db_connection()
    cursor = conn.cursor()

    def latest_prediction_meta(table_name):
        cursor.execute(
            f'''
            SELECT risk_level, probability, assessment_date
            FROM {table_name}
            WHERE username = ?
            ORDER BY assessment_date DESC, id DESC
            LIMIT 1
            ''',
            (username,)
        )
        row = cursor.fetchone()
        if not row:
            return {
                'exists': False,
                'risk_level': 'Not analyzed yet',
                'probability_text': '',
                'assessment_date': '',
                'cta_text': 'Start Assessment'
            }

        probability_text = ''
        if row['probability'] is not None:
            probability_text = f"{float(row['probability']) * 100:.1f}%"
        return {
            'exists': True,
            'risk_level': row['risk_level'] or 'Unknown',
            'probability_text': probability_text,
            'assessment_date': (row['assessment_date'] or '')[:10],
            'cta_text': 'Analyze Again'
        }

    prediction_cards = {
        'stroke': latest_prediction_meta('assessment_stroke'),
        'cardiovascular': latest_prediction_meta('assessment_cardiovascular'),
        'diabetes': latest_prediction_meta('assessment_diabetes'),
    }
    conn.close()
    return render_template('pages/index.html', msg='', prediction_cards=prediction_cards)

def profile():
    """
    User health profile management page.
    GET: Display user's current profile or profile form if incomplete
    POST: Save/update user's health profile
    """
    # Authentication check
    if 'loggedin' not in session:
        return redirect(url_for('landing'))
    user_id = get_current_user_id()
    if not user_id:
        return redirect(url_for('logout'))

    msg = request.args.get('msg', '')
    first_time = str(request.args.get('first_time', '0')).lower() in ('1', 'true', 'yes')
    
    if request.method == 'POST':
        # Collect profile data from form
        try:
            required_fields = [
                'age', 'gender', 'height', 'weight', 'blood_pressure_systolic',
                'blood_pressure_diastolic', 'glucose_level', 'cholesterol',
                'smoking_status', 'hypertension', 'heart_disease', 'ever_married',
                'work_type', 'residence_type', 'alcohol_consumption', 'physical_activity'
            ]
            missing_fields = [field for field in required_fields if request.form.get(field) in (None, '')]
            if missing_fields:
                msg = 'Please complete all required profile fields.'
                existing_profile = get_user_profile(user_id)
                return render_template('profile/profile.html', msg=msg, profile=existing_profile, first_time=first_time)

            height = float(request.form.get('height', 0))
            weight = float(request.form.get('weight', 0))
            bmi = weight / ((height / 100) ** 2) if height > 0 else 0
            
            profile_data = {
                'age': int(request.form.get('age', 0)),
                'gender': int(request.form.get('gender', 0)),
                'height': height,
                'weight': weight,
                'bmi': round(bmi, 2),
                'blood_pressure_systolic': int(request.form.get('blood_pressure_systolic', 0)),
                'blood_pressure_diastolic': int(request.form.get('blood_pressure_diastolic', 0)),
                'glucose_level': int(request.form.get('glucose_level', 0)),
                'cholesterol': int(request.form.get('cholesterol', 0)),
                'smoking_status': int(request.form.get('smoking_status', 0)),
                'hypertension': int(request.form.get('hypertension', 0)),
                'heart_disease': int(request.form.get('heart_disease', 0)),
                'ever_married': int(request.form.get('ever_married', 0)),
                'work_type': int(request.form.get('work_type', 0)),
                'residence_type': int(request.form.get('residence_type', 0)),
                'pregnancies': int(request.form.get('pregnancies', 0)) if request.form.get('pregnancies') else 0,
                'insulin': int(request.form.get('insulin', 0)) if request.form.get('insulin') else 0,
                'skin_thickness': int(request.form.get('skin_thickness', 0)) if request.form.get('skin_thickness') else 0,
                'diabetes_pedigree_function': float(request.form.get('diabetes_pedigree_function', 0)) if request.form.get('diabetes_pedigree_function') else 0.0,
                'alcohol_consumption': int(request.form.get('alcohol_consumption', 0)),
                'physical_activity': int(request.form.get('physical_activity', 0)),
            }

            if profile_data['height'] <= 0 or profile_data['weight'] <= 0:
                msg = 'Height and weight must be greater than zero.'
                existing_profile = get_user_profile(user_id)
                return render_template('profile/profile.html', msg=msg, profile=existing_profile, first_time=first_time)

            # Save profile and continue to dashboard.
            save_user_profile(user_id, profile_data)
            return redirect(url_for('index'))
        
        except ValueError as e:
            msg = 'Invalid input: Please check your entries'
    
    # GET request - Load existing profile
    existing_profile = get_user_profile(user_id)
    
    bmr_value = None
    if existing_profile and all(existing_profile.get(k) not in (None, '') for k in ['age', 'gender', 'height', 'weight']):
        bmr_value = calculate_bmr('male' if int(existing_profile['gender']) == 1 else 'female',
                                  float(existing_profile['weight']),
                                  float(existing_profile['height']),
                                  int(existing_profile['age']))

    return render_template('profile/profile.html', msg=msg, profile=existing_profile, first_time=first_time, bmr_value=bmr_value)

def output():
    """
    Output page - show results (protected).
    """
    if 'loggedin' not in session:
        return redirect(url_for('landing'))
    msg=' '
    return render_template('pages/output.html', msg=msg)

def details():
    # Authentication check - protect this route
    if 'loggedin' not in session:
        return redirect(url_for('landing'))
    return render_template('profile/details.html')

def stroke_info():
    # Authentication check - protect this route
    if 'loggedin' not in session:
        return redirect(url_for('landing'))
    return render_template('assessments/stroke/info.html')

def diabetes_info():
    # Authentication check - protect this route
    if 'loggedin' not in session:
        return redirect(url_for('landing'))
    return render_template('assessments/diabetes/info.html')

def cardiovascular_info():
    # Authentication check - protect this route
    if 'loggedin' not in session:
        return redirect(url_for('landing'))
    return render_template('assessments/cardiovascular/info.html')

def reports():
    """
    Display user health reports and analytics.
    """
    if 'loggedin' not in session:
        return redirect(url_for('landing'))
    
    # Fetch all assessments for this user
    conn = get_db_connection()
    cursor = conn.cursor()
    
    # Fetch all cardiovascular assessments
    cursor.execute('''
        SELECT id, assessment_date, risk_level, probability, patient_data, report_text 
        FROM assessment_cardiovascular 
        WHERE username = ?
        ORDER BY assessment_date DESC
    ''', (session['username'],))
    cardio_assessments = cursor.fetchall()
    
    # Fetch all diabetes assessments
    cursor.execute('''
        SELECT id, assessment_date, risk_level, probability, patient_data, report_text 
        FROM assessment_diabetes 
        WHERE username = ?
        ORDER BY assessment_date DESC
    ''', (session['username'],))
    diabetes_assessments = cursor.fetchall()
    
    # Fetch all stroke assessments
    cursor.execute('''
        SELECT id, assessment_date, risk_level, probability, patient_data, report_text 
        FROM assessment_stroke 
        WHERE username = ?
        ORDER BY assessment_date DESC
    ''', (session['username'],))
    stroke_assessments = cursor.fetchall()
    
    conn.close()
    
    # Convert to dict-like structure for template and parse patient_data JSON
    def parse_assessments(rows):
        parsed = []
        for row in rows:
            assessment = dict(row)
            # Parse patient_data JSON if it's a string
            if isinstance(assessment['patient_data'], str):
                try:
                    assessment['patient_data'] = json.loads(assessment['patient_data'])
                except (json.JSONDecodeError, TypeError):
                    assessment['patient_data'] = {}
            parsed.append(assessment)
        return parsed
    
    assessments = {
        'cardiovascular': parse_assessments(cardio_assessments) if cardio_assessments else [],
        'diabetes': parse_assessments(diabetes_assessments) if diabetes_assessments else [],
        'stroke': parse_assessments(stroke_assessments) if stroke_assessments else []
    }
    
    return render_template('reports/reports.html', username=session['username'], assessments=assessments)

def report():
    """
    Display comprehensive personalized health report.
    Combines user profile data with all prediction results.
    """
    if 'loggedin' not in session:
        return redirect(url_for('landing'))
    user_id = get_current_user_id()
    if not user_id:
        return redirect(url_for('logout'))
    
    # Check if user has profile
    profile = get_user_profile(user_id)
    if not profile:
        return redirect(url_for('profile'))
    
    conn = get_db_connection()
    cursor = conn.cursor()
    
    # Fetch latest assessment from each prediction type
    cursor.execute('''
        SELECT assessment_date, risk_level, probability, patient_data, report_text
        FROM assessment_cardiovascular 
        WHERE username = ?
        ORDER BY assessment_date DESC LIMIT 1
    ''', (session['username'],))
    cardio = cursor.fetchone()
    
    cursor.execute('''
        SELECT assessment_date, risk_level, probability, patient_data, report_text
        FROM assessment_diabetes 
        WHERE username = ?
        ORDER BY assessment_date DESC LIMIT 1
    ''', (session['username'],))
    diabetes = cursor.fetchone()
    
    cursor.execute('''
        SELECT assessment_date, risk_level, probability, patient_data, report_text
        FROM assessment_stroke 
        WHERE username = ?
        ORDER BY assessment_date DESC LIMIT 1
    ''', (session['username'],))
    stroke = cursor.fetchone()
    
    conn.close()
    
    # Parse assessments
    assessments = {}
    for assessment_type, data in [('cardio', cardio), ('diabetes', diabetes), ('stroke', stroke)]:
        if data:
            assessment = dict(data)
            if isinstance(assessment['patient_data'], str):
                try:
                    assessment['patient_data'] = json.loads(assessment['patient_data'])
                except (json.JSONDecodeError, TypeError):
                    assessment['patient_data'] = {}
            assessments[assessment_type] = assessment
        else:
            assessments[assessment_type] = None
    
    # Prepare user profile data for display
    profile_data = dict(profile) if profile else {}
    
    # Calculate BMI category
    if profile_data.get('bmi'):
        bmi = profile_data['bmi']
        if bmi < 18.5:
            bmi_category = 'Underweight'
        elif bmi < 25:
            bmi_category = 'Normal Weight'
        elif bmi < 30:
            bmi_category = 'Overweight'
        else:
            bmi_category = 'Obese'
        profile_data['bmi_category'] = bmi_category
    
    # Calculate BP category
    if profile_data.get('blood_pressure_systolic') and profile_data.get('blood_pressure_diastolic'):
        systolic = profile_data['blood_pressure_systolic']
        diastolic = profile_data['blood_pressure_diastolic']
        if systolic < 120 and diastolic < 80:
            bp_category = 'Normal'
        elif systolic < 130 and diastolic < 80:
            bp_category = 'Elevated'
        elif systolic < 140 or diastolic < 90:
            bp_category = 'Stage 1 Hypertension'
        else:
            bp_category = 'Stage 2 Hypertension'
        profile_data['bp_category'] = bp_category
    
    # Generate preventive health suggestions
    suggestions = generate_health_suggestions(profile_data, assessments)
    
    return render_template('reports/report.html', 
                         username=session['username'],
                         profile=profile_data,
                         assessments=assessments,
                         suggestions=suggestions)

def download_report(assessment_type, assessment_id):
    """
    Generate and download a PDF report.
    """
    if 'loggedin' not in session:
        return redirect(url_for('landing'))
    
    conn = get_db_connection()
    cursor = conn.cursor()
    
    # Map assessment type to table
    table_map = {
        'cardiovascular': 'assessment_cardiovascular',
        'diabetes': 'assessment_diabetes',
        'stroke': 'assessment_stroke'
    }
    
    if assessment_type not in table_map:
        return "Invalid assessment type", 400
    
    table = table_map[assessment_type]
    cursor.execute(f'''
        SELECT report_text, assessment_date 
        FROM {table}
        WHERE id = ? AND username = ?
    ''', (assessment_id, session['username']))
    
    result = cursor.fetchone()
    conn.close()
    
    if not result:
        return "Assessment not found", 404
    
    report_text = result['report_text']
    assessment_date = result['assessment_date']
    
    try:
        from reportlab.lib.pagesizes import letter, A4
        from reportlab.lib.styles import getSampleStyleSheet, ParagraphStyle
        from reportlab.lib.units import inch
        from reportlab.platypus import SimpleDocTemplate, Paragraph, Spacer, Table, TableStyle, PageBreak
        from reportlab.lib import colors
        
        # Create PDF
        pdf_buffer = BytesIO()
        doc = SimpleDocTemplate(pdf_buffer, pagesize=letter)
        story = []
        styles = getSampleStyleSheet()
        
        # Add title
        title_style = ParagraphStyle(
            'CustomTitle',
            parent=styles['Heading1'],
            fontSize=20,
            textColor=colors.HexColor('#0f172a'),
            spaceAfter=30,
            alignment=1  # center
        )
        story.append(Paragraph(f"{assessment_type.upper()} HEALTH REPORT", title_style))
        
        # Add date
        date_style = ParagraphStyle(
            'CustomDate',
            parent=styles['Normal'],
            fontSize=10,
            textColor=colors.HexColor('#475569'),
            spaceAfter=20,
            alignment=1  # center
        )
        story.append(Paragraph(f"Generated: {assessment_date}", date_style))
        story.append(Spacer(1, 0.3*inch))
        
        # Add report text as preformatted (preserve formatting)
        report_style = ParagraphStyle(
            'ReportText',
            parent=styles['Normal'],
            fontSize=9,
            leftIndent=20,
            rightIndent=20,
            spaceAfter=10,
            fontName='Courier'
        )
        
        # Split report into lines to preserve structure
        for line in report_text.split('\n'):
            if line.strip():
                story.append(Paragraph(line.replace('<', '&lt;').replace('>', '&gt;'), report_style))
            else:
                story.append(Spacer(1, 0.1*inch))
        
        # Build PDF
        doc.build(story)
        pdf_buffer.seek(0)
        
        # Return PDF
        filename = f"{assessment_type}_report_{assessment_id}.pdf"
        return send_file(
            pdf_buffer,
            mimetype='application/pdf',
            as_attachment=True,
            download_name=filename
        )
    
    except ImportError:
        # Fallback: return text file
        return send_file(
            BytesIO(report_text.encode('utf-8')),
            mimetype='text/plain',
            as_attachment=True,
            download_name=f"{assessment_type}_report_{assessment_id}.txt"
        )
