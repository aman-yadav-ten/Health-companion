from .app_context import *

def stroke():
    # Authentication check - protect this route
    if 'loggedin' not in session:
        return redirect(url_for('landing'))
    user_id = get_current_user_id()
    if not user_id:
        return redirect(url_for('logout'))
    
    # Check if user has completed profile
    if not profile_exists(user_id):
        return redirect(url_for('profile'))
    
    msg = ' '
    username = session.get('username', '')
    analyze_button_label = (
        'Analyze Stroke Risk'
        if not has_user_assessment(username, 'assessment_stroke')
        else 'Analyze Stroke Risk Again'
    )

    def render_stroke_page(message):
        return render_template(
            'assessments/stroke/form.html',
            msg=message,
            auto_fetch=True,
            analyze_button_label=analyze_button_label
        )

    if request.method == 'POST':
        try:
            # Fetch user's profile data automatically
            profile = get_user_profile(user_id)
            
            if not profile:
                msg = 'Please complete your health profile first'
                return render_stroke_page(msg)
            
            # Extract stroke-related data from profile
            gender = profile['gender']
            age = profile['age']
            hypertension = profile['hypertension']
            heart_disease = profile['heart_disease']
            ever_married = profile['ever_married']
            work_type = profile['work_type']
            residence_type = profile['residence_type']
            avg_glucose_level = profile['glucose_level']
            bmi = profile['bmi']
            smoking_status = profile['smoking_status']
            
            # Validate profile fields without rejecting valid categorical zero values.
            required_profile_values = {
                'gender': gender,
                'age': age,
                'hypertension': hypertension,
                'heart_disease': heart_disease,
                'ever_married': ever_married,
                'work_type': work_type,
                'residence_type': residence_type,
                'avg_glucose_level': avg_glucose_level,
                'bmi': bmi,
                'smoking_status': smoking_status
            }
            if any(value is None or value == '' for value in required_profile_values.values()):
                msg = 'Your profile is incomplete. Please update it.'
                return render_stroke_page(msg)
            
            # Store in assessment history
            connection = get_db_connection()
            cursor = connection.cursor()
            cursor.execute('INSERT INTO account_stroke VALUES (NULL, ?,?,?,?,?,?,?,?,?,?,?,NULL)', 
                          (session['username'],gender,age,hypertension,heart_disease,
                           ever_married,work_type,residence_type,avg_glucose_level,bmi,smoking_status))
            connection.commit()
            cursor.close()
            connection.close()
            
            # Get ML prediction
            prediction_result = strokeml(gender,age,hypertension,heart_disease,ever_married,
                                        work_type,residence_type,avg_glucose_level,bmi,smoking_status)
            
            if 'error' in prediction_result:
                msg = prediction_result['error']
                return render_template('pages/output.html', msg=msg)
            
            # Prepare patient data for report
            patient_data = {
                'name': session.get('username', 'Patient'),
                'age': int(age),
                'gender': 'Male' if int(gender) == 1 else 'Female',
                'height': profile.get('height', 'N/A'),
                'weight': profile.get('weight', 'N/A'),
                'bmi': float(bmi),
                'bmi_category': 'Normal' if 18.5 <= float(bmi) < 25 else ('Overweight' if float(bmi) < 30 else 'Obese'),
                'hypertension': int(hypertension),
                'heart_disease': int(heart_disease),
                'avg_glucose': float(avg_glucose_level),
                'smoking_status': int(smoking_status),
                'ever_married': int(ever_married),
                'work_type': work_type,
                'residence_type': int(residence_type)
            }
            
            risk_prediction = {
                'risk_level': prediction_result['risk_level'],
                'probability': prediction_result['probability'],
                'recommendation': 'Consult with a healthcare provider'
            }
            
            # Generate professional report
            generator = HealthReportGenerator()
            msg = generator.generate_stroke_report(patient_data, risk_prediction)
            
            # Store assessment in database for history
            import json
            conn = get_db_connection()
            cursor = conn.cursor()
            cursor.execute('''
                INSERT INTO assessment_stroke 
                (username, patient_data, prediction_result, risk_level, probability, report_text)
                VALUES (?, ?, ?, ?, ?, ?)
            ''', (
                session['username'],
                json.dumps(patient_data),
                json.dumps(prediction_result),
                risk_prediction['risk_level'],
                risk_prediction['probability'],
                msg
            ))
            conn.commit()
            conn.close()
            
            return render_template('pages/output.html', msg=msg)
        except Exception as e:
            msg = f'Error processing prediction: {str(e)}'
            return render_stroke_page(msg)
    elif request.method == 'POST':
        msg = 'Error processing request'
    return render_stroke_page(msg)

def diabetes():
    # Authentication check - protect this route
    if 'loggedin' not in session:
        return redirect(url_for('landing'))
    user_id = get_current_user_id()
    if not user_id:
        return redirect(url_for('logout'))
    
    # Check if user has completed profile
    if not profile_exists(user_id):
        return redirect(url_for('profile'))
    
    msg = ''
    username = session.get('username', '')
    analyze_button_label = (
        'Analyze Diabetes Risk'
        if not has_user_assessment(username, 'assessment_diabetes')
        else 'Analyze Diabetes Risk Again'
    )

    def render_diabetes_page(message):
        return render_template(
            'assessments/diabetes/form.html',
            msg=message,
            auto_fetch=True,
            analyze_button_label=analyze_button_label
        )

    if request.method == 'POST':
        try:
            # Fetch user's profile data automatically
            profile = get_user_profile(user_id)
            
            if not profile:
                msg = 'Please complete your health profile first'
                return render_diabetes_page(msg)
            
            # Extract diabetes-related data from profile
            pregnancies = profile['pregnancies'] or 0
            glucose = profile['glucose_level']
            bloodpressure = profile['blood_pressure_diastolic']  # Using diastolic BP
            skinthickness = profile['skin_thickness'] or 0
            insulin = profile['insulin'] or 0
            bmi_dia = profile['bmi']
            diabetes_pedigree_fnc = profile['diabetes_pedigree_function'] or 0.0
            age_dia = profile['age']
            
            # Validate critical data
            if not all([glucose, bloodpressure, bmi_dia, age_dia]):
                msg = 'Your profile is incomplete. Please update it.'
                return render_diabetes_page(msg)
            
            # Store in assessment history
            connection = get_db_connection()
            cursor = connection.cursor()
            cursor.execute('INSERT INTO account_dia VALUES (NULL, ?, ?, ?, ?,?,?,?,?,?,NULL)', 
                          (session['username'],pregnancies,glucose,bloodpressure,skinthickness,
                           insulin,bmi_dia,diabetes_pedigree_fnc,age_dia))
            connection.commit()
            cursor.close()
            connection.close()
            
            # Get ML prediction
            prediction_result = diaml(pregnancies,glucose,bloodpressure,skinthickness,insulin,
                                     bmi_dia,diabetes_pedigree_fnc,age_dia)
            
            if 'error' in prediction_result:
                msg = prediction_result['error']
                return render_template('pages/output.html', msg=msg)
            
            # Prepare patient data for report
            patient_data = {
                'name': session.get('username', 'Patient'),
                'age': int(age_dia),
                'gender': 'Female',
                'pregnancies': int(pregnancies),
                'weight': profile.get('weight', 'N/A'),
                'height': profile.get('height', 'N/A'),
                'bmi': float(bmi_dia),
                'bmi_category': 'Normal' if 18.5 <= float(bmi_dia) < 25 else ('Overweight' if float(bmi_dia) < 30 else 'Obese'),
                'glucose': float(glucose),
                'blood_pressure': float(bloodpressure),
                'insulin': float(insulin),
                'skin_thickness': float(skinthickness),
                'diabetes_pedigree_function': float(diabetes_pedigree_fnc)
            }
            
            risk_prediction = {
                'risk_level': prediction_result['risk_level'],
                'probability': prediction_result['probability'],
                'recommendation': 'Consult with an endocrinologist'
            }
            
            # Generate professional report
            generator = HealthReportGenerator()
            msg = generator.generate_diabetes_report(patient_data, risk_prediction)
            
            # Store assessment in database for history
            import json
            conn = get_db_connection()
            cursor = conn.cursor()
            cursor.execute('''
                INSERT INTO assessment_diabetes 
                (username, patient_data, prediction_result, risk_level, probability, report_text)
                VALUES (?, ?, ?, ?, ?, ?)
            ''', (
                session['username'],
                json.dumps(patient_data),
                json.dumps(prediction_result),
                risk_prediction['risk_level'],
                risk_prediction['probability'],
                msg
            ))
            conn.commit()
            conn.close()
            
            return render_template('pages/output.html', msg=msg)
        except Exception as e:
            msg = f'Error processing prediction: {str(e)}'
            return render_diabetes_page(msg)
    elif request.method == 'POST':
        msg = 'Error processing request'
    return render_diabetes_page(msg)

def cardiovascular():
    # Authentication check - protect this route
    if 'loggedin' not in session:
        return redirect(url_for('landing'))
    user_id = get_current_user_id()
    if not user_id:
        return redirect(url_for('logout'))
    
    # Check if user has completed profile
    if not profile_exists(user_id):
        return redirect(url_for('profile'))
    
    msg = ''
    username = session.get('username', '')
    latest_cardio_risk = None
    latest_cardio_probability = None
    latest_cardio_date = None
    if username:
        conn = get_db_connection()
        cursor = conn.cursor()
        cursor.execute(
            '''
            SELECT risk_level, probability, assessment_date
            FROM assessment_cardiovascular
            WHERE username = ?
            ORDER BY assessment_date DESC, id DESC
            LIMIT 1
            ''',
            (username,)
        )
        latest_row = cursor.fetchone()
        conn.close()
        if latest_row:
            latest_cardio_risk = latest_row['risk_level']
            latest_cardio_probability = latest_row['probability']
            latest_cardio_date = (latest_row['assessment_date'] or '')[:10]

    analyze_button_label = (
        'Analyze Cardiovascular Risk'
        if not has_user_assessment(username, 'assessment_cardiovascular')
        else 'Analyze Cardiovascular Risk Again'
    )
    latest_cardio_status = 'No previous cardiovascular assessment yet.'
    if latest_cardio_risk:
        latest_cardio_status = f"Latest: {latest_cardio_risk}"
        if latest_cardio_probability is not None:
            latest_cardio_status += f" ({float(latest_cardio_probability) * 100:.1f}%)"
        if latest_cardio_date:
            latest_cardio_status += f" on {latest_cardio_date}"

    def render_cardiovascular_page(message):
        return render_template(
            'assessments/cardiovascular/form.html',
            msg=message,
            auto_fetch=True,
            analyze_button_label=analyze_button_label,
            latest_cardio_status=latest_cardio_status
        )

    if request.method == 'POST':
        try:
            # Fetch user's profile data automatically
            profile = get_user_profile(user_id)
            
            if not profile:
                msg = 'Please complete your health profile first'
                return render_cardiovascular_page(msg)
            
            # Extract cardiovascular-related data from profile
            age1 = profile['age']
            gender1 = profile['gender']
            height = profile['height']
            weight = profile['weight']
            ap_hi = profile['blood_pressure_systolic']
            ap_lo = profile['blood_pressure_diastolic']
            cholesterol = profile['cholesterol']
            glu = profile['glucose_level']
            smoke = profile['smoking_status']
            alco = profile['alcohol_consumption']
            active = profile['physical_activity']
            
            # Validate profile fields without rejecting valid categorical zero values.
            required_profile_values = {
                'age1': age1,
                'gender1': gender1,
                'height': height,
                'weight': weight,
                'ap_hi': ap_hi,
                'ap_lo': ap_lo,
                'cholesterol': cholesterol,
                'glu': glu,
                'smoke': smoke,
                'alco': alco,
                'active': active,
            }
            if any(value is None or value == '' for value in required_profile_values.values()):
                msg = 'Your profile is incomplete. Please update it.'
                return render_cardiovascular_page(msg)
            
            # Store in assessment history
            connection = get_db_connection()
            cursor = connection.cursor()
            cursor.execute('INSERT INTO account_cardiovascular VALUES (NULL, ?, ?, ?, ?,?,?,?,?,?,?,?,?,NULL)', 
                          (session['username'],age1,gender1,height,weight,ap_hi,ap_lo,cholesterol,glu,smoke,alco,active))
            connection.commit()
            cursor.close()
            connection.close()
            
            # Get ML prediction
            prediction_result = cardiovascularml(age1,gender1,height,weight,ap_hi,ap_lo,cholesterol,glu,smoke,alco,active)
            
            if 'error' in prediction_result:
                msg = prediction_result['error']
                return render_template('pages/output.html', msg=msg)
            
            # Prepare patient data for report
            bmi = float(weight) / ((float(height) / 100) ** 2)
            patient_data = {
                'name': session.get('username', 'Patient'),
                'age': int(age1),
                'gender': 'Male' if int(gender1) == 1 else 'Female',
                'height': float(height),
                'weight': float(weight),
                'bmi': bmi,
                'bmi_category': 'Underweight' if bmi < 18.5 else ('Normal' if bmi < 25 else ('Overweight' if bmi < 30 else 'Obese')),
                'systolic_bp': int(ap_hi),
                'diastolic_bp': int(ap_lo),
                'bp_category': 'Normal' if int(ap_hi) < 120 and int(ap_lo) < 80 else ('Elevated' if int(ap_hi) < 130 else ('Stage 1 Hypertension' if int(ap_hi) < 140 else 'Stage 2 Hypertension')),
                'cholesterol': int(cholesterol),
                'glucose': int(glu),
                'smoking': int(smoke),
                'alcohol': int(alco),
                'physical_activity': int(active)
            }
            
            risk_prediction = {
                'risk_level': prediction_result['risk_level'],
                'probability': prediction_result['probability'],
                'recommendation': 'Consult with a cardiologist'
            }
            
            # Generate professional report
            generator = HealthReportGenerator()
            msg = generator.generate_cardiovascular_report(patient_data, risk_prediction)
            
            # Store assessment in database for history
            import json
            conn = get_db_connection()
            cursor = conn.cursor()
            cursor.execute('''
                INSERT INTO assessment_cardiovascular 
                (username, patient_data, prediction_result, risk_level, probability, report_text)
                VALUES (?, ?, ?, ?, ?, ?)
            ''', (
                session['username'],
                json.dumps(patient_data),
                json.dumps(prediction_result),
                risk_prediction['risk_level'],
                risk_prediction['probability'],
                msg
            ))
            conn.commit()
            conn.close()
            
            return render_template('pages/output.html', msg=msg)
        except Exception as e:
            msg = f'Error processing prediction: {str(e)}'
            return render_cardiovascular_page(msg)
    elif request.method == 'POST':
        msg = 'Error processing request'
    return render_cardiovascular_page(msg)

def calculate_bmi():
    # Authentication check - protect this route
    if 'loggedin' not in session:
        return redirect(url_for('landing'))
    
    msg = 'BMI CALCULATOR'
    if request.method == 'POST' and 'weight' in request.form and 'height' in request.form:
        weight = request.form['weight']
        height = request.form['height']

        if not weight or not height:
            msg = 'Please fill out the form!'
        else:
            try:
                weight = float(weight)
                height = float(height)
                if weight <= 0 or height <= 0:
                    msg = 'Weight and height must be greater than zero.'
                    return render_template('assessments/calculators/bmi.html', msg=msg)

                bmi = calculate_bmi_value(weight, height)
                msg = f'Your BMI is: {bmi}'

                connection = get_db_connection()
                cursor = connection.cursor()
                cursor.execute('INSERT INTO account_bmi VALUES (NULL, ?, ?,?,?)' ,(session['username'],weight,height, bmi,))
                connection.commit()
                cursor.close()
                connection.close()
                return render_template('pages/output.html', msg = msg)
            except ValueError:
                msg = 'Invalid input. Please enter numeric values.'
    return render_template('assessments/calculators/bmi.html', msg=msg)

def calculate_calories():
    # Authentication check - protect this route
    if 'loggedin' not in session:
        return redirect(url_for('landing'))
    
    msg = 'CALORIE CALCULATOR'
    if request.method == 'POST' and 'gender' in request.form and 'weight' in request.form and 'height' in request.form and 'age' in request.form and 'activity_level' in request.form:
        gender = request.form['gender']
        weight = request.form['weight']
        height = request.form['height']
        age = request.form['age']
        activity_level = request.form['activity_level']

        if not gender or not weight or not height or not age or not activity_level:
            msg = 'Please fill out the form!'
        else:
            weight = float(weight)
            height = float(height)
            age = int(age)
            bmr = calculate_bmr(gender, weight, height, age)
            calorie_msg = calculate_calories_based_on_activity(bmr, activity_level)
            msg = f'Your BMR is: {bmr} calories. {calorie_msg}'
            return render_template('pages/output.html', msg = msg)
    return render_template('assessments/calculators/calories.html', msg=msg)
