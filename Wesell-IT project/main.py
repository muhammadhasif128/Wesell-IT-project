from flask import Flask, render_template, request, redirect, url_for, session, flash
from flask_mysqldb import MySQL
import MySQLdb.cursors
from flask_bcrypt import Bcrypt
from flask_mail import Mail, Message
import random, time
from wtforms.validators import InputRequired, regexp
from wtforms import StringField, SelectField, DateField, BooleanField
from flask_wtf import FlaskForm, RecaptchaField
from mysql.connector import connect


app = Flask(__name__)
app.secret_key = 'your secret key'
app.config['RECAPTCHA_PUBLIC_KEY'] = "6LdXxSsnAAAAAI_dz4BUEBxolopEv0nlBK7F_-4-"
app.config['RECAPTCHA_PRIVATE_KEY'] = "6LdXxSsnAAAAAAEyr-iHH4t8MkViAO2I-9zwv1QH"

app.config['MYSQL_HOST'] = 'localhost'
app.config['MYSQL_USER'] = 'root'
app.config['MYSQL_PASSWORD'] = 'JALALASSS'
app.config['MYSQL_DB'] = 'project_db'



mysql = MySQL(app)
bcrypt = Bcrypt(app)

# admin password = 123
# Flask-Mail configuration for Gmail SMTP
app.config['MAIL_SERVER'] = 'smtp.gmail.com'
app.config['MAIL_PORT'] = 587
app.config['MAIL_USE_TLS'] = True
app.config['MAIL_USERNAME'] = 'Wesellit.nyp@gmail.com'
app.config['MAIL_PASSWORD'] = 'hmel dybf srwh tmmz'
# Initialize Flask-Mail
mail = Mail(app)

@app.route('/')
def home():
    return render_template('home.html')

@app.route('/loginpage', methods=['GET', 'POST'])
def customer_login():
    msg = ''
    locked = False
    # Set a maximum number of login attempts
    MAX_LOGIN_ATTEMPTS = 3
    if request.method == 'POST' and 'username' in request.form and 'password' in request.form:
        username = request.form['username']
        password = request.form['password']

        cursor = mysql.connection.cursor(MySQLdb.cursors.DictCursor)
        cursor.execute('SELECT * FROM user WHERE username = %s', (username,))
        account = cursor.fetchone()

        if account:
            if account['login_attempts'] >= MAX_LOGIN_ATTEMPTS:
                locked = True
                msg = 'Your account is locked. Please contact the administrator.'
            elif bcrypt.check_password_hash(account['password'], password):
                # Reset the login attempts if the user is not an admin
                if not account['is_admin']:
                    cursor.execute('UPDATE user SET login_attempts = 0 WHERE user_id = %s', (account['user_id'],))
                    mysql.connection.commit()

                session['loggedin'] = True
                session['id'] = account['user_id']
                session['username'] = account['username']

                if account['is_admin'] == 1:
                    cursor = mysql.connection.cursor(MySQLdb.cursors.DictCursor)
                    cursor.execute('SELECT * FROM appts_table where is_approved = False')
                    appointments = cursor.fetchall()

                    return render_template('adminhome.html', username=account['username'],appointments_list = appointments)
                else:
                    return render_template('customerhome.html', username=account['username'])
            else:
                # Increment the login attempts if the user is not an admin
                if not account['is_admin']:
                    cursor.execute('UPDATE user SET login_attempts = login_attempts + 1 WHERE user_id = %s', (account['user_id'],))
                    mysql.connection.commit()

                msg = 'Incorrect username/password!'
        else:
            msg = 'User does not exist!'

    return render_template('loginpage.html', msg=msg, locked=locked)
@app.route('/approveCust',methods = ['GET','POST'])
def approve_cust():
    if request.method == 'POST':
        appt_id_updating = request.form['appointment_id']
        update_query = "UPDATE appts_table SET is_approved = True WHERE appointment_id = %s"
        cursor = mysql.connection.cursor(MySQLdb.cursors.DictCursor)
        cursor.execute(update_query,(appt_id_updating,))
        mysql.connection.commit()

        if 'loggedin' in session:
          # We need all the account info for the user so we can display it on the profile page
          cursor = mysql.connection.cursor(MySQLdb.cursors.DictCursor)
          cursor.execute('SELECT * FROM user WHERE user_id = %s', (session['id'],))
          account = cursor.fetchone()

          cursor = mysql.connection.cursor(MySQLdb.cursors.DictCursor)
          cursor.execute('SELECT * FROM appts_table where is_approved = False')
          appointments = cursor.fetchall()

          return render_template('adminhome.html', username=account['username'],appointments_list = appointments)
@app.route('/register', methods=['GET', 'POST'])
def register():
    # Output message if something goes wrong...
    message = ''

    # Check if "username", "password", "email", and "phone" POST requests exist (user submitted form)
    if request.method == 'POST' and 'username' in request.form and 'password' in request.form and 'email' in request.form and 'phone' in request.form:
        # Create variables for easy access
        username = request.form['username']
        password = request.form['password']
        email = request.form['email']
        phone = request.form['phone']
        confirm_password = request.form['confirm_password']

        # Check if the username already exists in the database
        cursor = mysql.connection.cursor(MySQLdb.cursors.DictCursor)
        cursor.execute('SELECT * FROM user WHERE username = %s', (username,))
        existing_user = cursor.fetchone()

        if existing_user:
            message = 'Username already exists. Please choose a different username.'
        elif password != confirm_password:
            message = 'Password and confirm password do not match.'
        else:
            # Hash the password
            hashed_password = bcrypt.generate_password_hash(password).decode('utf-8')

            # Insert the user into the database
            cursor.execute('INSERT INTO user (username, password, email, phone_number, is_admin) VALUES (%s, %s, %s, %s, 0)',
                           (username, hashed_password, email, phone,))
            mysql.connection.commit()

            message = 'You have successfully registered!'
            return redirect(url_for('customer_login', message=message))

    elif request.method == 'POST':
        # Form is empty... (no POST data)
        message = 'Please fill out the form completely!'

    return render_template('register.html', message=message)

@app.route('/forgetpassword', methods=['GET', 'POST'])
def forget_password():
    error_message = None

    if request.method == 'POST' and 'username' in request.form and 'email' in request.form:
        username = request.form['username']
        email = request.form['email']
        cursor = mysql.connection.cursor(MySQLdb.cursors.DictCursor)
        cursor.execute('SELECT * FROM user WHERE username = %s AND email = %s', (username, email))
        user = cursor.fetchone()

        if user:
            # Set the reset_username in the session
            session['reset_username'] = username

            # Redirect to the OTP generation page
            return redirect(url_for('generate_otp'))

        else:
            # No match found for the provided username and email
            error_message = 'Invalid username or email. Please try again.'

    return render_template('forgetpassword.html', error_message=error_message)

@app.route('/recoveraccount', methods=['GET', 'POST'])
def recover_account():
    error_message = None
    MAX_LOGIN_ATTEMPTS = 3
    if request.method == 'POST' and 'username' in request.form and 'email' in request.form:
        username = request.form['username']
        email = request.form['email']
        cursor = mysql.connection.cursor(MySQLdb.cursors.DictCursor)
        cursor.execute('SELECT login_attempts FROM user WHERE username = %s AND email = %s', (username, email))
        user = cursor.fetchone()

        if user:
            login_attempts = user['login_attempts']
            if login_attempts >= MAX_LOGIN_ATTEMPTS:
                session['reset_account'] = username

                # Set the reset_username in the session
                session['reset_username'] = username

                # Redirect to the OTP generation page
                return redirect(url_for('generate_otp_lock'))

            else:
                # Account is not locked, display an error message
                error_message = 'Account is not locked.'
        else:
            # No match found for the provided username and email
            error_message = 'Invalid username or email. Please try again.'

    return render_template('recoveraccount.html', error_message=error_message)


def send_otp_email(username, otp):
    # Fetch the user's email from the database using the username
    cursor = mysql.connection.cursor(MySQLdb.cursors.DictCursor)
    cursor.execute('SELECT email FROM user WHERE username = %s', (username,))
    user = cursor.fetchone()
    email = user['email']

    # Compose the email message
    subject = 'OTP for Password Reset'
    body = f'Your OTP is: {otp}'
    sender = 'your-email@example.com'
    recipients = [email]

    # Create and send the email message
    msg = Message(subject=subject, body=body, sender=sender, recipients=recipients)
    mail.send(msg)




@app.route('/generateotp_lock')
def generate_otp_lock():
    # Generate a new OTP
    otp = str(random.randint(100000, 999999))

    # Set the OTP expiry time in seconds (5 minutes in this case)
    otp_expiry = 300

    # Store the OTP and its expiry timestamp in the session
    session['otp'] = {
        'code': otp,
        'expiry_timestamp': time.time() + otp_expiry
    }

    # Send the OTP to the user's email address
    send_otp_email(session['reset_username'], otp)

    # Render the template with the OTP form and expiry time
    return render_template('getotp_lock.html', expiry_time=otp_expiry)



@app.route('/verifyotp_lock', methods=['POST'])
def verify_otp_lock():
    user_otp = request.form['otp']
    stored_otp = session.get('otp')
    new_otp = session.get('new_otp')  # Get the new OTP from the session

    if new_otp:
        if user_otp == new_otp['code']:
            current_timestamp = time.time()
            if current_timestamp <= new_otp['expiry_timestamp']:
                # Clear the new OTP from the session
                session.pop('new_otp', None)
                cursor = mysql.connection.cursor()
                cursor.execute('UPDATE user SET login_attempts = 0 WHERE username = %s', (session['reset_account'],))
                mysql.connection.commit()
                return redirect(url_for('recover_success'))  # Example action after new OTP verification
            else:
                # New OTP has expired
                return render_template('getotp_lock.html', error_message='New OTP has expired. Please request a new OTP.')

    elif stored_otp:
        if user_otp == stored_otp['code']:
            current_timestamp = time.time()
            if current_timestamp <= stored_otp['expiry_timestamp']:
                # Clear the old OTP from the session
                session.pop('otp', None)
                cursor = mysql.connection.cursor()
                cursor.execute('UPDATE user SET login_attempts = 0 WHERE username = %s', (session['reset_account'],))
                mysql.connection.commit()
                return redirect(url_for('recover_success'))  # Example action after old OTP verification
            else:
                # Old OTP has expired
                return render_template('getotp_lock.html', error_message='Old OTP has expired. Please request a new OTP.')

    # OTP does not match or is not found in the session
    return render_template('getotp_lock.html', error_message='Invalid OTP')  # Example error message




@app.route('/resend_otp_lock', methods=['POST'])
def resend_otp_lock():
    stored_otp = session.get('otp')
    if stored_otp:
        # Generate a new OTP
        new_otp = {
            'code': str(random.randint(100000, 999999)),
            'expiry_timestamp': time.time() + 300
        }

        # Update the new OTP in the session
        session['new_otp'] = new_otp

        # Send the new OTP to the user's email address
        send_otp_email(session['reset_username'], new_otp['code'])

        return render_template('getotp_lock.html', message='OTP has been resent successfully!', expiry_time=300)

    # OTP data not found, handle it (e.g., show an error message or redirect)
    return render_template('getotp_lock.html', error_message='OTP not found. Please generate a new OTP.')

@app.route('/recoversuccess')
def recover_success():
    return render_template('recoversuccess.html')




@app.route('/generateotp')
def generate_otp():
    # Generate a new OTP
    otp = str(random.randint(100000, 999999))

    # Set the OTP expiry time in seconds (10 seconds in this case)
    otp_expiry = 300

    # Store the OTP and its expiry timestamp in the session
    session['otp'] = {
        'code': otp,
        'expiry_timestamp': time.time() + otp_expiry
    }

    # Send the OTP to the user's email address
    send_otp_email(session['reset_username'], otp)

    # Render the template with the OTP form and expiry time
    return render_template('getotp.html', expiry_time=otp_expiry)

@app.route('/verifyotp', methods=['POST'])
def verify_otp():
    user_otp = request.form['otp']
    stored_otp = session.get('otp')
    new_otp = session.get('new_otp')  # Get the new OTP from the session

    if new_otp:
        if user_otp == new_otp['code']:
            current_timestamp = time.time()
            if current_timestamp <= new_otp['expiry_timestamp']:
                # Clear the new OTP from the session
                session.pop('new_otp', None)
                return redirect(url_for('reset_password'))  # Example action after new OTP verification
            else:
                # New OTP has expired
                return render_template('getotp.html', error_message='New OTP has expired. Please request a new OTP.')

    elif stored_otp:
        if user_otp == stored_otp['code']:
            current_timestamp = time.time()
            if current_timestamp <= stored_otp['expiry_timestamp']:
                # Clear the old OTP from the session
                session.pop('otp', None)
                return redirect(url_for('reset_password'))  # Example action after old OTP verification
            else:
                # Old OTP has expired
                return render_template('getotp.html', error_message='Old OTP has expired. Please request a new OTP.')

    # OTP does not match or is not found in the session
    return render_template('getotp.html', error_message='Invalid OTP')  # Example error message



@app.route('/resend_otp', methods=['POST'])
def resend_otp():
    stored_otp = session.get('otp')
    if stored_otp:
        # Generate a new OTP
        new_otp = {
            'code': str(random.randint(100000, 999999)),
            'expiry_timestamp': time.time() + 300
        }

        # Update the new OTP in the session
        session['new_otp'] = new_otp

        # Send the new OTP to the user's email address
        send_otp_email(session['reset_username'], new_otp['code'])

        return render_template('getotp.html', message='OTP has been resent successfully!', expiry_time=300)

    # OTP data not found, handle it (e.g., show an error message or redirect)
    return render_template('getotp.html', error_message='OTP not found. Please generate a new OTP.')




@app.route('/reset_password', methods=['GET', 'POST'])
def reset_password():
    if 'reset_username' not in session:
        return redirect(url_for('customer_login'))

    if request.method == 'POST' and 'new_password' in request.form and 'confirm_password' in request.form:
        new_password = request.form['new_password']
        confirm_password = request.form['confirm_password']

        if new_password == confirm_password:
            # Hash the new password
            hashed_password = bcrypt.generate_password_hash(new_password).decode('utf-8')

            # Update the user's password in the database
            cursor = mysql.connection.cursor()
            cursor.execute('UPDATE user SET password = %s WHERE username = %s', (hashed_password, session['reset_username']))
            mysql.connection.commit()

            session.pop('reset_username', None)  # Remove reset_username from session

            return redirect(url_for('customer_login', message='Your password has been successfully updated!'))
        else:
            return render_template('resetpassword.html', error_message='Password and confirm password do not match.')

    return render_template('resetpassword.html')



@app.route('/user/home')
def customer_home():
    # Check if user is logged in
    if 'loggedin' in session:
        # User is logged in, show them the home page
        return render_template('customerhome.html', username=session['username'])
    # User is not logged in, redirect to login page
    return redirect(url_for('customer_login'))


@app.route('/user/profile')
def profile():
    # Check if user is logged in
    if 'loggedin' in session:
        # We need all the account info for the user so we can display it on the profile page
        cursor = mysql.connection.cursor(MySQLdb.cursors.DictCursor)
        cursor.execute('SELECT * FROM user WHERE user_id = %s', (session['id'],))
        account = cursor.fetchone()
        # Show the profile page with account info
        return render_template('userprofile.html', account=account)
    # User is not logged in, redirect to login page
    return redirect(url_for('customer_login'))


@app.route('/admin/home')
def admin_home():
    # Check if user is logged in
    if 'loggedin' in session:
        # User is logged in, show them the home page
        return render_template('adminhome.html', username=session['username'])
    # User is not logged in, redirect to login page
    return redirect(url_for('customer_login'))


@app.route('/admin/profile')
def admin_profile():
    # Check if user is logged in
    if 'loggedin' in session:
        # We need all the account info for the user so we can display it on the profile page
        cursor = mysql.connection.cursor(MySQLdb.cursors.DictCursor)
        cursor.execute('SELECT * FROM user WHERE user_id = %s', (session['id'],))
        account = cursor.fetchone()
        # Show the profile page with account info
        return render_template('adminprofile.html', account=account)
    # User is not logged in, redirect to login page
    return redirect(url_for('customer_login'))



@app.route('/logout')
def logout():
    # Remove session data, this will log the user out
    session.pop('loggedin', None)
    session.pop('id', None)
    session.pop('username', None)
    # Redirect to login page
    return redirect(url_for('customer_login'))

@app.route('/protected')
def protected():
    if 'logged_in' in session:
        # The user is logged in, allow access to the protected page
        return "Welcome to the protected page!"
    else:
        # Redirect to the login page if the user is not logged in
        return redirect(url_for('customer_login'))

class apptform(FlaskForm):
    username = StringField('Name', validators=[InputRequired(), regexp(r'^[a-zA-Z0-9_]{3,16}$')])
    # ^ asserts the start of the string.
    # [a-zA-Z0-9_-] matches any alphanumeric character (letters and digits), underscores, or hyphens.
    # {3,16} specifies the allowed length range for the username (between 3 and 16 characters).
    # $ asserts the end of the string.
    recaptcha = RecaptchaField()
    choices = [('Laptops', 'Laptops'), ('PC', 'PC'), ('Phones', 'Phones'), ('Drives', 'Drives')]
    dropdown = SelectField('Type Gadgets To Trade In', choices=choices)
    appointment_datetime = DateField('Booking Date', validators=[InputRequired()])
    tc = BooleanField('I accept the terms and conditions', validators=[InputRequired()])


@app.route('/appointment', methods=['GET', 'POST'])
def index():
    form = apptform()
    if form.validate_on_submit():
        username = form.username.data
        appointment_datetime = form.appointment_datetime.data

        # Create a cursor to execute SQL queries
        cursor = mysql.connection.cursor()

        # Check if the username exists in the user table
        cursor.execute("SELECT username FROM user WHERE username = %s", (username,))
        existing_username = cursor.fetchone()

        if existing_username:
            # Insert the data into the database
            cursor.execute("INSERT INTO appts_table (username, appointment_datetime) VALUES (%s, %s)", (username, appointment_datetime))

            mysql.connection.commit()
            cursor.close()

            return '<h1 style="text-align:center; color:red;">Thank you {}, for submitting your appointment' .format(form.username.data)
        else:
            return 'Invalid username. Please provide a valid username.'

    else:
          return render_template('index.html', form=form)

if __name__ == '__main__':
    app.run(debug=True)
