from flask import Flask, render_template, request, redirect, url_for, session
from flask_mysqldb import MySQL
import MySQLdb.cursors
from flask_bcrypt import Bcrypt
from flask_mail import Mail, Message
import random
app = Flask(__name__)
app.secret_key = 'your secret key'

app.config['MYSQL_HOST'] = 'localhost'
app.config['MYSQL_USER'] = 'root'
app.config['MYSQL_PASSWORD'] = 'JALALASSS'
app.config['MYSQL_DB'] = 'project_db'

mysql = MySQL(app)
bcrypt = Bcrypt(app)

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
            elif password == account['password']:
                # Reset the login attempts if the user is not an admin
                if not account['is_admin']:
                    cursor.execute('UPDATE user SET login_attempts = 0 WHERE user_id = %s', (account['user_id'],))
                    mysql.connection.commit()

                session['loggedin'] = True
                session['id'] = account['user_id']
                session['username'] = account['username']

                if account['is_admin'] == 1:
                    return render_template('adminhome.html', username=account['username'])
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
            cursor.execute('INSERT INTO user (username, password, email, phone_number, is_admin) VALUES (%s, %s, %s, %s, 0)',
                           (username, password, email, phone,))
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

                # Redirect to the OTP generation page
                return redirect(url_for('generate_otp_lock'))


            else:
                # Account is not locked, display an error message
                error_message = 'Account is not locked.'
        else:
            # No match found for the provided username and email
            error_message = 'Invalid username or email. Please try again.'

    return render_template('recoveraccount.html', error_message=error_message)


@app.route('/generateotp_lock')
def generate_otp_lock():
    # Generate a 6-digit random OTP
    otp = str(random.randint(100000, 999999))

    # Send the OTP to the user's email address
    send_otp_email(session['reset_account'], otp)

    # Store the OTP in the session for verification
    session['otp'] = otp

    return render_template('getotp_lock.html')


@app.route('/verifyotp_lock', methods=['POST'])
def verify_otp_lock():
    user_otp = request.form['otp']
    stored_otp = session.get('otp')

    if user_otp == stored_otp:
        # OTP matches, perform the desired action (e.g., reset password, grant access)
        # Clear the OTP from the session
        session.pop('otp', None)

        # Reset login_attempts to 0 for the user
        cursor = mysql.connection.cursor()
        cursor.execute('UPDATE user SET login_attempts = 0 WHERE username = %s', (session['reset_account'],))
        mysql.connection.commit()

        return redirect(url_for('recover_success'))  # Redirect to the recover_success page

    else:
        # OTP does not match, show an error message or redirect to a failure page
        return render_template('getotp_lock.html', error_message='Invalid OTP')  # Example error message




@app.route('/recoversuccess')
def recover_success():
    return render_template('recoversuccess.html')




@app.route('/generateotp')
def generate_otp():
    # Generate a 6-digit random OTP
    otp = str(random.randint(100000, 999999))

    # Send the OTP to the user's email address
    send_otp_email(session['reset_username'], otp)

    # Store the OTP in the session for verification
    session['otp'] = otp

    return render_template('getotp.html')


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


@app.route('/verifyotp', methods=['POST'])
def verify_otp():
    user_otp = request.form['otp']
    stored_otp = session.get('otp')

    if user_otp == stored_otp:
        # OTP matches, perform the desired action (e.g., reset password, grant access)
        # Clear the OTP from the session
        session.pop('otp', None)
        return redirect(url_for('reset_password'))  # Example action

    else:
        # OTP does not match, show an error message or redirect to a failure page
        return render_template('getotp.html', error_message='Invalid OTP')  # Example error message


# Route for resetting the password
@app.route('/reset_password', methods=['GET', 'POST'])
def reset_password():
    if 'reset_username' not in session:
        return redirect(url_for('customer_login'))

    if request.method == 'POST' and 'new_password' in request.form and 'confirm_password' in request.form:
        new_password = request.form['new_password']
        confirm_password = request.form['confirm_password']

        if new_password == confirm_password:
            # Update the user's password in the database
            cursor = mysql.connection.cursor()
            cursor.execute('UPDATE user SET password = %s WHERE username = %s', (new_password, session['reset_username']))
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


if __name__ == '__main__':
    app.run(debug=True)
