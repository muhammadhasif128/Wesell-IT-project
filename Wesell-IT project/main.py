from flask import Flask, render_template, request, redirect, url_for, session
from flask_mysqldb import MySQL
import MySQLdb.cursors
from flask_bcrypt import Bcrypt

app = Flask(__name__)
app.secret_key = 'your secret key'

app.config['MYSQL_HOST'] = 'localhost'
app.config['MYSQL_USER'] = 'root'
app.config['MYSQL_PASSWORD'] = 'JALALASSS'
app.config['MYSQL_DB'] = 'project_db'

mysql = MySQL(app)
bcrypt = Bcrypt(app)


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

        # Check if the username already exists in the database
        cursor = mysql.connection.cursor(MySQLdb.cursors.DictCursor)
        cursor.execute('SELECT * FROM user WHERE username = %s', (username,))
        existing_user = cursor.fetchone()

        if existing_user:
            message = 'Username already exists. Please choose a different username.'
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
        cursor.execute('SELECT * FROM accounts WHERE id = %s', (session['id'],))
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
