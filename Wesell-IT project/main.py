from flask import Flask, render_template, request, redirect, url_for, jsonify, session
from flask_mysqldb import MySQL
import MySQLdb.cursors
from flask_bcrypt import Bcrypt

app = Flask(__name__)
app.secret_key = 'your secret key'

app.config['MYSQL_HOST'] = 'localhost'
app.config['MYSQL_USER'] = 'root'
app.config['MYSQL_PASSWORD'] = 'pwd'
app.config['MYSQL_DB'] = 'pythonlogin'

mysql = MySQL(app)
bcrypt = Bcrypt(app)


@app.route('/')
def home():
    return render_template('home.html')


@app.route('/customerlogin', methods=['GET', 'POST'])
def customer_login():

    msg = ''

    if request.method == 'POST' and 'username' in request.form and 'password' in request.form:
        username = request.form['username']
        password = request.form['password']

        cursor = mysql.connection.cursor(MySQLdb.cursors.DictCursor)
        cursor.execute('SELECT * FROM accounts WHERE username = %s', (username,))
        account = cursor.fetchone()

        if account:
            session['loggedin'] = True
            session['id'] = account['id']
            session['username'] = account['username']
            # Pass the 'account' variable to the userprofile.html template
            return render_template('customerhome.html', username=account['username'])
        else:
            msg = 'Incorrect username/password!'

    return render_template('customerlogin.html', msg=msg)

@app.route('/user/home')
def customer_home():
    # Check if user is loggedin
    if 'loggedin' in session:
        # User is loggedin show them the home page
        return render_template('customerhome.html', username=session['username'])
    # User is not loggedin redirect to login page
    return redirect(url_for('customerlogin'))
# http://localhost:5000/MyWebApp/profile - this will be the profile page, onlyaccessible for loggedin users


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
