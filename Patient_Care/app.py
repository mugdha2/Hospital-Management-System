from flask import Flask, render_template, flash, redirect, url_for, session, logging, request
#from data import Articles
from flask_mysqldb import MySQL
from wtforms import Form, StringField, TextAreaField, PasswordField, validators
from passlib.hash import sha256_crypt
from functools import wraps

app = Flask(__name__)

# Config MySQL
app.config['MYSQL_HOST'] = 'localhost'
app.config['MYSQL_USER'] = 'root'
app.config['MYSQL_PASSWORD'] = 'msb1998'
app.config['MYSQL_DB'] = 'hospital'
app.config['MYSQL_CURSORCLASS'] = 'DictCursor'

# Initializing MySQL
mysql = MySQL(app)

@app.route('/')
def index():
    return render_template('home.html')

@app.route('/about')
def about():
    return render_template('about.html')

# Register Form Class
class RegisterForm(Form):
    aadharNo = StringField("Aadhar Number", [validators.Length(min=1, max=16)])
    username = StringField('Username', [validators.Length(min=1, max=25)])
    email = StringField('Email', [validators.Length(min=1, max=50)])
    password = PasswordField('Password', [
        validators.DataRequired(),
        validators.EqualTo('confirm', message='Passwords do not match')
        ])
    confirm = PasswordField('Confirm Password')

#User Registration
@app.route('/register', methods=['GET', 'POST'])
def register():
        form = RegisterForm(request.form)
        if request.method == 'POST' and form.validate():
            aadharNo = form.aadharNo.data
            email = form.email.data
            username = form.username.data
            password = sha256_crypt.encrypt(str(form.password.data))

            # Creating the cursor
            cur = mysql.connection.cursor()

            # Executing Query
            cur.execute("INSERT INTO users(aadharNo, username, email, password) VALUES(%s, %s, %s, %s)", (aadharNo, username,  email, password))


            # Commit to database
            mysql.connection.commit()

            # Close connection
            cur.close()

            flash("You are now registered.", 'success')

            return redirect(url_for('login'))

        return render_template('register.html', form= form )

# User Login
@app.route('/login', methods=['GET', 'POST'])
def login():
    if request.method == 'POST':

        #Get form fields
        username = request.form['username']
        password_candidate = request.form['password']

        # Create Cursor
        cur = mysql.connection.cursor()

        # Get user by Username
        result = cur.execute("SELECT * FROM users WHERE username = %s", [username])

        if result > 0:

            # Get the stored hash
            data = cur.fetchone()
            password = data['password']


            # Comparing the Passwords
            if sha256_crypt.verify(password_candidate, password):

                # Password matched
                session['logged_in'] = True
                session['username'] = username
                session['aadharNo'] = data['aadharNo']

                flash('You have successfully logged in', 'success')
                return redirect(url_for('hospitallist'))

            else:
                error = 'Invalid login.'
                return render_template('login.html', error = error)

            #Close connection
            cur.close()

        else:
            error = 'Username not found.'
            return render_template('login.html', error = error)

    return render_template('login.html')

# Check if user logged in
def is_logged_in(f):
    @wraps(f)
    def wrap(*args, **kwargs):
        if 'logged_in' in session:
            return f(*args,**kwargs)
        else:
            flash('Unauthorized, please Login.', 'danger')
            return redirect(url_for('login'))
    return wrap

# Creating the hospital list
@app.route('/hospitallist')
# @is_logged_in
def hospitallist():

    # Create Cursor
    cur = mysql.connection.cursor()

    # Execute
    result = cur.execute("SELECT * FROM hospital ORDER BY location")

    hospitals = cur.fetchall()

    if result > 0:
        return render_template('hospitallist.html', hospitals = hospitals)
    else:
        msg = 'No hospitals found'
        return render_template('hospitallist.html', msg= msg)

    # Close connection
    cur.close()

# Creating the Report list
@app.route('/detail')
@is_logged_in
def detail():

    # Create Cursor
    cur = mysql.connection.cursor()

    # Execute
    result = cur.execute("SELECT * FROM data NATURAL JOIN hospital WHERE aadharNo= %s ORDER BY date_of_test desc", (session['aadharNo'],))

    reports = cur.fetchall()

    if result > 0:
        return render_template('detail.html', reports = reports)
    else:
        msg = 'No reports found'
        return render_template('detail.html', msg= msg)

    # Close connection
    cur.close()

# Displaying each individual report
@app.route('/viewReport/<string:test_id>/')
def viewReport(test_id):
    # Create Cursor
    cur = mysql.connection.cursor()

    # Get Article
    result = cur.execute("SELECT * FROM data NATURAL JOIN hospital WHERE test_id= %s", [test_id])

    report = cur.fetchone()

    #if result > 0:
    return render_template('viewReport.html', report=report)
    # Close connection
    #cur.close()

# Creating the blood bank
@app.route('/bloodbank')

def bloodbank():

    # Create Cursor
    cur = mysql.connection.cursor()

    # Execute
    result = cur.execute("SELECT * FROM bloodbank NATURAL JOIN hospital ORDER BY bb_name")

    bloodbanks = cur.fetchall()

    if result > 0:
        return render_template('bloodbank.html', bloodbanks = bloodbanks)
    else:
        msg = 'No Stock'
        return render_template('bloodbank.html', msg= msg)

    # Close connection
    cur.close()

# Logout
@app.route('/logout')
@is_logged_in
def logout():
    session.clear()
    flash('You have logged out.', 'success')
    return redirect(url_for('login'))


if __name__ == '__main__':
    app.secret_key = 'secret123'
    app.run(debug=True)
