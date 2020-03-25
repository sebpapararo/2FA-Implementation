import datetime
import os
import random
import sqlite3
import uuid

from flask import Flask, render_template, request, flash, redirect, session, make_response, g
from flask_bcrypt import Bcrypt

# Config statements
app = Flask(__name__)
bcrypt = Bcrypt(app)
DATABASE = 'database.db'
app.secret_key = os.urandom(64)
context = ('certificate.pem', 'key.pem')
app.config['SESSION_COOKIE_SAMESITE'] = 'Strict'
app.config['SESSION_COOKIE_SECURE'] = True


# Database Methods - Courtesy of Oli
def get_db():
    db = getattr(g, '_database', None)
    if db is None:
        db = g._database = sqlite3.connect(DATABASE)

    def make_dicts(cursor, row):
        return dict((cursor.description[idx][0], value)
                    for idx, value in enumerate(row))

    db.row_factory = make_dicts
    return db


def query_db(query, args=(), one=False):
    cur = None
    rv = None
    try:
        cur = get_db().execute(query, args)
        rv = cur.fetchall()
    except sqlite3.Error as e:
        app.logger.info('Database error: %s' % e)
    except Exception as e:
        app.logger.info('Exception in query_db: %s' % e)
    finally:
        if cur:
            cur.close()
    return (rv[0] if rv else None) if one else rv


@app.teardown_appcontext
def close_connection(exception):
    db = getattr(g, '_database', None)
    if db is not None:
        db.close()


# Set the response headers
def setHeaders(response):
    response.headers['X-Frame-Options'] = 'DENY'
    response.headers['Cache-Control'] = 'no-cache; no-store; must-revalidate;'
    response.headers['Pragma'] = 'no-cache;'
    response.headers['X-Content-Type-Options'] = 'nosniff;'
    response.headers['Content-Security-Policy'] = "default-src 'self';" \
                                                  "style-src stackpath.bootstrapcdn.com 'self';" \
                                                  "img-src i.redd.it 'self';"
    return response


# Route to load the index page
@app.route('/', methods=['GET'])
def index():
    # Check if they are already logged in
    if 'username' in session:
        flash('You are already logged in. Log out to visit the index!')
        response = make_response(redirect('/dashboard'))
    else:
        response = make_response(render_template('index.html'))

    response = setHeaders(response)
    return response


# Route to load the index page
@app.route('/register', methods=['GET'])
def register():
    # Check if they are already logged in
    if 'username' in session:
        flash('You are already logged in. Log out to register!')
        response = make_response(redirect('/dashboard'))
    else:
        response = make_response(render_template('register.html'))

    response = setHeaders(response)
    return response


# Route to load the dashboard page
@app.route('/dashboard', methods=['GET'])
def dashboard():
    # Check if they are already logged in
    if 'username' in session:
        randMeme = getRandomMeme()
        response = make_response(render_template('dashboard.html', meme=randMeme, user=session['username']))
    else:
        flash('You must be logged in to visit the dashboard!')
        response = make_response(redirect('/'))

    response = setHeaders(response)
    return response


@app.route('/login', methods=['POST'])
def login():

    if 'username' in session:
        flash('You are already logged in. Log out to register!')
        response = make_response(redirect('/dashboard'))
        response = setHeaders(response)
        return response

    # Get fields from submitted form
    username = request.form.get('username', None)
    password = request.form.get('password', None)

    # Make sure both fields are sent
    if username is None or password is None:
        flash('Either the username or password field was not submitted!')
        response = make_response(redirect('/'))
        response = setHeaders(response)
        return response

    # Make sure both fields are not empty
    if username == '' or password == '':
        flash('Either the username or password field was empty!')
        response = make_response(redirect('/'))
        response = setHeaders(response)
        return response

    # If the user exists in the database
    if query_db('SELECT COUNT(username) FROM users WHERE username = "%s"' % username) and \
            query_db('SELECT COUNT(username) FROM users WHERE username = "%s"' % username)[0].get('COUNT(username)') == 1:
        # Check password is correct
        if bcrypt.check_password_hash(query_db('SELECT password FROM users WHERE username = "%s"' % username)[0].get('password'), password):
            session['username'] = username
            session.permanent = True
            app.permanent_session_lifetime = datetime.timedelta(minutes=10)
            response = make_response(redirect('/dashboard'))
        else:
            flash('Username or password was incorrect!')
            response = make_response(redirect('/'))
    else:
        flash('Username or password was incorrect!')
        response = make_response(redirect('/'))

    response = setHeaders(response)
    return response


@app.route('/register/createAccount', methods=['POST'])
def createAccount():
    if 'username' in session:
        flash('You are already logged in. Log out to register!')
        response = make_response(redirect('/dashboard'))
        response = setHeaders(response)
        return response

    username = request.form.get('username', None)
    password = request.form.get('password', None)
    passwordCheck = request.form.get('passwordCheck', None)

    # Make sure all fields are sent
    if username is None or password is None or passwordCheck is None:
        flash('One of the fields was not submitted!')
        response = make_response(redirect('/register'))
        response = setHeaders(response)
        return response

    # Make sure all fields are not empty
    if username == '' or password == '' or passwordCheck == '':
        flash('One of the fields was empty!')
        response = make_response(redirect('/register'))
        response = setHeaders(response)
        return response

    # Make sure passwords match each other
    if password != passwordCheck:
        flash('Passwords do not match!')
        response = make_response(redirect('/register'))
        response = setHeaders(response)
        return response

    # Get information ready for database
    userID = str(uuid.uuid4())
    hashedPass = bcrypt.generate_password_hash(password).decode('utf-8')

    query_db('INSERT INTO users VALUES("%s", "%s", "%s")' % (userID, username, hashedPass))
    get_db().commit()

    flash('Account has been created, please login!')
    response = make_response(redirect('/'))
    response = setHeaders(response)
    return response


@app.route('/logout', methods=['POST'])
def logout():
    if 'username' in session:
        session.pop('username', None)
        flash('Successfully logged out!')
    else:
        flash('You were not logged in!')

    response = make_response(redirect('/'))
    response = setHeaders(response)
    return response


# Function get a meme from the available choices
def getRandomMeme():
    choice = random.choice(os.listdir("static/memes"))
    return 'static/memes/' + choice


# Run the Flask server
if __name__ == '__main__':
    app.run(host='127.0.0.1', port=5000, debug=False, ssl_context=context)
