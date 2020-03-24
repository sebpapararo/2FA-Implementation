import datetime
import os
import random

from flask import Flask, render_template, request, flash, redirect, session, make_response

# Config statements
app = Flask(__name__)
app.secret_key = os.urandom(64)
app.config['SESSION_COOKIE_SAMESITE'] = 'Strict'
# app.config['SESSION_COOKIE_SECURE'] = True


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


# TODO: 23/03/2020 Make the dashboard.html file
# Route to load the dashboard page
@app.route('/dashboard', methods=['GET'])
def dashboard():
    # Check if they are already logged in
    if 'username' in session:
        randMeme = getRandomMeme()
        response = make_response(render_template('dashboard.html', meme=randMeme))
    else:
        flash('You must be logged in to visit the dashboard!')
        response = make_response(redirect('/'))

    response = setHeaders(response)
    return response


@app.route('/login', methods=['POST'])
def login():
    # Get fields from submitted form
    username = request.form.get('username', None)
    password = request.form.get('password', None)

    # Make sure both fields are sent
    if username is None or password is None:
        flash('Either the username or password field was not submitted!')
        response = make_response(redirect('/'))
        response = setHeaders(response)
        return response

    # Make sure sure both fields are not empty
    if username == '' or password == '':
        flash('Either the username or password field was empty!')
        response = make_response(redirect('/'))
        response = setHeaders(response)
        return response

    # TODO: 23/03/2020 Implement a basic register thing
    #  leave it hard coded for now
    # TODO: 23/03/2020 Add hashing passwords
    if username == 'admin' and password == 'admin':
        session['username'] = username
        session.permanent = True
        app.permanent_session_lifetime = datetime.timedelta(minutes=5)
        response = make_response(redirect('/dashboard'))
    else:
        flash('Username or password was incorrect!')
        response = make_response(redirect('/'))

    response = setHeaders(response)
    return response


@app.route('/logout')
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
    app.run(host='127.0.0.1', port=5000, debug=False)