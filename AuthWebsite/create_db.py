import os
import sqlite3
import uuid

from flask import Flask
from flask_bcrypt import Bcrypt

# Required configuration
app = Flask(__name__)
bcrypt = Bcrypt(app)
DATABASE = 'database.db'


# Function to create the database tables and populate some fake users and posts
def create():
    db = sqlite3.connect(DATABASE)
    c = db.cursor()

    # Create the users table
    c.execute('''
        CREATE TABLE users (
            id varchar PRIMARY KEY,
            username varchar UNIQUE,
            password varchar,
            secretKey varchar
        );
    ''')

    # Create a pre-made user with a known secret
    userID = uuid.uuid4()
    hashedPass = bcrypt.generate_password_hash('admin').decode('utf-8')
    secretKey = 'admin'
    query = 'INSERT INTO users VALUES("%s", "admin", "%s", "%s")' % (userID, hashedPass, secretKey)
    c.execute(query)

    # Commit all changes to the database
    db.commit()


# Delete the database, ready to create a new one
def delete_db():
    if os.path.exists(DATABASE):
        os.remove(DATABASE)


# Run the functions to recreate the database
if __name__ == '__main__':
    delete_db()
    create()
