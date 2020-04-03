from flask import Flask, render_template, request, flash, redirect, session
import os
import math
import hmac
from hashlib import sha1
import time

app = Flask(__name__)
app.secret_key = os.urandom(64)
context = ('certificate.pem', 'key.pem')


# Route to load the index page
@app.route('/', methods=['GET'])
def index():
    # Check if they are already logged in
    if 'token' in session:
        return render_template('index.html', token=session['token'], time=session['expiryTime'])
    else:
        return render_template('index.html')




@app.route('/genToken', methods=['POST'])
def genToken():
    # Get the current time floored to nearest 30 seconds
    unixTime = time.time()
    secsToExpire = int(30 - (unixTime % 30))
    flooredTime = math.floor(unixTime / 30)

    # Generate the secret key
    secretKey = request.form.get('secKey', None)

    if secretKey is None or secretKey == '':
        flash('The secret key field was empty or net sent!')
        return redirect('/')

    # Generate the hash value using the secret key and current time using SHA-1
    hashVal = hmac.new(secretKey.encode(), str(flooredTime).encode(), sha1).hexdigest()

    # Get the last bit of the hash value in decimal format
    lastBit = int(hashVal[-1:], 16)

    # Dynamically truncate the value and convert to decimal
    truncatedVal = int(hashVal[lastBit * 2:lastBit * 2 + 8], 16)

    # Truncate the value to a 6 digit code
    totp = truncatedVal % 10 ** 6

    # Get the code using using zfill to add leading zeros if the int becomes less than 6 digits
    session['token'] = str(totp).zfill(6)
    session['expiryTime'] = str(secsToExpire)

    flash('New token generated!')
    return redirect('/')

if __name__ == '__main__':
    app.run(host='127.0.0.2', port=5000, debug=False, ssl_context=context)

