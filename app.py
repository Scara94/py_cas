from flask import Flask, redirect, request, session, url_for, jsonify
from cas import CASClient
import logging
import os

# Configura il logging
logging.basicConfig(level=logging.DEBUG)

app = Flask(__name__)
#app.secret_key = 'V7nlCN90LPHOTA9PGGyf'  # Assicurati di usare una chiave segreta sicura in produzione
app.secret_key = os.urandom(24)

# Configura CASClient
cas_client = CASClient(
    version=3,
    service_url='http://localhost:5000/login?next=/profile',  # Cambia con il tuo URL di servizio
    server_url='https://sso.staging.unimi.it:6443/',  # URL del tuo server CAS
    verify_ssl_certificate=False
)

@app.route('/')
def index():
    return '''
        <h1>Benvenuti nel test di login di CAS</h1>
        <a href="/login"><button>Login</button></a>
    '''

@app.route('/profile')
def profile():
    if 'username' in session:
        username = session['username']
        return f'Ciao {username}'
    else:
        return redirect(url_for('login'))

@app.route('/login')
def cas():
    next_url = request.args.get('next')
    app.logger.debug('next: %s', next_url)
    ticket = request.args.get('ticket')
    app.logger.debug('ticket: %s', ticket)

    if not ticket:
        # No ticket, the request comes from end user, send to CAS login
        cas_login_url = cas_client.get_login_url()
        app.logger.debug('case no ticket')
        app.logger.debug('CAS login URL: %s', cas_login_url)
        if next_url:
            cas_login_url += '&next=' + next_url
        return redirect(cas_login_url)
    app.logger.debug('ticket:', request.args.get('ticket'))
    
    app.logger.debug('prima del blocco try-catch')

    # There is a ticket, the request comes from CAS as callback.
    # Need to call `verify_ticket()` to validate ticket and get user profile.
    app.logger.debug('ticket: %s', ticket)
    app.logger.debug('next: %s', next_url)

    try:
        app.logger.debug('siamo prima della validazione del ticket')
        email, attributes, pgtiou = cas_client.verify_ticket(ticket)
        app.logger.debug('Email: %s', email)
        session['username'] = email
        if next_url:
            return redirect(next_url)
        else:
            return redirect(url_for('profile'))
    except Exception as e:
        app.logger.error('Error verifying ticket: %s', str(e))
        return jsonify({"error": "Login failed. Please try again later.", "success": False}), 500

@app.route('/logout')
def logout():
    session.pop('username', None)
    cas_logout_url = cas_client.get_logout_url(url_for('logout_callback', _external=True))
    return redirect(cas_logout_url)

@app.route('/logout_callback')
def logout_callback():
    return 'Logout effettuato con successo. <a href="/login">Login</a>'

if __name__ == '__main__':
    app.run(debug=True)
