from flask import Flask, redirect, request, session as flask_session, url_for, jsonify
from cas import CASClient
import logging
import os
import ssl
import requests
from requests.adapters import HTTPAdapter
from requests.packages.urllib3.poolmanager import PoolManager

class SSLAdapter(HTTPAdapter):
    def init_poolmanager(self, *args, **kwargs):
        context = ssl.create_default_context()
        context.set_ciphers('DEFAULT@SECLEVEL=1')  # Abbassa il livello di sicurezza per consentire chiavi DH più piccole
        kwargs['ssl_context'] = context
        return super(SSLAdapter, self).init_poolmanager(*args, **kwargs)


# Configura il logging
logging.basicConfig(level=logging.DEBUG)

# Crea una sessione personalizzata
http_session = requests.Session()
http_session.mount('https://', SSLAdapter())

app = Flask(__name__)
#app.secret_key = 'V7nlCN90LPHOTA9PGGyf'  # Assicurati di usare una chiave segreta sicura in produzione
app.secret_key = os.urandom(24)

# Configura CASClient
cas_client = CASClient(
    version=3,
    service_url='http://127.0.0.1:5000/login?next=%2Flogin',  # URL di servizio
    server_url='https://sso.staging.unimi.it:6443/',  # URL del tuo server CAS
    #verify_ssl_certificate=False
    session=http_session
)

@app.route('/')
def index():
    return '''
        <h1>Benvenuti nel test di login di CAS</h1>
        <a href="/login"><button>Login</button></a>
    '''

@app.route('/profile')
def profile():
    if 'username' in flask_session:
        username = flask_session['username']
        return f'Ciao {username}'
    else:
        #return redirect(url_for('login'))
        return f'non ti conosco'

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
    #app.logger.debug('ticket:', request.args.get('ticket'))
    
    app.logger.debug('prima del blocco try-catch')

    # There is a ticket, the request comes from CAS as callback.
    # Need to call `verify_ticket()` to validate ticket and get user profile.
    app.logger.debug('ticket: %s', ticket)
    app.logger.debug('next: %s', next_url)

    try:
        app.logger.debug('siamo dentro al try catch')
        app.logger.debug('siamo prima della validazione del ticket')
        user, attributes, pgtiou = cas_client.verify_ticket(ticket)
        app.logger.debug('Email: %s', user)
        flask_session['username'] = user
        #if next_url:
        #    return redirect(next_url)
        #else:
        #    return redirect(url_for('profile'))
        #print(attributes)
        app.logger.debug(f"attributes: {attributes}")
        return jsonify({"attributes": attributes, "user":user})
    except Exception as e:
        app.logger.error('Error verifying ticket: %s', str(e))
        return jsonify({"error": "Login failed. Please try again later.", "success": False}), 500

@app.route('/logout')
def logout():
    flask_session.pop('username', None)
    cas_logout_url = cas_client.get_logout_url(url_for('logout_callback', _external=True))
    return redirect(cas_logout_url)

@app.route('/logout_callback')
def logout_callback():
    return 'Logout effettuato con successo. <a href="/login">Login</a>'

if __name__ == '__main__':
    app.run(debug=True)
