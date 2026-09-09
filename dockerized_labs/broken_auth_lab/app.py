from flask import Flask, abort, render_template, request, redirect, url_for, make_response, flash, session
import hmac
import json
import os
import secrets
from datetime import datetime, timedelta
import base64

app = Flask(__name__)
app.secret_key = 'your-secret-key-here'  # Vulnerable: Hardcoded secret key

# CWE-614: attributes applied to every session cookie this app issues.
# HttpOnly keeps the cookie out of document.cookie and SameSite=Lax keeps it
# off cross-site requests, so both are always on. The Secure attribute has to
# follow the transport actually in use: docker-compose serves this lab over
# plain http://localhost:5000 (see docker-compose.yml and README.md), and a
# browser silently drops a Secure cookie on a plaintext origin, so it defaults
# to off here and is switched on with SESSION_COOKIE_SECURE=true when the app
# is deployed behind HTTPS.
SESSION_COOKIE_SECURE = os.environ.get('SESSION_COOKIE_SECURE', 'false').strip().lower() in ('1', 'true', 'yes', 'on')
SESSION_COOKIE_HTTPONLY = True
SESSION_COOKIE_SAMESITE = 'Lax'

# CWE-352: /login, /register and /reset-password all change state, so the forms
# in templates/lab.html and templates/reset.html have to prove the request came
# from a page this app rendered. Jinja2 has no Django style {% csrf_token %}
# tag, so the per-session token is exposed to the templates as csrf_token() and
# checked here for every unsafe request.
CSRF_FIELD_NAME = 'csrf_token'
CSRF_SESSION_KEY = '_csrf_token'
CSRF_SAFE_METHODS = frozenset(('GET', 'HEAD', 'OPTIONS', 'TRACE'))


def csrf_token():
    """Return this session's CSRF token, creating it on first use."""
    token = session.get(CSRF_SESSION_KEY)
    if not token:
        token = secrets.token_urlsafe(32)
        session[CSRF_SESSION_KEY] = token
    return token


app.jinja_env.globals['csrf_token'] = csrf_token


@app.before_request
def require_csrf_token():
    """Reject unsafe requests with a missing or wrong CSRF token.

    The submitted value is compared with hmac.compare_digest so a token cannot
    be recovered one character at a time from response timing.
    """
    if request.method in CSRF_SAFE_METHODS:
        return None

    expected = session.get(CSRF_SESSION_KEY, '')
    submitted = (request.form.get(CSRF_FIELD_NAME, '')
                 or request.headers.get('X-CSRFToken', ''))
    if not expected or not submitted.isascii():
        abort(400)
    if not hmac.compare_digest(expected, submitted):
        abort(400)
    return None

# Vulnerable: Storing user data in memory
users = {
    'admin': {
        'password': 'admin123',  # Vulnerable: Weak password
        'email': 'admin@example.com',
        'role': 'admin'
    },
    'user': {
        'password': 'password123',  # Vulnerable: Weak password
        'email': 'user@example.com',
        'role': 'user'
    }
}

# Vulnerable: Storing reset tokens in memory
password_reset_tokens = {}

@app.route('/')
def index():
    return render_template('index.html')

@app.route('/lab')
def lab():
    return render_template('lab.html')

@app.route('/login', methods=['POST'])
def login():
    username = request.form.get('username')
    password = request.form.get('password')
    remember_me = request.form.get('remember_me')

    if username in users and users[username]['password'] == password:  # Vulnerable: Plain text password comparison
        response = make_response(redirect(url_for('dashboard')))
        
        # Vulnerable: Insecure session management
        session_token = base64.b64encode(f"{username}:{datetime.now()}".encode()).decode()
        
        if remember_me:
            # Vulnerable: Insecure "Remember Me" implementation
            response.set_cookie('session', session_token, max_age=30*24*60*60,
                                secure=SESSION_COOKIE_SECURE,
                                httponly=SESSION_COOKIE_HTTPONLY,
                                samesite=SESSION_COOKIE_SAMESITE)
        else:
            response.set_cookie('session', session_token,
                                secure=SESSION_COOKIE_SECURE,
                                httponly=SESSION_COOKIE_HTTPONLY,
                                samesite=SESSION_COOKIE_SAMESITE)

        return response
    
    flash('Invalid username or password')
    return redirect(url_for('lab'))

@app.route('/register', methods=['POST'])
def register():
    username = request.form.get('username')
    password = request.form.get('password')
    email = request.form.get('email')
    
    # Vulnerable: No password complexity requirements
    if username and password and email:
        if username not in users:
            users[username] = {
                'password': password,  # Vulnerable: Storing plain text passwords
                'email': email,
                'role': 'user'
            }
            flash('Registration successful')
            return redirect(url_for('lab'))
    
    flash('Registration failed')
    return redirect(url_for('lab'))

@app.route('/reset-password', methods=['POST'])
def reset_password():
    email = request.form.get('email')
    
    for username, user_data in users.items():
        if user_data['email'] == email:
            # CWE-327/CWE-330: the reset token is 256 bits from the OS CSPRNG
            # instead of an MD5 digest of the email and timestamp, which is both
            # a broken hash and guessable from values an attacker knows.
            token = secrets.token_urlsafe(32)
            password_reset_tokens[token] = username
            
            # In a real application, this would send an email
            # Vulnerable: Token exposed in response
            flash(f'Password reset link: /reset/{token}')
            return redirect(url_for('lab'))
    
    flash('Email not found')
    return redirect(url_for('lab'))

def lookup_reset_token(token):
    """Return the username a reset token belongs to, or None.

    The candidate is compared with hmac.compare_digest so a submitted token is
    matched in constant time and its correct prefix length cannot be recovered
    from response timing.
    """
    if not token or not token.isascii():
        return None
    for candidate, username in password_reset_tokens.items():
        if hmac.compare_digest(candidate, token):
            return username
    return None


@app.route('/reset/<token>')
def reset_form(token):
    if lookup_reset_token(token) is not None:
        return render_template('reset.html', token=token)
    return 'Invalid token'

@app.route('/dashboard')
def dashboard():
    session_token = request.cookies.get('session')
    if not session_token:
        return redirect(url_for('lab'))
    
    try:
        # Vulnerable: Insecure session validation
        username = base64.b64decode(session_token).decode().split(':')[0]
        if username in users:
            return render_template('dashboard.html', 
                                username=username, 
                                role=users[username]['role'],
                                email=users[username]['email'])
    except:
        pass
    
    return redirect(url_for('lab'))

@app.route('/logout')
def logout():
    # The session cookie is HttpOnly, so it can no longer be cleared from
    # JavaScript (see templates/dashboard.html); expire it on the server with
    # the same attributes it was issued with.
    response = make_response(redirect(url_for('lab')))
    response.delete_cookie('session',
                           secure=SESSION_COOKIE_SECURE,
                           httponly=SESSION_COOKIE_HTTPONLY,
                           samesite=SESSION_COOKIE_SAMESITE)
    return response

if __name__ == '__main__':
    # CWE-489: the Werkzeug debugger hands out an interactive Python console on
    # any unhandled exception, so a shipped app that runs with debug=True is
    # remote code execution. The debugger is therefore off unless it is asked
    # for explicitly with FLASK_DEBUG=true in the environment, parsed the same
    # way as SESSION_COOKIE_SECURE above. The lab still comes up on
    # http://localhost:5000 (see docker-compose.yml and README.md) with it off.
    FLASK_DEBUG = os.environ.get('FLASK_DEBUG', 'false').strip().lower() in ('1', 'true', 'yes', 'on')
    app.run(host='0.0.0.0', port=5000, debug=FLASK_DEBUG) 