from flask import (Flask, abort, render_template, request, redirect, url_for,
                   make_response, flash, session)
import hmac
import json
import secrets
from datetime import datetime, timedelta
import base64

app = Flask(__name__)
app.secret_key = 'your-secret-key-here'  # Vulnerable: Hardcoded secret key

# Cookie hardening (CWE-614 / CWE-1004 / CWE-1275). Every cookie this app
# issues carries:
#   secure=True     -> never transmitted over plaintext HTTP
#   httponly=True   -> not readable from document.cookie (XSS cannot steal it)
#   samesite='Lax'  -> not attached to cross-site requests (CSRF hardening)
# The lab is reached at http://localhost:5000 and browsers treat localhost as a
# trustworthy origin, so Secure cookies keep working without terminating TLS.
# The same attributes are applied to the framework session cookie used by
# flash() through the SESSION_COOKIE_* config below.
app.config['SESSION_COOKIE_SECURE'] = True
app.config['SESSION_COOKIE_HTTPONLY'] = True
app.config['SESSION_COOKIE_SAMESITE'] = 'Lax'

# The lab issues its own deliberately weak cookie called "session" (see login()),
# which is also Flask's default name for the framework session cookie used by
# flash() and by the CSRF token below. Give the framework cookie its own name so
# the two no longer overwrite each other and the base64 session token exercise
# behaves exactly as before.
app.config['SESSION_COOKIE_NAME'] = 'lab_framework_session'

# --- CSRF protection (CWE-352) ---------------------------------------------
# The login, register, password reset and logout forms all change state over
# POST and used to carry no CSRF token, so any site could submit them on a
# visitor's behalf. {% csrf_token %} is a Django tag and does not exist in
# Jinja2, so this is the equivalent control for a Flask app: a per-session
# random token rendered into every form and compared in constant time on unsafe
# requests. It uses the standard library instead of Flask-WTF to avoid adding a
# dependency to this single-file lab. CSRF is not one of the weaknesses this lab
# teaches, so protecting it leaves every exercise intact.
CSRF_FIELD_NAME = 'csrf_token'
CSRF_SESSION_KEY = '_csrf_token'
CSRF_SAFE_METHODS = frozenset({'GET', 'HEAD', 'OPTIONS', 'TRACE'})


def csrf_token():
    """Return this session's CSRF token, creating it on first use."""
    token = session.get(CSRF_SESSION_KEY)
    if not token:
        token = secrets.token_urlsafe(32)
        session[CSRF_SESSION_KEY] = token
    return token


# Exposed to Jinja2 so templates can render {{ csrf_token() }}.
app.jinja_env.globals['csrf_token'] = csrf_token


@app.before_request
def verify_csrf_token():
    """Reject state changing requests that do not present the session token."""
    if request.method in CSRF_SAFE_METHODS:
        return None
    expected = session.get(CSRF_SESSION_KEY)
    submitted = (request.form.get(CSRF_FIELD_NAME)
                 or request.headers.get('X-CSRFToken', ''))
    # Compare as bytes: compare_digest rejects non-ASCII str input, and the
    # submitted value is attacker controlled.
    if not expected or not hmac.compare_digest(expected.encode('utf-8'),
                                               submitted.encode('utf-8')):
        abort(400, 'CSRF token missing or invalid')
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
            # Long-lived cookie (30 days), still Secure/HttpOnly/SameSite=Lax.
            response.set_cookie('session', session_token,
                                max_age=30*24*60*60,
                                secure=True,
                                httponly=True,
                                samesite='Lax')
        else:
            # Browser-session cookie: no max_age, so it dies with the browser.
            response.set_cookie('session', session_token,
                                secure=True,
                                httponly=True,
                                samesite='Lax')


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
    
    # Vulnerable: Password reset token generation
    for username, user_data in users.items():
        if user_data['email'] == email:
            # Reset tokens are unguessable random values from the OS CSPRNG.
            # The previous MD5 digest of "email:timestamp" was both a broken
            # hash (CWE-327) and derived from guessable inputs (CWE-330), so a
            # token could be recomputed offline.
            token = secrets.token_urlsafe(32)
            password_reset_tokens[token] = username
            
            # In a real application, this would send an email
            # Vulnerable: Token exposed in response
            flash(f'Password reset link: /reset/{token}')
            return redirect(url_for('lab'))
    
    flash('Email not found')
    return redirect(url_for('lab'))

@app.route('/reset/<token>')
def reset_form(token):
    if token in password_reset_tokens:
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

@app.route('/logout', methods=['POST'])
def logout():
    # The session cookie is HttpOnly, so JavaScript can no longer clear it.
    # Expire it server-side with the same attributes it was issued with.
    response = make_response(redirect(url_for('lab')))
    response.delete_cookie('session',
                           secure=True,
                           httponly=True,
                           samesite='Lax')
    return response

if __name__ == '__main__':
    # Local development entrypoint only (CWE-489). Debug mode is never enabled:
    # the Werkzeug debugger renders tracebacks with source, locals and config
    # into HTTP responses and exposes an interactive console that allows
    # arbitrary code execution. It is not made configurable either, so it cannot
    # be switched back on by an environment variable or request input.
    # The shipped container does not use this server at all -- it serves the app
    # with gunicorn ("app:app", see Dockerfile), which is the production WSGI
    # entrypoint on the same port 5000.
    # The bind address is the loopback interface rather than the 0.0.0.0
    # wildcard (CWE-668): this development server is for the local browser only,
    # and the wildcard would publish an intentionally vulnerable lab on every
    # interface of the host machine. The container is unaffected -- gunicorn
    # binds 0.0.0.0 inside the container namespace, which is what makes the
    # port published by docker-compose reachable from the host.
    app.run(host='127.0.0.1', port=5000) 