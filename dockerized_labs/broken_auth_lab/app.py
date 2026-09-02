from flask import (
    Flask,
    abort,
    flash,
    g,
    make_response,
    redirect,
    render_template,
    request,
    url_for,
)
import hashlib
import hmac
import json
import os
import secrets
from datetime import datetime, timedelta
import base64

app = Flask(__name__)
app.secret_key = 'your-secret-key-here'  # Vulnerable: Hardcoded secret key

# CWE-614: the session cookie is only marked Secure when the lab is actually
# served over HTTPS. The shipped docker-compose setup serves plain HTTP on
# port 5000, so a hard-coded secure=True would make browsers drop the cookie
# and break the lab; set BROKEN_AUTH_LAB_HTTPS=1 when fronting it with TLS.
SESSION_COOKIE_SECURE = os.environ.get('BROKEN_AUTH_LAB_HTTPS', '').strip().lower() in (
    '1', 'true', 'yes', 'on'
)

# CWE-489: Flask's debug mode mounts the Werkzeug interactive debugger, which
# hands anyone able to reach the port an arbitrary-code-execution console (and
# leaks tracebacks with source and config), so it stays off by default even
# though the container image sets FLASK_ENV=development. Developers who want
# the reloader/debugger can opt in per run with BROKEN_AUTH_LAB_DEBUG=1.
DEBUG_ENABLED = os.environ.get('BROKEN_AUTH_LAB_DEBUG', '').strip().lower() in (
    '1', 'true', 'yes', 'on'
)

# CWE-668: the development server binds loopback only, so a `python app.py` run
# on a workstation or shared host is not reachable from the network. Binding
# every interface is a deployment decision, not a source-code default: the
# container image sets BROKEN_AUTH_LAB_HOST=0.0.0.0 (see Dockerfile) because a
# process inside a container must bind a container-visible address for the
# published port to work.
LISTEN_HOST = os.environ.get('BROKEN_AUTH_LAB_HOST', '').strip() or '127.0.0.1'

# CWE-352: Jinja2 has no {% csrf_token %} tag, so this lab issues its own
# per-visitor CSRF token. The token is a random nonce plus an HMAC-SHA256
# signature, handed to the browser in a cookie and rendered into every
# state-changing form. A cross-site page can neither read the cookie nor mint a
# correctly signed value, so forged POSTs are rejected below. The signing key
# comes from the environment; when unset a random per-process key is used,
# which only invalidates tokens issued by earlier runs.
CSRF_COOKIE_NAME = 'csrf_token'
CSRF_FORM_FIELD = 'csrf_token'
CSRF_PROTECTED_METHODS = ('POST', 'PUT', 'PATCH', 'DELETE')
CSRF_SIGNING_KEY = (
    os.environ.get('BROKEN_AUTH_LAB_CSRF_KEY', '').encode() or secrets.token_bytes(32)
)


def _csrf_signature(nonce):
    return hmac.new(CSRF_SIGNING_KEY, nonce.encode(), hashlib.sha256).hexdigest()


def _issue_csrf_token():
    nonce = secrets.token_urlsafe(32)
    return '{}.{}'.format(nonce, _csrf_signature(nonce))


def _is_valid_csrf_token(token):
    nonce, separator, signature = token.partition('.')
    if not separator or not nonce or not signature:
        return False
    return hmac.compare_digest(signature, _csrf_signature(nonce))


def _current_csrf_token():
    """Return this visitor's CSRF token, issuing one when needed."""
    token = getattr(g, 'csrf_token', None)
    if token is None:
        token = request.cookies.get(CSRF_COOKIE_NAME, '')
        if not _is_valid_csrf_token(token):
            token = _issue_csrf_token()
            g.csrf_token_is_new = True
        g.csrf_token = token
    return token


@app.context_processor
def inject_csrf_token():
    # Templates call {{ csrf_token() }} inside every POST form.
    return {'csrf_token': _current_csrf_token}


@app.before_request
def verify_csrf_token():
    if request.method not in CSRF_PROTECTED_METHODS:
        return
    cookie_token = request.cookies.get(CSRF_COOKIE_NAME, '')
    form_token = request.form.get(CSRF_FORM_FIELD, '')
    if not cookie_token or not form_token:
        abort(400, description='CSRF token missing')
    if not hmac.compare_digest(cookie_token, form_token) or not _is_valid_csrf_token(
        form_token
    ):
        abort(400, description='CSRF token invalid')


@app.after_request
def store_csrf_token(response):
    if getattr(g, 'csrf_token_is_new', False):
        response.set_cookie(
            CSRF_COOKIE_NAME,
            g.csrf_token,
            httponly=True,
            samesite='Lax',
            secure=SESSION_COOKIE_SECURE,
        )
    return response

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
            response.set_cookie(
                'session',
                session_token,
                max_age=30*24*60*60,
                httponly=True,
                samesite='Lax',
                secure=SESSION_COOKIE_SECURE,
            )
        else:
            response.set_cookie(
                'session',
                session_token,
                httponly=True,
                samesite='Lax',
                secure=SESSION_COOKIE_SECURE,
            )


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
            # CWE-327/CWE-330: the reset token is drawn from the OS CSPRNG
            # instead of being an MD5 digest of guessable inputs (the email
            # address plus a timestamp), which an attacker could recompute.
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
    # The session cookie is HttpOnly, so it cannot be cleared from JavaScript;
    # the server clears it here instead.
    response = make_response(redirect(url_for('lab')))
    response.delete_cookie('session', samesite='Lax', secure=SESSION_COOKIE_SECURE)
    return response

if __name__ == '__main__':
    # Debug defaults to off; passing it explicitly also keeps a stray
    # FLASK_DEBUG/FLASK_ENV in the environment from turning the debugger on.
    app.run(host=LISTEN_HOST, port=5000, debug=DEBUG_ENABLED) 