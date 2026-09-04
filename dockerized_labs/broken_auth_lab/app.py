from flask import Flask, render_template, request, redirect, url_for, make_response, flash, abort, g
import hmac
import json
import os
import re
import secrets
from datetime import datetime, timedelta
from hashlib import sha256
import base64

app = Flask(__name__)
app.secret_key = 'your-secret-key-here'  # Vulnerable: Hardcoded secret key

# "Remember me" cookie lifetime (30 days).
REMEMBER_ME_MAX_AGE = 30 * 24 * 60 * 60

# Environment flag that lets an operator serve this lab over plain HTTP.
# Secure cookies are the default; opting out has to be explicit.
INSECURE_COOKIES_ENV = 'BROKEN_AUTH_LAB_INSECURE_COOKIES'


def secure_cookies_enabled():
    """Return True unless the operator explicitly opts out.

    The session cookie is marked Secure by default so it is never sent over
    plaintext HTTP. Browsers only return Secure cookies over HTTPS, so a
    deployment that is intentionally served over plain HTTP (for example the
    local docker-compose lab on http://localhost:5000) must opt out by setting
    BROKEN_AUTH_LAB_INSECURE_COOKIES to 1/true/yes/on - see README.md.
    """
    opt_out = os.environ.get(INSECURE_COOKIES_ENV, '')
    return opt_out.strip().lower() not in ('1', 'true', 'yes', 'on')


# Environment flag that lets an operator turn Flask's debug mode back on for a
# local troubleshooting session. Debug mode is off unless this is set.
DEBUG_ENV = 'BROKEN_AUTH_LAB_DEBUG'


def debug_enabled():
    """Return True only when the operator explicitly opts in to debug mode.

    Flask's debug mode serves the Werkzeug interactive debugger, which turns any
    unhandled exception into an in-browser Python console (remote code
    execution) and leaks source plus local variables in tracebacks. It is
    therefore off by default: an unset, empty or unrecognised value means OFF,
    and only 1/true/yes/on (case-insensitive) enable it - see README.md.

    An explicit bool is returned so the result always wins over Flask's own
    FLASK_DEBUG/FLASK_ENV defaults rather than falling back to them.
    """
    opt_in = os.environ.get(DEBUG_ENV, '')
    return opt_in.strip().lower() in ('1', 'true', 'yes', 'on')


# Interface the development server binds to. It defaults to loopback, so running
# "python app.py" straight on a workstation exposes this deliberately vulnerable
# lab to that machine only - never to the rest of the LAN/VPC. The container
# image sets BROKEN_AUTH_LAB_HOST=0.0.0.0 (see Dockerfile), where binding every
# interface is the correct behaviour: the network namespace is the isolation
# boundary and the published port has to be able to reach the app - see README.md.
BIND_HOST_ENV = 'BROKEN_AUTH_LAB_HOST'
DEFAULT_BIND_HOST = '127.0.0.1'

# A bind address is a hostname or an IP literal: letters, digits, dot, dash and
# underscore, plus colon and brackets for IPv6 forms such as [::1].
BIND_HOST_PATTERN = re.compile(r'^[A-Za-z0-9._:\[\]-]{1,253}$')


def bind_host():
    """Return the validated address app.run() should bind to.

    An unset, empty, whitespace-only or malformed value falls back to
    DEFAULT_BIND_HOST: a value that is not a usable address must never silently
    turn into "bind every interface". Only an explicit, well formed value from
    the environment widens the bind address.
    """
    requested = os.environ.get(BIND_HOST_ENV, '').strip()
    if not requested:
        return DEFAULT_BIND_HOST
    if not BIND_HOST_PATTERN.match(requested):
        # The rejected value is deliberately not logged (it is attacker/operator
        # supplied text that would land in the log verbatim).
        app.logger.warning('Ignoring malformed %s; binding to %s instead.', BIND_HOST_ENV, DEFAULT_BIND_HOST)
        return DEFAULT_BIND_HOST
    return requested


# --------------------------------------------------------------------------
# CSRF protection
#
# Every state changing request (POST/PUT/PATCH/DELETE) has to carry a token
# that matches the one bound to the caller's own browser, so another site can
# no longer make a logged in browser submit these forms (login, register,
# password reset, logout).
#
# The token is an HMAC over a random per-browser id stored in the "csrf_id"
# cookie. The HMAC key is process local (or supplied through the environment)
# and is deliberately NOT app.secret_key: this lab intentionally ships a weak,
# publicly known Flask secret key as one of its exercises, and the CSRF token
# has to stay unguessable regardless of that.
# --------------------------------------------------------------------------
CSRF_COOKIE_NAME = 'csrf_id'
CSRF_FIELD_NAME = 'csrf_token'
CSRF_HEADER_NAME = 'X-CSRF-Token'
CSRF_SAFE_METHODS = frozenset(('GET', 'HEAD', 'OPTIONS', 'TRACE'))
CSRF_KEY_ENV = 'BROKEN_AUTH_LAB_CSRF_KEY'
CSRF_KEY = (os.environ.get(CSRF_KEY_ENV) or secrets.token_urlsafe(32)).encode('utf-8')


def csrf_token_for(csrf_id):
    """Return the CSRF token bound to a single browser's csrf_id."""
    return hmac.new(CSRF_KEY, csrf_id.encode('utf-8'), sha256).hexdigest()


def current_csrf_token():
    """Return the CSRF token for the request being handled ('' if unknown)."""
    csrf_id = getattr(g, 'csrf_id', '')
    return csrf_token_for(csrf_id) if csrf_id else ''


@app.before_request
def csrf_protect():
    """Fail closed on any state changing request without a valid token."""
    cookie_id = request.cookies.get(CSRF_COOKIE_NAME, '')
    if request.method not in CSRF_SAFE_METHODS:
        submitted = request.form.get(CSRF_FIELD_NAME, '') or request.headers.get(CSRF_HEADER_NAME, '')
        expected = csrf_token_for(cookie_id) if cookie_id else ''
        if not expected or not submitted or not hmac.compare_digest(submitted, expected):
            abort(400, 'CSRF token missing or invalid')
    if not cookie_id:
        cookie_id = secrets.token_urlsafe(32)
        g.csrf_cookie_pending = True
    g.csrf_id = cookie_id


@app.after_request
def send_csrf_cookie(response):
    """Hand a browser its csrf_id the first time we see it."""
    if getattr(g, 'csrf_cookie_pending', False):
        response.set_cookie(
            CSRF_COOKIE_NAME,
            g.csrf_id,
            secure=secure_cookies_enabled(),
            httponly=True,
            samesite='Lax',
        )
    return response


@app.context_processor
def inject_csrf_token():
    """Expose {{ csrf_token() }} to templates (same shape as Flask-WTF)."""
    return {'csrf_token': current_csrf_token}


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
        
        # Vulnerable: Insecure "Remember Me" implementation (long-lived,
        # guessable token). The token contents stay part of the exercise, but
        # the cookie carrying it is now protected: HttpOnly keeps it out of
        # document.cookie/XSS, SameSite blocks cross-site sends, and Secure
        # (on by default) keeps it off plaintext HTTP.
        max_age = REMEMBER_ME_MAX_AGE if remember_me else None
        response.set_cookie(
            'session',
            session_token,
            max_age=max_age,
            secure=secure_cookies_enabled(),
            httponly=True,
            samesite='Lax',
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
            # Fixed: the reset token is 32 bytes from the OS CSPRNG instead of
            # an MD5 digest of guessable data (email + timestamp), so it cannot
            # be predicted or brute forced offline.
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
    # The session cookie is HttpOnly, so it cannot be cleared from JavaScript
    # any more: clearing it is done server side with the same attributes it
    # was set with.
    response = make_response(redirect(url_for('lab')))
    response.delete_cookie(
        'session',
        secure=secure_cookies_enabled(),
        httponly=True,
        samesite='Lax',
    )
    return response

if __name__ == '__main__':
    # Fixed: debug mode is no longer hardcoded on. It defaults to OFF, so the
    # Werkzeug interactive debugger (an unauthenticated RCE console on any
    # unhandled exception) is not exposed; an operator has to opt in explicitly
    # with BROKEN_AUTH_LAB_DEBUG - see README.md.
    # Fixed: the bind address is no longer hardcoded to every interface. It
    # defaults to loopback and is only widened when BROKEN_AUTH_LAB_HOST asks
    # for it - the container sets that to 0.0.0.0 so the published port keeps
    # working - see README.md.
    app.run(host=bind_host(), port=5000, debug=debug_enabled())
