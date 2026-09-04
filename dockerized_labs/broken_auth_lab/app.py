from flask import Flask, render_template, request, redirect, url_for, make_response, flash
import json
import os
import secrets
from datetime import datetime, timedelta
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
    app.run(host='0.0.0.0', port=5000, debug=True)  # Vulnerable: Debug mode enabled in production 