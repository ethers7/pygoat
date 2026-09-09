# Broken Authentication Lab

This is a deliberately vulnerable web application that demonstrates common authentication vulnerabilities. It is designed for educational purposes to help understand various authentication security issues and their prevention.

## Vulnerabilities Included

1. Weak Password Requirements
2. Plain Text Password Storage
3. Insecure Session Management
4. Vulnerable "Remember Me" Functionality
5. Predictable Password Reset Tokens
6. No Brute Force Protection

## Setup Instructions

### Prerequisites
- Docker
- Docker Compose

### Running the Lab

1. Clone the repository
2. Navigate to the broken_auth_lab directory
3. Build and run the container:
   ```bash
   docker-compose up --build
   ```
4. Access the lab at http://localhost:5000
   (browsers treat `localhost` as a trustworthy origin, so the `Secure` session
   cookie works over plain HTTP on this address; reach the lab through
   `localhost`, not a LAN IP)

> **Note on how the app is served:** the container runs the app through
> `gunicorn --bind 0.0.0.0:5000 --workers 2 app:app` as the unprivileged
> `appuser`, and the Flask/Werkzeug debugger is disabled. The debugger used to
> be enabled here, which leaked source code and configuration in tracebacks and
> exposed an interactive console that could run arbitrary code inside the
> container -- neither of which is an authentication lesson. If you prefer to run
> the lab without Docker, `python app.py` still starts Flask's development
> server on port 5000, also without debug mode. All the authentication
> weaknesses below behave exactly the same under either entrypoint.

### Default Credentials

The lab comes with two pre-configured users:
- Admin User:
  - Username: admin
  - Password: admin123
  - Email: admin@example.com

- Regular User:
  - Username: user
  - Password: password123
  - Email: user@example.com

## Lab Exercises

> **Note on CSRF:** every form in this lab posts a hidden `csrf_token` field that
> is bound to the framework session cookie (`lab_framework_session`), and the app
> answers `400` to any POST that does not present a matching token. Cross-site
> request forgery is not one of the weaknesses this lab teaches, so the exercises
> below are unaffected. If you replay a request with curl, Burp or a script, send
> the `lab_framework_session` cookie together with the `csrf_token` value taken
> from the form (or pass it as the `X-CSRFToken` header). The deliberately weak
> base64 `session` cookie is a separate cookie and is still yours to attack.

1. **Password Policy Bypass**
   - Try to create accounts with weak passwords
   - Observe the lack of password requirements

2. **Session Token Analysis**
   - Login with remember me enabled
   - Analyze the session cookie structure
   - Try to manipulate the session token
   - Note: the `session` cookie is issued with `Secure`, `HttpOnly` and
     `SameSite=Lax`, so it is not readable from `document.cookie`. Inspect it in
     your browser devtools (Application > Cookies) and use the Logout button,
     which clears the cookie server-side. The token itself is still an
     unauthenticated base64 blob, so the exercise is unchanged.

3. **Password Reset Exploitation**
   - Request a password reset
   - Analyze the reset token generation
   - Try to predict or manipulate reset tokens

4. **Role Escalation**
   - Login as a regular user
   - Try to escalate privileges to admin

## Security Notice

This application contains intentional security vulnerabilities for educational purposes. DO NOT deploy this in a production environment or expose it to the public internet.

## Prevention Tips

1. Implement strong password policies
2. Use secure password hashing (bcrypt, Argon2)
3. Implement proper session management
4. Use secure token generation
5. Implement rate limiting and brute force protection
6. Use HTTPS
7. Implement proper access controls
8. Enable security headers
9. Use secure configuration in production 