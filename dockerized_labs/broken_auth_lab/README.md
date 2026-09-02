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

### Configuration

- `BROKEN_AUTH_LAB_CSRF_KEY` - key used to sign CSRF tokens. When unset, a
  random per-process key is generated, so tokens from earlier runs stop working.
- `BROKEN_AUTH_LAB_HTTPS=1` - set when the lab is fronted with TLS so the
  session and CSRF cookies are also marked `Secure`.
- `BROKEN_AUTH_LAB_DEBUG=1` - opt in to Flask's debug mode (reloader plus the
  Werkzeug interactive debugger). It is **off by default**: the debugger is a
  remote code execution console for anyone who can reach port 5000, so only
  enable it on a local, non-shared run. Leaving it unset does not change how
  the lab is started or exercised.

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

1. **Password Policy Bypass**
   - Try to create accounts with weak passwords
   - Observe the lack of password requirements

2. **Session Token Analysis**
   - Login with remember me enabled
   - Analyze the session cookie structure
   - Try to manipulate the session token

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