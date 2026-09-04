# Broken Authentication Lab

This is a deliberately vulnerable web application that demonstrates common authentication vulnerabilities. It is designed for educational purposes to help understand various authentication security issues and their prevention.

## Vulnerabilities Included

1. Weak Password Requirements
2. Plain Text Password Storage
3. Insecure Session Management (the session token is still a guessable base64 blob, but the
   cookie carrying it is now fixed: it is set with `HttpOnly`, `SameSite=Lax` and `Secure`)
4. Vulnerable "Remember Me" Functionality (still a 30-day token; the cookie flags above apply
   to it as well)
5. Password Reset Token Handling (token generation is now fixed: reset tokens come from a
   cryptographically secure random generator instead of an MD5 digest of email + timestamp;
   the remaining reset weaknesses - no expiry, token shown in the UI - are still exercises)
6. No Brute Force Protection
7. Debug Mode Enabled in Production

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

### Cookie security flag (plain HTTP opt-out)

The session cookie is set with `Secure` **by default**, which means browsers only send it back
over HTTPS. This lab is served over plain HTTP on `http://localhost:5000`, so if you run it that
way you must explicitly opt out, otherwise the browser will drop the cookie and login will appear
to do nothing:

```bash
# only for local, plain-HTTP runs of this lab
BROKEN_AUTH_LAB_INSECURE_COOKIES=1 docker-compose up --build
```

or add it to the `environment:` block in `docker-compose.yml`:

```yaml
    environment:
      - BROKEN_AUTH_LAB_INSECURE_COOKIES=1
```

Accepted opt-out values are `1`, `true`, `yes` and `on` (case-insensitive). Anything else - including
leaving the variable unset - keeps the secure behaviour. When the lab is served over HTTPS, leave the
variable unset. `HttpOnly` and `SameSite=Lax` are always applied and are not configurable.

### CSRF protection

CSRF is **not** one of this lab's exercises, so it is fixed rather than left open. Every state
changing request (`/login`, `/register`, `/reset-password`, `/logout`) must carry a `csrf_token`
form field (or an `X-CSRF-Token` header); requests without a valid token are rejected with
`400 CSRF token missing or invalid`. The token is an HMAC over a random per-browser id kept in the
`csrf_id` cookie, and it is verified **server side** on every unsafe request - a hidden field on its
own would be no protection at all. The HMAC key is generated per process, or can be pinned across
restarts with `BROKEN_AUTH_LAB_CSRF_KEY`; it is intentionally independent of the weak, hardcoded
Flask `secret_key` that is still part of the lab. The `csrf_id` cookie follows the same
`Secure`/`HttpOnly`/`SameSite=Lax` rules as the session cookie, so plain-HTTP runs need the opt-out
above for the forms to work.

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
   - Analyze the session cookie structure - it is now `HttpOnly`, so `document.cookie` cannot
     read it; use developer tools (Application > Cookies) or a proxy instead
   - Try to manipulate the session token (the token itself is still forgeable: that is the exercise)

3. **Password Reset Exploitation**
   - Request a password reset
   - Analyze the reset token generation: it now uses `secrets.token_urlsafe(32)` (CSPRNG),
     so predicting it is no longer feasible - contrast that with the old MD5(email + timestamp) token
   - The token still never expires and is shown in the UI: exploit those instead

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