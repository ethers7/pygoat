# Insecure Deserialization Lab

A vulnerable web application demonstrating insecure deserialization vulnerabilities in Python using pickle.

## Description

This lab demonstrates the dangers of insecure deserialization by walking through a user session mechanism that round-trips state through a client-supplied token. The application allows users to:

1. Create a regular user account
2. Receive a serialized token
3. Submit the token for deserialization
4. Attempt to tamper with the token to gain admin access

The deserialization step is now hardened (see [Remediation](#remediation)): the token is signed JSON instead of a pickle payload, so tampering is detected and rejected instead of being executed.

## Features

- Signed JSON tokens (`itsdangerous.URLSafeSerializer`, bundled with Flask)
- Strict type checks on the decoded payload
- User role system (regular user vs admin)
- Docker containerization
- Light/Dark theme support

## Security Warning

⚠️ This lab contains intentionally vulnerable code for educational purposes. Do not use this code in production environments.

## Installation

### Using Docker (Recommended)

1. Build and run using Docker Compose:
```bash
docker-compose up --build
```

2. Access the lab at http://localhost:8080

   (the session cookie that carries the CSRF token is issued with `Secure`,
   `HttpOnly` and `SameSite=Lax`; browsers treat `localhost` as a trustworthy
   origin, so reach the lab through `localhost`, not a LAN IP)

### Manual Setup

1. Create a virtual environment:
```bash
python -m venv venv
source venv/bin/activate  # Linux/Mac
# or
venv\Scripts\activate     # Windows
```

2. Install requirements:
```bash
pip install -r requirements.txt
```

3. Run the application:
```bash
python main.py
```

## Lab Structure

```
insec_des_lab/
├── docker-compose.yml    # Docker Compose configuration
├── Dockerfile           # Docker container definition
├── main.py             # Flask application
├── requirements.txt    # Python dependencies
├── static/            # Static assets
│   └── style.css     # Theme and styling
└── templates/        # HTML templates
    ├── base.html    # Base template with theme support
    ├── index.html   # Main page
    └── result.html  # Results display
```

## Vulnerability Details

The original version of this lab used Python's `pickle` module for serialization/deserialization of user data. The vulnerability existed because:

1. The application trusted user-provided serialized data
2. It called `pickle.loads()` without any integrity check or validation
3. The `User` class exposed a `__reduce__` method, turning deserialization into arbitrary code execution

## Exploitation Steps (against the vulnerable version)

1. Create a regular user account
2. Intercept the serialized token
3. Decode the base64 token
4. Modify the serialized data to set is_admin=True
5. Re-encode the modified data
6. Submit the modified token to gain admin access

## Remediation

The lab feature is unchanged &mdash; `/serialize` still issues a token and `/deserialize` still restores the user from it &mdash; but both sides now use a safe format:

- `/serialize` returns `URLSafeSerializer.dumps()` output: a URL-safe JSON payload plus a signature.
- `/deserialize` calls `URLSafeSerializer.loads()`, which verifies the signature before the payload is parsed, then rebuilds `User` from validated JSON primitives (`str` username, `bool` is_admin). There is no pickle fallback.
- The `__reduce__` gadget was removed from `User`.
- The signing key is read from the `LAB_SECRET_KEY` environment variable; when unset, a random per-process key is generated (no secret is committed).
- Both forms post a hidden `csrf_token` field that is bound to the session cookie, and unsafe requests without a matching token are rejected with `400` (CWE-352). CSRF is not the weakness this lab teaches, so the exercise is unchanged; when replaying `/serialize` or `/deserialize` with curl or a script, send the session cookie plus the `csrf_token` value from the form (or the `X-CSRFToken` header).

Tampering with the payload now yields a signature error, which is exactly the behaviour the lab is meant to teach.

## Mitigation Strategies

To prevent insecure deserialization vulnerabilities:

1. Never use pickle for user-controlled data
2. Use secure serialization formats like JSON
3. Implement digital signatures for serialized data
4. Validate and sanitize all user input
5. Use principle of least privilege

