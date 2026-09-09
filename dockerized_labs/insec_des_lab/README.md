# Insecure Deserialization Lab

A web application demonstrating insecure deserialization in Python, and the remediated token handling that replaces it.

## Description

This lab demonstrates the dangers of insecure deserialization through a user session mechanism. The application allows users to:

1. Create a regular user account
2. Receive a serialized token
3. Submit the token for deserialization
4. See why tampering with the token no longer grants admin access

The token round-trip uses signed JSON (a base64url payload plus an HMAC-SHA256 signature) instead of `pickle`, so a hostile token cannot execute code and a client cannot flip its own `is_admin` flag.

## Features

- Signed, data-only (JSON) session tokens with strict type validation
- Base64url encoded payload and signature
- User role system (regular user vs admin)
- Docker containerization
- Light/Dark theme support

## Security Warning

⚠️ This lab exists to teach an OWASP Top 10 category. Do not reuse the demo admin content or the ephemeral key fallback in production environments.

## Configuration

Set `LAB_TOKEN_SIGNING_KEY` to keep tokens valid across restarts. When it is unset the app generates a random per-process key, so previously issued tokens stop validating after a restart. No key is hard-coded.

## Installation

### Using Docker (Recommended)

1. Build and run using Docker Compose:
```bash
docker-compose up --build
```

2. Access the lab at http://localhost:8080

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

The server listens on `127.0.0.1:8080` by default, so it is only reachable from the machine running it. Set `FLASK_RUN_HOST=0.0.0.0` to bind every interface (the Docker setup above does this so the published port works); only do that on a network you trust, because this lab is intentionally vulnerable.

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

The original version of this lab used Python's `pickle` module for serialization/deserialization of user data. That was exploitable because:

1. The application trusted user-provided serialized data
2. It called `pickle.loads()` without integrity or type validation
3. The `User` class exposed a `__reduce__` method, so a crafted payload could run arbitrary code

## What Changed

1. `pickle.dumps()` / `pickle.loads()` were replaced with signed JSON (`json` + `hmac.new(..., hashlib.sha256)`)
2. Signatures are compared with `hmac.compare_digest` before the payload is parsed
3. The parsed payload must contain exactly a string `username` and a boolean `is_admin`; anything else is rejected
4. The pickle-only `__reduce__` method was removed

## Try It

1. Create a regular user account
2. Intercept the token and base64url-decode the payload segment
3. Modify the payload to set `is_admin` to `true` and re-encode it
4. Submit the modified token — the signature check rejects it and admin content stays hidden

## Mitigation Strategies

To prevent insecure deserialization vulnerabilities:

1. Never use pickle for user-controlled data
2. Use secure serialization formats like JSON
3. Implement digital signatures for serialized data
4. Validate and sanitize all user input
5. Use principle of least privilege

