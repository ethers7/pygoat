# Insecure Deserialization Lab

A web application lab demonstrating deserialization / token tampering issues in Python.

## Description

This lab demonstrates the dangers of trusting client-supplied serialized data. It originally used Python's `pickle`
module, which allowed remote code execution; it now uses a data-only format (JSON) with strict type checks, so the
access-control tampering lesson remains while arbitrary code execution is no longer possible. The application allows
users to:

1. Create a regular user account
2. Receive a serialized token
3. Submit the token for deserialization
4. Exploit the vulnerability to gain admin access

## Features

- Safe, data-only (JSON) deserialization with strict type validation
- Base64 encoded serialized data
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

## CSRF protection

CSRF is not part of this lab's lesson, so it is fixed rather than left open. Both forms
(`/serialize` and `/deserialize`) send a `csrf_token` hidden field (an `X-CSRF-Token` header also
works), and the server rejects any POST whose token does not match the one bound to the caller's
browser with `400 CSRF token missing or invalid`. The token is an HMAC over a random per-browser id
kept in the `csrf_id` cookie and is verified **server side** on every unsafe request. The HMAC key
is generated per process, or can be pinned across restarts with `INSEC_DES_LAB_CSRF_KEY`. The
`csrf_id` cookie is always `HttpOnly` and `SameSite=Lax`; since the lab is served over plain HTTP on
`http://localhost:8080`, the `Secure` flag is off by default and can be switched on with
`INSEC_DES_LAB_SECURE_COOKIES=1` when the lab is placed behind HTTPS.

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

The lab issues a serialized token that carries the user's role, and the role is still taken from that
client-controlled token. Originally the token was a pickled `User` object, so a crafted token could execute arbitrary
code (`pickle.loads` on untrusted input, plus a `__reduce__` gadget on the `User` class). The token is now a JSON
document parsed with `json.loads` and validated field by field, so only primitive data can be reconstructed.

## Exploitation Steps

1. Create a regular user account
2. Intercept the serialized token
3. Decode the base64 token to reveal the JSON payload
4. Modify the payload to set `"is_admin": true`
5. Re-encode the modified JSON as base64
6. Submit the modified token to gain admin access

Note that the remaining lesson is data tampering / broken access control: the server should derive privileges from
server-side state (or a signed token), never from an attribute the client can edit. Code execution via the token is
no longer possible.

## Mitigation Strategies

To prevent insecure deserialization vulnerabilities:

1. Never use pickle for user-controlled data
2. Use secure serialization formats like JSON
3. Implement digital signatures for serialized data
4. Validate and sanitize all user input
5. Use principle of least privilege

