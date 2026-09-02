# Insecure Deserialization Lab

A web application demonstrating insecure deserialization concepts in Python, and the safe pattern that prevents them.

## Description

This lab demonstrates the dangers of insecure deserialization through a user session mechanism. The application allows users to:

1. Create a regular user account
2. Receive a serialized token
3. Submit the token for deserialization
4. Observe that tampering with the token is detected instead of granting admin access

## Features

- Signed JSON tokens instead of pickle
- Base64 encoded payload with an HMAC-SHA256 signature
- Strict type validation of the decoded payload
- User role system (regular user vs admin)
- Docker containerization
- Light/Dark theme support

## Configuration

Set `INSEC_DES_LAB_SECRET_KEY` to the HMAC signing key. When it is unset, a
random key is generated per process, which invalidates tokens from earlier runs.

Set `INSEC_DES_LAB_CSRF_KEY` to the key used to sign CSRF tokens (a random
per-process key is used when unset). Set `INSEC_DES_LAB_HTTPS=1` when the lab is
served over TLS so the CSRF cookie is also marked `Secure`.

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

Insecure deserialization arises when an application reconstructs objects from
attacker-controlled bytes, for example with `pickle.loads()`. Because pickle can
execute arbitrary callables while loading, any tampered payload can lead to
remote code execution as well as privilege escalation.

This lab now serializes user data as JSON and signs it with HMAC-SHA256, so
untrusted bytes are never turned into an arbitrary object graph.

## Lab Steps

1. Create a regular user account
2. Inspect the token: base64 payload, `.`, base64 signature
3. Decode the base64 payload and modify it to set `is_admin` to `true`
4. Re-encode the modified payload and submit the token
5. Observe that the signature check rejects it, so admin content stays out of reach

## Mitigation Strategies

To prevent insecure deserialization vulnerabilities:

1. Never use pickle for user-controlled data
2. Use secure serialization formats like JSON
3. Implement digital signatures for serialized data
4. Validate and sanitize all user input
5. Use principle of least privilege

