# Insecure Deserialization Lab

A vulnerable web application demonstrating serialized-token tampering (OWASP insecure deserialization) in Python.

## Description

This lab demonstrates the dangers of trusting client-supplied serialized data by implementing a vulnerable user session mechanism built on an unsigned, base64 encoded JSON token. The application allows users to:

1. Create a regular user account
2. Receive a serialized token
3. Submit the token for deserialization
4. Exploit the vulnerability to gain admin access

## Features

- Tamperable, unsigned user token
- Base64 encoded JSON serialized data
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

The lab uses a base64 encoded JSON token to carry user data. The remaining (data tampering) vulnerability exists because:

1. The application trusts the role attribute inside a user-provided token
2. The token is not integrity protected (no signature)

Note: the deserialization step itself is no longer code-execution prone. Tokens are parsed as JSON, which only
carries primitive data types, and every field is type checked before a User is built. Never use pickle for
user-controlled data.

## Exploitation Steps

1. Create a regular user account
2. Intercept the serialized token
3. Decode the base64 token
4. Modify the serialized data to set is_admin=True
5. Re-encode the modified data
6. Submit the modified token to gain admin access

## Mitigation Strategies

To prevent insecure deserialization vulnerabilities:

1. Never use pickle for user-controlled data
2. Use secure serialization formats like JSON
3. Implement digital signatures for serialized data
4. Validate and sanitize all user input
5. Use principle of least privilege

