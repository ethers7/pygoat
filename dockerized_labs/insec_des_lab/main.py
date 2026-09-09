from flask import Flask, render_template, request
import base64
import binascii
import hashlib
import hmac
import json
import os
import secrets
from dataclasses import dataclass

app = Flask(__name__)

# Key used to sign the user tokens handed to the browser. Supplied through the
# environment so nothing is hard-coded; when it is absent a random per-process
# key is generated (tokens then simply stop validating after a restart).
TOKEN_SIGNING_KEY = os.environ.get('LAB_TOKEN_SIGNING_KEY', '').encode() or secrets.token_bytes(32)


@dataclass
class User:
    username: str
    is_admin: bool = False


def _b64url_encode(raw):
    return base64.urlsafe_b64encode(raw).decode().rstrip('=')


def _b64url_decode(value):
    padding = '=' * (-len(value) % 4)
    return base64.urlsafe_b64decode(value + padding)


def dump_user(user):
    """Serialise a user as signed JSON: primitive data only, no code paths."""
    payload = json.dumps(
        {'username': user.username, 'is_admin': user.is_admin},
        separators=(',', ':'),
        sort_keys=True,
    ).encode()
    signature = hmac.new(TOKEN_SIGNING_KEY, payload, hashlib.sha256).digest()
    return '{}.{}'.format(_b64url_encode(payload), _b64url_encode(signature))


def load_user(token):
    """Verify the HMAC signature, then parse the JSON payload into a User.

    JSON is a data-only format, so a tampered or hostile token can never
    execute code the way an object-graph format such as pickle would. The
    signature check plus the strict type constraints below also stop a client
    from simply flipping is_admin on its own token.

    Raises ValueError when the token is malformed, unsigned/tampered, or does
    not describe exactly the expected primitive fields.
    """
    payload_part, separator, signature_part = token.strip().partition('.')
    if not payload_part or not separator or not signature_part:
        raise ValueError('Malformed token')

    payload = _b64url_decode(payload_part)
    provided_signature = _b64url_decode(signature_part)
    expected_signature = hmac.new(TOKEN_SIGNING_KEY, payload, hashlib.sha256).digest()
    if not hmac.compare_digest(expected_signature, provided_signature):
        raise ValueError('Signature verification failed')

    data = json.loads(payload.decode('utf-8'))
    if not isinstance(data, dict) or set(data) != {'username', 'is_admin'}:
        raise ValueError('Unexpected token payload')

    username = data['username']
    is_admin = data['is_admin']
    if not isinstance(username, str) or not isinstance(is_admin, bool):
        raise ValueError('Unexpected token field types')

    return User(username=username, is_admin=is_admin)


@app.route('/')
def index():
    return render_template('index.html')


@app.route('/serialize', methods=['POST'])
def serialize_data():
    username = request.form.get('username', 'guest')
    # Create regular user with admin=False
    user = User(username=username, is_admin=False)
    # Signed JSON token instead of a pickled object graph
    serialized = dump_user(user)
    return render_template('result.html', serialized=serialized)


@app.route('/deserialize', methods=['POST'])
def deserialize_data():
    serialized_data = request.form.get('serialized_data', '')
    try:
        # Signature-checked, type-constrained JSON: no code execution and no
        # client-side privilege escalation.
        user = load_user(serialized_data)
    except (ValueError, binascii.Error):
        # Log/report the failure without echoing attacker-supplied details.
        app.logger.warning('Rejected invalid or tampered user token')
        return render_template('result.html', message='Invalid or tampered token')

    if user.is_admin:
        message = f"Welcome Admin {user.username}! Here's the secret admin content: ADMIN_KEY_123"
    else:
        message = f"Welcome {user.username}. Only admins can see the secret content."

    return render_template('result.html', message=message)


if __name__ == '__main__':
    app.run(host='0.0.0.0', port=8080)
