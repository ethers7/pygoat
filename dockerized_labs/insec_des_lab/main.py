from flask import Flask, render_template, request
import base64
import binascii
import hashlib
import hmac
import json
import os
import secrets
from dataclasses import asdict, dataclass

app = Flask(__name__)

# Key used to sign and verify user tokens. It is read from the environment so
# that no secret is hard-coded; when unset a random per-process key is used,
# which simply invalidates tokens issued by previous runs.
TOKEN_SIGNING_KEY = (
    os.environ.get('INSEC_DES_LAB_SECRET_KEY', '').encode() or secrets.token_bytes(32)
)

@dataclass
class User:
    username: str
    is_admin: bool = False

def _signature(payload: bytes) -> bytes:
    return hmac.new(TOKEN_SIGNING_KEY, payload, hashlib.sha256).digest()

def dump_user(user: User) -> str:
    """Serialize a User as a base64 JSON payload plus an HMAC signature.

    JSON only carries primitive values, and the signature lets the server
    detect any tampering with the token it handed out.
    """
    payload = json.dumps(asdict(user), sort_keys=True, separators=(',', ':')).encode()
    return '{}.{}'.format(
        base64.urlsafe_b64encode(payload).decode(),
        base64.urlsafe_b64encode(_signature(payload)).decode(),
    )

def load_user(token: str) -> User:
    """Verify and parse a token previously produced by dump_user.

    The signature is checked before the payload is parsed, and only
    well-typed JSON primitives are accepted, so request data can never
    drive object construction or code execution.
    """
    encoded_payload, separator, encoded_signature = token.partition('.')
    if not separator or not encoded_payload or not encoded_signature:
        raise ValueError('Malformed token')
    try:
        payload = base64.urlsafe_b64decode(encoded_payload)
        signature = base64.urlsafe_b64decode(encoded_signature)
    except (binascii.Error, ValueError):
        raise ValueError('Malformed token')
    if not hmac.compare_digest(signature, _signature(payload)):
        raise ValueError('Signature verification failed')
    data = json.loads(payload.decode('utf-8'))
    if not isinstance(data, dict):
        raise ValueError('Unexpected token payload')
    username = data.get('username')
    is_admin = data.get('is_admin', False)
    if not isinstance(username, str) or not isinstance(is_admin, bool):
        raise ValueError('Unexpected token payload')
    return User(username=username, is_admin=is_admin)

@app.route('/')
def index():
    return render_template('index.html')

@app.route('/serialize', methods=['POST'])
def serialize_data():
    username = request.form.get('username', 'guest')
    # Create regular user with admin=False
    user = User(username=username, is_admin=False)
    # Signed JSON token: primitives only, integrity protected
    serialized = dump_user(user)
    return render_template('result.html', serialized=serialized)

@app.route('/deserialize', methods=['POST'])
def deserialize_data():
    serialized_data = request.form.get('serialized_data', '')
    try:
        # Signature-checked, primitive-only parsing of untrusted input
        user = load_user(serialized_data)
    except ValueError:
        return render_template('result.html', message="Invalid user data")

    if user.is_admin:
        message = f"Welcome Admin {user.username}! Here's the secret admin content: ADMIN_KEY_123"
    else:
        message = f"Welcome {user.username}. Only admins can see the secret content."

    return render_template('result.html', message=message)

if __name__ == '__main__':
    app.run(host='0.0.0.0', port=8080)
