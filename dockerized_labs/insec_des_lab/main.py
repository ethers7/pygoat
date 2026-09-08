from flask import Flask, render_template, request, make_response
import base64
import json
from dataclasses import dataclass, asdict

app = Flask(__name__)

@dataclass
class User:
    username: str
    is_admin: bool = False


def encode_user(user):
    """Serialize a User to an opaque base64 token using JSON (no code execution)."""
    payload = json.dumps(asdict(user), separators=(',', ':')).encode('utf-8')
    return base64.b64encode(payload).decode()


def decode_user(token):
    """Decode a base64 JSON token into a User, or None when the token is not valid.

    JSON only carries primitive data types, so a tampered token can never lead to
    code execution the way pickle deserialization does. Unknown or wrongly typed
    fields are rejected (fail closed) instead of being trusted.
    """
    try:
        payload = base64.b64decode(token, validate=True)
        data = json.loads(payload.decode('utf-8'))
    except (ValueError, TypeError):
        return None

    if not isinstance(data, dict):
        return None

    username = data.get('username')
    is_admin = data.get('is_admin', False)
    if not isinstance(username, str) or not isinstance(is_admin, bool):
        return None

    return User(username=username, is_admin=is_admin)

@app.route('/')
def index():
    return render_template('index.html')

@app.route('/serialize', methods=['POST'])
def serialize_data():
    username = request.form.get('username', 'guest')
    # Create regular user with admin=False
    user = User(username=username, is_admin=False)
    # Base64 encoded JSON token: opaque for transport, safe to decode
    serialized = encode_user(user)
    return render_template('result.html', serialized=serialized)

@app.route('/deserialize', methods=['POST'])
def deserialize_data():
    serialized_data = request.form.get('serialized_data', '')
    user = decode_user(serialized_data)

    if user is None:
        # Malformed or untrusted token: fail closed, no object is instantiated
        return render_template('result.html', message="Invalid user data")

    if user.is_admin:
        message = f"Welcome Admin {user.username}! Here's the secret admin content: ADMIN_KEY_123"
    else:
        message = f"Welcome {user.username}. Only admins can see the secret content."

    return render_template('result.html', message=message)

if __name__ == '__main__':
    app.run(host='0.0.0.0', port=8080)

    