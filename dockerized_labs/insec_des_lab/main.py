import os

from flask import Flask, render_template, request, make_response
from flask_wtf.csrf import CSRFProtect
import json
import base64
import hmac
import hashlib
from dataclasses import dataclass

app = Flask(__name__)
app.secret_key = os.environ.get('SECRET_KEY', 'change-this-to-a-strong-random-secret')
csrf = CSRFProtect(app)

HMAC_KEY = app.secret_key.encode()


def _sign(payload_b64: str) -> str:
    """Return HMAC-SHA256 hex signature for the given base64 payload."""
    return hmac.new(HMAC_KEY, payload_b64.encode(), hashlib.sha256).hexdigest()


@dataclass
class User:
    username: str
    is_admin: bool = False

@app.route('/')
def index():
    return render_template('index.html')

@app.route('/serialize', methods=['POST'])
def serialize_data():
    username = request.form.get('username', 'guest')
    # Create regular user with admin=False
    user = User(username=username, is_admin=False)
    # Safe JSON serialization with HMAC signing
    user_dict = {'username': user.username, 'is_admin': user.is_admin}
    payload_b64 = base64.b64encode(json.dumps(user_dict).encode()).decode()
    signature = _sign(payload_b64)
    serialized = f"{payload_b64}.{signature}"
    return render_template('result.html', serialized=serialized)

@app.route('/deserialize', methods=['POST'])
def deserialize_data():
    try:
        serialized_data = request.form.get('serialized_data', '')
        # Verify HMAC signature before deserializing
        if '.' not in serialized_data:
            return render_template('result.html', message="Error: Invalid token format")

        payload_b64, provided_sig = serialized_data.rsplit('.', 1)
        expected_sig = _sign(payload_b64)
        if not hmac.compare_digest(provided_sig, expected_sig):
            return render_template('result.html', message="Error: Invalid signature - data may have been tampered with")

        # Safe JSON deserialization
        user_data = json.loads(base64.b64decode(payload_b64))
        user = User(
            username=str(user_data.get('username', 'guest')),
            is_admin=bool(user_data.get('is_admin', False))
        )

        if user.is_admin:
            message = f"Welcome Admin {user.username}! Here's the secret admin content: ADMIN_KEY_123"
        else:
            message = f"Welcome {user.username}. Only admins can see the secret content."

        return render_template('result.html', message=message)
    except Exception as e:
        return render_template('result.html', message=f"Error: {str(e)}")

if __name__ == '__main__':
    app.run(host='0.0.0.0', port=8080)

    