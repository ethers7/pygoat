from flask import Flask, render_template, request
import base64
import json
from dataclasses import dataclass, asdict

app = Flask(__name__)


@dataclass
class User:
    username: str
    is_admin: bool = False

    def to_token(self):
        """Serialize the user as a data-only (JSON) token.

        JSON carries primitive values only, so loading a token can never
        reconstruct arbitrary objects or execute code the way pickle does.
        """
        return base64.b64encode(json.dumps(asdict(self)).encode('utf-8')).decode()

    @classmethod
    def from_token(cls, token):
        """Parse a data-only token supplied by the client.

        json.loads can only produce primitives, so even a fully attacker
        controlled token cannot lead to code execution. Every field is type
        checked before it is used, and unknown fields are ignored.
        """
        payload = json.loads(base64.b64decode(token, validate=True).decode('utf-8'))
        if not isinstance(payload, dict):
            raise ValueError('token payload must be a JSON object')
        username = payload.get('username')
        if not isinstance(username, str):
            raise ValueError('username must be a string')
        is_admin = payload.get('is_admin', False)
        if not isinstance(is_admin, bool):
            raise ValueError('is_admin must be a boolean')
        return cls(username=username, is_admin=is_admin)

@app.route('/')
def index():
    return render_template('index.html')


@app.route('/serialize', methods=['POST'])
def serialize_data():
    username = request.form.get('username', 'guest')
    # Create regular user with admin=False
    user = User(username=username, is_admin=False)
    # Data-only (JSON) token instead of a pickled object graph
    serialized = user.to_token()
    return render_template('result.html', serialized=serialized)


@app.route('/deserialize', methods=['POST'])
def deserialize_data():
    try:
        serialized_data = request.form.get('serialized_data', '')
        # Safe deserialization: the untrusted token is parsed as JSON data and
        # type checked, never unpickled, so it cannot execute code.
        user = User.from_token(serialized_data)

        if user.is_admin:
            message = f"Welcome Admin {user.username}! Here's the secret admin content: ADMIN_KEY_123"
        else:
            message = f"Welcome {user.username}. Only admins can see the secret content."

        return render_template('result.html', message=message)
    except Exception as e:
        return render_template('result.html', message=f"Error: {str(e)}")

if __name__ == '__main__':
    app.run(host='0.0.0.0', port=8080)

    