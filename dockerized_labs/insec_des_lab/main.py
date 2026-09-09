import os
import secrets
from dataclasses import asdict, dataclass

from flask import Flask, render_template, request
from itsdangerous import BadData, URLSafeSerializer

app = Flask(__name__)
# The signing key is read from the environment. When it is not set we generate a
# random per-process key so the lab still runs locally without shipping a
# hard-coded secret in the repository.
app.secret_key = os.environ.get('LAB_SECRET_KEY') or secrets.token_urlsafe(32)

# Tokens are signed JSON documents: only primitive JSON types cross the trust
# boundary, and the signature proves the payload was produced by this app.
token_serializer = URLSafeSerializer(app.secret_key, salt='insec-des-lab-user')


@dataclass
class User:
    username: str
    is_admin: bool = False

    def to_token(self):
        """Serialize the user as signed JSON (no executable object graph)."""
        return token_serializer.dumps(asdict(self))

    @classmethod
    def from_token(cls, token):
        """Verify the signature, then rebuild the user from JSON primitives."""
        data = token_serializer.loads(token)  # raises BadData if tampered with
        if not isinstance(data, dict):
            raise ValueError('Unexpected token payload')
        username = data.get('username')
        is_admin = data.get('is_admin', False)
        if not isinstance(username, str) or not isinstance(is_admin, bool):
            raise ValueError('Unexpected token payload')
        return cls(username=username, is_admin=is_admin)


@app.route('/')
def index():
    return render_template('index.html')

@app.route('/serialize', methods=['POST'])
def serialize_data():
    username = request.form.get('username', 'guest')
    # Create regular user with admin=False
    user = User(username=username, is_admin=False)
    # Signed JSON token instead of a pickled object
    return render_template('result.html', serialized=user.to_token())

@app.route('/deserialize', methods=['POST'])
def deserialize_data():
    token = request.form.get('serialized_data', '')
    try:
        user = User.from_token(token)
    except BadData:
        message = ('Invalid token: the signature does not match, '
                   'so the data was rejected.')
        return render_template('result.html', message=message)
    except (ValueError, TypeError):
        return render_template('result.html', message="Invalid user data")

    if user.is_admin:
        message = f"Welcome Admin {user.username}! Here's the secret admin content: ADMIN_KEY_123"
    else:
        message = f"Welcome {user.username}. Only admins can see the secret content."

    return render_template('result.html', message=message)

if __name__ == '__main__':
    app.run(host='0.0.0.0', port=8080)
