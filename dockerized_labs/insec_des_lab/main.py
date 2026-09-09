import hmac
import os
import secrets
from dataclasses import asdict, dataclass

from flask import Flask, abort, render_template, request, session
from itsdangerous import BadData, URLSafeSerializer

app = Flask(__name__)
# The signing key is read from the environment. When it is not set we generate a
# random per-process key so the lab still runs locally without shipping a
# hard-coded secret in the repository.
app.secret_key = os.environ.get('LAB_SECRET_KEY') or secrets.token_urlsafe(32)

# The session cookie carries the CSRF token below, so keep it out of reach of
# JavaScript and off cross-site requests. The lab is reached at
# http://localhost:8080 and browsers treat localhost as a trustworthy origin, so
# a Secure cookie keeps working without terminating TLS.
app.config['SESSION_COOKIE_SECURE'] = True
app.config['SESSION_COOKIE_HTTPONLY'] = True
app.config['SESSION_COOKIE_SAMESITE'] = 'Lax'

# --- CSRF protection (CWE-352) ---------------------------------------------
# The forms in templates/index.html change server state over POST and used to
# carry no CSRF token, so any site could submit them on a visitor's behalf.
# {% csrf_token %} is a Django tag and does not exist in Jinja2, so this is the
# equivalent control for a Flask app: a per-session random token that is
# rendered into every form and compared in constant time on unsafe requests.
# It is implemented with the standard library instead of Flask-WTF to avoid
# adding a dependency to this single-file lab.
CSRF_FIELD_NAME = 'csrf_token'
CSRF_SESSION_KEY = '_csrf_token'
CSRF_SAFE_METHODS = frozenset({'GET', 'HEAD', 'OPTIONS', 'TRACE'})


def csrf_token():
    """Return this session's CSRF token, creating it on first use."""
    token = session.get(CSRF_SESSION_KEY)
    if not token:
        token = secrets.token_urlsafe(32)
        session[CSRF_SESSION_KEY] = token
    return token


# Exposed to Jinja2 so templates can render {{ csrf_token() }}.
app.jinja_env.globals['csrf_token'] = csrf_token


@app.before_request
def verify_csrf_token():
    """Reject state changing requests that do not present the session token."""
    if request.method in CSRF_SAFE_METHODS:
        return None
    expected = session.get(CSRF_SESSION_KEY)
    submitted = (request.form.get(CSRF_FIELD_NAME)
                 or request.headers.get('X-CSRFToken', ''))
    # Compare as bytes: compare_digest rejects non-ASCII str input, and the
    # submitted value is attacker controlled.
    if not expected or not hmac.compare_digest(expected.encode('utf-8'),
                                               submitted.encode('utf-8')):
        abort(400, 'CSRF token missing or invalid')
    return None

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
