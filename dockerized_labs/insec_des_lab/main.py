from flask import Flask, abort, g, render_template, request
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

# CWE-352: Jinja2 has no {% csrf_token %} tag, so this lab issues its own
# per-visitor CSRF token: a random nonce plus an HMAC-SHA256 signature, stored in
# a cookie and rendered into every state-changing form. A cross-site page can
# neither read the cookie nor mint a correctly signed value, so forged POSTs are
# rejected below. The signing key is read from the environment; when unset a
# random per-process key is used, which only invalidates tokens from earlier runs.
CSRF_COOKIE_NAME = 'csrf_token'
CSRF_FORM_FIELD = 'csrf_token'
CSRF_PROTECTED_METHODS = ('POST', 'PUT', 'PATCH', 'DELETE')
CSRF_SIGNING_KEY = (
    os.environ.get('INSEC_DES_LAB_CSRF_KEY', '').encode() or secrets.token_bytes(32)
)
# The shipped docker-compose setup serves plain HTTP on port 8080, so the cookie
# is only marked Secure when the lab is actually fronted with TLS.
CSRF_COOKIE_SECURE = os.environ.get('INSEC_DES_LAB_HTTPS', '').strip().lower() in (
    '1', 'true', 'yes', 'on'
)

# CWE-668: the development server binds loopback only, so a `python main.py` run
# on a workstation or shared host is not reachable from the network. Binding
# every interface is a deployment decision, not a source-code default: the
# container image sets INSEC_DES_LAB_HOST=0.0.0.0 (see Dockerfile) because a
# process inside a container must bind a container-visible address for the
# published port to work.
LISTEN_HOST = os.environ.get('INSEC_DES_LAB_HOST', '').strip() or '127.0.0.1'


def _csrf_signature(nonce: str) -> str:
    return hmac.new(CSRF_SIGNING_KEY, nonce.encode(), hashlib.sha256).hexdigest()


def _issue_csrf_token() -> str:
    nonce = secrets.token_urlsafe(32)
    return '{}.{}'.format(nonce, _csrf_signature(nonce))


def _is_valid_csrf_token(token: str) -> bool:
    nonce, separator, signature = token.partition('.')
    if not separator or not nonce or not signature:
        return False
    return hmac.compare_digest(signature, _csrf_signature(nonce))


def _current_csrf_token() -> str:
    """Return this visitor's CSRF token, issuing one when needed."""
    token = getattr(g, 'csrf_token', None)
    if token is None:
        token = request.cookies.get(CSRF_COOKIE_NAME, '')
        if not _is_valid_csrf_token(token):
            token = _issue_csrf_token()
            g.csrf_token_is_new = True
        g.csrf_token = token
    return token


@app.context_processor
def inject_csrf_token():
    # Templates call {{ csrf_token() }} inside every POST form.
    return {'csrf_token': _current_csrf_token}


@app.before_request
def verify_csrf_token():
    if request.method not in CSRF_PROTECTED_METHODS:
        return
    cookie_token = request.cookies.get(CSRF_COOKIE_NAME, '')
    form_token = request.form.get(CSRF_FORM_FIELD, '')
    if not cookie_token or not form_token:
        abort(400, description='CSRF token missing')
    if not hmac.compare_digest(cookie_token, form_token) or not _is_valid_csrf_token(
        form_token
    ):
        abort(400, description='CSRF token invalid')


@app.after_request
def store_csrf_token(response):
    if getattr(g, 'csrf_token_is_new', False):
        response.set_cookie(
            CSRF_COOKIE_NAME,
            g.csrf_token,
            httponly=True,
            samesite='Lax',
            secure=CSRF_COOKIE_SECURE,
        )
    return response

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
    app.run(host=LISTEN_HOST, port=8080)
