from flask import Flask, render_template, request, abort, g
import base64
import hmac
import json
import os
import re
import secrets
from dataclasses import dataclass, asdict
from hashlib import sha256

app = Flask(__name__)

# --------------------------------------------------------------------------
# CSRF protection
#
# The two lab forms below change server side state, so every POST has to carry
# a token bound to the caller's own browser: another site can no longer make a
# visitor's browser submit them.
#
# The token is an HMAC over a random per-browser id stored in the "csrf_id"
# cookie, keyed with a process local secret (or one supplied through the
# environment), and it is verified server side on every unsafe request.
# --------------------------------------------------------------------------
CSRF_COOKIE_NAME = 'csrf_id'
CSRF_FIELD_NAME = 'csrf_token'
CSRF_HEADER_NAME = 'X-CSRF-Token'
CSRF_SAFE_METHODS = frozenset(('GET', 'HEAD', 'OPTIONS', 'TRACE'))
CSRF_KEY_ENV = 'INSEC_DES_LAB_CSRF_KEY'
CSRF_KEY = (os.environ.get(CSRF_KEY_ENV) or secrets.token_urlsafe(32)).encode('utf-8')

# This lab is served over plain HTTP (http://localhost:8080), so the Secure
# flag follows the actual transport: it is switched on when the lab is put
# behind HTTPS by setting INSEC_DES_LAB_SECURE_COOKIES. HttpOnly and
# SameSite=Lax are always applied - see README.md.
SECURE_COOKIES_ENV = 'INSEC_DES_LAB_SECURE_COOKIES'


def secure_cookies_enabled():
    """Return True when the lab is served over HTTPS (opt in)."""
    return os.environ.get(SECURE_COOKIES_ENV, '').strip().lower() in ('1', 'true', 'yes', 'on')


# Interface the development server binds to. It defaults to loopback, so running
# "python main.py" straight on a workstation exposes this deliberately vulnerable
# lab to that machine only - never to the rest of the LAN/VPC. The container image
# sets INSEC_DES_LAB_HOST=0.0.0.0 (see Dockerfile), where binding every interface
# is the correct behaviour: the network namespace is the isolation boundary and the
# published port has to be able to reach the app - see README.md.
BIND_HOST_ENV = 'INSEC_DES_LAB_HOST'
DEFAULT_BIND_HOST = '127.0.0.1'

# A bind address is a hostname or an IP literal: letters, digits, dot, dash and
# underscore, plus colon and brackets for IPv6 forms such as [::1].
BIND_HOST_PATTERN = re.compile(r'^[A-Za-z0-9._:\[\]-]{1,253}$')


def bind_host():
    """Return the validated address app.run() should bind to.

    An unset, empty, whitespace-only or malformed value falls back to
    DEFAULT_BIND_HOST: a value that is not a usable address must never silently
    turn into "bind every interface". Only an explicit, well formed value from
    the environment widens the bind address.
    """
    requested = os.environ.get(BIND_HOST_ENV, '').strip()
    if not requested:
        return DEFAULT_BIND_HOST
    if not BIND_HOST_PATTERN.match(requested):
        # The rejected value is deliberately not logged (it is attacker/operator
        # supplied text that would land in the log verbatim).
        app.logger.warning('Ignoring malformed %s; binding to %s instead.', BIND_HOST_ENV, DEFAULT_BIND_HOST)
        return DEFAULT_BIND_HOST
    return requested


def csrf_token_for(csrf_id):
    """Return the CSRF token bound to a single browser's csrf_id."""
    return hmac.new(CSRF_KEY, csrf_id.encode('utf-8'), sha256).hexdigest()


def current_csrf_token():
    """Return the CSRF token for the request being handled ('' if unknown)."""
    csrf_id = getattr(g, 'csrf_id', '')
    return csrf_token_for(csrf_id) if csrf_id else ''


@app.before_request
def csrf_protect():
    """Fail closed on any state changing request without a valid token."""
    cookie_id = request.cookies.get(CSRF_COOKIE_NAME, '')
    if request.method not in CSRF_SAFE_METHODS:
        submitted = request.form.get(CSRF_FIELD_NAME, '') or request.headers.get(CSRF_HEADER_NAME, '')
        expected = csrf_token_for(cookie_id) if cookie_id else ''
        if not expected or not submitted or not hmac.compare_digest(submitted, expected):
            abort(400, 'CSRF token missing or invalid')
    if not cookie_id:
        cookie_id = secrets.token_urlsafe(32)
        g.csrf_cookie_pending = True
    g.csrf_id = cookie_id


@app.after_request
def send_csrf_cookie(response):
    """Hand a browser its csrf_id the first time we see it."""
    if getattr(g, 'csrf_cookie_pending', False):
        response.set_cookie(
            CSRF_COOKIE_NAME,
            g.csrf_id,
            secure=secure_cookies_enabled(),
            httponly=True,
            samesite='Lax',
        )
    return response


@app.context_processor
def inject_csrf_token():
    """Expose {{ csrf_token() }} to templates (same shape as Flask-WTF)."""
    return {'csrf_token': current_csrf_token}


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
    # Fixed: the bind address is no longer hardcoded to every interface. It
    # defaults to loopback and is only widened when INSEC_DES_LAB_HOST asks for
    # it - the container sets that to 0.0.0.0 so the published port keeps
    # working - see README.md.
    app.run(host=bind_host(), port=8080)

    