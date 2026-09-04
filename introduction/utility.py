import ast
import hashlib
import ipaddress
import math
import operator
import os
import re
import socket
import tempfile
import uuid
from urllib.parse import urlsplit, urlunsplit

from django.contrib.auth.hashers import (check_password, identify_hasher,
                                         make_password)

from .models import *

# Allowlist for host arguments handed to lookup/scan commands (dig, nslookup,
# nmap). Only DNS label characters and IP notation are accepted, so no shell
# metacharacter and no leading dash (option injection) can reach the argv.
_HOST_RE = re.compile(r'\A[A-Za-z0-9](?:[A-Za-z0-9._-]{0,251}[A-Za-z0-9])?\Z')


def validate_host(host):
    """Return a normalised hostname/IP, or None when it is not allowlisted."""
    if not isinstance(host, str):
        return None
    host = host.strip().rstrip('.')
    if not _HOST_RE.match(host):
        return None
    return host


# Allowlist for URLs the server fetches on behalf of a user. Only plain
# http(s) to one of these public hosts is fetched, so a user supplied URL can
# never reach an internal service (loopback, RFC1918, link-local / the
# 169.254.169.254 cloud metadata endpoint). Deployments can extend the list
# with the comma separated SSRF_ALLOWED_HOSTS environment variable.
_URL_ALLOWED_SCHEMES = ('http', 'https')
_URL_ALLOWED_PORTS = (80, 443)
_URL_ALLOWED_HOSTS = ('example.com', 'www.example.com', 'owasp.org', 'www.owasp.org')


def _allowed_fetch_hosts():
    """Return the set of hostnames the server may fetch from."""
    hosts = set(_URL_ALLOWED_HOSTS)
    for host in os.environ.get('SSRF_ALLOWED_HOSTS', '').split(','):
        host = host.strip().rstrip('.').lower()
        if host:
            hosts.add(host)
    return hosts


def _is_public_host(host):
    """True only when every address `host` resolves to is publicly routable."""
    try:
        addresses = socket.getaddrinfo(host, None)
    except socket.gaierror:
        return False
    if not addresses:
        return False
    for address in addresses:
        try:
            ip = ipaddress.ip_address(address[4][0])
        except ValueError:
            return False
        if (ip.is_private or ip.is_loopback or ip.is_link_local
                or ip.is_multicast or ip.is_reserved or ip.is_unspecified):
            return False
    return True


def validate_fetch_url(url):
    """Return a safe URL to fetch, or None when it is not allowlisted.

    Fails closed: the URL must use http(s) on a standard port, its host must
    be on the allowlist and must resolve only to publicly routable addresses.
    Any credentials and fragment are dropped and the URL is rebuilt from the
    validated parts, so only the checked destination is ever requested.
    """
    if not isinstance(url, str):
        return None
    try:
        parts = urlsplit(url.strip())
        port = parts.port
    except ValueError:
        return None
    scheme = parts.scheme.lower()
    if scheme not in _URL_ALLOWED_SCHEMES:
        return None
    if port is not None and port not in _URL_ALLOWED_PORTS:
        return None
    host = validate_host((parts.hostname or '').lower())
    if not host or host not in _allowed_fetch_hosts():
        return None
    if not _is_public_host(host):
        return None
    netloc = host if port is None else '{}:{}'.format(host, port)
    return urlunsplit((scheme, netloc, parts.path, parts.query, ''))


# ---------------------------------------------------------------------------
# The blog reader of the SSRF/LFI lab.
#
# The lab lets a request name the blog to display and used to join that name
# onto a server directory and open the result, which made the view read any
# file the app user could (CWE-22): '../../.env' or
# '../../pygoat/settings.py' walks out of the blogs directory, and
# os.path.join() throws the base away entirely when the second argument is
# absolute ('/etc/passwd'), so the base directory was no boundary at all.
#
# A blog is now addressed by a bare file name inside one fixed directory:
#   * the name must match _BLOG_NAME_RE, so a separator, a parent reference,
#     a drive letter, a NUL byte or an absolute path never reaches the join;
#   * the joined path is resolved with realpath (which also follows symlinks)
#     and must still sit directly inside the resolved blogs directory, so a
#     link planted in that directory cannot point the read outside of it
#     either;
#   * the target must be a regular file, so a directory or a device node is
#     not opened.
# Every rejection raises, so the caller fails closed instead of serving
# whatever the join happened to produce.
# ---------------------------------------------------------------------------

_BLOG_ROOT = os.path.realpath(os.path.join(os.path.dirname(os.path.realpath(__file__)),
                                           'templates', 'Lab', 'ssrf', 'blogs'))

_BLOG_NAME_RE = re.compile(r'\A[A-Za-z0-9][A-Za-z0-9_-]{0,63}\.txt\Z')


class BlogNotAllowed(ValueError):
    """Raised when a requested blog is not a file in the lab blogs directory."""


def blog_path(name):
    """Return the absolute path of lab blog *name*, or raise BlogNotAllowed.

    *name* is untrusted request data and is treated as a bare file name: it
    can only ever select one of the blog files shipped with the lab.
    """
    if not isinstance(name, str) or not _BLOG_NAME_RE.match(name):
        raise BlogNotAllowed('a blog is named like "blog1.txt"')
    path = os.path.realpath(os.path.join(_BLOG_ROOT, name))
    if os.path.dirname(path) != _BLOG_ROOT:
        raise BlogNotAllowed('blog is outside the blogs directory')
    if not os.path.isfile(path):
        raise BlogNotAllowed('no such blog')
    return path


# Safe evaluator for the calculator labs. The expression is parsed with `ast`
# and the resulting tree is walked: only numeric literals and this fixed
# allowlist of arithmetic operators are accepted. Name, Call, Attribute,
# Subscript, comprehension, ... nodes are refused, so nothing is ever executed
# and no builtin or module can be reached. (eval() with a restricted
# __builtins__ mapping is bypassable and is deliberately not used.)
_ARITHMETIC_BINARY_OPS = {
    ast.Add: operator.add,
    ast.Sub: operator.sub,
    ast.Mult: operator.mul,
    ast.Div: operator.truediv,
    ast.FloorDiv: operator.floordiv,
    ast.Mod: operator.mod,
    ast.Pow: operator.pow,
}
_ARITHMETIC_UNARY_OPS = {
    ast.UAdd: operator.pos,
    ast.USub: operator.neg,
}

# Bounds that keep a calculation cheap: they stop resource exhaustion through
# huge powers such as 9**9**9 or a very long chain of operations.
_MAX_EXPRESSION_LENGTH = 120
_MAX_POW_BASE = 1000
_MAX_POW_EXPONENT = 100
# The operand bounds above do not bound the *result*: a product of allowed
# powers ("999**99" repeated inside the length limit) reaches several thousand
# digits, and str()/json.dumps() raise ValueError on such an int (CPython caps
# int -> str conversion at 4300 digits). A calculation must never turn into an
# unhandled error in a caller, so the size of every value is capped here too.
# 4096 bits is about 1233 decimal digits: far beyond any calculator answer and
# comfortably inside that conversion limit.
_MAX_RESULT_BITS = 4096


class UnsafeExpression(ValueError):
    """Raised when an input is not a plain arithmetic calculation."""


def _check_pow_operands(base, exponent):
    """Refuse exponentiations that would burn CPU/memory."""
    if abs(base) > _MAX_POW_BASE or abs(exponent) > _MAX_POW_EXPONENT:
        raise UnsafeExpression('exponentiation operands are too large')


def _check_number(value):
    """Return *value* when it is a finite, bounded real number, else raise.

    Keeps the evaluator fail-closed on values that are numbers to python but
    not a calculator answer, so a caller never has to render or serialise
    them: a complex result (a negative base raised to a fractional power, e.g.
    ``(-1)**0.5``), a non-finite float (``1e1000`` -> inf, inf*0 -> nan) and an
    oversized integer are refused as UnsafeExpression instead of escaping as a
    TypeError/ValueError from the response layer.
    """
    if isinstance(value, bool) or not isinstance(value, (int, float)):
        raise UnsafeExpression('result is not a real number')
    if isinstance(value, float):
        if not math.isfinite(value):
            raise UnsafeExpression('result is not a finite number')
    elif value.bit_length() > _MAX_RESULT_BITS:
        raise UnsafeExpression('result is too large')
    return value


def _eval_arithmetic_node(node):
    """Evaluate one allowlisted node of an arithmetic expression tree."""
    if isinstance(node, ast.Constant):
        # bool is a subclass of int; only real numbers are calculator input.
        if isinstance(node.value, bool) or not isinstance(node.value, (int, float)):
            raise UnsafeExpression('only numeric literals are allowed')
        return _check_number(node.value)
    if isinstance(node, ast.UnaryOp):
        unary_op = _ARITHMETIC_UNARY_OPS.get(type(node.op))
        if unary_op is None:
            raise UnsafeExpression('unsupported unary operator')
        return _check_number(unary_op(_eval_arithmetic_node(node.operand)))
    if isinstance(node, ast.BinOp):
        binary_op = _ARITHMETIC_BINARY_OPS.get(type(node.op))
        if binary_op is None:
            raise UnsafeExpression('unsupported operator')
        left = _eval_arithmetic_node(node.left)
        right = _eval_arithmetic_node(node.right)
        if isinstance(node.op, ast.Pow):
            _check_pow_operands(left, right)
        # Every intermediate value is checked, so an oversized or non-real
        # result cannot be built up step by step either.
        return _check_number(binary_op(left, right))
    raise UnsafeExpression('only arithmetic on numeric literals is allowed')


def safe_arithmetic_eval(expression):
    """Return the value of the arithmetic *expression*, without executing code.

    Accepts numeric literals combined with + - * / // % ** and unary +/-
    (parentheses included). Everything else - variables, attribute access,
    function calls, subscripts, strings, comparisons - is rejected, so a
    payload such as ``os.system("id")`` or ``__import__('os')`` cannot run.

    The returned value is always a finite, bounded int or float, so a caller
    can render or serialise it without an unhandled error.

    Raises UnsafeExpression for any input that is not such a calculation.
    """
    if not isinstance(expression, str):
        raise UnsafeExpression('expression must be a string')
    expression = expression.strip()
    if not expression:
        raise UnsafeExpression('empty expression')
    if len(expression) > _MAX_EXPRESSION_LENGTH:
        raise UnsafeExpression('expression is too long')
    try:
        tree = ast.parse(expression, mode='eval')
    except (SyntaxError, ValueError, MemoryError, RecursionError):
        raise UnsafeExpression('not a valid arithmetic expression')
    try:
        return _eval_arithmetic_node(tree.body)
    except UnsafeExpression:
        raise
    except (ArithmeticError, TypeError, ValueError, RecursionError):
        raise UnsafeExpression('expression could not be calculated')


# import re
def ssrf_code_converter(code):
    list_input = code.split("\n")
    del_l = []
    for i in range(len(list_input)):
        if list_input[i].strip() == '':
            del_l.append(list_input[i])
    for l in del_l:
        list_input.remove(l)
    list_output = ['import os','def ssrf_lab(file):','    try:']
    extracted_code = []
    i = 7
    while i < (len(list_input)-2):
        extracted_code.append(list_input[i][8:])
        i += 1

    for i in range(len(extracted_code)):
        if extracted_code[i].strip()[:6] == 'return':
            space = extracted_code[i].split('return')[0]
            k = extracted_code[i].split('{')[1].split('}')[0]
            extracted_code[i] = space + "return {"+k+"}"
    
    list_output= list_output + extracted_code
    output_Code = "\n".join(list_output)

    dirname = os.path.dirname(__file__)
    filename = os.path.join(dirname, "playground/ssrf/main.py")
    f = open(filename,"w")
    f.write(output_Code)
    f.close()
    return 1

# ssrf_code_converter(input_code)
def ssrf_html_input_extractor(code):
    params = []
    list_input = code.split("\n")
    tokens = list(map(lambda x : x.strip().split(' '), list_input))
    for i in range(len(tokens)):
        if tokens[i][0] == '<input':
            for j in range(len(tokens[i])):
                if tokens[i][j][:7] == 'value="':
                    params.append(tokens[i][j][7:-2])
    return params

def unique_id_generator():
    id = str(uuid.uuid4()).split('-')[-1]

def filter_blog(code):
    return code

def customHash(password):
    return hashlib.sha256(password.encode()).hexdigest()[::-1]


# Password storage for the lab user tables (CF_user, CSRF_user_tbl). A bare
# fast digest (MD5/SHA1/SHA256) is not a password hash: it is unsalted and
# cheap, so a stolen table can be cracked with a wordlist or a rainbow table.
# These helpers delegate to Django's configured password hashers (PBKDF2-SHA256
# by default), which salt every password and apply a work factor, and compare
# in constant time.

# Legacy algorithms that must never be used to verify a password, even if a
# deployment re-enables them in PASSWORD_HASHERS.
_WEAK_PASSWORD_ALGORITHMS = frozenset(('md5', 'unsalted_md5', 'sha1',
                                       'unsalted_sha1', 'crypt'))


def hash_password(password):
    """Return a salted, iterated hash for *password* (never plaintext)."""
    return make_password(password)


def is_password_hash(value):
    """True when *value* is an encoded hash from a strong Django hasher.

    Bare digests (a 32 char MD5 or 64 char SHA256 hex string) and the legacy
    unsalted/crypt encodings are rejected: they are not password hashes, so a
    cracked database dump must never be replayed as a stored credential.
    """
    if not isinstance(value, str) or '$' not in value:
        return False
    try:
        hasher = identify_hasher(value)
    except ValueError:
        return False
    return hasher.algorithm not in _WEAK_PASSWORD_ALGORITHMS


def ensure_password_hash(value):
    """Hash *value* unless it already is a Django password hash.

    Used on write paths (e.g. the admin site) so a password typed in the clear
    is stored hashed and an already hashed value is not double hashed.
    """
    if not isinstance(value, str) or not value:
        return value
    if is_password_hash(value):
        return value
    return hash_password(value)


def verify_password(password, stored_hash):
    """Constant-time check of *password* against a stored password hash.

    Returns False for a missing password and for a stored value that is not a
    supported hash (e.g. a legacy MD5 row): such credentials must be re-set
    with hash_password(), they are never accepted as-is.
    """
    if not isinstance(password, str) or not password:
        return False
    if not is_password_hash(stored_hash):
        return False
    return check_password(password, stored_hash)


# ---------------------------------------------------------------------------
# Lab code drop for the A6 / A9 coding grounds (CWE-93 / CWE-434).
#
# Those two exercises let a signed-in student submit the source of a playground
# module, which the running app then imports. Executing that module IS the
# exercise, so these helpers deliberately do NOT claim to sandbox it: a
# denylist or regex over Python source is not a sandbox, and the only real
# containment is running the submission in an isolated interpreter/container.
# The endpoints therefore stay behind authentication, and everything about the
# write itself is constrained here:
#   * the destination is chosen by the server from a fixed allowlist, so no
#     part of the request can steer the path (no traversal, no new module),
#   * the payload is size limited,
#   * it must parse as Python before anything is written (compile() only
#     builds the code object, it never runs it), so a broken or truncated
#     submission cannot take the whole site down for every other user,
#   * both files of a submission are validated before either is replaced, and
#     each file is replaced atomically, so no importer can ever observe a half
#     written module.
# ---------------------------------------------------------------------------

# Playground modules a student may replace, keyed by a server side name. The
# values are relative to the playground package and never come from a request.
_LAB_CODE_TARGETS = {
    'A6_utility': 'A6/utility.py',
    'A9_log': 'A9/main.py',
    'A9_api': 'A9/api.py',
}

_LAB_CODE_ROOT = os.path.realpath(os.path.join(os.path.dirname(os.path.realpath(__file__)), 'playground'))

LAB_CODE_MAX_BYTES = 16 * 1024


class LabCodeRejected(ValueError):
    """Raised when submitted lab code is missing, too large or not Python."""


def lab_code_path(target):
    """Return the absolute path of the allowlisted playground module *target*."""
    relative = _LAB_CODE_TARGETS.get(target) if isinstance(target, str) else None
    if relative is None:
        raise LabCodeRejected('unknown lab code target')
    path = os.path.realpath(os.path.join(_LAB_CODE_ROOT, relative))
    # Defence in depth: the table above is static, so this can only trip if it
    # is edited badly - never because of request data.
    if path != _LAB_CODE_ROOT and not path.startswith(_LAB_CODE_ROOT + os.sep):
        raise LabCodeRejected('lab code target escapes the playground')
    return path


def validate_lab_code(code):
    """Return *code* when it is an acceptable Python module, else raise.

    Only the shape of the submission is checked (present, bounded, parseable).
    Nothing in here makes the submitted code safe to run.
    """
    if not isinstance(code, str) or not code.strip():
        raise LabCodeRejected('no code submitted')
    if len(code.encode('utf-8', 'surrogatepass')) > LAB_CODE_MAX_BYTES:
        raise LabCodeRejected('code is larger than {} bytes'.format(LAB_CODE_MAX_BYTES))
    try:
        compile(code, '<lab code>', 'exec')
    except (SyntaxError, ValueError, MemoryError, RecursionError):
        raise LabCodeRejected('code is not valid Python')
    return code


def write_lab_code(target, code):
    """Install *code* as the allowlisted playground module *target*.

    Validates first and then replaces the file atomically. Returns the path
    that was written.
    """
    path = lab_code_path(target)
    code = validate_lab_code(code)
    # The scratch file is not importable (leading dot, no .py suffix), so no
    # autoreloader or importer picks it up before the atomic replace below.
    handle, tmp_path = tempfile.mkstemp(dir=os.path.dirname(path),
                                        prefix='.lab_code_', suffix='.tmp')
    try:
        with os.fdopen(handle, 'w', encoding='utf-8') as tmp_file:
            tmp_file.write(code)
        os.replace(tmp_path, path)
    except BaseException:
        try:
            os.unlink(tmp_path)
        except OSError:
            pass
        raise
    return path
