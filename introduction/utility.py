import ast
import hashlib
import ipaddress
import math
import operator
import os
import re
import socket
import uuid
from urllib.parse import urlsplit, urlunsplit

from .models import *

# Plain DNS hostname: labels of alphanumerics/hyphens, no shell metacharacters,
# no whitespace, no path or scheme parts.
_HOSTNAME_RE = re.compile(
    r'(?=.{1,253}\Z)[A-Za-z0-9](?:[A-Za-z0-9-]{0,61}[A-Za-z0-9])?'
    r'(?:\.[A-Za-z0-9](?:[A-Za-z0-9-]{0,61}[A-Za-z0-9])?)*\Z'
)


def safe_host_target(value, allow_networks=False):
    """Validate an untrusted host argument before it reaches a lookup tool.

    Returns the normalised IP address, CIDR network (only when
    ``allow_networks`` is set) or hostname, and ``None`` when the value is not
    a plain host. Callers must still pass the result as its own argv element
    and never build a shell command string from it.
    """
    if not isinstance(value, str):
        return None
    target = value.strip()
    if not target:
        return None
    try:
        return str(ipaddress.ip_address(target))
    except ValueError:
        pass
    if allow_networks and '/' in target:
        try:
            return str(ipaddress.ip_network(target, strict=False))
        except ValueError:
            return None
    if _HOSTNAME_RE.match(target):
        return target
    return None


# Positive allowlist of destinations the server may fetch on behalf of a
# request (CWE-918). Only these hosts, only http/https, only the default
# port. Deployments can override it with a comma separated list in the
# PYGOAT_FETCH_ALLOWED_HOSTS environment variable.
DEFAULT_FETCH_ALLOWED_HOSTS = (
    'example.com',
    'www.example.com',
    'owasp.org',
    'www.owasp.org',
)

# Redirects are re-validated, never followed blindly, and are bounded.
MAX_FETCH_REDIRECTS = 3

_FETCH_ALLOWED_SCHEME_PORTS = {'http': 80, 'https': 443}


def fetch_allowed_hosts():
    """Return the frozenset of hosts the server is allowed to fetch."""
    configured = os.environ.get('PYGOAT_FETCH_ALLOWED_HOSTS', '')
    hosts = [
        host.strip().lower().rstrip('.')
        for host in configured.split(',')
        if host.strip()
    ]
    return frozenset(hosts or DEFAULT_FETCH_ALLOWED_HOSTS)


def _is_public_address(address):
    """True only for addresses outside internal and reserved ranges."""
    try:
        ip = ipaddress.ip_address(address)
    except ValueError:
        return False
    mapped = getattr(ip, 'ipv4_mapped', None)
    if mapped is not None:
        ip = mapped
    return not (
        ip.is_private          # RFC1918 / unique-local, plus loopback for IPv4
        or ip.is_loopback
        or ip.is_link_local    # includes 169.254.169.254 cloud metadata
        or ip.is_multicast
        or ip.is_reserved
        or ip.is_unspecified
    )


def safe_fetch_url(value):
    """Validate an untrusted URL before the server fetches it (CWE-918, SSRF).

    Returns a normalised http(s) URL only when its host is on
    :func:`fetch_allowed_hosts`, no credentials are embedded, the port is the
    scheme default and every address the host resolves to is a public one
    (resolve-then-validate, so an allowlisted name cannot point at loopback,
    link-local cloud metadata or a private range). Returns ``None`` otherwise
    so callers fail closed. Callers must also re-validate each redirect
    target with this helper instead of following redirects blindly.
    """
    if not isinstance(value, str):
        return None
    candidate = value.strip()
    if not candidate:
        return None
    try:
        parsed = urlsplit(candidate)
        host = (parsed.hostname or '').lower().rstrip('.')
        port = parsed.port
    except ValueError:
        return None
    scheme = parsed.scheme.lower()
    if scheme not in _FETCH_ALLOWED_SCHEME_PORTS:
        return None
    if parsed.username or parsed.password:
        return None
    if host not in fetch_allowed_hosts():
        return None
    default_port = _FETCH_ALLOWED_SCHEME_PORTS[scheme]
    if port not in (None, default_port):
        return None
    try:
        addresses = socket.getaddrinfo(host, default_port, proto=socket.IPPROTO_TCP)
    except (OSError, UnicodeError):
        return None
    if not addresses:
        return None
    if not all(_is_public_address(info[4][0]) for info in addresses):
        return None
    # Rebuild from validated parts: no credentials, no fragment, no alternate
    # port, host taken from the allowlist comparison.
    return urlunsplit((scheme, host, parsed.path, parsed.query, ''))


# Outbound fetches are bounded in time and in size (CWE-400): a slow or
# endless upstream response must not pin a worker or be buffered into memory
# without limit. FETCH_TIMEOUT is the (connect, read) pair every outbound
# request passes as timeout=, and MAX_FETCH_RESPONSE_BYTES caps how much of a
# streamed body the server will ever hold.
FETCH_TIMEOUT = (5, 10)
MAX_FETCH_RESPONSE_BYTES = 1024 * 1024
_FETCH_CHUNK_BYTES = 8192


class ResponseTooLargeError(ValueError):
    """Raised when an upstream response is larger than the server will buffer."""


def read_bounded_response(response, max_bytes=MAX_FETCH_RESPONSE_BYTES):
    """Buffer at most ``max_bytes`` of an outbound response body (CWE-400).

    Callers issue the request with ``stream=True`` so the body arrives in
    chunks; as soon as the cap is exceeded the connection is closed and
    :class:`ResponseTooLargeError` is raised instead of reading an unbounded
    amount of remote data into memory. Returns the body as bytes.
    """
    body = bytearray()
    try:
        for chunk in response.iter_content(_FETCH_CHUNK_BYTES):
            if not chunk:
                continue
            body.extend(chunk)
            if len(body) > max_bytes:
                raise ResponseTooLargeError(
                    f'response is larger than the {max_bytes} byte limit'
                )
    finally:
        response.close()
    return bytes(body)


# Arithmetic-only expression evaluator for the calculator labs (CWE-94/95).
# Untrusted input is parsed with ast.parse(mode='eval') and then interpreted
# against the explicit node/operator allowlist below, so it is never handed to
# eval/exec/compile-as-code. Names, attributes, calls, subscripts, lambdas,
# comprehensions, imports and every other node type are rejected, which makes
# code execution structurally impossible rather than merely filtered.
_ALLOWED_BINARY_OPERATORS = {
    ast.Add: operator.add,
    ast.Sub: operator.sub,
    ast.Mult: operator.mul,
    ast.Div: operator.truediv,
    ast.FloorDiv: operator.floordiv,
    ast.Mod: operator.mod,
    ast.Pow: operator.pow,
}

_ALLOWED_UNARY_OPERATORS = {
    ast.UAdd: operator.pos,
    ast.USub: operator.neg,
}

# Hard limits so a syntactically valid but hostile expression (9**9**9, deeply
# nested parentheses) cannot burn CPU or memory as a denial of service.
MAX_EXPRESSION_LENGTH = 120
MAX_EXPRESSION_NODES = 60
MAX_EXPRESSION_DEPTH = 20
_MAX_EXPONENT = 64
_MAX_MAGNITUDE = 10 ** 18


class UnsafeExpressionError(ValueError):
    """Raised when input is not a plain, bounded arithmetic expression."""


def _bounded_number(value):
    """Reject non-finite or oversized intermediate results."""
    if isinstance(value, bool) or not isinstance(value, (int, float)):
        raise UnsafeExpressionError('only numeric values are supported')
    if isinstance(value, float) and not math.isfinite(value):
        raise UnsafeExpressionError('result is not a finite number')
    if abs(value) > _MAX_MAGNITUDE:
        raise UnsafeExpressionError('result is out of the supported range')
    return value


def _eval_expression_node(node, depth=0):
    """Interpret one allowlisted arithmetic node; refuse everything else."""
    if depth > MAX_EXPRESSION_DEPTH:
        raise UnsafeExpressionError('expression is nested too deeply')
    if isinstance(node, ast.Constant):
        return _bounded_number(node.value)
    if isinstance(node, ast.UnaryOp) and type(node.op) in _ALLOWED_UNARY_OPERATORS:
        operand = _eval_expression_node(node.operand, depth + 1)
        return _bounded_number(_ALLOWED_UNARY_OPERATORS[type(node.op)](operand))
    if isinstance(node, ast.BinOp) and type(node.op) in _ALLOWED_BINARY_OPERATORS:
        left = _eval_expression_node(node.left, depth + 1)
        right = _eval_expression_node(node.right, depth + 1)
        if isinstance(node.op, ast.Pow) and (
            abs(right) > _MAX_EXPONENT or abs(left) > _MAX_EXPONENT
        ):
            raise UnsafeExpressionError('exponent is too large')
        try:
            result = _ALLOWED_BINARY_OPERATORS[type(node.op)](left, right)
        except ZeroDivisionError:
            raise UnsafeExpressionError('division by zero')
        except (ArithmeticError, ValueError):
            raise UnsafeExpressionError('result is out of the supported range')
        return _bounded_number(result)
    raise UnsafeExpressionError('only numbers and + - * / // % ** are supported')


def safe_arithmetic_eval(expression):
    """Evaluate an untrusted arithmetic expression without eval/exec (CWE-95).

    Returns the numeric result of a bounded arithmetic expression built from
    numeric literals, ``+ - * / // % **``, unary sign and parentheses. Raises
    :class:`UnsafeExpressionError` for anything else so callers fail closed and
    can report a handled error message.
    """
    if not isinstance(expression, str):
        raise UnsafeExpressionError('an expression is required')
    candidate = expression.strip()
    if not candidate:
        raise UnsafeExpressionError('an expression is required')
    if len(candidate) > MAX_EXPRESSION_LENGTH:
        raise UnsafeExpressionError('expression is too long')
    try:
        tree = ast.parse(candidate, mode='eval')
    except (SyntaxError, ValueError, MemoryError, RecursionError):
        raise UnsafeExpressionError('expression is not valid arithmetic')
    if sum(1 for _ in ast.walk(tree)) > MAX_EXPRESSION_NODES:
        raise UnsafeExpressionError('expression is too complex')
    return _eval_expression_node(tree.body)


# Validation for request data that a view persists (CWE-915). Values that
# arrive on a request and are then written to a store (a file on disk for these
# labs) are normalised and bounded here first: callers persist what these
# helpers return, never the raw request field, and report the raised message
# instead of writing unchecked input.
MAX_STORED_TEXT_LENGTH = 8000
MAX_STORED_SOURCE_LENGTH = 20000

# Tab and newline are the only control characters stored text may contain;
# anything else means smuggled binary or terminal escape sequences.
_CONTROL_CHAR_RE = re.compile(r'[\x00-\x08\x0b-\x1f\x7f-\x9f]')


class InvalidStoredTextError(ValueError):
    """Raised when untrusted text is not acceptable to persist."""


def safe_stored_text(value, field='value', max_length=MAX_STORED_TEXT_LENGTH):
    """Validate and normalise untrusted text before it is written to a store.

    Checks the type (a string), presence, an upper length bound and the absence
    of control characters, and normalises line endings so what gets stored is
    exactly what was validated. Raises :class:`InvalidStoredTextError` with a
    reportable message otherwise, so callers fail closed with an error response
    instead of persisting unchecked request data.
    """
    if not isinstance(value, str):
        raise InvalidStoredTextError(f'{field} is required')
    text = value.replace('\r\n', '\n').replace('\r', '\n').strip()
    if not text:
        raise InvalidStoredTextError(f'{field} is required')
    if len(text) > max_length:
        raise InvalidStoredTextError(
            f'{field} is longer than the {max_length} character limit'
        )
    if _CONTROL_CHAR_RE.search(text):
        raise InvalidStoredTextError(
            f'{field} contains unsupported control characters'
        )
    return text


def safe_python_source(value, field='code', max_length=MAX_STORED_SOURCE_LENGTH):
    """Validate untrusted Python source before it replaces a module on disk.

    The lab code checkers overwrite a module with whatever was submitted, so the
    payload must be a bounded, control character free string that parses as
    Python (``ast.parse`` only builds a syntax tree, it never runs the code)
    before anything is written. Returns the normalised source, or raises
    :class:`InvalidStoredTextError` so the caller can answer with an error.
    """
    source = safe_stored_text(value, field=field, max_length=max_length)
    try:
        ast.parse(source)
    except (SyntaxError, ValueError, MemoryError, RecursionError):
        raise InvalidStoredTextError(f'{field} is not valid Python source')
    return source


# Containment check for request supplied file paths (CWE-22). A view that lets
# the request choose which file to read must resolve the candidate and prove it
# stays inside the directory the lab is meant to serve, otherwise `../`
# segments, a symlink or an absolute path walk out of that directory and expose
# arbitrary files. Callers open only what this helper returns, never the raw
# request value, and report the raised message instead.
class UnsafePathError(ValueError):
    """Raised when a request supplied path escapes its allowed directory."""


def safe_contained_path(base_dir, candidate, allowed_dir=None, allowed_suffixes=None):
    """Resolve an untrusted relative path and keep it inside a directory.

    ``candidate`` must be a relative path with no ``..`` segment; it is joined
    onto ``base_dir``, fully resolved (so symlinks cannot point out either) and
    then required to sit inside ``allowed_dir`` (``base_dir`` when it is not
    given) and, when ``allowed_suffixes`` is set, to carry one of those
    extensions. Returns the absolute path that is safe to open, or raises
    :class:`UnsafePathError` so callers fail closed with an error response.
    """
    if not isinstance(candidate, str):
        raise UnsafePathError('a file name is required')
    relative = candidate.strip()
    if not relative:
        raise UnsafePathError('a file name is required')
    if '\x00' in relative:
        raise UnsafePathError('file name contains an unsupported character')
    # Backslash is a separator on Windows and an ordinary character elsewhere;
    # refusing it keeps this check identical on every platform.
    if '\\' in relative:
        raise UnsafePathError('file name may not contain a backslash')
    if os.path.isabs(relative) or relative.startswith('/'):
        raise UnsafePathError('an absolute path is not allowed')
    if os.pardir in relative.split('/'):
        raise UnsafePathError('a path outside the allowed directory is not allowed')

    root = os.path.realpath(base_dir if allowed_dir is None else allowed_dir)
    resolved = os.path.realpath(os.path.join(base_dir, relative))
    try:
        contained = os.path.commonpath([root, resolved]) == root
    except ValueError:
        contained = False
    if not contained or resolved == root:
        raise UnsafePathError('a path outside the allowed directory is not allowed')
    if allowed_suffixes and os.path.splitext(resolved)[1].lower() not in allowed_suffixes:
        raise UnsafePathError('that file type is not allowed')
    return resolved


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