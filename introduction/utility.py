import ast
import hashlib
import ipaddress
import operator
import os
import re
import socket
import tempfile
import uuid
from urllib.parse import urljoin, urlsplit

import requests
from django.contrib.auth.hashers import check_password, make_password

from .models import *

# Hostname / IPv4-shaped values only. Rejects whitespace, shell metacharacters
# (; | & $ ` ( ) < > newline ...) and a leading '-' so a validated value is safe
# to pass as a single argv element of a subprocess call.
_SAFE_HOST_RE = re.compile(r'^[A-Za-z0-9](?:[A-Za-z0-9._-]{0,253}[A-Za-z0-9])?$')


def is_safe_host(value):
    """Return True when value is a plain hostname/IP usable as one argv element."""
    if not isinstance(value, str):
        return False
    return _SAFE_HOST_RE.match(value) is not None


_ALLOWED_URL_SCHEMES = ('http', 'https')
_DEFAULT_PORTS = {'http': 80, 'https': 443}


class UnsafeUrlError(ValueError):
    """Raised when a user supplied URL must not be fetched server-side."""


def _is_blocked_address(ip):
    """True for addresses a server-side request must never reach (SSRF)."""
    mapped = getattr(ip, 'ipv4_mapped', None)
    if mapped is not None:
        return _is_blocked_address(mapped)
    sixtofour = getattr(ip, 'sixtofour', None)
    if sixtofour is not None:
        return _is_blocked_address(sixtofour)
    return bool(
        ip.is_loopback           # 127.0.0.0/8, ::1
        or ip.is_link_local      # 169.254.0.0/16 (incl. 169.254.169.254), fe80::/10
        or ip.is_private         # 10/8, 172.16/12, 192.168/16, fc00::/7
        or ip.is_reserved
        or ip.is_multicast
        or ip.is_unspecified     # 0.0.0.0, ::
    )


def _resolve_addresses(hostname, port, resolver):
    """Return every IP the host resolves to, or raise UnsafeUrlError."""
    try:
        return [ipaddress.ip_address(hostname)]
    except ValueError:
        pass
    try:
        infos = resolver(hostname, port, proto=socket.IPPROTO_TCP)
    except (socket.gaierror, socket.herror, UnicodeError, ValueError):
        raise UnsafeUrlError('The host %s could not be resolved.' % hostname)
    addresses = []
    for info in infos:
        try:
            addresses.append(ipaddress.ip_address(info[4][0].split('%')[0]))
        except ValueError:
            raise UnsafeUrlError(
                'The host %s resolved to an unusable address.' % hostname)
    if not addresses:
        raise UnsafeUrlError('The host %s could not be resolved.' % hostname)
    return addresses


def validate_public_url(url, allowed_hosts=None, resolver=socket.getaddrinfo):
    """Validate a user supplied URL before it is requested server-side.

    Returns the normalised URL. Raises UnsafeUrlError when the URL does not use
    http/https, when its host is absent or not in ``allowed_hosts`` (when an
    allowlist is supplied), or when the host resolves to a loopback,
    link-local, private, reserved, multicast or unspecified address - which
    covers the cloud metadata endpoint 169.254.169.254 as well as 127.0.0.0/8,
    10/8, 172.16/12, 192.168/16, ::1 and fc00::/7.
    """
    if not isinstance(url, str) or not url.strip():
        raise UnsafeUrlError('A URL is required.')
    parts = urlsplit(url.strip())
    scheme = parts.scheme.lower()
    if scheme not in _ALLOWED_URL_SCHEMES:
        raise UnsafeUrlError('Only http and https URLs are allowed.')
    hostname = parts.hostname
    if not hostname:
        raise UnsafeUrlError('The URL must contain a host name.')
    if allowed_hosts is not None and hostname not in allowed_hosts:
        raise UnsafeUrlError('The host %s is not on the allowlist.' % hostname)
    try:
        port = parts.port or _DEFAULT_PORTS[scheme]
    except ValueError:
        raise UnsafeUrlError('The URL contains an invalid port.')
    for address in _resolve_addresses(hostname, port, resolver):
        if _is_blocked_address(address):
            raise UnsafeUrlError(
                'The URL resolves to the non-routable address %s.' % address)
    return parts.geturl()


def fetch_url_safely(url, allowed_hosts=None, timeout=5, max_redirects=3):
    """GET a user supplied URL with SSRF protection.

    Redirects are not followed by requests; each hop is validated with
    validate_public_url before it is fetched, because a single up-front check
    is bypassed by a redirect to an internal address.
    """
    target = validate_public_url(url, allowed_hosts=allowed_hosts)
    for _ in range(max_redirects + 1):
        response = requests.get(target, timeout=timeout, allow_redirects=False)
        if not response.is_redirect and not response.is_permanent_redirect:
            return response
        location = response.headers.get('Location', '')
        if not location:
            return response
        target = validate_public_url(urljoin(target, location),
                                     allowed_hosts=allowed_hosts)
    raise UnsafeUrlError('The URL redirected too many times.')


class UnsafeExpressionError(ValueError):
    """Raised when user input is not a plain arithmetic expression."""


# Only these node types are evaluated. Everything else - names, attributes,
# calls, subscripts, comparisons, comprehensions, strings, lambdas, the walrus
# operator - is rejected, so no attacker supplied expression can reach a
# builtin, an import or an attribute lookup. Parentheses are grouping syntax
# and produce no node of their own, so they are supported for free.
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

# Denial of service guards: an expression such as 9**9**9 is syntactically a
# plain arithmetic expression but would burn CPU and memory, so bound the input
# size, the nesting depth and the size of exponentiations.
_MAX_EXPRESSION_LENGTH = 200
_MAX_EXPRESSION_DEPTH = 32
_MAX_POW_EXPONENT = 64
_MAX_POW_BASE = 10 ** 6

_ARITHMETIC_ERROR_MESSAGE = (
    'Only arithmetic expressions using numbers and + - * / // % ** are allowed.')


def _safe_pow(base, exponent):
    """Exponentiation bounded so a small input cannot exhaust CPU or memory."""
    if abs(exponent) > _MAX_POW_EXPONENT or abs(base) > _MAX_POW_BASE:
        raise UnsafeExpressionError(
            'Exponentiation is limited to bases up to %d and exponents up to %d.'
            % (_MAX_POW_BASE, _MAX_POW_EXPONENT))
    return operator.pow(base, exponent)


def _eval_arithmetic_node(node, depth):
    """Recursively evaluate an allowlisted arithmetic AST node."""
    if depth > _MAX_EXPRESSION_DEPTH:
        raise UnsafeExpressionError('The expression is nested too deeply.')

    if isinstance(node, ast.Constant):
        # bool is a subclass of int; only real numbers are accepted here.
        if isinstance(node.value, bool) or not isinstance(node.value, (int, float)):
            raise UnsafeExpressionError(_ARITHMETIC_ERROR_MESSAGE)
        return node.value

    if isinstance(node, ast.UnaryOp):
        op = _ARITHMETIC_UNARY_OPS.get(type(node.op))
        if op is None:
            raise UnsafeExpressionError(_ARITHMETIC_ERROR_MESSAGE)
        return op(_eval_arithmetic_node(node.operand, depth + 1))

    if isinstance(node, ast.BinOp):
        op_type = type(node.op)
        op = _ARITHMETIC_BINARY_OPS.get(op_type)
        if op is None:
            raise UnsafeExpressionError(_ARITHMETIC_ERROR_MESSAGE)
        left = _eval_arithmetic_node(node.left, depth + 1)
        right = _eval_arithmetic_node(node.right, depth + 1)
        if op_type is ast.Pow:
            return _safe_pow(left, right)
        try:
            return op(left, right)
        except ZeroDivisionError:
            raise UnsafeExpressionError('Division by zero is not allowed.')
        except (OverflowError, ValueError):
            raise UnsafeExpressionError('The result is too large to compute.')

    raise UnsafeExpressionError(_ARITHMETIC_ERROR_MESSAGE)


def safe_arithmetic_eval(expression):
    """Evaluate a user supplied arithmetic expression without eval()/exec().

    The expression is parsed with ``ast.parse(..., mode='eval')`` and the
    resulting tree is walked with a strict allowlist of node types: numeric
    literals, the binary operators + - * / // % ** and unary + / -. Any other
    construct (function call, name, attribute, string, comparison, ...) raises
    ``UnsafeExpressionError``, so arbitrary code execution (CWE-94/CWE-95) is
    not possible. Exponentiation, nesting depth and input length are bounded to
    prevent denial of service.
    """
    if not isinstance(expression, str) or not expression.strip():
        raise UnsafeExpressionError('An arithmetic expression is required.')
    if len(expression) > _MAX_EXPRESSION_LENGTH:
        raise UnsafeExpressionError(
            'The expression must be at most %d characters long.'
            % _MAX_EXPRESSION_LENGTH)
    try:
        tree = ast.parse(expression.strip(), mode='eval')
    except (SyntaxError, ValueError, MemoryError, RecursionError):
        raise UnsafeExpressionError('The expression could not be parsed.')
    return _eval_arithmetic_node(tree.body, 0)


# --------------------------- lab file write guards ----------------------------
# Several labs let a student POST code or blog text that the app then stores in a
# file. The helpers below are the guardrails those writes go through:
#   * the destination directory is always a constant computed in code, never a
#     value taken from the request,
#   * the submitted text is size capped, so a caller cannot fill the disk or roll
#     over a large file (CWE-400),
#   * the resolved destination is checked to still be inside its dedicated
#     directory before anything is opened (CWE-22),
#   * the content is written in one step - atomically replaced or exclusively
#     created - so a request never appends to an existing file and a reader never
#     sees a half written one (CWE-93).

# Generous for a lab code editor, far below anything that could fill a disk.
MAX_LAB_CODE_BYTES = 32 * 1024
MAX_BLOG_BODY_BYTES = 16 * 1024


class SubmittedContentTooLargeError(ValueError):
    """Raised when submitted content is missing, not text, or over the limit."""


class UnsafeWritePathError(ValueError):
    """Raised when a write target would leave its dedicated directory."""


def validate_submitted_text(value, max_bytes):
    """Return value when it is text of at most max_bytes encoded bytes.

    Missing and non string values raise as well, so a caller fails closed
    instead of writing "None" into a lab file.
    """
    if not isinstance(value, str):
        raise SubmittedContentTooLargeError('Text content is required.')
    if len(value.encode('utf-8')) > max_bytes:
        raise SubmittedContentTooLargeError(
            'The submitted content is larger than the %d byte limit.' % max_bytes)
    return value


def resolve_inside_directory(base_dir, name):
    """Return the real path of name inside base_dir, or raise.

    base_dir is a fixed directory computed by the application. name must be a
    bare file name: an empty value, a value holding a path separator, '.', '..'
    or an absolute path is rejected, and so is a name whose resolved path (for
    example through a symlink) would end up outside base_dir.
    """
    if not isinstance(name, str) or not name.strip():
        raise UnsafeWritePathError('A file name is required.')
    if name in ('.', '..') or name != os.path.basename(name) or os.path.isabs(name):
        raise UnsafeWritePathError('The file name must not contain a path.')
    base = os.path.realpath(base_dir)
    target = os.path.realpath(os.path.join(base, name))
    # The resolved file must sit directly in base_dir; a symlinked entry that
    # points somewhere else resolves to another parent and is refused here.
    if os.path.dirname(target) != base or not target.startswith(base + os.sep):
        raise UnsafeWritePathError('The resolved path leaves the lab directory.')
    return target


def write_text_atomically(path, content):
    """Replace path with content in one atomic step.

    The bytes go to a temporary file in the same directory which is then renamed
    over the destination, so the write never appends to the existing file and a
    concurrent reader (or Django's autoreloader) never picks up a partially
    written file.
    """
    directory = os.path.dirname(path)
    handle_fd, temp_path = tempfile.mkstemp(dir=directory, prefix='.write-',
                                            suffix='.part')
    try:
        with os.fdopen(handle_fd, 'w', encoding='utf-8') as handle:
            handle.write(content)
        os.replace(temp_path, path)
    except BaseException:
        try:
            os.unlink(temp_path)
        except OSError:
            pass
        raise


def write_text_exclusively(path, content):
    """Create path with content, failing when the file already exists.

    Used where every write must land in a brand new file, so a request can
    neither truncate nor append to a file that is already there.
    """
    handle_fd = os.open(path, os.O_WRONLY | os.O_CREAT | os.O_EXCL, 0o600)
    with os.fdopen(handle_fd, 'w', encoding='utf-8') as handle:
        handle.write(content)


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

# Django template constructs: {% tag %}, {{ variable }}, {# comment #} and any
# stray delimiter of those forms.
_TEMPLATE_SYNTAX_RE = re.compile(
    r'{%.*?%}|{{.*?}}|{#.*?#}|{%|%}|{{|}}|{#|#}', re.DOTALL)


def filter_blog(code):
    """Remove Django template syntax from a user supplied blog body.

    The blog body is stored as data and rendered through an autoescaped context
    variable, so template syntax would only ever be displayed. Dropping the
    constructs here keeps the stored file free of them as a second layer, so the
    body stays inert even if some caller ever loaded it as a template
    (server-side template injection, CWE-1336/CWE-94).
    """
    if not isinstance(code, str):
        return ''
    return _TEMPLATE_SYNTAX_RE.sub('', code)

def customHash(password):
    return hashlib.sha256(password.encode()).hexdigest()[::-1]


def hash_lab_password(raw_password):
    """Return a salted, iterated hash for a lab credential.

    Delegates to Django's configured password hashers (PBKDF2 by default), so
    lab credentials are stored the same way as real Django user passwords
    instead of as an unsalted MD5/SHA digest (CWE-327). ``raw_password=None``
    produces an unusable password, which lets callers seed a row fail-closed
    when no credential has been configured.
    """
    return make_password(raw_password)


def verify_lab_password(raw_password, encoded):
    """Verify ``raw_password`` against the stored hash ``encoded``.

    The comparison is delegated to the hasher, which is salt aware and does a
    constant-time digest comparison, so callers never compare hashes with
    ``==``. Values that are empty, unusable, or not a recognised Django hash
    (for example a legacy unsalted MD5 digest left in a database) are rejected
    instead of raising, so verification fails closed.
    """
    if not raw_password or not encoded:
        return False
    try:
        return check_password(raw_password, encoded)
    except ValueError:
        return False