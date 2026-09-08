import ast
import hashlib
import ipaddress
import operator
import os
import re
import socket
import uuid
from urllib.parse import urlsplit, urlunsplit

from .models import *

# Hostname label rules from RFC 1123: letters, digits and hyphens only, no
# leading/trailing hyphen, 1-63 chars per label, 253 chars overall.
_HOSTNAME_RE = re.compile(
    r'^(?!-)[A-Za-z0-9-]{1,63}(?<!-)'
    r'(?:\.(?!-)[A-Za-z0-9-]{1,63}(?<!-))*\.?$'
)

# Only plain web schemes may be fetched server-side; everything else (file://,
# gopher://, ftp://, dict://, ...) is a classic SSRF escalation vector.
_ALLOWED_URL_SCHEMES = ('http', 'https')


def validate_target_host(value):
    """Validate an untrusted host so it is safe as a single argv element.

    The command labs must still run their tool (``dig``, ``nslookup``,
    ``nmap``) against user supplied input, so the input is allowlisted at the
    trust boundary instead of being interpolated into a shell string
    (CWE-78). Returns the normalised host and raises ``ValueError`` for
    anything that is not a plausible hostname, IP address or CIDR range --
    which also rejects values starting with ``-`` that the tool would
    otherwise read as an extra command line option.
    """
    if not isinstance(value, str):
        raise ValueError('not a valid hostname or IP address')
    host = value.strip()
    if not host or len(host) > 253 or host.startswith('-'):
        raise ValueError('not a valid hostname or IP address')
    try:
        return str(ipaddress.ip_address(host))
    except ValueError:
        pass
    try:
        return str(ipaddress.ip_network(host, strict=False))
    except ValueError:
        pass
    if _HOSTNAME_RE.match(host):
        return host
    raise ValueError('not a valid hostname or IP address')


def _assert_public_destination(host):
    """Reject a host that resolves to an address the server must not reach.

    The literal string is not enough: ``localtest.me`` or an attacker
    controlled record both look public while resolving inside the perimeter,
    so every address returned for *host* is checked.
    """
    try:
        infos = socket.getaddrinfo(host, None, proto=socket.IPPROTO_TCP)
    except socket.gaierror:
        raise ValueError('URL host could not be resolved')
    addresses = {info[4][0] for info in infos}
    if not addresses:
        raise ValueError('URL host could not be resolved')
    for address in addresses:
        # getaddrinfo can hand back a scoped IPv6 literal (fe80::1%eth0).
        ip = ipaddress.ip_address(address.split('%')[0])
        ip = getattr(ip, 'ipv4_mapped', None) or ip
        if (ip.is_loopback or ip.is_link_local or ip.is_private
                or ip.is_multicast or ip.is_reserved or ip.is_unspecified):
            raise ValueError('URL resolves to a blocked internal address')


def validate_outbound_url(value):
    """Validate an untrusted URL before it is fetched server-side.

    The SSRF lab must still fetch a URL supplied by the user, so the request
    target is allowlisted at the trust boundary instead of being handed
    straight to ``requests`` (CWE-918): the scheme must be http/https and the
    destination must resolve to a public unicast address, which keeps
    loopback, the 169.254.169.254 cloud metadata service and other
    link-local, private or reserved ranges out of reach. Returns the
    normalised URL and raises ``ValueError`` for anything rejected, so the
    caller can fail closed. Redirect targets must be re-validated with this
    same helper.
    """
    if not isinstance(value, str):
        raise ValueError('not a valid http(s) URL')
    url = value.strip()
    if not url:
        raise ValueError('not a valid http(s) URL')
    try:
        parts = urlsplit(url)
        host = parts.hostname
        parts.port  # a malformed port raises ValueError
    except ValueError:
        raise ValueError('not a valid http(s) URL')
    if parts.scheme.lower() not in _ALLOWED_URL_SCHEMES:
        raise ValueError('only http:// and https:// URLs may be fetched')
    if not host:
        raise ValueError('not a valid http(s) URL')
    if parts.username or parts.password:
        raise ValueError('credentials are not allowed in the URL')
    _assert_public_destination(host)
    return urlunsplit(
        (parts.scheme.lower(), parts.netloc, parts.path, parts.query, '')
    )


class ArithmeticExpressionError(ValueError):
    """Raised when input is not a plain, safe arithmetic expression."""


# 9**9**9 is a valid arithmetic expression that would pin a worker for hours
# and exhaust memory, so exponentiation is bounded (CWE-400).
_MAX_POW_BASE = 10 ** 6
_MAX_POW_EXPONENT = 100
# A legitimate calculator entry is short; a huge chain of operators is only
# ever an attempt to burn CPU in the parser.
_MAX_EXPRESSION_LENGTH = 200


def _safe_pow(base, exponent):
    if abs(base) > _MAX_POW_BASE or abs(exponent) > _MAX_POW_EXPONENT:
        raise ArithmeticExpressionError('numbers are too large')
    return operator.pow(base, exponent)


# The calculator labs only ever need numbers and these operators. Handing the
# input to eval()/exec() instead turns the calculator into arbitrary code
# execution (CWE-95), so the parsed tree is walked and every node that is not
# in this allowlist -- names, attributes, calls, subscripts, comparisons,
# comprehensions, lambdas, walrus, f-strings, ... -- is refused.
_SAFE_BINARY_OPS = {
    ast.Add: operator.add,
    ast.Sub: operator.sub,
    ast.Mult: operator.mul,
    ast.Div: operator.truediv,
    ast.FloorDiv: operator.floordiv,
    ast.Mod: operator.mod,
    ast.Pow: _safe_pow,
}
_SAFE_UNARY_OPS = {
    ast.UAdd: operator.pos,
    ast.USub: operator.neg,
}


def _safe_number(value):
    # bool is a subclass of int, but True/False are not calculator input.
    if isinstance(value, bool) or not isinstance(value, (int, float)):
        raise ArithmeticExpressionError('only numbers are allowed')
    return value


def _eval_node(node):
    """Evaluate one allowlisted node of an arithmetic expression tree."""
    if isinstance(node, ast.Constant):
        return _safe_number(node.value)
    if isinstance(node, ast.UnaryOp) and type(node.op) in _SAFE_UNARY_OPS:
        return _SAFE_UNARY_OPS[type(node.op)](_eval_node(node.operand))
    if isinstance(node, ast.BinOp) and type(node.op) in _SAFE_BINARY_OPS:
        return _SAFE_BINARY_OPS[type(node.op)](
            _eval_node(node.left), _eval_node(node.right)
        )
    raise ArithmeticExpressionError('unsupported expression')


def evaluate_arithmetic(expression):
    """Evaluate an untrusted arithmetic expression without eval/exec/compile.

    The calculator labs must keep answering ``7*7``, so the expression is
    parsed with ``ast.parse(mode='eval')`` and the resulting tree is walked
    with an allowlist of numeric constants, unary ``+``/``-`` and the binary
    ``+ - * / // % **`` operators. Nothing is ever executed and no name,
    attribute or call can be reached, so the classic ``eval`` payloads
    (``__import__('os').system(...)``) are rejected instead of run.

    Returns the numeric result and raises ``ArithmeticExpressionError`` for
    anything rejected -- including division by zero and oversized powers --
    so callers can fail closed on their existing error path.
    """
    if not isinstance(expression, str):
        raise ArithmeticExpressionError('not an arithmetic expression')
    text = expression.strip()
    if not text or len(text) > _MAX_EXPRESSION_LENGTH:
        raise ArithmeticExpressionError('not an arithmetic expression')
    try:
        tree = ast.parse(text, mode='eval')
    except (SyntaxError, ValueError, MemoryError, RecursionError):
        raise ArithmeticExpressionError('not an arithmetic expression')
    try:
        return _safe_number(_eval_node(tree.body))
    except ArithmeticExpressionError:
        raise
    except (ArithmeticError, TypeError, ValueError, RecursionError):
        raise ArithmeticExpressionError('expression could not be evaluated')


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