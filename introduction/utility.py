import hashlib
import ipaddress
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