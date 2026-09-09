import hashlib
import ipaddress
import os
import re
import socket
import uuid
from urllib.parse import urlsplit, urlunsplit

from defusedxml import DefusedXmlException
from defusedxml.ElementTree import ParseError, fromstring

from .models import *


# Hostname / IP allowlist for the lookup commands (dig, nslookup, nmap). The
# validated value is passed as a single argv element with shell=False, so this
# only has to reject non-host shapes and leading "-" option injection.
_LOOKUP_TARGET_RE = re.compile(
    r'^(?=.{1,253}$)[A-Za-z0-9](?:[A-Za-z0-9-]{0,61}[A-Za-z0-9])?'
    r'(?:\.[A-Za-z0-9](?:[A-Za-z0-9-]{0,61}[A-Za-z0-9])?)*$'
)


def safe_lookup_target(value):
    """Return a validated hostname/IP address, or None when the value is not one.

    Callers must treat None as "reject the request" and must pass the returned
    value as its own argv element (never through a shell), so that shell
    metacharacters can never be interpreted as command syntax.
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
    target = target.rstrip('.')
    if _LOOKUP_TARGET_RE.match(target):
        return target
    return None


# Destination allowlist for server-side fetches (SSRF, CWE-918). Override per
# deployment with PYGOAT_ALLOWED_FETCH_HOSTS, a comma separated list of
# hostnames/IPs; sub-domains of a listed name are accepted as well.
_DEFAULT_ALLOWED_FETCH_HOSTS = ('example.com',)
_ALLOWED_FETCH_SCHEMES = ('http', 'https')
_ALLOWED_FETCH_PORTS = (80, 443)


def allowed_fetch_hosts():
    """Return the set of hosts this deployment may fetch server-side."""
    raw = os.environ.get('PYGOAT_ALLOWED_FETCH_HOSTS', '')
    hosts = {h.strip().lower().rstrip('.') for h in raw.split(',') if h.strip()}
    return hosts or set(_DEFAULT_ALLOWED_FETCH_HOSTS)


def _is_public_ip(value):
    """True when value is an IP address that is publicly routable."""
    try:
        ip = ipaddress.ip_address(value)
    except ValueError:
        return False
    mapped = getattr(ip, 'ipv4_mapped', None)
    if mapped is not None:
        ip = mapped
    return not (
        ip.is_private
        or ip.is_loopback
        or ip.is_link_local
        or ip.is_multicast
        or ip.is_reserved
        or ip.is_unspecified
        or getattr(ip, 'is_site_local', False)
    )


def _host_is_allowed(host):
    for allowed in allowed_fetch_hosts():
        if host == allowed or host.endswith('.' + allowed):
            return True
    return False


def _host_resolves_to_public_addresses(host):
    """True when every address host resolves to is publicly routable."""
    if _is_public_ip(host):
        return True
    try:
        infos = socket.getaddrinfo(host, None)
    except (socket.gaierror, UnicodeError, ValueError):
        return False
    addresses = {info[4][0] for info in infos}
    return bool(addresses) and all(_is_public_ip(address) for address in addresses)


def safe_outbound_url(value):
    """Return a URL safe to fetch server-side, or None when it must be rejected.

    Guards against SSRF (CWE-918): the scheme has to be http/https, embedded
    credentials and non standard ports are refused, the host has to be on the
    deployment allowlist (see allowed_fetch_hosts) and every IP address it
    resolves to has to be publicly routable. Loopback, link-local
    (169.254.0.0/16 cloud metadata), RFC1918 and other internal destinations are
    therefore unreachable even when a user supplies them directly.

    Callers must treat None as "reject the request", must fetch the returned
    value instead of the raw user input, and must re-validate every redirect
    hop with this function.
    """
    if not isinstance(value, str):
        return None
    candidate = value.strip()
    if not candidate:
        return None
    try:
        parts = urlsplit(candidate)
        host = parts.hostname
        port = parts.port
        credentials = parts.username or parts.password
    except ValueError:
        return None
    if parts.scheme.lower() not in _ALLOWED_FETCH_SCHEMES:
        return None
    if credentials:
        return None
    if not host:
        return None
    if port is not None and port not in _ALLOWED_FETCH_PORTS:
        return None
    host = host.lower().rstrip('.')
    if not _host_is_allowed(host):
        return None
    if not _host_resolves_to_public_addresses(host):
        return None
    netloc = '[%s]' % host if ':' in host else host
    if port is not None:
        netloc = '%s:%d' % (netloc, port)
    return urlunsplit((parts.scheme.lower(), netloc, parts.path, parts.query, ''))


# XML documents posted to the comment lab are untrusted input. They are parsed
# with defusedxml, which refuses doctype declarations, entity declarations and
# external references, so neither XXE (CWE-611) nor entity expansion ("billion
# laughs") payloads can be resolved by the parser.
_XML_COMMENT_TAG = 'text'
_MAX_XML_BODY_BYTES = 64 * 1024


def safe_parse_comment_xml(body):
    """Return the text of the <text> element of an untrusted XML document.

    Raises ValueError when the document is oversized, not UTF-8, not well
    formed, carries a doctype/entity/external reference or has no <text>
    element. Callers must treat ValueError as "reject the request" and must
    never fall back to an entity aware parser.
    """
    if isinstance(body, (bytes, bytearray)):
        if len(body) > _MAX_XML_BODY_BYTES:
            raise ValueError('the XML document is too large')
        try:
            body = bytes(body).decode('utf-8')
        except UnicodeDecodeError:
            raise ValueError('the XML document is not valid UTF-8')
    if not isinstance(body, str):
        raise ValueError('the XML document must be text')
    if len(body) > _MAX_XML_BODY_BYTES:
        raise ValueError('the XML document is too large')
    try:
        root = fromstring(body, forbid_dtd=True)
    except DefusedXmlException:
        raise ValueError(
            'doctypes, entities and external references are not allowed')
    except ParseError:
        raise ValueError('the XML document is not well formed')
    if root.tag == _XML_COMMENT_TAG:
        node = root
    else:
        node = root.find('.//' + _XML_COMMENT_TAG)
    if node is None:
        raise ValueError('the XML document has no %s element' % _XML_COMMENT_TAG)
    return ''.join(node.itertext())


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