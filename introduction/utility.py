import hashlib
import ipaddress
import os
import re
import socket
import uuid
from urllib.parse import urlsplit, urlunsplit

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