import hashlib
import ipaddress
import os
import re
import uuid

from .models import *

# Hostname label rules from RFC 1123: letters, digits and hyphens only, no
# leading/trailing hyphen, 1-63 chars per label, 253 chars overall.
_HOSTNAME_RE = re.compile(
    r'^(?!-)[A-Za-z0-9-]{1,63}(?<!-)'
    r'(?:\.(?!-)[A-Za-z0-9-]{1,63}(?<!-))*\.?$'
)


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