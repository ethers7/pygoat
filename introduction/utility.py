import hashlib
import ipaddress
import os
import re
import uuid

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