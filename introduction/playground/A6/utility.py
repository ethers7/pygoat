import json

import requests

# Uncontrolled resource consumption (CWE-400): the PyPI lookups below are
# bounded so a slow, endless or oversized upstream response cannot pin the
# worker or exhaust its memory. REQUEST_TIMEOUT is the (connect, read) pair
# every request passes as timeout=, MAX_MODULES caps how many requests one
# call may issue and MAX_RESPONSE_BYTES caps the body buffered per response.
REQUEST_TIMEOUT = (5, 10)
MAX_MODULES = 50
MAX_RESPONSE_BYTES = 2 * 1024 * 1024
CHUNK_BYTES = 8192


def fetch_json(url):
    """Fetch a JSON document with a timeout and a hard response size cap."""
    response = requests.get(url, timeout=REQUEST_TIMEOUT, stream=True)
    try:
        response.raise_for_status()
        body = bytearray()
        for chunk in response.iter_content(CHUNK_BYTES):
            if not chunk:
                continue
            body.extend(chunk)
            if len(body) > MAX_RESPONSE_BYTES:
                raise ValueError(
                    f"response is larger than the {MAX_RESPONSE_BYTES} byte limit"
                )
    finally:
        response.close()
    return json.loads(bytes(body).decode("utf-8", errors="replace"))


def check_vuln(list_of_modules)->list:
    modules = list(list_of_modules)
    if len(modules) > MAX_MODULES:
        raise ValueError(f"at most {MAX_MODULES} modules can be checked per call")
    vulns = []
    for i in modules:
        k = i.split("==")
        url = f"https://pypi.org/pypi/{k[0]}/{k[1]}/json"
        info = fetch_json(url)
        existing_vuln = info['vulnerabilities']
        if len(existing_vuln) > 0:
            vulns.append(existing_vuln)
    return vulns
