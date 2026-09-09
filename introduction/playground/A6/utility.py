import json

import requests

# Every outbound call has to be bounded (CWE-400): without an explicit timeout a
# slow or silent PyPI keeps this request handler blocked forever, and reading the
# body with response.json() would buffer a response of unknown size into memory.
# The limits are defined here, and not imported from introduction.utility,
# because the A6 lab overwrites this module with the learner's own submission
# (see A6_disscussion_api_2), so it has to stay standalone and stdlib only.
PYPI_TIMEOUT = (5, 10)  # (connect, read) seconds
MAX_PYPI_RESPONSE_BYTES = 1024 * 1024
_CHUNK_BYTES = 64 * 1024


def _read_bounded_json(response):
    """Decode a streamed JSON body, refusing to buffer more than the limit."""
    chunks = []
    size = 0
    for chunk in response.iter_content(_CHUNK_BYTES):
        if not chunk:
            continue
        size += len(chunk)
        if size > MAX_PYPI_RESPONSE_BYTES:
            raise ValueError(
                "the response body is larger than %d bytes" % MAX_PYPI_RESPONSE_BYTES)
        chunks.append(chunk)
    return json.loads(b"".join(chunks).decode("utf-8"))


def check_vuln(list_of_modules)->list:
    vulns = []
    for i in list_of_modules:
        k = i.split("==")
        url = f"https://pypi.org/pypi/{k[0]}/{k[1]}/json"
        with requests.get(url, timeout=PYPI_TIMEOUT, stream=True) as response:
            response.raise_for_status()
            info = _read_bounded_json(response)
        existing_vuln = info['vulnerabilities']
        if len(existing_vuln) > 0:
            vulns.append(existing_vuln)
    return vulns
