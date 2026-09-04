import requests

# (connect, read) seconds for the PyPI lookups below. requests waits for ever
# by default, so one endpoint that accepts the connection and then never
# answers pins this worker - and there is one request per module (CWE-400).
REQUEST_TIMEOUT = (3, 5)


def check_vuln(list_of_modules)->list:
    vulns = []
    for i in list_of_modules:
        k = i.split("==")
        url = f"https://pypi.org/pypi/{k[0]}/{k[1]}/json"
        response = requests.get(url, timeout=REQUEST_TIMEOUT)
        response.raise_for_status()
        info = response.json()
        existing_vuln = info['vulnerabilities']
        if len(existing_vuln) > 0:
            vulns.append(existing_vuln) 
    return vulns