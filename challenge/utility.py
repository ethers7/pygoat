import re
import socket

# Docker container ids / names are hex digests or [a-zA-Z0-9][a-zA-Z0-9_.-]* names.
# The validated value is passed as its own argv element with shell=False, so this
# only has to reject shell metacharacters, whitespace and leading "-" option injection.
_CONTAINER_ID_RE = re.compile(r'^[A-Za-z0-9][A-Za-z0-9_.-]{0,127}$')


def safe_container_id(value):
    """Return a validated docker container id/name, or None when the value is not one.

    Callers must treat None as "do not run the command" and must pass the returned
    value as its own argv element (never through a shell), so that shell
    metacharacters can never be interpreted as command syntax.
    """
    if not isinstance(value, str):
        return None
    container_id = value.strip()
    if not container_id:
        return None
    if _CONTAINER_ID_RE.match(container_id):
        return container_id
    return None


def get_free_port(START_PORT, END_PORT, HOST="localhost"):
    for port in range(START_PORT, END_PORT):
        with socket.socket(socket.AF_INET, socket.SOCK_STREAM) as s:
            result = s.connect_ex((HOST, port))
            if result == 111:
                print(f"Port {port} is avilable")
                return port
    return None
