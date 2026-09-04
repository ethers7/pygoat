import re
import socket

# Allowlist for the container id handed to `docker` as an argv element. Docker
# ids are hex digests, so accepting only hex characters keeps shell
# metacharacters and a leading dash (option injection) out of the command.
_CONTAINER_ID_RE = re.compile(r'\A[0-9a-fA-F]{12,64}\Z')


def validate_container_id(container_id):
    """Return the container id when allowlisted, or None when it is not."""
    if not isinstance(container_id, str):
        return None
    container_id = container_id.strip()
    if not _CONTAINER_ID_RE.match(container_id):
        return None
    return container_id


def get_free_port(START_PORT, END_PORT, HOST="localhost"):
    for port in range(START_PORT, END_PORT):
        with socket.socket(socket.AF_INET, socket.SOCK_STREAM) as s:
            result = s.connect_ex((HOST, port))
            if result == 111:
                print(f"Port {port} is avilable")
                return port
    return None
