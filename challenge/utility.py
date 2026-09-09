import re
import socket

# Docker container ids are hex digests (short form is 12 chars, full form 64).
# Rejecting anything else keeps whitespace, shell metacharacters (; | & $ ` ( )
# < > newline ...) and leading '-' out of the value, so a validated id is safe
# to pass as a single argv element of a subprocess call.
_CONTAINER_ID_RE = re.compile(r'^[0-9a-fA-F]{12,64}$')


def is_safe_container_id(value):
    """Return True when value is a docker container id usable as one argv element."""
    if not isinstance(value, str):
        return False
    return _CONTAINER_ID_RE.match(value) is not None


def get_free_port(START_PORT, END_PORT, HOST="localhost"):
    for port in range(START_PORT, END_PORT):
        with socket.socket(socket.AF_INET, socket.SOCK_STREAM) as s:
            result = s.connect_ex((HOST, port))
            if result == 111:
                print(f"Port {port} is avilable")
                return port
    return None
