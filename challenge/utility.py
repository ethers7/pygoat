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


# Docker image references such as "nginx", "nginx:1.25", "org/name:tag",
# "registry.example.com:5000/org/name" or "org/name@sha256:<digest>". The
# pattern rejects whitespace, shell metacharacters (; | & $ ` ( ) < > newline
# ...) and a leading '-', so a validated reference is safe to pass as a single
# argv element and cannot be mistaken for an extra `docker run` option.
_DOCKER_IMAGE_RE = re.compile(r'^[A-Za-z0-9][A-Za-z0-9._:/@-]{0,254}$')


def is_safe_docker_image(value):
    """Return True when value is a docker image reference usable as one argv element."""
    if not isinstance(value, str):
        return False
    return _DOCKER_IMAGE_RE.match(value) is not None


def normalize_port(value):
    """Return value as a TCP port int, or None when it is not a valid port.

    Ports are interpolated into the `docker run -p host:container` argument, so
    they are coerced to plain integers instead of being trusted as stored text.
    """
    if isinstance(value, bool):
        return None
    try:
        port = int(value)
    except (TypeError, ValueError):
        return None
    if 1 <= port <= 65535:
        return port
    return None


def get_free_port(START_PORT, END_PORT, HOST="localhost"):
    for port in range(START_PORT, END_PORT):
        with socket.socket(socket.AF_INET, socket.SOCK_STREAM) as s:
            result = s.connect_ex((HOST, port))
            if result == 111:
                print(f"Port {port} is avilable")
                return port
    return None
