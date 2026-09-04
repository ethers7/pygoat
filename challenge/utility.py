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


# Allowlist for the image reference handed to `docker` as an argv element. Only
# registry/repository[:tag][@sha256:digest] characters are accepted and the
# reference must start with an alphanumeric, so no whitespace can split it into
# extra arguments and no leading dash (option injection) can reach the command.
_DOCKER_IMAGE_RE = re.compile(
    r'\A[0-9a-zA-Z][0-9a-zA-Z._/-]*(?::[0-9a-zA-Z][0-9a-zA-Z._-]*)?'
    r'(?:@sha256:[0-9a-fA-F]{64})?\Z')


def validate_docker_image(image):
    """Return the image reference when allowlisted, or None when it is not."""
    if not isinstance(image, str):
        return None
    image = image.strip()
    if len(image) > 255 or not _DOCKER_IMAGE_RE.match(image):
        return None
    return image


def validate_port(port):
    """Return the port as an int in the valid TCP range, or None otherwise."""
    if isinstance(port, bool):
        return None
    try:
        port = int(str(port).strip())
    except (TypeError, ValueError):
        return None
    if not 1 <= port <= 65535:
        return None
    return port


def get_free_port(START_PORT, END_PORT, HOST="localhost"):
    for port in range(START_PORT, END_PORT):
        with socket.socket(socket.AF_INET, socket.SOCK_STREAM) as s:
            result = s.connect_ex((HOST, port))
            if result == 111:
                print(f"Port {port} is avilable")
                return port
    return None
