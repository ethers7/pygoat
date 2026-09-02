import re
import socket

# A docker container reference is either a hex id (short or full) or a
# container name: it must start with an alphanumeric and may then only contain
# alphanumerics, underscore, period or hyphen. That excludes whitespace, path
# separators, option-looking leading dashes and every shell metacharacter.
_CONTAINER_REF_RE = re.compile(r'[A-Za-z0-9][A-Za-z0-9_.-]{0,127}\Z')


def safe_container_ref(value):
    """Validate an untrusted container id/name before it reaches ``docker``.

    Returns the normalised reference when the value is a plain docker container
    id or name, and ``None`` otherwise. Callers must still pass the result as
    its own argv element and never build a shell command string from it.
    """
    if not isinstance(value, str):
        return None
    ref = value.strip()
    if not ref:
        return None
    if _CONTAINER_REF_RE.match(ref):
        return ref
    return None


def get_free_port(START_PORT, END_PORT, HOST="localhost"):
    for port in range(START_PORT, END_PORT):
        with socket.socket(socket.AF_INET, socket.SOCK_STREAM) as s:
            result = s.connect_ex((HOST, port))
            if result == 111:
                print(f"Port {port} is avilable")
                return port
    return None
