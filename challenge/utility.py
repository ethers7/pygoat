import re
import socket

# Docker container references (id or name) are alphanumerics plus ``_``, ``.``
# and ``-``, and never start with a separator.  Anything else -- whitespace,
# shell metacharacters, or a leading ``-`` that docker would read as an extra
# command line option -- is rejected before the value becomes an argv element.
_CONTAINER_REF_RE = re.compile(r'^[A-Za-z0-9][A-Za-z0-9_.-]{0,127}$')


def validate_container_ref(value):
    """Validate an untrusted docker container id/name for use in argv.

    The challenge runner must still be able to stop the container it started,
    so the stored reference is allowlisted at the trust boundary instead of
    being interpolated into a command string that is later split on spaces
    (CWE-78).  ``str.split`` is not a validation step: it happily forwards
    extra arguments.  Returns the normalised reference and raises
    ``ValueError`` for anything that is not a plausible container id or name.
    """
    if not isinstance(value, str):
        raise ValueError('not a valid container reference')
    ref = value.strip()
    if not _CONTAINER_REF_RE.match(ref):
        raise ValueError('not a valid container reference')
    return ref


def get_free_port(START_PORT, END_PORT, HOST="localhost"):
    for port in range(START_PORT, END_PORT):
        with socket.socket(socket.AF_INET, socket.SOCK_STREAM) as s:
            result = s.connect_ex((HOST, port))
            if result == 111:
                print(f"Port {port} is avilable")
                return port
    return None
