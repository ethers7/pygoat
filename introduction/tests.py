import os
from unittest import mock

from django.test import SimpleTestCase

from .utility import validate_fetch_url


class ValidateFetchUrlTests(SimpleTestCase):
    """The SSRF lab2 fetch must only accept allowlisted public http(s) URLs."""

    def test_rejects_non_http_schemes(self):
        for url in ("file:///etc/passwd", "gopher://example.com/", "ftp://example.com/x"):
            self.assertIsNone(validate_fetch_url(url))

    def test_rejects_hosts_outside_the_allowlist(self):
        self.assertIsNone(validate_fetch_url("http://attacker.example.net/"))

    def test_rejects_internal_and_metadata_addresses(self):
        for url in ("http://127.0.0.1:8000/ssrf_target",
                    "http://169.254.169.254/latest/meta-data/",
                    "http://10.0.0.1/",
                    "http://[::1]/"):
            self.assertIsNone(validate_fetch_url(url))

    def test_rejects_allowlisted_host_resolving_to_a_private_address(self):
        with mock.patch.dict(os.environ, {"SSRF_ALLOWED_HOSTS": "localhost"}):
            self.assertIsNone(validate_fetch_url("http://localhost:80/ssrf_target"))

    def test_rejects_non_standard_ports_and_bad_input(self):
        self.assertIsNone(validate_fetch_url("http://example.com:8000/"))
        self.assertIsNone(validate_fetch_url("http://example.com:notaport/"))
        self.assertIsNone(validate_fetch_url(None))
        self.assertIsNone(validate_fetch_url(""))

    def test_accepts_allowlisted_host_and_drops_credentials_and_fragment(self):
        with mock.patch("introduction.utility._is_public_host", return_value=True):
            self.assertEqual(
                validate_fetch_url(" https://user:pass@example.com/page?q=1#frag "),
                "https://example.com/page?q=1")

    def test_credential_trick_pointing_at_metadata_is_rejected(self):
        self.assertIsNone(validate_fetch_url("http://example.com@169.254.169.254/"))
