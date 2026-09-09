from django.test import SimpleTestCase

from .utility import UnsafeUrlError, validate_public_url

# Create your tests here.


class ValidatePublicUrlTests(SimpleTestCase):
    """Regression tests for the SSRF guard used by the SSRF lab (CWE-918)."""

    def assert_rejected(self, url):
        with self.assertRaises(UnsafeUrlError):
            validate_public_url(url)

    def test_rejects_non_http_schemes(self):
        for url in ("file:///etc/passwd", "gopher://example.com/", "ftp://example.com/"):
            self.assert_rejected(url)

    def test_rejects_missing_or_empty_url(self):
        for url in ("", "   ", "http://", None):
            self.assert_rejected(url)

    def test_rejects_metadata_and_internal_addresses(self):
        for url in ("http://169.254.169.254/latest/meta-data/",
                    "http://127.0.0.1:8000/admin",
                    "http://0.0.0.0/",
                    "http://10.0.0.5/",
                    "http://172.16.0.1/",
                    "http://192.168.1.1/",
                    "http://[::1]/",
                    "http://[fc00::1]/",
                    "http://[::ffff:169.254.169.254]/"):
            self.assert_rejected(url)

    def test_rejects_hosts_outside_allowlist(self):
        with self.assertRaises(UnsafeUrlError):
            validate_public_url("http://93.184.216.34/", allowed_hosts=("example.org",))

    def test_allows_public_address(self):
        self.assertEqual(validate_public_url("http://93.184.216.34/page"),
                         "http://93.184.216.34/page")

    def test_allows_host_resolving_to_public_address(self):
        def resolver(host, port, **kwargs):
            return [(None, None, None, "", ("93.184.216.34", port))]

        self.assertEqual(
            validate_public_url("https://example.org/x", allowed_hosts=("example.org",),
                                resolver=resolver),
            "https://example.org/x")

    def test_rejects_host_resolving_to_internal_address(self):
        def resolver(host, port, **kwargs):
            return [(None, None, None, "", ("169.254.169.254", port))]

        with self.assertRaises(UnsafeUrlError):
            validate_public_url("http://metadata.example/", resolver=resolver)
