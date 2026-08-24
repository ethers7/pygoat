from unittest.mock import patch

from django.contrib.auth.models import User
from django.test import TestCase, RequestFactory

from introduction.views import _is_safe_url, xxe_parse


class IsSSRFSafeUrlTests(TestCase):
    """Tests for the _is_safe_url SSRF validation helper."""

    @patch("introduction.views.socket.getaddrinfo")
    def test_public_http_url_allowed(self, mock_getaddrinfo):
        mock_getaddrinfo.return_value = [
            (2, 1, 6, "", ("93.184.216.34", 0)),
        ]
        self.assertTrue(_is_safe_url("http://example.com/path"))

    @patch("introduction.views.socket.getaddrinfo")
    def test_public_https_url_allowed(self, mock_getaddrinfo):
        mock_getaddrinfo.return_value = [
            (2, 1, 6, "", ("93.184.216.34", 0)),
        ]
        self.assertTrue(_is_safe_url("https://example.com/path"))

    def test_ftp_scheme_rejected(self):
        self.assertFalse(_is_safe_url("ftp://example.com/file"))

    def test_file_scheme_rejected(self):
        self.assertFalse(_is_safe_url("file:///etc/passwd"))

    def test_no_scheme_rejected(self):
        self.assertFalse(_is_safe_url("example.com"))

    @patch("introduction.views.socket.getaddrinfo")
    def test_loopback_ip_rejected(self, mock_getaddrinfo):
        mock_getaddrinfo.return_value = [
            (2, 1, 6, "", ("127.0.0.1", 0)),
        ]
        self.assertFalse(_is_safe_url("http://127.0.0.1/admin"))

    @patch("introduction.views.socket.getaddrinfo")
    def test_private_ip_10_rejected(self, mock_getaddrinfo):
        mock_getaddrinfo.return_value = [
            (2, 1, 6, "", ("10.0.0.1", 0)),
        ]
        self.assertFalse(_is_safe_url("http://10.0.0.1/internal"))

    @patch("introduction.views.socket.getaddrinfo")
    def test_private_ip_192_168_rejected(self, mock_getaddrinfo):
        mock_getaddrinfo.return_value = [
            (2, 1, 6, "", ("192.168.1.1", 0)),
        ]
        self.assertFalse(_is_safe_url("http://192.168.1.1/"))

    @patch("introduction.views.socket.getaddrinfo")
    def test_link_local_rejected(self, mock_getaddrinfo):
        mock_getaddrinfo.return_value = [
            (2, 1, 6, "", ("169.254.169.254", 0)),
        ]
        self.assertFalse(_is_safe_url("http://169.254.169.254/latest/meta-data/"))

    def test_empty_string_rejected(self):
        self.assertFalse(_is_safe_url(""))

    def test_no_hostname_rejected(self):
        self.assertFalse(_is_safe_url("http://"))


class SSRFLab2ViewTests(TestCase):
    """Integration tests for the ssrf_lab2 view endpoint."""

    def setUp(self):
        self.user = User.objects.create_user(username="testuser", password="testpass123")
        self.client.login(username="testuser", password="testpass123")

    @patch("introduction.views.socket.getaddrinfo")
    def test_post_internal_url_blocked(self, mock_getaddrinfo):
        mock_getaddrinfo.return_value = [
            (2, 1, 6, "", ("127.0.0.1", 0)),
        ]
        response = self.client.post("/ssrf_lab2", {"url": "http://127.0.0.1/secret"})
        self.assertEqual(response.status_code, 200)
        self.assertContains(response, "Invalid or disallowed URL")

    @patch("introduction.views.socket.getaddrinfo")
    def test_post_metadata_endpoint_blocked(self, mock_getaddrinfo):
        mock_getaddrinfo.return_value = [
            (2, 1, 6, "", ("169.254.169.254", 0)),
        ]
        response = self.client.post("/ssrf_lab2", {"url": "http://169.254.169.254/latest/meta-data/"})
        self.assertEqual(response.status_code, 200)
        self.assertContains(response, "Invalid or disallowed URL")

    def test_post_file_scheme_blocked(self):
        response = self.client.post("/ssrf_lab2", {"url": "file:///etc/passwd"})
        self.assertEqual(response.status_code, 200)
        self.assertContains(response, "Invalid or disallowed URL")

    def test_get_renders_form(self):
        response = self.client.get("/ssrf_lab2")
        self.assertEqual(response.status_code, 200)


class XXEParseSecureTests(TestCase):
    """Tests that XML parsing uses defusedxml and rejects XXE payloads."""

    def test_parseString_uses_defusedxml(self):
        """Verify that the parseString used in views is from defusedxml."""
        from introduction import views
        import defusedxml.pulldom

        self.assertIs(views.parseString, defusedxml.pulldom.parseString)

    def test_xxe_payload_rejected(self):
        """Verify that an XXE payload with external entity is rejected."""
        from defusedxml.pulldom import parseString
        from defusedxml import DTDForbidden, EntitiesForbidden, ExternalReferenceForbidden

        xxe_payload = (
            '<?xml version="1.0" encoding="UTF-8"?>'
            '<!DOCTYPE foo [ <!ENTITY xxe SYSTEM "file:///etc/passwd"> ]>'
            '<comment><text>&xxe;</text></comment>'
        )
        with self.assertRaises((DTDForbidden, EntitiesForbidden, ExternalReferenceForbidden)):
            doc = parseString(xxe_payload)
            for event, node in doc:
                pass
