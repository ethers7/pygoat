from unittest.mock import patch, MagicMock

from django.contrib.auth.models import User
from django.test import TestCase, RequestFactory

from introduction.views import cmd_lab, _is_safe_url_for_ssrf, ssrf_lab2


class CmdLabSecurityTest(TestCase):
    def setUp(self):
        self.factory = RequestFactory()
        self.user = User.objects.create_user(
            username='testuser', password='testpass123'
        )

    def _post(self, domain, os_val='linux'):
        request = self.factory.post('/cmd_lab', {'domain': domain, 'os': os_val})
        request.user = self.user
        return cmd_lab(request)

    def test_rejects_command_injection_semicolon(self):
        response = self._post('example.com; cat /etc/passwd')
        self.assertContains(response, 'Invalid domain name')

    def test_rejects_command_injection_backtick(self):
        response = self._post('`whoami`.example.com')
        self.assertContains(response, 'Invalid domain name')

    def test_rejects_command_injection_pipe(self):
        response = self._post('example.com | ls')
        self.assertContains(response, 'Invalid domain name')

    def test_rejects_command_injection_ampersand(self):
        response = self._post('example.com && id')
        self.assertContains(response, 'Invalid domain name')

    def test_rejects_empty_domain(self):
        response = self._post('')
        self.assertContains(response, 'Invalid domain name')

    @patch('introduction.views.socket.getaddrinfo')
    def test_valid_domain_resolves_dns(self, mock_getaddrinfo):
        mock_getaddrinfo.return_value = [
            (2, 1, 6, '', ('93.184.216.34', 0)),
        ]

        response = self._post('example.com', 'linux')
        mock_getaddrinfo.assert_called_once_with(
            'example.com', None, 0, 1,
        )
        self.assertContains(response, 'DNS lookup for example.com')
        self.assertContains(response, '93.184.216.34')

    @patch('introduction.views.socket.getaddrinfo')
    def test_valid_domain_multiple_addresses(self, mock_getaddrinfo):
        mock_getaddrinfo.return_value = [
            (2, 1, 6, '', ('93.184.216.34', 0)),
            (10, 1, 6, '', ('2606:2800:220:1:248:1893:25c8:1946', 0, 0, 0)),
        ]

        response = self._post('example.com', 'win')
        self.assertContains(response, '93.184.216.34')
        self.assertContains(response, '2606:2800:220:1:248:1893:25c8:1946')

    @patch('introduction.views.socket.getaddrinfo')
    def test_dns_lookup_failure(self, mock_getaddrinfo):
        import socket
        mock_getaddrinfo.side_effect = socket.gaierror('Name or service not known')

        response = self._post('nonexistent.invalid', 'linux')
        self.assertContains(response, 'DNS lookup failed')

    def test_strips_protocol_and_validates(self):
        # After stripping protocol/www, domain is "example.com" which is valid
        # so no "Invalid domain name" should appear
        response = self._post('https://www.example.com')
        self.assertNotContains(response, 'Invalid domain name')


class SsrfLab2SecurityTest(TestCase):
    def setUp(self):
        self.factory = RequestFactory()
        self.user = User.objects.create_user(
            username='testuser2', password='testpass123'
        )

    def _post(self, url):
        request = self.factory.post('/ssrf_lab2', {'url': url})
        request.user = self.user
        return ssrf_lab2(request)

    def test_rejects_localhost(self):
        response = self._post('http://127.0.0.1/admin')
        self.assertContains(response, 'URL not allowed')

    def test_rejects_localhost_name(self):
        response = self._post('http://localhost/secret')
        self.assertContains(response, 'URL not allowed')

    def test_rejects_metadata_endpoint(self):
        response = self._post('http://169.254.169.254/latest/meta-data/')
        self.assertContains(response, 'URL not allowed')

    def test_rejects_ftp_scheme(self):
        response = self._post('ftp://example.com/file')
        self.assertContains(response, 'URL not allowed')

    def test_rejects_file_scheme(self):
        response = self._post('file:///etc/passwd')
        self.assertContains(response, 'URL not allowed')

    def test_rejects_no_scheme(self):
        response = self._post('127.0.0.1')
        self.assertContains(response, 'URL not allowed')

    @patch('introduction.views.socket.getaddrinfo')
    def test_rejects_private_ip_after_resolution(self, mock_getaddrinfo):
        mock_getaddrinfo.return_value = [
            (2, 1, 6, '', ('10.0.0.1', 80))
        ]
        response = self._post('http://evil.example.com/')
        self.assertContains(response, 'URL not allowed')

    @patch('introduction.views.requests.get')
    @patch('introduction.views.socket.getaddrinfo')
    def test_allows_valid_external_url(self, mock_getaddrinfo, mock_get):
        mock_getaddrinfo.return_value = [
            (2, 1, 6, '', ('93.184.216.34', 80))
        ]
        mock_response = MagicMock()
        mock_response.content = b'Hello World'
        mock_get.return_value = mock_response
        response = self._post('http://example.com/')
        self.assertContains(response, 'Hello World')

    def test_is_safe_url_rejects_ipv6_loopback(self):
        self.assertFalse(_is_safe_url_for_ssrf('http://[::1]/'))

    def test_get_returns_form(self):
        request = self.factory.get('/ssrf_lab2')
        request.user = self.user
        response = ssrf_lab2(request)
        self.assertEqual(response.status_code, 200)
