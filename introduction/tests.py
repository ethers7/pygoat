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

    @patch('introduction.views.subprocess.Popen')
    def test_valid_domain_uses_allowlisted_dig(self, mock_popen):
        mock_proc = MagicMock()
        mock_proc.communicate.return_value = (b'result\n', b'')
        mock_popen.return_value = mock_proc

        response = self._post('example.com', 'linux')
        mock_popen.assert_called_once_with(
            ['dig', 'example.com'],
            shell=False,
            stdout=-1,
            stderr=-1,
        )
        self.assertContains(response, 'result')

    @patch('introduction.views.subprocess.Popen')
    def test_valid_domain_uses_allowlisted_nslookup(self, mock_popen):
        mock_proc = MagicMock()
        mock_proc.communicate.return_value = (b'lookup result\n', b'')
        mock_popen.return_value = mock_proc

        response = self._post('example.com', 'win')
        mock_popen.assert_called_once_with(
            ['nslookup', 'example.com'],
            shell=False,
            stdout=-1,
            stderr=-1,
        )
        self.assertContains(response, 'lookup result')

    @patch('introduction.views.subprocess.Popen')
    def test_unknown_os_defaults_to_dig(self, mock_popen):
        mock_proc = MagicMock()
        mock_proc.communicate.return_value = (b'dig output\n', b'')
        mock_popen.return_value = mock_proc

        response = self._post('example.com', 'unknown')
        mock_popen.assert_called_once_with(
            ['dig', 'example.com'],
            shell=False,
            stdout=-1,
            stderr=-1,
        )

    def test_strips_protocol_and_validates(self):
        response = self._post('https://www.example.com')
        # After stripping protocol/www, domain is "example.com" which is valid
        # so no "Invalid domain name" should appear
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
