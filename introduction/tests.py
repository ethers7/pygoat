from unittest.mock import patch, MagicMock

from django.contrib.auth.models import User
from django.test import TestCase, RequestFactory

from introduction.views import cmd_lab


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
