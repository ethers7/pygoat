from django.test import TestCase, Client, RequestFactory
from django.contrib.auth.models import User
from unittest.mock import patch, MagicMock

from .models import login as LoginModel
from .models import sql_lab_table as SqlLabTableModel


class SqlLabParameterizedQueryTest(TestCase):
    """Test that sql_lab view uses parameterized queries instead of string concatenation."""

    def setUp(self):
        self.client = Client()
        self.user = User.objects.create_user(
            username='testuser', password='testpass'
        )
        self.client.login(username='testuser', password='testpass')
        LoginModel.objects.create(user='admin', password='secret')

    @patch('introduction.models.login.objects.raw')
    def test_sql_lab_uses_parameterized_query(self, mock_raw):
        """Verify that raw() is called with params list, not concatenated SQL."""
        mock_raw.return_value = []
        response = self.client.post(
            '/sql_lab',
            {'name': "admin", 'pass': "secret"}
        )
        mock_raw.assert_called_once()
        args, kwargs = mock_raw.call_args
        sql_query = args[0]
        params = args[1] if len(args) > 1 else kwargs.get('params')
        # The query must use %s placeholders, not string interpolation
        self.assertIn('%s', sql_query)
        self.assertNotIn("admin", sql_query)
        self.assertNotIn("secret", sql_query)
        # Parameters must be passed separately
        self.assertEqual(params, ['admin', 'secret'])

    @patch('introduction.models.login.objects.raw')
    def test_sql_lab_injection_attempt_is_parameterized(self, mock_raw):
        """Verify SQL injection payloads are passed as parameters, not in SQL string."""
        mock_raw.return_value = []
        injection_payload = "' OR '1'='1"
        response = self.client.post(
            '/sql_lab',
            {'name': "admin", 'pass': injection_payload}
        )
        mock_raw.assert_called_once()
        args, kwargs = mock_raw.call_args
        sql_query = args[0]
        params = args[1] if len(args) > 1 else kwargs.get('params')
        # The injection string must NOT appear in the SQL query itself
        self.assertNotIn(injection_payload, sql_query)
        # It must be safely passed as a parameter
        self.assertIn(injection_payload, params)


class InjectionSqlLabParameterizedQueryTest(TestCase):
    """Test that injection_sql_lab view uses parameterized queries."""

    def setUp(self):
        self.client = Client()
        self.user = User.objects.create_user(
            username='testuser', password='testpass'
        )
        self.client.login(username='testuser', password='testpass')

    @patch('introduction.models.sql_lab_table.objects.raw')
    @patch('introduction.models.sql_lab_table.save', create=True)
    def test_injection_sql_lab_uses_parameterized_query(self, mock_save, mock_raw):
        """Verify that raw() is called with params list, not concatenated SQL."""
        mock_obj = MagicMock()
        mock_obj.id = 'admin'
        mock_raw.return_value = [mock_obj]
        response = self.client.post(
            '/injection_sql_lab',
            {'name': "admin", 'pass': "secret"}
        )
        mock_raw.assert_called_once()
        args, kwargs = mock_raw.call_args
        sql_query = args[0]
        params = args[1] if len(args) > 1 else kwargs.get('params')
        # The query must use %s placeholders, not string interpolation
        self.assertIn('%s', sql_query)
        self.assertNotIn("admin", sql_query)
        self.assertNotIn("secret", sql_query)
        # Parameters must be passed separately
        self.assertEqual(params, ['admin', 'secret'])

    @patch('introduction.models.sql_lab_table.objects.raw')
    @patch('introduction.models.sql_lab_table.save', create=True)
    def test_injection_sql_lab_injection_attempt_is_parameterized(self, mock_save, mock_raw):
        """Verify SQL injection payloads are passed as parameters, not in SQL string."""
        mock_obj = MagicMock()
        mock_obj.id = 'admin'
        mock_raw.return_value = [mock_obj]
        injection_payload = "' OR '1'='1"
        response = self.client.post(
            '/injection_sql_lab',
            {'name': "admin", 'pass': injection_payload}
        )
        mock_raw.assert_called_once()
        args, kwargs = mock_raw.call_args
        sql_query = args[0]
        params = args[1] if len(args) > 1 else kwargs.get('params')
        # The injection string must NOT appear in the SQL query itself
        self.assertNotIn(injection_payload, sql_query)
        # It must be safely passed as a parameter
        self.assertIn(injection_payload, params)
