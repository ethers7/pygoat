from django.contrib.auth.models import User
from django.test import TestCase, override_settings

from .models import login as login_row


@override_settings(
    DEBUG=True,
    STATICFILES_STORAGE="django.contrib.staticfiles.storage.StaticFilesStorage",
)
class SqlLabParameterizationTests(TestCase):
    """The SQL labs must keep looking rows up, but with bound parameters.

    Guards introduction.views.sql_lab / injection_sql_lab against a
    regression back to string-concatenated SQL (CWE-89 / CWE-915).
    """

    PASSWORD = "Str0ng-Passw0rd!"
    TAUTOLOGY = "' OR '1'='1"

    def setUp(self):
        self.user = User.objects.create_user(
            username="sqluser",
            email="sqluser@example.com",
            password=self.PASSWORD,
        )
        self.client.force_login(self.user)
        login_row.objects.create(user="jack", password="jacktheripper")

    def test_sql_lab_valid_credentials_still_resolve(self):
        r = self.client.post("/sql_lab", {"name": "jack", "pass": "jacktheripper"})
        self.assertEqual(r.status_code, 200)
        self.assertEqual(r.context["user1"], "jack")

    def test_sql_lab_tautology_does_not_authenticate(self):
        r = self.client.post("/sql_lab", {"name": "jack", "pass": self.TAUTOLOGY})
        self.assertEqual(r.status_code, 200)
        self.assertIsNone(r.context.get("user1"))

    def test_injection_sql_lab_valid_credentials_still_resolve(self):
        r = self.client.post("/injection_sql_lab", {"name": "jack", "pass": "jack"})
        self.assertEqual(r.status_code, 200)
        self.assertEqual(r.context["user1"], "jack")

    def test_injection_sql_lab_tautology_does_not_authenticate(self):
        r = self.client.post(
            "/injection_sql_lab",
            {"name": "jack", "pass": self.TAUTOLOGY},
        )
        self.assertEqual(r.status_code, 200)
        self.assertIsNone(r.context.get("user1"))
