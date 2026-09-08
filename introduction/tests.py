from hashlib import md5
from unittest.mock import patch

import jwt
from django.contrib.auth.models import User
from django.core.exceptions import ImproperlyConfigured
from django.test import SimpleTestCase, TestCase, override_settings

from .mitre import command_out, csrf_lab_jwt_key
from .models import CSRF_user_tbl
from .models import login as login_row
from .utility import validate_target_host

# Test-only signing key for the CSRF lab. It is injected through settings so
# that no JWT key literal is ever handed to jwt.encode()/jwt.decode() (CWE-522).
TEST_CSRF_LAB_JWT_KEY = "unit-test-csrf-lab-signing-key"


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


class TargetHostValidationTests(SimpleTestCase):
    """Guards introduction.utility.validate_target_host (CWE-78 allowlist)."""

    def test_accepts_hostnames_addresses_and_ranges(self):
        for value, expected in (
            ("example.com", "example.com"),
            ("  scanme.nmap.org ", "scanme.nmap.org"),
            ("127.0.0.1", "127.0.0.1"),
            ("::1", "::1"),
            ("10.0.0.0/24", "10.0.0.0/24"),
        ):
            self.assertEqual(validate_target_host(value), expected)

    def test_rejects_metacharacters_option_flags_and_blanks(self):
        for value in (
            "example.com; id",
            "example.com && id",
            "example.com | cat /etc/passwd",
            "$(id).example.com",
            "`id`",
            "example.com\nid",
            "-oN/tmp/pwned",
            "--script=http-vuln",
            "/etc/passwd",
            "",
            "   ",
            None,
        ):
            with self.assertRaises(ValueError, msg=repr(value)):
                validate_target_host(value)


@override_settings(
    DEBUG=True,
    STATICFILES_STORAGE="django.contrib.staticfiles.storage.StaticFilesStorage",
)
class CommandLabArgvTests(TestCase):
    """The command labs must still run their tool, but never through a shell.

    Guards introduction.views.cmd_lab and introduction.mitre.command_out /
    mitre_lab_17_api against a regression back to shell=True on a command
    string built from user input (CWE-78).
    """

    PASSWORD = "Str0ng-Passw0rd!"
    NMAP_OUT = b"PORT   STATE SERVICE\n22/tcp open  ssh\n\n"

    def setUp(self):
        self.user = User.objects.create_user(
            username="cmduser",
            email="cmduser@example.com",
            password=self.PASSWORD,
        )
        self.client.force_login(self.user)

    def test_cmd_lab_still_runs_lookup_as_argv(self):
        with patch("introduction.views.subprocess.Popen") as popen:
            popen.return_value.communicate.return_value = (b"1.2.3.4\n", b"")
            r = self.client.post(
                "/cmd_lab",
                {"domain": "https://www.example.com", "os": "lin"},
            )
        self.assertEqual(r.status_code, 200)
        args, kwargs = popen.call_args
        self.assertEqual(args[0], ["dig", "example.com"])
        self.assertFalse(kwargs.get("shell", False))
        self.assertIn("1.2.3.4", r.context["output"])

    def test_cmd_lab_windows_branch_still_runs_argv(self):
        with patch("introduction.views.subprocess.Popen") as popen:
            popen.return_value.communicate.return_value = (b"1.2.3.4\n", b"")
            r = self.client.post("/cmd_lab", {"domain": "example.com", "os": "win"})
        self.assertEqual(r.status_code, 200)
        self.assertEqual(popen.call_args[0][0], ["nslookup", "example.com"])

    def test_cmd_lab_rejects_shell_metacharacters(self):
        with patch("introduction.views.subprocess.Popen") as popen:
            r = self.client.post(
                "/cmd_lab",
                {"domain": "example.com; id", "os": "lin"},
            )
        popen.assert_not_called()
        self.assertEqual(r.status_code, 200)
        self.assertIn("Invalid domain name", r.context["output"])

    def test_mitre_lab_17_api_still_scans_as_argv(self):
        with patch("introduction.mitre.subprocess.Popen") as popen:
            popen.return_value.communicate.return_value = (self.NMAP_OUT, b"")
            r = self.client.post("/mitre/17/lab/api", {"ip": "127.0.0.1"})
        self.assertEqual(r.status_code, 200)
        args, kwargs = popen.call_args
        self.assertEqual(args[0], ["nmap", "127.0.0.1"])
        self.assertFalse(kwargs.get("shell", False))
        self.assertEqual(r.json()["ports"], ["22/tcp open  ssh"])

    def test_mitre_lab_17_api_rejects_injected_command(self):
        with patch("introduction.mitre.subprocess.Popen") as popen:
            r = self.client.post("/mitre/17/lab/api", {"ip": "127.0.0.1 && id"})
        popen.assert_not_called()
        self.assertEqual(r.status_code, 400)
        self.assertEqual(r.json()["ports"], [])

    def test_command_out_refuses_shell_command_string(self):
        with self.assertRaises(TypeError):
            command_out("nmap 127.0.0.1")


@override_settings(
    DEBUG=True,
    STATICFILES_STORAGE="django.contrib.staticfiles.storage.StaticFilesStorage",
    CSRF_LAB_JWT_KEY=TEST_CSRF_LAB_JWT_KEY,
)
class CsrfLabJwtKeyTests(TestCase):
    """The CSRF lab must sign its cookie with a configured key, not a literal.

    Guards introduction.mitre.csrf_lab_login / csrf_transfer_monei /
    csrf_transfer_monei_api against a regression back to a hardcoded JWT
    signing key in source (CWE-522).
    """

    PASSWORD = "Str0ng-Passw0rd!"
    LAB_PASSWORD = "lab-password"
    REMOVED_KEY = "csrf_vulneribility"

    def setUp(self):
        self.user = User.objects.create_user(
            username="csrfuser",
            email="csrfuser@example.com",
            password=self.PASSWORD,
        )
        self.client.force_login(self.user)
        CSRF_user_tbl.objects.create(
            username="alice",
            password=md5(self.LAB_PASSWORD.encode()).hexdigest(),
            balance=100,
        )
        CSRF_user_tbl.objects.create(
            username="bob",
            password=md5(self.LAB_PASSWORD.encode()).hexdigest(),
            balance=0,
        )

    def _issued_cookie(self):
        r = self.client.post(
            "/mitre/9/lab/login",
            {"username": "alice", "password": self.LAB_PASSWORD},
        )
        self.assertEqual(r.status_code, 302)
        return r.cookies["auth_cookiee"].value

    def test_cookie_is_signed_with_configured_key(self):
        payload = jwt.decode(
            self._issued_cookie(),
            TEST_CSRF_LAB_JWT_KEY,
            algorithms=["HS256"],
        )
        self.assertEqual(payload["username"], "alice")

    def test_cookie_is_not_signed_with_the_removed_literal(self):
        with self.assertRaises(jwt.InvalidSignatureError):
            jwt.decode(
                self._issued_cookie(),
                self.REMOVED_KEY,
                algorithms=["HS256"],
            )

    def test_dashboard_still_accepts_a_freshly_issued_cookie(self):
        self.client.cookies["auth_cookiee"] = self._issued_cookie()
        r = self.client.get("/mitre/9/lab/transaction")
        self.assertEqual(r.status_code, 200)
        self.assertEqual(r.context["balance"], 100)

    def test_transfer_api_still_accepts_a_freshly_issued_cookie(self):
        self.client.cookies["auth_cookiee"] = self._issued_cookie()
        r = self.client.get("/mitre/9/lab/api/bob/10")
        self.assertEqual(r.status_code, 302)
        self.assertEqual(CSRF_user_tbl.objects.get(username="alice").balance, 90)
        self.assertEqual(CSRF_user_tbl.objects.get(username="bob").balance, 10)

    def test_dashboard_rejects_cookie_signed_with_the_removed_literal(self):
        forged = jwt.encode(
            {"username": "alice"},
            self.REMOVED_KEY,
            algorithm="HS256",
        )
        self.client.cookies["auth_cookiee"] = forged
        r = self.client.get("/mitre/9/lab/transaction")
        self.assertEqual(r.status_code, 302)
        self.assertEqual(r.url, "/mitre/9/lab/login")

    @override_settings(CSRF_LAB_JWT_KEY=None)
    def test_missing_configuration_fails_closed(self):
        with self.assertRaises(ImproperlyConfigured):
            csrf_lab_jwt_key()
