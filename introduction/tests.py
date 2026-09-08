import base64
import json
import socket
from hashlib import md5
from unittest.mock import patch

import jwt
import requests
from django.contrib.auth.models import User
from django.core.exceptions import ImproperlyConfigured
from django.core.files.uploadedfile import SimpleUploadedFile
from django.test import SimpleTestCase, TestCase, override_settings
from requests.structures import CaseInsensitiveDict

from .mitre import command_out, csrf_lab_jwt_key
from .models import CSRF_user_tbl
from .models import login as login_row
from .utility import validate_outbound_url, validate_target_host
from .views import SSRF_MAX_REDIRECTS, TestUser, encode_user

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


class OutboundUrlValidationTests(SimpleTestCase):
    """Guards introduction.utility.validate_outbound_url (CWE-918 allowlist)."""

    @staticmethod
    def _addrinfo(*addresses):
        return [
            (socket.AF_INET, socket.SOCK_STREAM, socket.IPPROTO_TCP, "", (a, 0))
            for a in addresses
        ]

    def test_accepts_and_normalises_public_web_urls(self):
        with patch("introduction.utility.socket.getaddrinfo") as getaddrinfo:
            getaddrinfo.return_value = self._addrinfo("93.184.216.34")
            for value, expected in (
                ("http://example.com", "http://example.com"),
                ("https://example.com/page?q=1", "https://example.com/page?q=1"),
                ("  HTTP://example.com/a#frag ", "http://example.com/a"),
            ):
                self.assertEqual(validate_outbound_url(value), expected)

    def test_rejects_non_web_schemes_and_malformed_input(self):
        for value in (
            "file:///etc/passwd",
            "gopher://example.com/_test",
            "ftp://example.com/secret",
            "dict://example.com:11211/stat",
            "data:text/plain,hello",
            "example.com/no-scheme",
            "http://",
            "http://user:pass@example.com",
            "http://example.com:notaport",
            "",
            "   ",
            None,
        ):
            with self.assertRaises(ValueError, msg=repr(value)):
                validate_outbound_url(value)

    def test_rejects_destinations_that_resolve_internally(self):
        for address in (
            "127.0.0.1",
            "169.254.169.254",
            "10.0.0.5",
            "172.16.4.9",
            "192.168.1.1",
            "0.0.0.0",
            "224.0.0.1",
            "::1",
            "fe80::1",
            "::ffff:127.0.0.1",
        ):
            with patch("introduction.utility.socket.getaddrinfo") as getaddrinfo:
                getaddrinfo.return_value = self._addrinfo(address)
                with self.assertRaises(ValueError, msg=address):
                    validate_outbound_url("http://rebind.example.com")

    def test_rejects_when_any_resolved_address_is_internal(self):
        with patch("introduction.utility.socket.getaddrinfo") as getaddrinfo:
            getaddrinfo.return_value = self._addrinfo("93.184.216.34", "127.0.0.1")
            with self.assertRaises(ValueError):
                validate_outbound_url("http://rebind.example.com")

    def test_rejects_hosts_that_do_not_resolve(self):
        with patch("introduction.utility.socket.getaddrinfo") as getaddrinfo:
            getaddrinfo.side_effect = socket.gaierror("no such host")
            with self.assertRaises(ValueError):
                validate_outbound_url("http://nx.example.invalid")

    def test_metadata_and_loopback_literals_are_rejected_without_dns(self):
        for value in (
            "http://169.254.169.254/latest/meta-data/",
            "http://127.0.0.1:8080/admin",
            "http://[::1]:8080/admin",
        ):
            with self.assertRaises(ValueError, msg=value):
                validate_outbound_url(value)


class _FakeResponse:
    """Minimal stand-in for requests.Response used by the SSRF lab tests."""

    def __init__(self, status_code=200, content=b"", location=None):
        self.status_code = status_code
        self.content = content
        self.headers = CaseInsensitiveDict()
        if location is not None:
            self.headers["Location"] = location


@override_settings(
    DEBUG=True,
    STATICFILES_STORAGE="django.contrib.staticfiles.storage.StaticFilesStorage",
)
class SsrfLabFetchTests(TestCase):
    """The SSRF lab must still fetch a URL, but only a public one.

    Guards introduction.views.ssrf_lab2 against a regression back to
    requests.get() on an unvalidated, redirect-following request built from
    request.POST (CWE-918).
    """

    PASSWORD = "Str0ng-Passw0rd!"
    PUBLIC_URL = "http://example.com/index.html"
    METADATA_URL = "http://169.254.169.254/latest/meta-data/"

    def setUp(self):
        self.user = User.objects.create_user(
            username="ssrfuser",
            email="ssrfuser@example.com",
            password=self.PASSWORD,
        )
        self.client.force_login(self.user)

    def _post(self, url):
        return self.client.post("/ssrf_lab2", {"url": url})

    def test_still_fetches_a_public_url_and_renders_the_body(self):
        with patch("introduction.utility.socket.getaddrinfo") as getaddrinfo, \
                patch("introduction.views.requests.get") as get:
            getaddrinfo.return_value = OutboundUrlValidationTests._addrinfo(
                "93.184.216.34"
            )
            get.return_value = _FakeResponse(content=b"<h1>public page</h1>")
            r = self._post(self.PUBLIC_URL)
        self.assertEqual(r.status_code, 200)
        self.assertEqual(r.context["response"], "<h1>public page</h1>")
        args, kwargs = get.call_args
        self.assertEqual(args[0], self.PUBLIC_URL)
        self.assertFalse(kwargs["allow_redirects"])
        self.assertTrue(kwargs["timeout"])

    def test_cloud_metadata_endpoint_is_never_requested(self):
        with patch("introduction.views.requests.get") as get:
            r = self._post(self.METADATA_URL)
        get.assert_not_called()
        self.assertEqual(r.status_code, 200)
        self.assertIn("Invalid URL", r.context["error"])
        self.assertIsNone(r.context.get("response"))

    def test_non_web_scheme_is_never_requested(self):
        with patch("introduction.views.requests.get") as get:
            r = self._post("file:///etc/passwd")
        get.assert_not_called()
        self.assertEqual(r.status_code, 200)
        self.assertIn("Invalid URL", r.context["error"])

    def test_public_redirect_is_followed(self):
        with patch("introduction.utility.socket.getaddrinfo") as getaddrinfo, \
                patch("introduction.views.requests.get") as get:
            getaddrinfo.return_value = OutboundUrlValidationTests._addrinfo(
                "93.184.216.34"
            )
            get.side_effect = [
                _FakeResponse(302, location="http://example.org/moved"),
                _FakeResponse(content=b"redirected body"),
            ]
            r = self._post(self.PUBLIC_URL)
        self.assertEqual(r.status_code, 200)
        self.assertEqual(r.context["response"], "redirected body")
        self.assertEqual(get.call_args_list[1][0][0], "http://example.org/moved")

    def test_redirect_into_a_blocked_destination_is_not_followed(self):
        with patch("introduction.utility.socket.getaddrinfo") as getaddrinfo, \
                patch("introduction.views.requests.get") as get:
            getaddrinfo.return_value = OutboundUrlValidationTests._addrinfo(
                "93.184.216.34"
            )
            get.side_effect = [
                _FakeResponse(302, location=self.METADATA_URL),
                _FakeResponse(content=b"metadata leak"),
            ]
            r = self._post(self.PUBLIC_URL)
        self.assertEqual(get.call_count, 1)
        self.assertEqual(r.status_code, 200)
        self.assertIn("Invalid URL", r.context["error"])
        self.assertIsNone(r.context.get("response"))

    def test_redirect_loop_fails_closed(self):
        with patch("introduction.utility.socket.getaddrinfo") as getaddrinfo, \
                patch("introduction.views.requests.get") as get:
            getaddrinfo.return_value = OutboundUrlValidationTests._addrinfo(
                "93.184.216.34"
            )
            get.return_value = _FakeResponse(302, location=self.PUBLIC_URL)
            r = self._post(self.PUBLIC_URL)
        self.assertEqual(r.status_code, 200)
        self.assertEqual(r.context["error"], "Too many redirects")
        self.assertLessEqual(get.call_count, SSRF_MAX_REDIRECTS + 1)

    def test_transport_errors_still_fail_closed(self):
        with patch("introduction.utility.socket.getaddrinfo") as getaddrinfo, \
                patch("introduction.views.requests.get") as get:
            getaddrinfo.return_value = OutboundUrlValidationTests._addrinfo(
                "93.184.216.34"
            )
            get.side_effect = requests.Timeout("too slow")
            r = self._post(self.PUBLIC_URL)
        self.assertEqual(r.status_code, 200)
        self.assertEqual(r.context["error"], "Invalid URL")


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


@override_settings(
    DEBUG=True,
    STATICFILES_STORAGE="django.contrib.staticfiles.storage.StaticFilesStorage",
)
class DeserializationLabTests(TestCase):
    """The deserialization labs must keep working without executing payloads.

    Guards introduction.views.insec_des_lab against a regression back to
    pickle.loads() on the 'token' cookie, and introduction.views.a9_lab
    against a regression back to yaml.load() with the full Loader (CWE-502).
    """

    PASSWORD = "Str0ng-Passw0rd!"
    NON_ADMIN_MESSAGE = "Only Admins can see this page"
    ADMIN_MESSAGE = "Welcome Admin, SECRETKEY:ADMIN123"
    # base64 of a pickle stream building introduction.views.TestUser(admin=1).
    # Nothing unpickles it any more; a pickle regression would grant admin.
    PICKLED_ADMIN_TOKEN = "gAJjaW50cm9kdWN0aW9uLnZpZXdzClRlc3RVc2VyCimBfVUFYWRtaW5LAXNiLg=="
    # A python/object tag only the unsafe loaders honour.
    YAML_PYTHON_TAG = b"!!python/object:introduction.views.TestUser {admin: 1}\n"

    def setUp(self):
        self.user = User.objects.create_user(
            username="desuser",
            email="desuser@example.com",
            password=self.PASSWORD,
        )
        self.client.force_login(self.user)

    @staticmethod
    def _token(payload):
        return base64.b64encode(json.dumps(payload).encode()).decode()

    def test_first_visit_issues_a_json_data_token(self):
        r = self.client.get("/insec_des_lab")
        self.assertEqual(r.status_code, 200)
        cookie = r.cookies["token"].value
        self.assertEqual(json.loads(base64.b64decode(cookie).decode()), {"admin": 0})
        self.assertEqual(r.context["message"], self.NON_ADMIN_MESSAGE)

    def test_issued_token_round_trips_as_non_admin(self):
        self.client.cookies["token"] = encode_user(TestUser())
        r = self.client.get("/insec_des_lab")
        self.assertEqual(r.status_code, 200)
        self.assertEqual(r.context["message"], self.NON_ADMIN_MESSAGE)

    def test_admin_token_still_reveals_the_lab_secret(self):
        self.client.cookies["token"] = self._token({"admin": 1})
        r = self.client.get("/insec_des_lab")
        self.assertEqual(r.status_code, 200)
        self.assertEqual(r.context["message"], self.ADMIN_MESSAGE)

    def test_pickle_payload_is_not_deserialized(self):
        self.client.cookies["token"] = self.PICKLED_ADMIN_TOKEN
        r = self.client.get("/insec_des_lab")
        self.assertEqual(r.status_code, 200)
        self.assertEqual(r.context["message"], self.NON_ADMIN_MESSAGE)

    def test_malformed_tokens_fail_closed(self):
        for value in (
            "not-base64!!",
            base64.b64encode(b"[]").decode(),
            base64.b64encode(b"\xff\xfe not json").decode(),
            self._token({"admin": "1"}),
            self._token({"admin": True}),
        ):
            self.client.cookies["token"] = value
            r = self.client.get("/insec_des_lab")
            self.assertEqual(r.status_code, 200, msg=value)
            self.assertEqual(r.context["message"], self.NON_ADMIN_MESSAGE, msg=value)

    def test_a9_lab_still_converts_plain_yaml(self):
        upload = SimpleUploadedFile(
            "data.yaml",
            b"name: pygoat\nversion: 1\n",
            content_type="application/x-yaml",
        )
        r = self.client.post("/a9_lab", {"file": upload})
        self.assertEqual(r.status_code, 200)
        self.assertEqual(r.context["data"], {"name": "pygoat", "version": 1})

    def test_a9_lab_refuses_python_object_tags(self):
        upload = SimpleUploadedFile(
            "payload.yaml",
            self.YAML_PYTHON_TAG,
            content_type="application/x-yaml",
        )
        r = self.client.post("/a9_lab", {"file": upload})
        self.assertEqual(r.status_code, 200)
        self.assertEqual(r.context["data"], "Error")

    def test_a9_lab_without_a_file_still_asks_for_one(self):
        r = self.client.post("/a9_lab", {})
        self.assertEqual(r.status_code, 200)
        self.assertEqual(r.context["data"], "Please Upload a Yaml file.")
