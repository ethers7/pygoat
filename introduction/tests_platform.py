"""PyGoat platform regression for remedia CI.

Guards auth + named routes + cmd lab still serving.
Does NOT assert command injection still works.

django-heroku sets CompressedManifestStaticFilesStorage. Django tests run with
DEBUG=False, so {% static %} blows up without collectstatic (and collectstatic
fails upstream on a missing font). Gunicorn smoke uses DEBUG=True. Tests force
plain StaticFilesStorage so we gate routes/auth, not WhiteNoise manifests.
"""
from pathlib import Path
from unittest.mock import patch

from django.contrib.auth.models import User
from django.test import Client, TestCase, override_settings
from django.urls import reverse

from .models import (Blogs, CF_user, CSRF_user_tbl, comments,
                     hash_lab_password, verify_lab_password)
from .playground.A6.utility import MAX_MODULES as A6_MAX_MODULES
from .playground.A6.utility import MAX_RESPONSE_BYTES as A6_MAX_RESPONSE_BYTES
from .playground.A6.utility import check_vuln
from .utility import (FETCH_TIMEOUT, MAX_FETCH_RESPONSE_BYTES,
                      MAX_STORED_TEXT_LENGTH, InvalidStoredTextError,
                      ResponseTooLargeError, UnsafeExpressionError,
                      read_bounded_response, safe_arithmetic_eval,
                      safe_fetch_url, safe_host_target, safe_python_source,
                      safe_stored_text)

APP_DIR = Path(__file__).resolve().parent


class _StubResponse:
    """Minimal stand-in for requests.Response used by the outbound fetch tests."""

    def __init__(self, content=b"", headers=None, is_redirect=False):
        self.content = content
        self.headers = headers or {}
        self.is_redirect = is_redirect
        self.closed = False

    def iter_content(self, chunk_size=1):
        for start in range(0, len(self.content), max(chunk_size, 1)):
            yield self.content[start:start + max(chunk_size, 1)]

    def raise_for_status(self):
        return None

    def close(self):
        self.closed = True


@override_settings(
    DEBUG=True,
    STATICFILES_STORAGE="django.contrib.staticfiles.storage.StaticFilesStorage",
)
class PlatformRegressionTests(TestCase):
    PASSWORD = "Str0ng-Passw0rd!"

    def setUp(self):
        self.user = User.objects.create_user(
            username="gateuser",
            email="gateuser@example.com",
            password=self.PASSWORD,
        )

    def test_named_routes_resolve(self):
        for name in (
            "homepage",
            "Command Injection",
            "Command Injection Lab",
            "Registration",
            "login",
        ):
            reverse(name)

    def test_login_page_ok(self):
        self.assertEqual(self.client.get(reverse("login")).status_code, 200)

    def test_register_page_ok(self):
        self.assertEqual(self.client.get(reverse("Registration")).status_code, 200)

    def test_home_anon_redirects_login(self):
        r = self.client.get("/")
        self.assertEqual(r.status_code, 302)
        self.assertIn("/login", r["Location"])

    def test_cmd_lab_anon_redirects_login(self):
        r = self.client.get("/cmd_lab")
        self.assertEqual(r.status_code, 302)
        self.assertIn("/login", r["Location"])

    def test_home_authed_ok(self):
        self.client.force_login(self.user)
        self.assertEqual(self.client.get("/").status_code, 200)

    def test_cmd_pages_authed_ok(self):
        self.client.force_login(self.user)
        self.assertEqual(self.client.get("/cmd").status_code, 200)
        self.assertEqual(self.client.get("/cmd_lab").status_code, 200)

    def test_other_lesson_pages_still_route(self):
        self.client.force_login(self.user)
        for name in ("xss", "sql"):
            r = self.client.get(reverse(name))
            self.assertEqual(r.status_code, 200, msg=name)

    def test_register_then_home(self):
        r = self.client.post(
            reverse("Registration"),
            {
                "username": "newgate",
                "email": "newgate@example.com",
                "password1": self.PASSWORD,
                "password2": self.PASSWORD,
            },
        )
        self.assertEqual(r.status_code, 302)
        self.assertTrue(User.objects.filter(username="newgate").exists())
        # views.register login() often drops the session (two AUTHENTICATION_BACKENDS).
        # Gate: account was created and can sign in.
        self.assertTrue(
            self.client.login(username="newgate", password=self.PASSWORD)
        )
        self.assertEqual(self.client.get("/").status_code, 200)

    def test_cmd_lab_rejects_shell_metacharacters(self):
        """CWE-78 regression: injected payloads never reach a shell."""
        self.client.force_login(self.user)
        for payload in (
            "example.com; id",
            "example.com && whoami",
            "example.com | cat /etc/passwd",
            "$(id).example.com",
            "`id`",
        ):
            r = self.client.post("/cmd_lab", {"domain": payload, "os": "lin"})
            self.assertEqual(r.status_code, 200, msg=payload)
            self.assertContains(r, "Invalid domain name", msg_prefix=payload)

    def test_safe_host_target_accepts_plain_hosts(self):
        self.assertEqual(safe_host_target("example.com"), "example.com")
        self.assertEqual(safe_host_target(" 127.0.0.1 "), "127.0.0.1")
        self.assertEqual(
            safe_host_target("10.0.0.0/24", allow_networks=True), "10.0.0.0/24"
        )

    def test_safe_host_target_rejects_injection(self):
        for payload in (
            None,
            "",
            "   ",
            "example.com; id",
            "example.com\nid",
            "example.com/../etc",
            "10.0.0.0/24",
        ):
            self.assertIsNone(safe_host_target(payload), msg=repr(payload))

    @patch("introduction.utility.socket.getaddrinfo")
    def test_safe_fetch_url_accepts_allowlisted_public_host(self, getaddrinfo):
        getaddrinfo.return_value = [(2, 1, 6, "", ("93.184.216.34", 80))]
        self.assertEqual(
            safe_fetch_url(" http://example.com/blog?id=1#frag "),
            "http://example.com/blog?id=1",
        )

    @patch("introduction.utility.socket.getaddrinfo")
    def test_safe_fetch_url_rejects_host_resolving_internally(self, getaddrinfo):
        """CWE-918: resolve-then-validate, an allowed name may not point inside."""
        for address in ("127.0.0.1", "169.254.169.254", "10.1.2.3", "::1"):
            getaddrinfo.return_value = [(2, 1, 6, "", (address, 80))]
            self.assertIsNone(
                safe_fetch_url("http://example.com/"), msg=address
            )

    def test_safe_fetch_url_rejects_non_allowlisted_targets(self):
        for payload in (
            None,
            "",
            "   ",
            "file:///etc/passwd",
            "gopher://example.com/",
            "http://127.0.0.1:8000/ssrf_target",
            "http://localhost/ssrf_target",
            "http://169.254.169.254/latest/meta-data/",
            "http://[::1]/ssrf_target",
            "http://evil.example.net/",
            "http://example.com.evil.net/",
            "http://example.com:8000/",
            "http://user:pass@example.com/",
        ):
            self.assertIsNone(safe_fetch_url(payload), msg=repr(payload))

    @patch("introduction.views.requests.get")
    def test_ssrf_lab2_blocks_internal_targets(self, requests_get):
        """CWE-918 regression: internal destinations never reach requests."""
        self.client.force_login(self.user)
        for payload in (
            "http://127.0.0.1:8000/ssrf_target",
            "http://169.254.169.254/latest/meta-data/",
            "http://10.0.0.5/",
            "file:///etc/passwd",
            "http://evil.example.net/",
        ):
            r = self.client.post("/ssrf_lab2", {"url": payload})
            self.assertEqual(r.status_code, 200, msg=payload)
            self.assertContains(r, "not allowed", msg_prefix=payload)
        requests_get.assert_not_called()

    @patch("introduction.views.requests.get")
    @patch("introduction.utility.socket.getaddrinfo")
    def test_ssrf_lab2_fetches_allowlisted_url(self, getaddrinfo, requests_get):
        """The lab still fetches and displays an allowed destination."""
        getaddrinfo.return_value = [(2, 1, 6, "", ("93.184.216.34", 80))]
        requests_get.return_value = _StubResponse(content=b"allowed blog body")
        self.client.force_login(self.user)
        r = self.client.post("/ssrf_lab2", {"url": "http://example.com/blog"})
        self.assertEqual(r.status_code, 200)
        self.assertContains(r, "allowed blog body")
        args, kwargs = requests_get.call_args
        self.assertEqual(args[0], "http://example.com/blog")
        self.assertFalse(kwargs["allow_redirects"])
        self.assertTrue(kwargs["timeout"])
        # CWE-400: the body is streamed so it can be capped while it arrives.
        self.assertTrue(kwargs["stream"])

    @patch("introduction.views.requests.get")
    @patch("introduction.utility.socket.getaddrinfo")
    def test_ssrf_lab2_refuses_oversized_response(self, getaddrinfo, requests_get):
        """CWE-400 regression: an endless remote body is capped, not buffered."""
        getaddrinfo.return_value = [(2, 1, 6, "", ("93.184.216.34", 80))]
        requests_get.return_value = _StubResponse(
            content=b"x" * (MAX_FETCH_RESPONSE_BYTES + 1)
        )
        self.client.force_login(self.user)
        r = self.client.post("/ssrf_lab2", {"url": "http://example.com/blog"})
        self.assertEqual(r.status_code, 200)
        self.assertContains(r, "more data than this lab will display")

    def test_read_bounded_response_caps_body(self):
        """CWE-400 regression: read_bounded_response never buffers past the cap."""
        small = _StubResponse(content=b"a" * 32)
        self.assertEqual(read_bounded_response(small), b"a" * 32)
        self.assertTrue(small.closed)

        oversized = _StubResponse(content=b"a" * (MAX_FETCH_RESPONSE_BYTES + 1))
        with self.assertRaises(ResponseTooLargeError):
            read_bounded_response(oversized)
        self.assertTrue(oversized.closed)

    def test_fetch_timeout_is_configured(self):
        """Every outbound fetch has a connect and a read timeout."""
        connect_timeout, read_timeout = FETCH_TIMEOUT
        self.assertGreater(connect_timeout, 0)
        self.assertGreater(read_timeout, 0)

    @patch("introduction.playground.A6.utility.requests.get")
    def test_a6_check_vuln_bounds_pypi_lookups(self, requests_get):
        """CWE-400 regression: the A6 lab lookups are bounded and still work."""
        requests_get.return_value = _StubResponse(
            content=b'{"vulnerabilities": [{"id": "PYSEC-0000"}]}'
        )
        self.assertEqual(
            check_vuln(["Pillow==8.0.0"]), [[{"id": "PYSEC-0000"}]]
        )
        _, kwargs = requests_get.call_args
        self.assertTrue(kwargs["timeout"])
        self.assertTrue(kwargs["stream"])

        requests_get.return_value = _StubResponse(
            content=b"x" * (A6_MAX_RESPONSE_BYTES + 1)
        )
        with self.assertRaises(ValueError):
            check_vuln(["Pillow==8.0.0"])

        requests_get.reset_mock()
        too_many = ["Pillow==8.0.0"] * (A6_MAX_MODULES + 1)
        with self.assertRaises(ValueError):
            check_vuln(too_many)
        requests_get.assert_not_called()

    @patch("introduction.views.requests.get")
    @patch("introduction.utility.socket.getaddrinfo")
    def test_ssrf_lab2_blocks_redirect_to_internal_target(self, getaddrinfo, requests_get):
        getaddrinfo.return_value = [(2, 1, 6, "", ("93.184.216.34", 80))]
        requests_get.return_value = _StubResponse(
            headers={"Location": "http://169.254.169.254/latest/meta-data/"},
            is_redirect=True,
        )
        self.client.force_login(self.user)
        r = self.client.post("/ssrf_lab2", {"url": "http://example.com/blog"})
        self.assertEqual(r.status_code, 200)
        self.assertContains(r, "Blocked a redirect")
        self.assertEqual(requests_get.call_count, 1)

    def test_xxe_parse_stores_well_formed_comment(self):
        """The XXE lab still parses plain XML and stores the comment."""
        comments.objects.create(id=1, name="System", comment="old")
        r = self.client.post(
            "/xxe_parse",
            data="<?xml version='1.0'?><comm><text>hello world</text></comm>",
            content_type="text/xml",
        )
        self.assertEqual(r.status_code, 200)
        self.assertEqual(comments.objects.get(id=1).comment, "hello world")

    def test_xxe_parse_rejects_external_entity_payload(self):
        """CWE-611 regression: DTD/entity payloads are refused, not expanded."""
        comments.objects.create(id=1, name="System", comment="old")
        payloads = (
            '<?xml version="1.0"?>'
            '<!DOCTYPE comm [<!ELEMENT comm (#PCDATA)>'
            '<!ENTITY xxe SYSTEM "file:///etc/passwd">]>'
            "<comm><text>&xxe;</text></comm>",
            '<?xml version="1.0"?>'
            '<!DOCTYPE comm [<!ENTITY a "expanded">]>'
            "<comm><text>&a;</text></comm>",
        )
        for payload in payloads:
            r = self.client.post(
                "/xxe_parse", data=payload, content_type="text/xml"
            )
            self.assertEqual(r.status_code, 400, msg=payload)
            self.assertEqual(comments.objects.get(id=1).comment, "old")

    def test_xxe_parse_rejects_malformed_xml(self):
        comments.objects.create(id=1, name="System", comment="old")
        r = self.client.post(
            "/xxe_parse", data="<comm><text>oops", content_type="text/xml"
        )
        self.assertEqual(r.status_code, 400)
        self.assertEqual(comments.objects.get(id=1).comment, "old")

    def test_safe_arithmetic_eval_computes_expressions(self):
        """The calculator labs still evaluate legitimate arithmetic."""
        self.assertEqual(safe_arithmetic_eval("7*7"), 49)
        self.assertEqual(safe_arithmetic_eval(" (2 + 3) * -4 "), -20)
        self.assertEqual(safe_arithmetic_eval("7/2"), 3.5)
        self.assertEqual(safe_arithmetic_eval("2**10"), 1024)
        self.assertEqual(safe_arithmetic_eval("7//2 + 7%2"), 4)

    def test_safe_arithmetic_eval_rejects_code_execution(self):
        """CWE-95 regression: no name, call or import ever gets interpreted."""
        for payload in (
            None,
            "",
            "   ",
            "__import__('os').system('id')",
            "print(1)",
            "os.popen('id').read()",
            "().__class__.__bases__[0].__subclasses__()",
            "[x for x in (1, 2)]",
            "lambda: 1",
            "'a'*3",
            "9**9**9",
            "1 if True else 2",
            "1 == 1",
            "x + 1",
            "1;2",
        ):
            with self.assertRaises(UnsafeExpressionError, msg=repr(payload)):
                safe_arithmetic_eval(payload)

    def test_cmd_lab2_evaluates_arithmetic(self):
        self.client.force_login(self.user)
        r = self.client.post("/cmd_lab2", {"val": "7*7"})
        self.assertEqual(r.status_code, 200)
        self.assertContains(r, "49")

    def test_cmd_lab2_rejects_code_payloads(self):
        """CWE-95 regression: injected Python is refused, not executed."""
        self.client.force_login(self.user)
        for payload in (
            "__import__('os').system('id')",
            "open('/etc/passwd').read()",
            "().__class__.__bases__",
        ):
            r = self.client.post("/cmd_lab2", {"val": payload})
            self.assertEqual(r.status_code, 200, msg=payload)
            self.assertContains(r, "Invalid expression", msg_prefix=payload)

    def test_mitre_lab_25_api_evaluates_arithmetic(self):
        r = self.client.post("/mitre/25/lab/api", {"expression": "(2+3)*4"})
        self.assertEqual(r.status_code, 200)
        self.assertEqual(r.json()["result"], 20)

    def test_mitre_lab_25_api_rejects_code_payloads(self):
        """CWE-95 regression: the calculator API never executes Python."""
        for payload in (
            "__import__('os').system('id')",
            "eval('1+1')",
            "globals()",
        ):
            r = self.client.post("/mitre/25/lab/api", {"expression": payload})
            self.assertEqual(r.status_code, 400, msg=payload)
            self.assertIn("Invalid expression", r.json()["result"])

    def _csrf_client(self, login=True):
        """A client that enforces CSRF checks the way a real browser POST does."""
        client = Client(enforce_csrf_checks=True)
        if login:
            client.force_login(self.user)
        return client

    def _csrf_token(self, client, path="/cmd_lab"):
        """Load a page so Django sets the csrftoken cookie, then return it."""
        page = client.get(path)
        self.assertEqual(page.status_code, 200, msg=path)
        self.assertContains(page, "csrfmiddlewaretoken")
        return client.cookies["csrftoken"].value

    def test_lab_post_endpoints_require_csrf_token(self):
        """CWE-352 regression: no lab view is exempt from CsrfViewMiddleware."""
        client = self._csrf_client()
        for path, data in (
            ("/cmd_lab", {"domain": "example.com", "os": "lin"}),
            ("/cmd_lab2", {"val": "7*7"}),
            ("/ba_lab", {"name": "jack", "pass": "jacktheripper"}),
            ("/broken_access_lab_1", {"name": "jack", "pass": "jacktheripper"}),
            ("/broken_access_lab_2", {"name": "jack", "pass": "jacktheripper"}),
            ("/injection_sql_lab", {"name": "admin", "pass": "admin"}),
            ("/a9_lab", {}),
            ("/a9_lab2", {}),
            ("/otp", {"otp": "123"}),
            ("/mitre/25/lab/api", {"expression": "1+1"}),
            ("/mitre/17/lab/api", {"ip": "127.0.0.1"}),
            ("/2021/discussion/A7/api", {"code": "x"}),
            ("/2021/discussion/A6/api2", {"code": "x"}),
            ("/api/ssrf", {"python_code": "x", "html_code": "x"}),
            ("/2021/discussion/A9/target", {"username": "admin", "password": "admin"}),
        ):
            r = client.post(path, data)
            self.assertEqual(r.status_code, 403, msg=path)

    def test_xxe_parse_requires_csrf_token(self):
        """CWE-352 regression: the XML endpoint is CSRF protected too."""
        comments.objects.create(id=1, name="System", comment="old")
        r = self._csrf_client(login=False).post(
            "/xxe_parse",
            data="<comm><text>forged</text></comm>",
            content_type="text/xml",
        )
        self.assertEqual(r.status_code, 403)
        self.assertEqual(comments.objects.get(id=1).comment, "old")

    def test_cmd_lab_form_post_works_with_csrf_token(self):
        """The lab form still submits once the rendered token is sent back."""
        client = self._csrf_client()
        token = self._csrf_token(client)
        r = client.post(
            "/cmd_lab",
            {
                "domain": "example.com; id",
                "os": "lin",
                "csrfmiddlewaretoken": token,
            },
        )
        self.assertEqual(r.status_code, 200)
        self.assertContains(r, "Invalid domain name")

    def test_mitre_lab_25_api_works_with_csrf_header(self):
        """AJAX callers still reach the API by sending the X-CSRFToken header."""
        client = self._csrf_client()
        token = self._csrf_token(client)
        r = client.post(
            "/mitre/25/lab/api",
            {"expression": "(2+3)*4"},
            HTTP_X_CSRFTOKEN=token,
        )
        self.assertEqual(r.status_code, 200)
        self.assertEqual(r.json()["result"], 20)

    def test_xxe_parse_works_with_csrf_header(self):
        """The XML AJAX caller still stores comments when it sends the token."""
        comments.objects.create(id=1, name="System", comment="old")
        client = self._csrf_client()
        token = self._csrf_token(client)
        r = client.post(
            "/xxe_parse",
            data="<?xml version='1.0'?><comm><text>hello world</text></comm>",
            content_type="text/xml",
            HTTP_X_CSRFTOKEN=token,
        )
        self.assertEqual(r.status_code, 200)
        self.assertEqual(comments.objects.get(id=1).comment, "hello world")

    def test_login_post(self):
        r = self.client.post(
            reverse("login"),
            {"username": "gateuser", "password": self.PASSWORD},
        )
        self.assertEqual(r.status_code, 302)
        self.assertEqual(self.client.get("/").status_code, 200)

    def test_lab_credentials_are_stored_as_pbkdf2(self):
        """CWE-327 regression: lab seeding never persists MD5/plaintext."""
        cf = CF_user.objects.create(username="cf", password="labpass", password2="x")
        csrf = CSRF_user_tbl.objects.create(username="cu", password="labpass", balance=10)
        for row in (cf, csrf):
            row.refresh_from_db()
            self.assertTrue(row.password.startswith("pbkdf2_sha256$"), msg=row.password)
            self.assertNotEqual(row.password, "labpass")
            self.assertTrue(verify_lab_password("labpass", row.password))
            self.assertFalse(verify_lab_password("wrong", row.password))

    def test_hash_lab_password_is_idempotent(self):
        """Re-saving a row (balance transfer) must not re-hash the hash."""
        csrf = CSRF_user_tbl.objects.create(username="cu2", password="labpass")
        stored = csrf.password
        csrf.balance = 50
        csrf.save()
        csrf.refresh_from_db()
        self.assertEqual(csrf.password, stored)
        self.assertTrue(verify_lab_password("labpass", csrf.password))
        self.assertEqual(hash_lab_password(stored), stored)

    def test_verify_lab_password_rejects_legacy_md5_digest(self):
        """Rows still holding a bare MD5 digest fail closed, they do not crash."""
        legacy = "0" * 32  # shape of a bare MD5 hex digest, no configured hasher
        self.assertFalse(verify_lab_password("labpass", legacy))
        self.assertFalse(verify_lab_password("", legacy))
        self.assertFalse(verify_lab_password("labpass", ""))

    def test_crypto_failure_lab_login(self):
        """The lab still authenticates a correctly seeded user, and only that user."""
        CF_user.objects.create(username="cfuser", password="labpass", password2="x")
        self.client.force_login(self.user)
        ok = self.client.post(
            reverse("cryptographic_failure_lab"),
            {"username": "cfuser", "password": "labpass"},
        )
        self.assertEqual(ok.status_code, 200)
        self.assertContains(ok, "Successfully logged in as cfuser")
        bad = self.client.post(
            reverse("cryptographic_failure_lab"),
            {"username": "cfuser", "password": "wrong"},
        )
        self.assertEqual(bad.status_code, 200)
        self.assertContains(bad, "Login Failed")

    def test_safe_stored_text_normalises_valid_text(self):
        """Stored text keeps its content, with normalised line endings."""
        self.assertEqual(safe_stored_text(" hello\r\nworld "), "hello\nworld")
        self.assertEqual(safe_stored_text("a\tb"), "a\tb")

    def test_safe_stored_text_rejects_unusable_values(self):
        """CWE-915 regression: unchecked request values never reach a store."""
        for payload in (
            None,
            42,
            b"bytes",
            "",
            "   ",
            "null\x00byte",
            "escape\x1b[31m",
            "bell\x07",
            "x" * (MAX_STORED_TEXT_LENGTH + 1),
        ):
            with self.assertRaises(InvalidStoredTextError, msg=repr(payload)):
                safe_stored_text(payload)

    def test_safe_python_source_accepts_a_lab_module(self):
        self.assertEqual(
            safe_python_source("def log(msg):\r\n    return msg\r\n"),
            "def log(msg):\n    return msg",
        )

    def test_safe_python_source_rejects_unparsable_payloads(self):
        """Only syntactically valid Python may replace a module on disk."""
        for payload in (
            None,
            "",
            "   ",
            "def broken(:",
            "class Bad",
            "print('unclosed",
            "def f():\npass",
            "ok = 1\x00",
        ):
            with self.assertRaises(InvalidStoredTextError, msg=repr(payload)):
                safe_python_source(payload)

    def test_a9_code_checker_rejects_unvalidated_source(self):
        """CWE-915 regression: the A9 lab modules are not overwritten."""
        main_path = APP_DIR / "playground" / "A9" / "main.py"
        api_path = APP_DIR / "playground" / "A9" / "api.py"
        before = (main_path.read_text(), api_path.read_text())
        for data in (
            {},
            {"log_code": "", "api_code": ""},
            {"log_code": "def broken(:", "api_code": "x = 1"},
            {"log_code": "x = 1", "api_code": "class Bad(:"},
            {"log_code": "x = 1", "api_code": "y = 2\x1b[31m"},
            {"log_code": "x = 1", "api_code": "y = 2" + "#" * 30000},
        ):
            r = self.client.post("/2021/discussion/A9/api", data)
            self.assertEqual(r.status_code, 400, msg=repr(data))
            self.assertIn("code", r.json()["message"])
        self.assertEqual((main_path.read_text(), api_path.read_text()), before)

    def test_a6_code_checker_rejects_unvalidated_source(self):
        """CWE-915 regression: the A6 lab module is not overwritten."""
        utility_path = APP_DIR / "playground" / "A6" / "utility.py"
        before = utility_path.read_text()
        for data in (
            {},
            {"code": ""},
            {"code": "   "},
            {"code": "def broken(:"},
            {"code": "x = 1\x1b[31m"},
        ):
            r = self.client.post("/2021/discussion/A6/api2", data)
            self.assertEqual(r.status_code, 400, msg=repr(data))
            self.assertIn("code", r.json()["message"])
        self.assertEqual(utility_path.read_text(), before)

    def _ssti_blogs_dir(self):
        """The lab writes blog templates here; keep the tree clean afterwards."""
        blogs_dir = APP_DIR / "templates" / "Lab_2021" / "A3_Injection" / "Blogs"
        existing = {path.name for path in blogs_dir.iterdir()}

        def remove_blogs_written_by_this_test():
            for path in blogs_dir.iterdir():
                if path.name not in existing:
                    path.unlink()

        self.addCleanup(remove_blogs_written_by_this_test)
        return blogs_dir

    def test_ssti_lab_rejects_unvalidated_blog_body(self):
        """CWE-915 regression: no row and no template file for bad input."""
        self.client.force_login(self.user)
        blogs_dir = self._ssti_blogs_dir()
        before = sorted(path.name for path in blogs_dir.iterdir())
        for data in (
            {},
            {"blog": ""},
            {"blog": "   "},
            {"blog": "post\x1b[31m"},
            {"blog": "x" * (MAX_STORED_TEXT_LENGTH + 1)},
        ):
            r = self.client.post(reverse("SSTI Lab"), data)
            self.assertEqual(r.status_code, 200, msg=repr(data))
            self.assertContains(r, "alert-danger", msg_prefix=repr(data))
        self.assertEqual(Blogs.objects.count(), 0)
        self.assertEqual(sorted(path.name for path in blogs_dir.iterdir()), before)

    def test_ssti_lab_still_stores_a_valid_blog(self):
        """A valid submission is still persisted and redirects to the blog."""
        self.client.force_login(self.user)
        blogs_dir = self._ssti_blogs_dir()
        r = self.client.post(reverse("SSTI Lab"), {"blog": "my safe blog body"})
        self.assertEqual(r.status_code, 302)
        blog = Blogs.objects.get(author=self.user)
        path = blogs_dir / f"{blog.blog_id}.html"
        self.assertIn("blog/" + blog.blog_id, r["Location"])
        self.assertIn("my safe blog body", path.read_text())

    def test_csrf_lab_login(self):
        """The CSRF lab still issues its JWT cookie for valid credentials only."""
        CSRF_user_tbl.objects.create(username="csrfuser", password="labpass", balance=100)
        self.client.force_login(self.user)
        ok = self.client.post(
            reverse("csrf_lab_login"),
            {"username": "csrfuser", "password": "labpass"},
        )
        self.assertEqual(ok.status_code, 302)
        self.assertIn("auth_cookiee", ok.cookies)
        bad = self.client.post(
            reverse("csrf_lab_login"),
            {"username": "csrfuser", "password": "wrong"},
        )
        self.assertEqual(bad.status_code, 302)
        self.assertNotIn("auth_cookiee", bad.cookies)
