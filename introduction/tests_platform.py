"""PyGoat platform regression for remedia CI.

Guards auth + named routes + cmd lab still serving.
Does NOT assert command injection still works.

django-heroku sets CompressedManifestStaticFilesStorage. Django tests run with
DEBUG=False, so {% static %} blows up without collectstatic (and collectstatic
fails upstream on a missing font). Gunicorn smoke uses DEBUG=True. Tests force
plain StaticFilesStorage so we gate routes/auth, not WhiteNoise manifests.
"""
from unittest.mock import patch

from django.contrib.auth.models import User
from django.test import TestCase, override_settings
from django.urls import reverse

from .models import (CF_user, CSRF_user_tbl, comments, hash_lab_password,
                     verify_lab_password)
from .utility import (UnsafeExpressionError, safe_arithmetic_eval,
                      safe_fetch_url, safe_host_target)


class _StubResponse:
    """Minimal stand-in for requests.Response used by the SSRF lab tests."""

    def __init__(self, content=b"", headers=None, is_redirect=False):
        self.content = content
        self.headers = headers or {}
        self.is_redirect = is_redirect


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
