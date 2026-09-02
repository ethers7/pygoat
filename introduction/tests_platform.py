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

from .utility import safe_fetch_url, safe_host_target


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

    def test_login_post(self):
        r = self.client.post(
            reverse("login"),
            {"username": "gateuser", "password": self.PASSWORD},
        )
        self.assertEqual(r.status_code, 302)
        self.assertEqual(self.client.get("/").status_code, 200)
