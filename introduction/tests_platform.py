"""PyGoat platform regression for remedia CI.

Guards auth + named routes + cmd lab still serving.
Does NOT assert command injection still works.

django-heroku sets CompressedManifestStaticFilesStorage. Django tests run with
DEBUG=False, so {% static %} blows up without collectstatic (and collectstatic
fails upstream on a missing font). Gunicorn smoke uses DEBUG=True. Tests force
plain StaticFilesStorage so we gate routes/auth, not WhiteNoise manifests.
"""
import inspect
import re
from hashlib import md5

import jwt
from django.conf import settings
from django.contrib.auth.models import User
from django.test import TestCase, override_settings
from django.urls import reverse

from .models import CSRF_user_tbl
from .utility import safe_lookup_target


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

    def test_login_post(self):
        r = self.client.post(
            reverse("login"),
            {"username": "gateuser", "password": self.PASSWORD},
        )
        self.assertEqual(r.status_code, 302)
        self.assertEqual(self.client.get("/").status_code, 200)


class CommandInjectionRegressionTests(TestCase):
    """CWE-78: the lookup labs must never hand user input to a shell.

    These assert the argv + allowlist control, not that injection works.
    """

    INJECTION_PAYLOADS = (
        "example.com; id",
        "example.com && id",
        "example.com | id",
        "$(id)",
        "`id`",
        "example.com\nid",
        "-oN/tmp/pwn",
    )

    def test_allowlist_rejects_shell_metacharacters(self):
        for payload in self.INJECTION_PAYLOADS:
            self.assertIsNone(safe_lookup_target(payload), msg=payload)

    def test_allowlist_rejects_empty_and_non_string(self):
        for value in ("", "   ", None, 1234, ["example.com"]):
            self.assertIsNone(safe_lookup_target(value), msg=repr(value))

    def test_allowlist_accepts_plain_hosts_and_ips(self):
        self.assertEqual(safe_lookup_target(" example.com "), "example.com")
        self.assertEqual(safe_lookup_target("sub.example.co.uk."), "sub.example.co.uk")
        self.assertEqual(safe_lookup_target("127.0.0.1"), "127.0.0.1")
        self.assertEqual(safe_lookup_target("::1"), "::1")

    @override_settings(
        DEBUG=True,
        STATICFILES_STORAGE="django.contrib.staticfiles.storage.StaticFilesStorage",
    )
    def test_cmd_lab_rejects_injection_without_executing(self):
        user = User.objects.create_user(
            username="cmduser",
            email="cmduser@example.com",
            password="Str0ng-Passw0rd!",
        )
        self.client.force_login(user)
        for payload in self.INJECTION_PAYLOADS:
            r = self.client.post("/cmd_lab", {"domain": payload, "os": "linux"})
            self.assertEqual(r.status_code, 200, msg=payload)
            self.assertContains(r, "Invalid domain", msg_prefix=payload)

    def test_mitre_lab_17_api_rejects_injection_without_executing(self):
        for payload in self.INJECTION_PAYLOADS:
            r = self.client.post("/mitre/17/lab/api", {"ip": payload})
            self.assertEqual(r.status_code, 400, msg=payload)
            self.assertEqual(r.json()["ports"], [], msg=payload)

    def test_command_out_refuses_command_strings(self):
        from .mitre import command_out

        with self.assertRaises(TypeError):
            command_out("nmap 127.0.0.1; id")


@override_settings(
    DEBUG=True,
    STATICFILES_STORAGE="django.contrib.staticfiles.storage.StaticFilesStorage",
    CSRF_LAB_JWT_KEY="unit-test-csrf-lab-signing-key",
)
class CsrfLabJwtKeyTests(TestCase):
    """CWE-522: the CSRF lab JWT must use a runtime-supplied signing key.

    Gates that the lab still issues and accepts its cookie, and that the key
    comes from settings rather than a literal in introduction/mitre.py.
    """

    PASSWORD = "Str0ng-Passw0rd!"
    LAB_USERNAME = "csrflabuser"

    def setUp(self):
        self.user = User.objects.create_user(
            username="jwtgateuser",
            email="jwtgateuser@example.com",
            password=self.PASSWORD,
        )
        self.lab_user = CSRF_user_tbl.objects.create(
            username=self.LAB_USERNAME,
            password=md5(self.PASSWORD.encode()).hexdigest(),
            balance=100,
        )
        self.client.force_login(self.user)

    def _login_cookie(self):
        r = self.client.post(
            reverse("csrf_lab_login"),
            {"username": self.LAB_USERNAME, "password": self.PASSWORD},
        )
        self.assertEqual(r.status_code, 302)
        self.assertIn("auth_cookiee", r.cookies)
        return r.cookies["auth_cookiee"].value

    def test_no_signing_key_literal_in_mitre_module(self):
        from . import mitre

        source = inspect.getsource(mitre)
        literal_key = re.search(
            r"jwt\.(?:encode|decode)\(\s*[\w\[\]'\"]+\s*,\s*['\"]", source
        )
        self.assertIsNone(
            literal_key,
            msg="jwt.encode/decode must take the key from settings, not a literal",
        )

    def test_lab_cookie_is_signed_with_configured_key(self):
        cookie = self._login_cookie()
        payload = jwt.decode(
            cookie, settings.CSRF_LAB_JWT_KEY, algorithms=["HS256"]
        )
        self.assertEqual(payload["username"], self.LAB_USERNAME)

    def test_lab_cookie_rejects_other_keys(self):
        cookie = self._login_cookie()
        with self.assertRaises(jwt.InvalidSignatureError):
            jwt.decode(cookie, "some-other-key", algorithms=["HS256"])

    def test_dashboard_accepts_cookie_from_configured_key(self):
        self.client.cookies["auth_cookiee"] = self._login_cookie()
        r = self.client.get("/mitre/9/lab/transaction")
        self.assertEqual(r.status_code, 200)

    def test_dashboard_rejects_cookie_signed_with_foreign_key(self):
        forged = jwt.encode(
            {"username": self.LAB_USERNAME}, "some-other-key", algorithm="HS256"
        )
        self.client.cookies["auth_cookiee"] = forged
        r = self.client.get("/mitre/9/lab/transaction")
        self.assertEqual(r.status_code, 302)
        self.assertIn("/mitre/9/lab/login", r["Location"])
