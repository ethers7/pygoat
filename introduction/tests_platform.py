"""PyGoat platform regression for remedia CI.

Guards auth + named routes + cmd lab still serving.
Does NOT assert command injection still works.

django-heroku sets CompressedManifestStaticFilesStorage. Django tests run with
DEBUG=False, so {% static %} blows up without collectstatic (and collectstatic
fails upstream on a missing font). Gunicorn smoke uses DEBUG=True. Tests force
plain StaticFilesStorage so we gate routes/auth, not WhiteNoise manifests.
"""
import hashlib
from unittest import mock

from django.contrib.auth.models import User
from django.test import Client, TestCase, override_settings
from django.urls import reverse

from .models import CF_user, CSRF_user_tbl
from .utility import hash_password


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

    def test_cmd_lab_runs_lookup_without_shell(self):
        """Lab still runs the lookup, but as an argv list with no shell."""
        self.client.force_login(self.user)
        with mock.patch("introduction.views.subprocess.Popen") as popen:
            popen.return_value.communicate.return_value = (b"1.2.3.4", b"")
            r = self.client.post("/cmd_lab", {"domain": "example.com", "os": "linux"})
        self.assertEqual(r.status_code, 200)
        self.assertContains(r, "1.2.3.4")
        args, kwargs = popen.call_args
        self.assertEqual(args[0], ["dig", "example.com"])
        self.assertFalse(kwargs.get("shell", False))

    def test_cmd_lab_rejects_shell_metacharacters(self):
        """Injection payloads never reach a subprocess call."""
        self.client.force_login(self.user)
        for payload in ("example.com; id", "example.com && id", "example.com | id",
                        "$(id)", "`id`", "-oG/tmp/x"):
            with mock.patch("introduction.views.subprocess.Popen") as popen:
                r = self.client.post("/cmd_lab", {"domain": payload, "os": "linux"})
            self.assertEqual(r.status_code, 200, msg=payload)
            self.assertContains(r, "Invalid domain", msg_prefix=payload)
            popen.assert_not_called()

    def test_cmd_lab2_calculates_without_eval(self):
        """Lab 2 still answers arithmetic, but code payloads are refused."""
        self.client.force_login(self.user)
        r = self.client.post("/cmd_lab2", {"val": "7 * 7"})
        self.assertEqual(r.status_code, 200)
        self.assertContains(r, "49")
        for payload in ("__import__('os').system('id')", "os.system('id')",
                        "open('/etc/passwd').read()", "9 ** 9 ** 9"):
            r = self.client.post("/cmd_lab2", {"val": payload})
            self.assertEqual(r.status_code, 200, msg=payload)
            self.assertContains(r, "Invalid expression", msg_prefix=payload)

    def test_mitre_lab_25_api_calculates_without_eval(self):
        """CWE-94 calculator API returns results and rejects code payloads."""
        r = self.client.post("/mitre/25/lab/api", {"expression": "1 + 1"})
        self.assertEqual(r.status_code, 200)
        self.assertEqual(r.json()["result"], 2)
        for payload in ("__import__('os').system('id')", "os.system('id')",
                        "().__class__.__bases__[0].__subclasses__()"):
            r = self.client.post("/mitre/25/lab/api", {"expression": payload})
            self.assertEqual(r.status_code, 400, msg=payload)
            self.assertIn("Invalid expression", r.json()["error"])

    def test_login_post(self):
        r = self.client.post(
            reverse("login"),
            {"username": "gateuser", "password": self.PASSWORD},
        )
        self.assertEqual(r.status_code, 302)
        self.assertEqual(self.client.get("/").status_code, 200)

    def test_crypto_failure_lab_login_uses_a_salted_password_hash(self):
        """Lab 1 still logs the seeded demo account in, without MD5 storage."""
        lab_password = "p@ssword"
        CF_user.objects.create(
            username="admin",
            password=hash_password(lab_password),
            password2="",
        )
        self.client.force_login(self.user)
        r = self.client.post(reverse("cryptographic_failure_lab"),
                             {"username": "admin", "password": lab_password})
        self.assertEqual(r.status_code, 200)
        self.assertContains(r, "Successfully logged in as admin")

    def test_crypto_failure_lab_login_rejects_wrong_password_and_md5_digest(self):
        lab_password = "p@ssword"
        CF_user.objects.create(
            username="admin",
            password=hash_password(lab_password),
            password2="",
        )
        self.client.force_login(self.user)
        for password in ("not-the-password",
                         hashlib.md5(lab_password.encode()).hexdigest()):
            r = self.client.post(reverse("cryptographic_failure_lab"),
                                 {"username": "admin", "password": password})
            self.assertEqual(r.status_code, 200, msg=password)
            self.assertContains(r, "Login Failed", msg_prefix=password)

    def test_crypto_failure_lab_login_fails_closed_on_a_legacy_md5_row(self):
        """A row still holding a bare MD5 digest is not a usable credential."""
        lab_password = "p@ssword"
        CF_user.objects.create(
            username="legacy",
            password=hashlib.md5(lab_password.encode()).hexdigest(),
            password2="",
        )
        self.client.force_login(self.user)
        r = self.client.post(reverse("cryptographic_failure_lab"),
                             {"username": "legacy", "password": lab_password})
        self.assertEqual(r.status_code, 200)
        self.assertContains(r, "Login Failed")

    def test_csrf_lab_login_verifies_the_stored_password_hash(self):
        """CSRF lab login still works for a hashed account and fails closed."""
        lab_password = "csrf-lab-pass"
        CSRF_user_tbl.objects.create(
            username="jack",
            password=hash_password(lab_password),
            balance=1000,
        )
        self.client.force_login(self.user)
        r = self.client.post("/mitre/9/lab/login",
                             {"username": "jack", "password": lab_password})
        self.assertEqual(r.status_code, 302)
        self.assertIn("/mitre/9/lab/transaction", r["Location"])
        self.assertIn("auth_cookiee", r.cookies)

        for username, password in (("jack", "wrong"),
                                   ("jack", hashlib.md5(lab_password.encode()).hexdigest()),
                                   ("nobody", lab_password)):
            r = self.client.post("/mitre/9/lab/login",
                                 {"username": username, "password": password})
            self.assertEqual(r.status_code, 302, msg=username)
            self.assertIn("/mitre/9/lab/login", r["Location"])

    def test_lab_user_admin_stores_typed_passwords_hashed(self):
        """The seeding path (admin site) never writes a plaintext password."""
        from django.contrib import admin as django_admin

        from .admin import LabUserAdmin

        model_admin = LabUserAdmin(CF_user, django_admin.site)
        obj = CF_user(username="seeded", password="p@ssword", password2="")
        model_admin.save_model(request=None, obj=obj, form=None, change=False)

        stored = CF_user.objects.get(username="seeded").password
        self.assertNotEqual(stored, "p@ssword")
        self.assertTrue(stored.startswith("pbkdf2_sha256$"))

        # Re-saving an already hashed value must not hash it twice.
        obj.password = stored
        model_admin.save_model(request=None, obj=obj, form=None, change=True)
        self.assertEqual(CF_user.objects.get(username="seeded").password, stored)

        self.client.force_login(self.user)
        r = self.client.post(reverse("cryptographic_failure_lab"),
                             {"username": "seeded", "password": "p@ssword"})
        self.assertContains(r, "Successfully logged in as seeded")


@override_settings(
    DEBUG=True,
    STATICFILES_STORAGE="django.contrib.staticfiles.storage.StaticFilesStorage",
)
class CsrfProtectionTests(TestCase):
    """The lab views no longer opt out of CsrfViewMiddleware (CWE-352).

    The default test client does not enforce CSRF, so these use a client with
    enforce_csrf_checks=True: an unsafe request without a token must be
    refused, and the browser flows (form field / X-CSRFToken header) must
    still work.
    """

    PASSWORD = "Str0ng-Passw0rd!"

    def setUp(self):
        self.user = User.objects.create_user(
            username="csrfuser",
            email="csrfuser@example.com",
            password=self.PASSWORD,
        )
        self.client = Client(enforce_csrf_checks=True)
        self.client.force_login(self.user)

    def _token(self, url):
        """Load a page and return the token it handed the browser."""
        response = self.client.get(url)
        self.assertEqual(response.status_code, 200, msg=url)
        self.assertContains(response, 'name="csrfmiddlewaretoken"')
        return self.client.cookies["csrftoken"].value

    def test_post_without_a_token_is_refused(self):
        for url, data in (("/cmd_lab", {"domain": "example.com", "os": "linux"}),
                          ("/cmd_lab2", {"val": "7 * 7"}),
                          ("/ba_lab", {"name": "admin", "pass": "admin"}),
                          ("/broken_access_lab_1", {"name": "jack", "pass": "x"}),
                          ("/broken_access_lab_2", {"name": "jack", "pass": "x"}),
                          ("/injection_sql_lab", {"name": "admin", "pass": "x"}),
                          ("/otp", {"otp": "123"})):
            r = self.client.post(url, data)
            self.assertEqual(r.status_code, 403, msg=url)

    def test_lab_forms_ship_a_token_so_the_post_still_works(self):
        token = self._token("/cmd_lab")
        with mock.patch("introduction.views.subprocess.Popen") as popen:
            popen.return_value.communicate.return_value = (b"1.2.3.4", b"")
            r = self.client.post("/cmd_lab", {"domain": "example.com",
                                              "os": "linux",
                                              "csrfmiddlewaretoken": token})
        self.assertEqual(r.status_code, 200)
        self.assertContains(r, "1.2.3.4")

    def test_ajax_api_accepts_the_x_csrftoken_header(self):
        r = self.client.post("/mitre/25/lab/api", {"expression": "1 + 1"})
        self.assertEqual(r.status_code, 403)

        token = self._token("/mitre/25/lab")
        r = self.client.post("/mitre/25/lab/api", {"expression": "1 + 1"},
                             HTTP_X_CSRFTOKEN=token)
        self.assertEqual(r.status_code, 200)
        self.assertEqual(r.json()["result"], 2)

    def test_xxe_parse_accepts_the_x_csrftoken_header(self):
        body = "<?xml version='1.0'?><comm><text>hello</text></comm>"
        r = self.client.post(reverse("xxe_parse"), data=body, content_type="text/xml")
        self.assertEqual(r.status_code, 403)

        token = self._token("/xxe_lab")
        r = self.client.post(reverse("xxe_parse"), data=body,
                             content_type="text/xml", HTTP_X_CSRFTOKEN=token)
        self.assertEqual(r.status_code, 200)
