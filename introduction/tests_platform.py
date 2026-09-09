"""PyGoat platform regression for remedia CI.

Guards auth + named routes + cmd lab still serving.
Does NOT assert command injection still works.

django-heroku sets CompressedManifestStaticFilesStorage. Django tests run with
DEBUG=False, so {% static %} blows up without collectstatic (and collectstatic
fails upstream on a missing font). Gunicorn smoke uses DEBUG=True. Tests force
plain StaticFilesStorage so we gate routes/auth, not WhiteNoise manifests.
"""
import base64
import pickle

from django.contrib.auth.models import User
from django.core import signing
from django.core.files.uploadedfile import SimpleUploadedFile
from django.test import TestCase, override_settings
from django.urls import reverse

from introduction.views import TOKEN_SALT, TestUser


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

    def test_cmd_lab_rejects_shell_metacharacters(self):
        self.client.force_login(self.user)
        r = self.client.post("/cmd_lab", {"domain": "example.com; id", "os": "nix"})
        self.assertEqual(r.status_code, 200)
        self.assertContains(r, "Invalid domain name")

    def test_mitre_17_api_rejects_shell_metacharacters(self):
        r = self.client.post("/mitre/17/lab/api", {"ip": "127.0.0.1; id"})
        self.assertEqual(r.status_code, 400)

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

    def test_insec_des_lab_issues_signed_json_token(self):
        self.client.force_login(self.user)
        r = self.client.get("/insec_des_lab")
        self.assertEqual(r.status_code, 200)
        token = r.cookies["token"].value
        # Cookie is signed JSON, not a pickle blob.
        self.assertEqual(
            signing.loads(token, salt=TOKEN_SALT, max_age=3600), {"admin": 0}
        )
        self.assertContains(r, "Only Admins can see this page")

    def test_insec_des_lab_rejects_pickle_cookie(self):
        self.client.force_login(self.user)
        evil = base64.b64encode(pickle.dumps(TestUser(admin=1))).decode()
        self.client.cookies["token"] = evil
        r = self.client.get("/insec_des_lab")
        self.assertEqual(r.status_code, 200)
        self.assertNotContains(r, "SECRETKEY:ADMIN123")

    def test_insec_des_lab_rejects_tampered_signed_token(self):
        self.client.force_login(self.user)
        forged = signing.dumps({"admin": 1}, salt="not-the-lab-salt")
        self.client.cookies["token"] = forged
        r = self.client.get("/insec_des_lab")
        self.assertEqual(r.status_code, 200)
        self.assertNotContains(r, "SECRETKEY:ADMIN123")

    def test_insec_des_lab_accepts_own_admin_token(self):
        self.client.force_login(self.user)
        self.client.cookies["token"] = signing.dumps(
            {"admin": 1}, salt=TOKEN_SALT
        )
        r = self.client.get("/insec_des_lab")
        self.assertContains(r, "SECRETKEY:ADMIN123")

    def test_a9_lab_converts_plain_yaml(self):
        self.client.force_login(self.user)
        upload = SimpleUploadedFile(
            "ok.yaml", b"name: pygoat\nitems:\n  - one\n", content_type="text/yaml"
        )
        r = self.client.post("/a9_lab", {"file": upload})
        self.assertEqual(r.status_code, 200)
        self.assertContains(r, "pygoat")

    def test_a9_lab_rejects_python_object_yaml_tag(self):
        self.client.force_login(self.user)
        upload = SimpleUploadedFile(
            "evil.yaml",
            b"!!python/object/apply:subprocess.check_output\n- [echo, pwned]\n",
            content_type="text/yaml",
        )
        r = self.client.post("/a9_lab", {"file": upload})
        self.assertEqual(r.status_code, 200)
        self.assertContains(r, "Error")
        self.assertNotContains(r, "pwned")

    def test_login_post(self):
        r = self.client.post(
            reverse("login"),
            {"username": "gateuser", "password": self.PASSWORD},
        )
        self.assertEqual(r.status_code, 302)
        self.assertEqual(self.client.get("/").status_code, 200)
