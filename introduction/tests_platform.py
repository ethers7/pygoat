"""PyGoat platform regression for remedia CI.

Guards auth + named routes + cmd lab still serving.
Does NOT assert command injection still works.

django-heroku sets CompressedManifestStaticFilesStorage. Django tests run with
DEBUG=False, so {% static %} blows up without collectstatic (and collectstatic
fails upstream on a missing font). Gunicorn smoke uses DEBUG=True. Tests force
plain StaticFilesStorage so we gate routes/auth, not WhiteNoise manifests.
"""
import base64
import hashlib
import os
import shutil
import tempfile
from unittest import mock

from django.contrib.auth.models import User
from django.test import Client, TestCase, override_settings
from django.urls import reverse

from . import views
from .models import AF_session_id, Blogs, CF_user, CSRF_user_tbl, authLogin
from .utility import hash_password

LAB_PASSWORD = "p@ssword"
CSRF_LAB_PASSWORD = "csrf-lab-pass"
# Frozen legacy-format fixtures: the md5 of LAB_PASSWORD / CSRF_LAB_PASSWORD
# above, pinned as literals so the tests never compute a weak digest at run
# time. They stand in for a dumped legacy row, which must never authenticate.
LEGACY_MD5_OF_LAB_PASSWORD = "90f2c9c53f66540e67349e0ab83d8cd0"
LEGACY_MD5_OF_CSRF_LAB_PASSWORD = "29d8e2fee5b7078dfbbff1f6e9badd72"


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

    def test_calculator_labs_reject_unserialisable_results(self):
        """Both calculators answer 400/"Invalid expression", never a 500.

        A complex result ((-1)**0.5) and a result too big to convert to a
        string used to escape the evaluator and blow up in the response layer.
        """
        payloads = ("(-1) ** 0.5", "1e1000", "*".join(["999**99"] * 15))
        for payload in payloads:
            r = self.client.post("/mitre/25/lab/api", {"expression": payload})
            self.assertEqual(r.status_code, 400, msg=payload)
            self.assertIn("Invalid expression", r.json()["error"])
        self.client.force_login(self.user)
        for payload in payloads:
            r = self.client.post("/cmd_lab2", {"val": payload})
            self.assertEqual(r.status_code, 200, msg=payload)
            self.assertContains(r, "Invalid expression", msg_prefix=payload)

    def test_login_post(self):
        r = self.client.post(
            reverse("login"),
            {"username": "gateuser", "password": self.PASSWORD},
        )
        self.assertEqual(r.status_code, 302)
        self.assertEqual(self.client.get("/").status_code, 200)

    def test_crypto_failure_lab_login_uses_a_salted_password_hash(self):
        """Lab 1 still logs the seeded demo account in, without MD5 storage."""
        lab_password = LAB_PASSWORD
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
        lab_password = LAB_PASSWORD
        CF_user.objects.create(
            username="admin",
            password=hash_password(lab_password),
            password2="",
        )
        self.client.force_login(self.user)
        for password in ("not-the-password",
                         LEGACY_MD5_OF_LAB_PASSWORD):
            r = self.client.post(reverse("cryptographic_failure_lab"),
                                 {"username": "admin", "password": password})
            self.assertEqual(r.status_code, 200, msg=password)
            self.assertContains(r, "Login Failed", msg_prefix=password)

    def test_crypto_failure_lab_login_fails_closed_on_a_legacy_md5_row(self):
        """A row still holding a bare MD5 digest is not a usable credential."""
        lab_password = LAB_PASSWORD
        CF_user.objects.create(
            username="legacy",
            password=LEGACY_MD5_OF_LAB_PASSWORD,
            password2="",
        )
        self.client.force_login(self.user)
        r = self.client.post(reverse("cryptographic_failure_lab"),
                             {"username": "legacy", "password": lab_password})
        self.assertEqual(r.status_code, 200)
        self.assertContains(r, "Login Failed")

    def test_csrf_lab_login_verifies_the_stored_password_hash(self):
        """CSRF lab login still works for a hashed account and fails closed."""
        lab_password = CSRF_LAB_PASSWORD
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
                                   ("jack", LEGACY_MD5_OF_CSRF_LAB_PASSWORD),
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
class AuthLabResponseRenderingTests(TestCase):
    """The broken-auth lab responses go through the escaping template path.

    The signup/login/logout views used to hand a pre-rendered string to
    HttpResponse (CWE-79). They now use django.shortcuts.render, so the
    stored name/username are escaped and base.html still receives a real
    {{ csrf_token }}. The lab itself (guessing the `userid` cookie) must
    keep working, so the cookie behaviour is asserted too.
    """

    SCRIPT_PAYLOAD = "<script>alert(1)</script>"
    IMG_PAYLOAD = "<img src=x onerror=alert(1)>"

    def test_signup_escapes_user_data_and_still_sets_the_cookie(self):
        r = self.client.post("/auth_lab/signup",
                             {"name": self.SCRIPT_PAYLOAD,
                              "username": "authuser1",
                              "pass": "pw"})
        self.assertEqual(r.status_code, 200)
        self.assertNotContains(r, self.SCRIPT_PAYLOAD)
        self.assertContains(r, "&lt;script&gt;alert(1)&lt;/script&gt;")
        obj = authLogin.objects.get(username="authuser1")
        self.assertEqual(r.cookies["userid"].value, str(obj.userid))

    def test_signup_response_carries_a_real_csrf_token(self):
        r = self.client.post("/auth_lab/signup",
                             {"name": "Jack", "username": "authuser2", "pass": "pw"})
        self.assertContains(r, 'name="csrfmiddlewaretoken"')
        self.assertNotContains(r, 'name="csrfmiddlewaretoken" value=""')

    def test_login_with_the_userid_cookie_escapes_stored_markup(self):
        """The cookie-swap exercise still works, and the name is not live markup."""
        obj = authLogin.objects.create(name=self.IMG_PAYLOAD,
                                       username="authuser3",
                                       password="pw")
        self.client.cookies["userid"] = str(obj.userid)
        r = self.client.get("/auth_lab/login")
        self.assertEqual(r.status_code, 200)
        self.assertContains(r, "authuser3")
        self.assertNotContains(r, self.IMG_PAYLOAD)
        self.assertContains(r, "&lt;img src=x onerror=alert(1)&gt;")

    def test_login_post_escapes_user_data_and_still_sets_the_cookie(self):
        obj = authLogin.objects.create(name=self.SCRIPT_PAYLOAD,
                                       username="authuser4",
                                       password="pw")
        r = self.client.post("/auth_lab/login",
                             {"username": "authuser4", "pass": "pw"})
        self.assertEqual(r.status_code, 200)
        self.assertNotContains(r, self.SCRIPT_PAYLOAD)
        self.assertContains(r, "&lt;script&gt;alert(1)&lt;/script&gt;")
        self.assertEqual(r.cookies["userid"].value, str(obj.userid))

    def test_logout_still_renders_and_clears_the_cookie(self):
        self.client.cookies["userid"] = "1"
        r = self.client.get("/auth_lab/logout")
        self.assertEqual(r.status_code, 200)
        self.assertContains(r, "Logout successful")
        self.assertEqual(r.cookies["userid"].value, "")


@override_settings(
    DEBUG=True,
    STATICFILES_STORAGE="django.contrib.staticfiles.storage.StaticFilesStorage",
)
class LabCodeGroundTests(TestCase):
    """The A6/A9 coding grounds still install submitted code, but not for anyone.

    Request data used to be written verbatim into modules of the running app by
    endpoints that were reachable anonymously (CWE-93). The exercises keep
    working for a signed-in student; the write is now authenticated, bounded,
    syntax checked and aimed at a server chosen path.
    """

    PASSWORD = "Str0ng-Passw0rd!"
    LOG_CODE = "class Log:\n    def __init__(self, request):\n        pass\n"
    API_CODE = "def log_function_target(request):\n    return None\n"
    A6_CODE = "def check_vuln(mods):\n    return []\n"

    def setUp(self):
        self.user = User.objects.create_user(
            username="labuser",
            email="labuser@example.com",
            password=self.PASSWORD,
        )
        # Point the allowlist at a scratch playground so the tests never
        # overwrite the modules shipped in the repository.
        self.root = tempfile.mkdtemp()
        self.addCleanup(shutil.rmtree, self.root, True)
        for package in ("A6", "A9"):
            os.mkdir(os.path.join(self.root, package))
        patcher = mock.patch("introduction.utility._LAB_CODE_ROOT", self.root)
        patcher.start()
        self.addCleanup(patcher.stop)

    def _written(self, *parts):
        with open(os.path.join(self.root, *parts), encoding="utf-8") as handle:
            return handle.read()

    def test_anonymous_callers_cannot_write_lab_modules(self):
        for url, data in (("/2021/discussion/A9/api",
                           {"log_code": self.LOG_CODE, "api_code": self.API_CODE}),
                          ("/2021/discussion/A6/api2", {"code": self.A6_CODE})):
            r = self.client.post(url, data)
            self.assertEqual(r.status_code, 302, msg=url)
            self.assertIn("/login", r["Location"])
        self.assertEqual(os.listdir(os.path.join(self.root, "A6")), [])
        self.assertEqual(os.listdir(os.path.join(self.root, "A9")), [])

    def test_a6_ground_still_saves_a_signed_in_submission(self):
        self.client.force_login(self.user)
        r = self.client.post("/2021/discussion/A6/api2", {"code": self.A6_CODE})
        self.assertEqual(r.status_code, 200)
        self.assertEqual(r.json()["message"], "success")
        self.assertEqual(self._written("A6", "utility.py"), self.A6_CODE)

    def test_a6_ground_refuses_missing_oversized_and_broken_code(self):
        self.client.force_login(self.user)
        for code in ("", "def broken(:\n", "# pad\n" * 20000):
            r = self.client.post("/2021/discussion/A6/api2", {"code": code})
            self.assertEqual(r.status_code, 400, msg=repr(code[:20]))
            self.assertIn("invalid code", r.json()["message"])
        self.assertEqual(os.listdir(os.path.join(self.root, "A6")), [])

    def test_a9_ground_installs_both_modules_and_keeps_forwarding_csrf(self):
        self.client.force_login(self.user)
        with mock.patch("introduction.apis.requests.request") as probe:
            r = self.client.post("/2021/discussion/A9/api",
                                 {"log_code": self.LOG_CODE,
                                  "api_code": self.API_CODE,
                                  "csrfmiddlewaretoken": "lab-token"})
        self.assertEqual(r.status_code, 200)
        self.assertEqual(r.json()["message"], "success")
        self.assertEqual(self._written("A9", "main.py"), self.LOG_CODE)
        self.assertEqual(self._written("A9", "api.py"), self.API_CODE)
        # The probe requests must keep carrying this caller's CSRF token.
        unsafe = [call for call in probe.call_args_list if call[0][0] != "GET"]
        self.assertTrue(unsafe)
        for call in unsafe:
            self.assertEqual(call[1]["headers"]["X-CSRFToken"], "lab-token")

    def test_a9_ground_refuses_a_broken_submission_without_writing_either_module(self):
        self.client.force_login(self.user)
        with mock.patch("introduction.apis.requests.request") as probe:
            r = self.client.post("/2021/discussion/A9/api",
                                 {"log_code": self.LOG_CODE,
                                  "api_code": "def broken(:\n"})
        self.assertEqual(r.status_code, 400)
        self.assertIn("invalid code", r.json()["message"])
        probe.assert_not_called()
        self.assertEqual(os.listdir(os.path.join(self.root, "A9")), [])


@override_settings(
    DEBUG=True,
    STATICFILES_STORAGE="django.contrib.staticfiles.storage.StaticFilesStorage",
)
class OutboundFetchBudgetTests(TestCase):
    """The SSRF lab fetch must be bounded in time and in size (CWE-400).

    requests waits for ever and buffers the whole body by default, so a host
    that accepts the connection and then stalls (or never stops sending) used
    to hold a worker for good. The lab must still show the fetched page.
    """

    PASSWORD = "Str0ng-Passw0rd!"

    def setUp(self):
        self.user = User.objects.create_user(
            username="fetchuser",
            email="fetchuser@example.com",
            password=self.PASSWORD,
        )
        self.client.force_login(self.user)

    def test_fetch_passes_a_timeout_and_reads_a_bounded_body(self):
        response = mock.MagicMock()
        response.__enter__.return_value = response
        response.iter_content.return_value = iter([b"hello from the internet"])
        # example.com is allowlisted; DNS is mocked so the test never resolves.
        with mock.patch("introduction.utility._is_public_host", return_value=True), \
                mock.patch("introduction.views.requests.get", return_value=response) as get:
            r = self.client.post("/ssrf_lab2", {"url": "https://example.com/page"})
        self.assertEqual(r.status_code, 200)
        self.assertContains(r, "hello from the internet")
        # An explicit (connect, read) budget, not the "wait for ever" default.
        connect, read = get.call_args[1]["timeout"]
        self.assertTrue(0 < connect <= 30, connect)
        self.assertTrue(0 < read <= 30, read)
        self.assertTrue(get.call_args[1]["stream"])
        self.assertFalse(get.call_args[1]["allow_redirects"])
        # Only one bounded chunk is buffered, never the whole stream.
        response.iter_content.assert_called_once_with(views.FETCH_MAX_BYTES)
        self.assertLessEqual(views.FETCH_MAX_BYTES, 4 * 1024 * 1024)


@override_settings(
    DEBUG=True,
    STATICFILES_STORAGE="django.contrib.staticfiles.storage.StaticFilesStorage",
)
class SsrfLabBlogReadTests(TestCase):
    """The blog reader of the SSRF lab serves blogs and nothing else (CWE-22).

    The posted value used to be a path that was joined onto a server directory
    and opened, so "../.env" (the old lab answer) or an absolute path read any
    file the app user could. Reading the lab's blogs must still work, and a
    traversal attempt must be refused with a 400 rather than a 500.
    """

    PASSWORD = "Str0ng-Passw0rd!"
    BLOG_DIR = os.path.join(os.path.dirname(os.path.abspath(__file__)),
                            "templates", "Lab", "ssrf", "blogs")

    def setUp(self):
        self.user = User.objects.create_user(
            username="blogreader",
            email="blogreader@example.com",
            password=self.PASSWORD,
        )
        self.client.force_login(self.user)

    def test_a_blog_of_the_lab_is_still_served(self):
        r = self.client.post("/ssrf_lab", {"blog": "blog1.txt"})
        self.assertEqual(r.status_code, 200)
        self.assertContains(r, "SSRF flaws occur whenever a web application")

    def test_the_lab_page_only_offers_blog_names(self):
        r = self.client.get("/ssrf_lab")
        self.assertEqual(r.status_code, 200)
        self.assertContains(r, 'name="blog" value="blog1.txt"')
        self.assertNotContains(r, 'value="templates/Lab/ssrf/blogs/blog1.txt"')

    def test_traversal_absolute_and_unknown_names_are_refused(self):
        for payload in ("../.env", "../../.env", "../../pygoat/settings.py",
                        "../secret.txt", "/etc/passwd", "..%2f.env",
                        "....//....//.env", "db.sqlite3", "secret.txt",
                        "views.py", ""):
            r = self.client.post("/ssrf_lab", {"blog": payload})
            self.assertEqual(r.status_code, 400, payload)
            self.assertContains(r, "Refused", status_code=400, msg_prefix=payload)
            self.assertNotContains(r, "SECRET_KEY", status_code=400,
                                   msg_prefix=payload)

    def test_a_missing_blog_field_does_not_raise(self):
        r = self.client.post("/ssrf_lab", {})
        self.assertEqual(r.status_code, 400)

    def test_the_lab_blogs_are_all_readable(self):
        for name in sorted(os.listdir(self.BLOG_DIR)):
            r = self.client.post("/ssrf_lab", {"blog": name})
            self.assertEqual(r.status_code, 200, name)

    def test_anonymous_user_is_redirected_to_login(self):
        client = Client()
        r = client.post("/ssrf_lab", {"blog": "blog1.txt"})
        self.assertEqual(r.status_code, 302)
        self.assertIn("/login", r["Location"])


@override_settings(
    DEBUG=True,
    STATICFILES_STORAGE="django.contrib.staticfiles.storage.StaticFilesStorage",
)
class SstiLabStorageTests(TestCase):
    """The SSTI lab stores posts as data instead of as template source.

    A post used to be concatenated into a template and written into the
    template directory, so the next render compiled it (CWE-93 / CWE-1336).
    Posting and reading a blog must still work, the payload must come back
    escaped, and no template file may be created.
    """

    PASSWORD = "Str0ng-Passw0rd!"
    PAYLOAD = "{% debug %}{{ 7*7 }}<script>alert(1)</script>"
    BLOG_DIR = os.path.join(os.path.dirname(os.path.abspath(__file__)),
                            "templates", "Lab_2021", "A3_Injection", "Blogs")

    def setUp(self):
        self.user = User.objects.create_user(
            username="sstiuser",
            email="sstiuser@example.com",
            password=self.PASSWORD,
        )
        self.client.force_login(self.user)

    def _blog_templates(self):
        if not os.path.isdir(self.BLOG_DIR):
            return set()
        return set(os.listdir(self.BLOG_DIR))

    def test_posting_a_blog_stores_it_and_writes_no_template(self):
        before = self._blog_templates()
        r = self.client.post("/ssti/lab", {"blog": self.PAYLOAD})
        self.assertEqual(r.status_code, 302)
        blog = Blogs.objects.get(author=self.user)
        self.assertEqual(blog.content, self.PAYLOAD)
        self.assertIn(blog.blog_id, r["Location"])
        self.assertEqual(self._blog_templates(), before)

    def test_viewing_a_blog_escapes_the_payload_instead_of_executing_it(self):
        self.client.post("/ssti/lab", {"blog": self.PAYLOAD})
        blog = Blogs.objects.get(author=self.user)
        r = self.client.get("/ssti/blog/" + blog.blog_id)
        self.assertEqual(r.status_code, 200)
        self.assertNotContains(r, "<script>alert(1)</script>")
        self.assertContains(r, "&lt;script&gt;alert(1)&lt;/script&gt;")
        # The tag and the expression are shown as text, not evaluated.
        self.assertContains(r, "{% debug %}")
        self.assertContains(r, "{{ 7*7 }}")

    def test_unknown_blog_id_is_rejected(self):
        r = self.client.get("/ssti/blog/../../../etc/passwd")
        self.assertIn(r.status_code, (400, 404))
        r = self.client.get("/ssti/blog/nosuchblog")
        self.assertEqual(r.status_code, 400)

    def test_no_leftover_blog_file_holds_template_source(self):
        """The directory the old view wrote into keeps no compilable payload.

        The files generated by the vulnerable version are still checked in but
        unreferenced; two of them carried the lab payloads that read the
        project secret key and the admin log. If a template name ever became
        dynamic again those tags would run, so the directory must contain no
        template tags at all.
        """
        for name in sorted(self._blog_templates()):
            with open(os.path.join(self.BLOG_DIR, name), encoding="utf-8") as handle:
                body = handle.read()
            self.assertNotIn("{%", body, name)
            self.assertNotIn("{{", body, name)

    def test_blog_list_still_shows_the_users_posts(self):
        self.client.post("/ssti/lab", {"blog": "hello lab"})
        blog = Blogs.objects.get(author=self.user)
        r = self.client.get("/ssti/lab")
        self.assertEqual(r.status_code, 200)
        self.assertContains(r, blog.blog_id)


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


@override_settings(
    DEBUG=True,
    STATICFILES_STORAGE="django.contrib.staticfiles.storage.StaticFilesStorage",
)
class LabCookieAttributeTests(TestCase):
    """The cookies the lessons set carry HttpOnly/SameSite/Secure (CWE-614/1004).

    Each of these cookies holds authentication or session state - a JWT, a
    session id, or the `userid` the broken-auth lab treats as an identity - and
    they used to be set with no attributes at all (the auth lab even sent
    `samesite=None, secure=False` and kept the identity for a year). The
    exercises are unchanged: the values are the same and developer tools or a
    proxy still show and rewrite them; the browser just no longer hands them to
    document.cookie, to cross-site subresource requests or to plaintext HTTP.
    """

    PASSWORD = "Str0ng-Passw0rd!"

    def setUp(self):
        self.user = User.objects.create_user(
            username="cookieuser",
            email="cookieuser@example.com",
            password=self.PASSWORD,
        )
        self.client.force_login(self.user)

    def _assert_hardened(self, response, name):
        """Assert the named cookie of *response* carries all three attributes."""
        self.assertIn(name, response.cookies, msg=name)
        morsel = response.cookies[name]
        self.assertTrue(morsel["httponly"], msg=name)
        self.assertEqual(morsel["samesite"], "Lax", msg=name)
        self.assertTrue(morsel["secure"], msg=name)
        return morsel

    def test_insecure_deserialization_lab_token_cookie(self):
        r = self.client.get("/insec_des_lab")
        self.assertEqual(r.status_code, 200)
        morsel = self._assert_hardened(r, "token")
        # The lab still hands out the tamperable {"admin": 0} token.
        self.assertEqual(base64.b64decode(morsel.value), b'{"admin": 0}')

    def test_auth_lab_signup_userid_cookie_is_not_kept_for_a_year(self):
        r = self.client.post("/auth_lab/signup",
                             {"name": "Jack", "username": "authcookie1",
                              "pass": "pw"})
        self.assertEqual(r.status_code, 200)
        morsel = self._assert_hardened(r, "userid")
        obj = authLogin.objects.get(username="authcookie1")
        self.assertEqual(morsel.value, str(obj.userid))
        self.assertEqual(int(morsel["max-age"]), views.AUTH_LAB_COOKIE_MAX_AGE)
        self.assertLessEqual(views.AUTH_LAB_COOKIE_MAX_AGE, 24 * 60 * 60)

    def test_auth_lab_login_userid_cookie(self):
        obj = authLogin.objects.create(name="Jack", username="authcookie2",
                                       password="pw")
        r = self.client.post("/auth_lab/login",
                             {"username": "authcookie2", "pass": "pw"})
        self.assertEqual(r.status_code, 200)
        self.assertEqual(self._assert_hardened(r, "userid").value, str(obj.userid))

        # The cookie-swap exercise (GET with someone else's userid) still works.
        self.client.cookies["userid"] = str(obj.userid)
        r = self.client.get("/auth_lab/login")
        self.assertEqual(r.status_code, 200)
        self._assert_hardened(r, "userid")

    def test_crypto_failure_lab3_cookie(self):
        r = self.client.post("/cryptographic_failure/lab3",
                             {"username": "User", "password": "P@$$w0rd"})
        self.assertEqual(r.status_code, 200)
        # Still the plaintext "{username}|{expiry}" value the lab is about.
        self.assertTrue(self._assert_hardened(r, "cookie").value.startswith("User|"))

        r = self.client.post("/cryptographic_failure/lab3",
                             {"username": "User", "password": "wrong"})
        self._assert_hardened(r, "cookie")

    def test_sec_misconfig_lab3_auth_cookie(self):
        r = self.client.get("/sec_mis_lab3")
        self.assertEqual(r.status_code, 200)
        self._assert_hardened(r, "auth_cookie")

    def test_auth_failure_lab3_session_cookie(self):
        # Missing credentials: the view clears the cookie, with the attributes.
        r = self.client.post("/auth_failure/lab3", {})
        self.assertEqual(r.status_code, 200)
        self._assert_hardened(r, "session_id")

        password = "lab3-password"
        users = {"User1": {"userid": "1", "username": "User1",
                           "password": hashlib.sha256(password.encode()).hexdigest()}}
        with mock.patch.dict("introduction.views.USER_A7_LAB3", users, clear=True):
            r = self.client.post("/auth_failure/lab3",
                                 {"username": "User1", "password": password})
        self.assertEqual(r.status_code, 200)
        morsel = self._assert_hardened(r, "session_id")
        # The lab still issues the session token it stores server side.
        self.assertTrue(AF_session_id.objects.filter(session_id=morsel.value).exists())

    def test_csrf_lab_auth_cookie(self):
        CSRF_user_tbl.objects.create(username="alfresko",
                                     password=hash_password("pw"),
                                     balance=100)
        r = self.client.post("/mitre/9/lab/login",
                             {"username": "alfresko", "password": "pw"})
        self.assertEqual(r.status_code, 302)
        self._assert_hardened(r, "auth_cookiee")

    def test_documented_opt_out_only_drops_secure(self):
        """PYGOAT_INSECURE_COOKIES is for plain-HTTP runs; it drops no other flag."""
        with mock.patch.dict(os.environ, {"PYGOAT_INSECURE_COOKIES": "1"}):
            r = self.client.get("/insec_des_lab")
        morsel = r.cookies["token"]
        self.assertFalse(morsel["secure"])
        self.assertTrue(morsel["httponly"])
        self.assertEqual(morsel["samesite"], "Lax")
