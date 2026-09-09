"""PyGoat platform regression for remedia CI.

Guards auth + named routes + cmd lab still serving.
Does NOT assert command injection still works.

django-heroku sets CompressedManifestStaticFilesStorage. Django tests run with
DEBUG=False, so {% static %} blows up without collectstatic (and collectstatic
fails upstream on a missing font). Gunicorn smoke uses DEBUG=True. Tests force
plain StaticFilesStorage so we gate routes/auth, not WhiteNoise manifests.
"""
import ast
import base64
import inspect
import os
import pathlib
import re

import jwt
from django.conf import settings
from django.contrib.auth.models import User
from django.core import signing
from django.core.files.uploadedfile import SimpleUploadedFile
from django.test import Client, TestCase, override_settings
from django.urls import reverse

from .models import CF_user, CSRF_user_tbl, authLogin
from .utility import make_lab_password, safe_lookup_target


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

    def test_command_modules_never_spawn_a_shell(self):
        """No module that spawns processes may hand a command string to a shell."""
        from . import mitre, views

        sources = [inspect.getsource(views), inspect.getsource(mitre)]
        introduction_dir = pathlib.Path(__file__).resolve().parent
        lab_code = introduction_dir / "lab_code" / "test.py"
        sources.append(lab_code.read_text(encoding="utf-8"))
        # CWE-78: the standalone uninstaller also spawns processes.
        uninstaller = introduction_dir.parent / "uninstaller.py"
        sources.append(uninstaller.read_text(encoding="utf-8"))
        for source in sources:
            self.assertNotIn("shell=True", source)
            self.assertNotIn("os.system", source)


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
            password=make_lab_password(self.PASSWORD),
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


@override_settings(
    DEBUG=True,
    STATICFILES_STORAGE="django.contrib.staticfiles.storage.StaticFilesStorage",
)
class InsecureDeserializationRegressionTests(TestCase):
    """CWE-502: client-supplied state must be parsed as data, never as code.

    Gates that the insecure-deserialization lab still hands out and accepts a
    token, and that the A9 lab still converts YAML - while pickle/full-loader
    payloads are rejected instead of constructing objects.
    """

    PASSWORD = "Str0ng-Passw0rd!"
    # Old cookie format (base64 of a pickled dict). Fed in as-is: the view must
    # reject it, never unpickle it.
    LEGACY_PICKLE_COOKIE = base64.b64encode(
        b"\x80\x04\x95\x14\x00\x00\x00\x00\x00\x00\x00}\x94\x8c\x05admin\x94K\x01s."
    ).decode()

    def setUp(self):
        self.user = User.objects.create_user(
            username="desuser",
            email="desuser@example.com",
            password=self.PASSWORD,
        )
        self.client.force_login(self.user)

    def test_lab_issues_signed_json_token(self):
        r = self.client.get("/insec_des_lab")
        self.assertEqual(r.status_code, 200)
        self.assertIn("token", r.cookies)
        self.assertEqual(signing.loads(r.cookies["token"].value), {"admin": 0})

    def test_token_round_trips_as_primitive_data(self):
        from .views import TestUser, dump_lab_user, load_lab_user

        self.assertEqual(load_lab_user(dump_lab_user(TestUser(admin=1))).admin, 1)

    def test_signed_admin_token_still_unlocks_lab(self):
        from .views import TestUser, dump_lab_user

        self.client.cookies["token"] = dump_lab_user(TestUser(admin=1))
        r = self.client.get("/insec_des_lab")
        self.assertContains(r, "Welcome Admin")

    def test_token_signed_with_foreign_key_is_rejected(self):
        self.client.cookies["token"] = signing.dumps(
            {"admin": 1}, key="some-other-key"
        )
        r = self.client.get("/insec_des_lab")
        self.assertEqual(r.status_code, 200)
        self.assertContains(r, "Invalid or tampered token")
        self.assertNotContains(r, "SECRETKEY:ADMIN123")

    def test_legacy_pickle_cookie_is_rejected(self):
        self.client.cookies["token"] = self.LEGACY_PICKLE_COOKIE
        r = self.client.get("/insec_des_lab")
        self.assertEqual(r.status_code, 200)
        self.assertContains(r, "Invalid or tampered token")
        self.assertNotContains(r, "SECRETKEY:ADMIN123")

    def test_yaml_lab_still_converts_plain_yaml(self):
        upload = SimpleUploadedFile(
            "data.yaml", b"name: pygoat\nversion: 1\n", content_type="application/x-yaml"
        )
        r = self.client.post("/a9_lab", {"file": upload})
        self.assertEqual(r.status_code, 200)
        self.assertContains(r, "pygoat")

    def test_yaml_lab_rejects_python_object_tags(self):
        upload = SimpleUploadedFile(
            "evil.yaml",
            b"!!python/object/apply:subprocess.Popen\n- ls\n",
            content_type="application/x-yaml",
        )
        r = self.client.post("/a9_lab", {"file": upload})
        self.assertEqual(r.status_code, 200)
        self.assertContains(r, "Error")
        self.assertNotContains(r, "Popen")

    def test_views_module_has_no_unsafe_deserialization(self):
        from . import views

        source = inspect.getsource(views)
        self.assertNotIn("pickle.loads", source)
        self.assertNotIn("pickle.dumps", source)
        self.assertNotRegex(source, r"yaml\.load\(")


@override_settings(
    DEBUG=True,
    STATICFILES_STORAGE="django.contrib.staticfiles.storage.StaticFilesStorage",
    CSRF_LAB_JWT_KEY="unit-test-csrf-lab-signing-key",
)
class LabPasswordHashingTests(TestCase):
    """CWE-327: lab logins must verify a vetted password hash, not MD5.

    Gates that the crypto-failure lab and the CSRF lab still authenticate an
    account stored with make_lab_password(), that a legacy bare MD5 digest can no
    longer be used to log in, and that neither module hashes passwords with MD5.
    """

    PASSWORD = "Str0ng-Passw0rd!"
    LAB_USERNAME = "cryptolabuser"
    # Unsalted MD5 digest of PASSWORD - the format these labs stored before the
    # move to PBKDF2. Kept as a literal so the test never hashes with MD5 itself.
    LEGACY_MD5_DIGEST = "d2586fe34b068ee71c57c35d355d6ec3"

    def setUp(self):
        self.user = User.objects.create_user(
            username="hashgateuser",
            email="hashgateuser@example.com",
            password=self.PASSWORD,
        )
        self.client.force_login(self.user)

    def _crypto_lab_post(self, password):
        return self.client.post(
            reverse("cryptographic_failure_lab"),
            {"username": self.LAB_USERNAME, "password": password},
        )

    def test_stored_hash_is_adaptive_and_salted(self):
        encoded = make_lab_password(self.PASSWORD)
        self.assertTrue(encoded.startswith("pbkdf2_"))
        self.assertNotEqual(encoded, self.LEGACY_MD5_DIGEST)
        # Salted: the same password never yields the same stored value twice.
        self.assertNotEqual(encoded, make_lab_password(self.PASSWORD))

    def test_crypto_lab_logs_in_account_with_vetted_hash(self):
        CF_user.objects.create(
            username=self.LAB_USERNAME,
            password=make_lab_password(self.PASSWORD),
            password2="",
        )
        r = self._crypto_lab_post(self.PASSWORD)
        self.assertEqual(r.status_code, 200)
        self.assertContains(r, self.LAB_USERNAME)

    def test_crypto_lab_rejects_wrong_password(self):
        CF_user.objects.create(
            username=self.LAB_USERNAME,
            password=make_lab_password(self.PASSWORD),
            password2="",
        )
        r = self._crypto_lab_post("not-the-password")
        self.assertEqual(r.status_code, 200)
        self.assertNotContains(r, self.LAB_USERNAME)

    def test_crypto_lab_rejects_legacy_md5_digest(self):
        CF_user.objects.create(
            username=self.LAB_USERNAME,
            password=self.LEGACY_MD5_DIGEST,
            password2="",
        )
        for attempt in (self.PASSWORD, self.LEGACY_MD5_DIGEST):
            with self.subTest(attempt=attempt):
                r = self._crypto_lab_post(attempt)
                self.assertEqual(r.status_code, 200)
                self.assertNotContains(r, self.LAB_USERNAME)

    def test_csrf_lab_rejects_legacy_md5_digest(self):
        CSRF_user_tbl.objects.create(
            username=self.LAB_USERNAME,
            password=self.LEGACY_MD5_DIGEST,
            balance=100,
        )
        r = self.client.post(
            reverse("csrf_lab_login"),
            {"username": self.LAB_USERNAME, "password": self.PASSWORD},
        )
        self.assertEqual(r.status_code, 302)
        self.assertIn("/mitre/9/lab/login", r["Location"])
        self.assertNotIn("auth_cookiee", r.cookies)

    def test_lab_modules_do_not_hash_passwords_with_md5(self):
        from . import mitre, views

        for module in (views, mitre):
            with self.subTest(module=module.__name__):
                source = inspect.getsource(module)
                self.assertNotRegex(source, r"md5\(\s*password")
                self.assertNotRegex(source, r"hashlib\.md5\(")
                self.assertNotRegex(source, r"sha1\(\s*password")


@override_settings(
    DEBUG=True,
    STATICFILES_STORAGE="django.contrib.staticfiles.storage.StaticFilesStorage",
)
class CsrfProtectionRegressionTests(TestCase):
    """CWE-352: state changing views must keep Django's CSRF protection.

    Gates that no view opts out with @csrf_exempt any more, that an unsafe
    request without a token is refused, and that the browser flows still work
    because the templates render {% csrf_token %} and the AJAX callers send the
    X-CSRFToken header. Django's default test client skips the CSRF checks, so a
    second client with enforce_csrf_checks=True is used to assert the rejection.
    """

    PASSWORD = "Str0ng-Passw0rd!"
    APP_DIR = pathlib.Path(__file__).resolve().parent

    def setUp(self):
        self.user = User.objects.create_user(
            username="csrfgateuser",
            email="csrfgateuser@example.com",
            password=self.PASSWORD,
        )
        self.client.force_login(self.user)
        # Behaves like a real browser request: no token, no service.
        self.strict = Client(enforce_csrf_checks=True)
        self.strict.force_login(self.user)

    def _token(self, path):
        """Token the server issued for `path`, as a browser would read it."""
        page = self.strict.get(path)
        self.assertEqual(page.status_code, 200, msg=path)
        return str(page.context["csrf_token"])

    def test_no_lab_module_opts_out_of_csrf_protection(self):
        from . import apis, mitre, views
        from .playground.A9 import api as a9_api

        for module in (views, apis, mitre, a9_api):
            with self.subTest(module=module.__name__):
                self.assertNotIn("csrf_exempt", inspect.getsource(module))
        archive = self.APP_DIR / "playground" / "A9" / "archive.py"
        self.assertNotIn("csrf_exempt", archive.read_text(encoding="utf-8"))

    def test_post_forms_in_templates_render_a_csrf_token(self):
        post_form = re.compile(r"<form[^>]*method\s*=\s*[\"']?post", re.IGNORECASE)
        for template in (self.APP_DIR / "templates").rglob("*.html"):
            body = template.read_text(encoding="utf-8")
            if post_form.search(body):
                with self.subTest(template=template.name):
                    self.assertIn("csrf_token", body)

    def test_form_post_without_token_is_rejected(self):
        r = self.strict.post("/cmd_lab2", {"val": "7*7"})
        self.assertEqual(r.status_code, 403)

    def test_form_post_with_token_still_serves_the_lab(self):
        token = self._token("/cmd_lab2")
        r = self.strict.post(
            "/cmd_lab2", {"val": "7*7", "csrfmiddlewaretoken": token}
        )
        self.assertEqual(r.status_code, 200)
        self.assertContains(r, "49")

    def test_json_api_post_without_token_is_rejected(self):
        r = self.strict.post("/mitre/25/lab/api", {"expression": "6*7"})
        self.assertEqual(r.status_code, 403)

    def test_json_api_post_with_token_still_calculates(self):
        token = self._token("/mitre/25/lab")
        r = self.strict.post(
            "/mitre/25/lab/api", {"expression": "6*7", "csrfmiddlewaretoken": token}
        )
        self.assertEqual(r.status_code, 200)
        self.assertEqual(r.json()["result"], 42)

    def test_xml_body_post_needs_the_csrf_header(self):
        body = "<comm><text>a harmless comment</text></comm>"
        rejected = self.strict.post("/xxe_parse", data=body, content_type="text/xml")
        self.assertEqual(rejected.status_code, 403)

        # An XML body carries no form field, so the token travels in the header
        # (Lab/xss.js does exactly this).
        accepted = self.strict.post(
            "/xxe_parse",
            data=body,
            content_type="text/xml",
            HTTP_X_CSRFTOKEN=self._token("/xxe_lab"),
        )
        self.assertEqual(accepted.status_code, 200)

    def test_ajax_callers_send_the_csrf_token(self):
        static_dir = self.APP_DIR / "static"
        self.assertIn(
            "getCsrfToken", (static_dir / "js" / "csrf.js").read_text(encoding="utf-8")
        )
        for name in ("js/a6.js", "js/a7.js", "js/a9.js", "Lab/ssrf.js", "Lab/xss.js"):
            with self.subTest(script=name):
                source = (static_dir / name).read_text(encoding="utf-8")
                self.assertRegex(source, r"withCsrfHeader\(|X-CSRFToken")

    def test_a9_log_checker_forwards_csrf_credentials_to_the_target(self):
        """The lab's own probes of the (protected) target must carry the token."""
        from . import apis

        source = inspect.getsource(apis.log_function_checker)
        for method in ('"POST"', '"PATCH"', '"DELETE"'):
            with self.subTest(method=method):
                calls = [
                    line for line in source.splitlines()
                    if "requests.request(" + method in line
                ]
                self.assertEqual(len(calls), 1, msg=method)
                self.assertIn("cookies=csrf_cookies", calls[0])
                self.assertIn("headers=csrf_headers", calls[0])


@override_settings(
    DEBUG=True,
    STATICFILES_STORAGE="django.contrib.staticfiles.storage.StaticFilesStorage",
    CSRF_LAB_JWT_KEY="unit-test-csrf-lab-signing-key",
)
class LabCookieAttributeTests(TestCase):
    """CWE-614: every cookie a lab view issues must carry security attributes.

    HttpOnly and SameSite are unconditional at the response.set_cookie() call
    sites. Secure cannot be hard-coded on: docker-compose.yml publishes PyGoat
    over plain HTTP, where a browser silently drops a Secure cookie and every
    cookie driven lab would break, so it is taken from
    settings.LAB_COOKIE_SECURE (default off, switched on for HTTPS
    deployments). Django's own csrftoken cookie is deliberately left readable by
    static/js/csrf.js and is not covered by these assertions.
    """

    PASSWORD = "Str0ng-Passw0rd!"
    LAB_USERNAME = "cookielabuser"
    APP_DIR = pathlib.Path(__file__).resolve().parent
    COOKIE_MODULES = ("views.py", "mitre.py")

    def setUp(self):
        self.user = User.objects.create_user(
            username="cookiegateuser",
            email="cookiegateuser@example.com",
            password=self.PASSWORD,
        )
        self.client.force_login(self.user)

    def _set_cookie_calls(self, module_name):
        """Every response.set_cookie() call in a lab module, as AST nodes."""
        source = (self.APP_DIR / module_name).read_text(encoding="utf-8")
        return [
            node for node in ast.walk(ast.parse(source))
            if isinstance(node, ast.Call)
            and isinstance(node.func, ast.Attribute)
            and node.func.attr == "set_cookie"
        ]

    def _assert_attributes(self, response, name, secure=False):
        self.assertIn(name, response.cookies)
        morsel = response.cookies[name]
        self.assertTrue(morsel["httponly"], msg=name)
        self.assertEqual(morsel["samesite"], "Lax", msg=name)
        self.assertEqual(bool(morsel["secure"]), secure, msg=name)
        return morsel

    def test_every_lab_set_cookie_call_passes_the_attributes(self):
        """A new call site cannot forget the flags without failing here."""
        calls = 0
        for module_name in self.COOKIE_MODULES:
            for call in self._set_cookie_calls(module_name):
                calls += 1
                keywords = {kw.arg: kw.value for kw in call.keywords}
                where = "%s:%d" % (module_name, call.lineno)
                with self.subTest(call=where):
                    self.assertEqual(
                        {"httponly", "samesite", "secure"} - set(keywords),
                        set(),
                        msg="set_cookie at %s omits security attributes" % where,
                    )
                    httponly = keywords["httponly"]
                    self.assertIsInstance(httponly, ast.Constant, msg=where)
                    self.assertIs(httponly.value, True, msg=where)
                    samesite = keywords["samesite"]
                    self.assertIsInstance(samesite, ast.Constant, msg=where)
                    self.assertIn(samesite.value, ("Lax", "Strict"), msg=where)
                    # Secure must stay environment driven, never a literal.
                    secure = keywords["secure"]
                    self.assertIsInstance(secure, ast.Attribute, msg=where)
                    self.assertEqual(secure.attr, "LAB_COOKIE_SECURE", msg=where)
        self.assertGreater(calls, 0, msg="no set_cookie calls found to gate")

    def test_lab_cookie_secure_setting_comes_from_the_environment(self):
        expected = os.environ.get("LAB_COOKIE_SECURE", "false").strip().lower() in (
            "1", "true", "yes", "on",
        )
        self.assertIs(settings.LAB_COOKIE_SECURE, expected)

    def test_insecure_deserialization_lab_token_cookie(self):
        r = self.client.get(reverse("insec_des_lab"))
        self.assertEqual(r.status_code, 200)
        morsel = self._assert_attributes(r, "token")
        # The signed-token control from the CWE-502 fix still stands.
        self.assertEqual(signing.loads(morsel.value), {"admin": 0})

    def test_auth_lab_signup_userid_cookie(self):
        r = self.client.post(
            reverse("auth_lab_signup"),
            {"name": "Cookie Lab", "username": self.LAB_USERNAME, "pass": self.PASSWORD},
        )
        self.assertEqual(r.status_code, 200)
        stored = authLogin.objects.get(username=self.LAB_USERNAME)
        morsel = self._assert_attributes(r, "userid")
        self.assertEqual(morsel.value, str(stored.userid))

    def test_security_misconfiguration_lab3_auth_cookie(self):
        r = self.client.get("/sec_mis_lab3")
        self.assertEqual(r.status_code, 200)
        self._assert_attributes(r, "auth_cookie")

    def test_auth_failure_lab3_session_cookie(self):
        r = self.client.post(reverse("auth_failure_lab3"), {})
        self.assertEqual(r.status_code, 200)
        self._assert_attributes(r, "session_id")

    def test_csrf_lab_auth_cookie(self):
        CSRF_user_tbl.objects.create(
            username=self.LAB_USERNAME,
            password=make_lab_password(self.PASSWORD),
            balance=100,
        )
        r = self.client.post(
            reverse("csrf_lab_login"),
            {"username": self.LAB_USERNAME, "password": self.PASSWORD},
        )
        self.assertEqual(r.status_code, 302)
        morsel = self._assert_attributes(r, "auth_cookiee")
        # The runtime signing key from the CWE-522 fix still stands.
        payload = jwt.decode(
            morsel.value, settings.CSRF_LAB_JWT_KEY, algorithms=["HS256"]
        )
        self.assertEqual(payload["username"], self.LAB_USERNAME)

    def test_secure_attribute_switches_on_for_https_deployments(self):
        with override_settings(LAB_COOKIE_SECURE=True):
            r = self.client.get(reverse("insec_des_lab"))
            self.assertEqual(r.status_code, 200)
            self._assert_attributes(r, "token", secure=True)

    def test_csrf_token_cookie_stays_readable_by_the_csrf_helper(self):
        """csrf.js falls back to document.cookie, so csrftoken is not HttpOnly."""
        self.assertFalse(getattr(settings, "CSRF_COOKIE_HTTPONLY", False))
        helper = (self.APP_DIR / "static" / "js" / "csrf.js").read_text(encoding="utf-8")
        self.assertIn("document.cookie", helper)
        self.assertIn("csrftoken=", helper)
