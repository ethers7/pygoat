import os
import re
from pathlib import Path
from tempfile import TemporaryDirectory
from unittest.mock import patch

from django.contrib.auth.hashers import is_password_usable
from django.contrib.auth.models import User
from django.test import Client, SimpleTestCase, TestCase, override_settings
from django.urls import reverse

from . import apis, mitre, views
from .models import Blogs, CF_user, CSRF_user_tbl, authLogin, comments
from .playground.A9.api import log_function_target
from .utility import (MAX_BLOG_BODY_BYTES, MAX_LAB_CODE_BYTES,
                      SubmittedContentTooLargeError, UnsafeExpressionError,
                      UnsafeUrlError, UnsafeWritePathError, filter_blog,
                      hash_lab_password, resolve_inside_directory,
                      safe_arithmetic_eval, validate_public_url,
                      validate_submitted_text, verify_lab_password,
                      write_text_atomically, write_text_exclusively)

# Create your tests here.


class ValidatePublicUrlTests(SimpleTestCase):
    """Regression tests for the SSRF guard used by the SSRF lab (CWE-918)."""

    def assert_rejected(self, url):
        with self.assertRaises(UnsafeUrlError):
            validate_public_url(url)

    def test_rejects_non_http_schemes(self):
        for url in ("file:///etc/passwd", "gopher://example.com/", "ftp://example.com/"):
            self.assert_rejected(url)

    def test_rejects_missing_or_empty_url(self):
        for url in ("", "   ", "http://", None):
            self.assert_rejected(url)

    def test_rejects_metadata_and_internal_addresses(self):
        for url in ("http://169.254.169.254/latest/meta-data/",
                    "http://127.0.0.1:8000/admin",
                    "http://0.0.0.0/",
                    "http://10.0.0.5/",
                    "http://172.16.0.1/",
                    "http://192.168.1.1/",
                    "http://[::1]/",
                    "http://[fc00::1]/",
                    "http://[::ffff:169.254.169.254]/"):
            self.assert_rejected(url)

    def test_rejects_hosts_outside_allowlist(self):
        with self.assertRaises(UnsafeUrlError):
            validate_public_url("http://93.184.216.34/", allowed_hosts=("example.org",))

    def test_allows_public_address(self):
        self.assertEqual(validate_public_url("http://93.184.216.34/page"),
                         "http://93.184.216.34/page")

    def test_allows_host_resolving_to_public_address(self):
        def resolver(host, port, **kwargs):
            return [(None, None, None, "", ("93.184.216.34", port))]

        self.assertEqual(
            validate_public_url("https://example.org/x", allowed_hosts=("example.org",),
                                resolver=resolver),
            "https://example.org/x")

    def test_rejects_host_resolving_to_internal_address(self):
        def resolver(host, port, **kwargs):
            return [(None, None, None, "", ("169.254.169.254", port))]

        with self.assertRaises(UnsafeUrlError):
            validate_public_url("http://metadata.example/", resolver=resolver)


class SafeArithmeticEvalTests(SimpleTestCase):
    """Regression tests for the eval() replacement in the code injection labs.

    Covers CWE-94/CWE-95: the calculator must still compute arithmetic while
    refusing anything that could execute code.
    """

    def assert_rejected(self, expression):
        with self.assertRaises(UnsafeExpressionError):
            safe_arithmetic_eval(expression)

    def test_evaluates_arithmetic(self):
        cases = {
            "7*7": 49,
            "1 + 1": 2,
            "(2 + 3) * -4": -20,
            "7 // 2": 3,
            "7 % 4": 3,
            "2 ** 10": 1024,
            "1.5 * 2": 3.0,
            "  10 / 4  ": 2.5,
        }
        for expression, expected in cases.items():
            self.assertEqual(safe_arithmetic_eval(expression), expected)

    def test_rejects_code_execution_payloads(self):
        for expression in ('os.system("id")',
                           '__import__("os").system("id")',
                           'open("/etc/passwd").read()',
                           '().__class__.__bases__[0].__subclasses__()',
                           '[x for x in (1, 2)]',
                           'print(1)',
                           'eval("1+1")',
                           'lambda: 1',
                           '"a" * 3',
                           '1 if 1 else 2',
                           '1 == 1',
                           'True and False'):
            self.assert_rejected(expression)

    def test_rejects_empty_and_non_string_input(self):
        for expression in ("", "   ", None, 42):
            self.assert_rejected(expression)

    def test_rejects_malformed_expression(self):
        for expression in ("1 +", "import os", "x = 1"):
            self.assert_rejected(expression)

    def test_rejects_denial_of_service_expressions(self):
        for expression in ("9 ** 9 ** 9", "10 ** 1000", "9" * 250):
            self.assert_rejected(expression)

    def test_rejects_division_by_zero(self):
        for expression in ("1/0", "1//0", "1 % 0"):
            self.assert_rejected(expression)


# DEBUG=False + django-heroku's manifest static storage makes {% static %} fail
# without collectstatic, so mirror tests_platform.py and force plain storage.
@override_settings(
    DEBUG=True,
    STATICFILES_STORAGE="django.contrib.staticfiles.storage.StaticFilesStorage",
)
class XxeParseTests(TestCase):
    """Regression tests for the XXE lab XML parser hardening (CWE-611)."""

    XXE_PAYLOAD = ("<?xml version='1.0'?>"
                   "<!DOCTYPE comm [<!ENTITY xxe SYSTEM 'file:///etc/passwd'>]>"
                   "<comm><text>&xxe;</text></comm>")

    def setUp(self):
        comments.objects.create(id=1, name="System", comment="unchanged")

    def post_xml(self, body):
        return self.client.post(reverse("xxe_parse"), data=body, content_type="text/xml")

    def test_rejects_entity_declaration(self):
        self.assertEqual(self.post_xml(self.XXE_PAYLOAD).status_code, 400)
        self.assertEqual(comments.objects.get(id=1).comment, "unchanged")

    def test_rejects_malformed_xml(self):
        self.assertEqual(self.post_xml("<comm><text>oops").status_code, 400)
        self.assertEqual(comments.objects.get(id=1).comment, "unchanged")

    def test_rejects_document_without_text_element(self):
        self.assertEqual(self.post_xml("<?xml version='1.0'?><comm/>").status_code, 400)
        self.assertEqual(comments.objects.get(id=1).comment, "unchanged")

    def test_accepts_well_formed_comment(self):
        response = self.post_xml("<?xml version='1.0'?><comm><text>hello lab</text></comm>")
        self.assertEqual(response.status_code, 200)
        self.assertEqual(comments.objects.get(id=1).comment, "hello lab")


class LabPasswordHashTests(SimpleTestCase):
    """Unit tests for the lab password hashing helpers (CWE-327).

    Lab logins used to hash the submitted password with unsalted MD5 and match
    that digest inside the query; they now store salted hashes and verify them
    with the hasher's constant-time check.
    """

    PASSWORD = "L4b-P@ssw0rd!"
    # Shape of a legacy stored value: an unsalted 32 hex char digest.
    LEGACY_DIGEST = "0" * 32

    def test_hash_is_salted_and_not_a_bare_digest(self):
        first = hash_lab_password(self.PASSWORD)
        second = hash_lab_password(self.PASSWORD)
        self.assertNotEqual(first, second)  # random per-password salt
        self.assertIn("$", first)
        self.assertNotEqual(len(first), len(self.LEGACY_DIGEST))
        self.assertTrue(is_password_usable(first))

    def test_verify_accepts_correct_password(self):
        self.assertTrue(verify_lab_password(self.PASSWORD,
                                            hash_lab_password(self.PASSWORD)))

    def test_verify_rejects_wrong_password(self):
        self.assertFalse(verify_lab_password("not-the-password",
                                             hash_lab_password(self.PASSWORD)))

    def test_verify_rejects_legacy_unsalted_digest(self):
        self.assertFalse(verify_lab_password(self.PASSWORD, self.LEGACY_DIGEST))

    def test_verify_rejects_unusable_and_missing_values(self):
        self.assertFalse(verify_lab_password(self.PASSWORD, hash_lab_password(None)))
        for raw, encoded in ((None, hash_lab_password(self.PASSWORD)),
                             ("", hash_lab_password(self.PASSWORD)),
                             (self.PASSWORD, None),
                             (self.PASSWORD, "")):
            self.assertFalse(verify_lab_password(raw, encoded))


# DEBUG=False + django-heroku's manifest static storage makes {% static %} fail
# without collectstatic, so mirror tests_platform.py and force plain storage.
@override_settings(
    DEBUG=True,
    STATICFILES_STORAGE="django.contrib.staticfiles.storage.StaticFilesStorage",
)
class LabLoginHashingTests(TestCase):
    """End to end tests for the lab logins that used to compare MD5 digests."""

    LAB_PASSWORD = "L4b-P@ssw0rd!"
    SEEDED_USERNAMES = ("alex", "admin", "rupak")

    def setUp(self):
        self.user = User.objects.create_user(username="labgate",
                                             password="Str0ng-Passw0rd!")
        self.client.force_login(self.user)

    def test_seeded_crypto_lab_rows_have_no_usable_password(self):
        """Migrations must not ship a crackable credential for the lab."""
        rows = CF_user.objects.filter(username__in=self.SEEDED_USERNAMES)
        self.assertTrue(rows.exists())
        for row in rows:
            self.assertFalse(is_password_usable(row.password), msg=row.username)
            self.assertFalse(verify_lab_password("admin", row.password))

    def test_crypto_lab_login_accepts_configured_password(self):
        CF_user.objects.filter(username="alex").update(
            password=hash_lab_password(self.LAB_PASSWORD))
        response = self.client.post(reverse("cryptographic_failure_lab"),
                                    {"username": "alex", "password": self.LAB_PASSWORD})
        self.assertEqual(response.status_code, 200)
        self.assertContains(response, "Successfully logged in as alex")

    def test_crypto_lab_login_rejects_wrong_password(self):
        CF_user.objects.filter(username="alex").update(
            password=hash_lab_password(self.LAB_PASSWORD))
        response = self.client.post(reverse("cryptographic_failure_lab"),
                                    {"username": "alex", "password": "wrong-password"})
        self.assertEqual(response.status_code, 200)
        self.assertNotContains(response, "Successfully logged in as alex")

    @override_settings(CSRF_LAB_JWT_SECRET="unit-test-signing-key")
    def test_csrf_lab_login_accepts_configured_password(self):
        CSRF_user_tbl.objects.create(username="susUser2878",
                                     password=hash_lab_password(self.LAB_PASSWORD),
                                     balance=1000)
        response = self.client.post(reverse("csrf_lab_login"),
                                    {"username": "susUser2878",
                                     "password": self.LAB_PASSWORD})
        self.assertEqual(response.status_code, 302)
        self.assertEqual(response["Location"], "/mitre/9/lab/transaction")
        self.assertIn("auth_cookiee", response.cookies)

    @override_settings(CSRF_LAB_JWT_SECRET="unit-test-signing-key")
    def test_csrf_lab_login_rejects_wrong_password(self):
        CSRF_user_tbl.objects.create(username="susUser2878",
                                     password=hash_lab_password(self.LAB_PASSWORD),
                                     balance=1000)
        response = self.client.post(reverse("csrf_lab_login"),
                                    {"username": "susUser2878",
                                     "password": "wrong-password"})
        self.assertEqual(response.status_code, 302)
        self.assertEqual(response["Location"], "/mitre/9/lab/login")
        self.assertNotIn("auth_cookiee", response.cookies)


# DEBUG=False + django-heroku's manifest static storage makes {% static %} fail
# without collectstatic, so mirror tests_platform.py and force plain storage.
@override_settings(
    DEBUG=True,
    STATICFILES_STORAGE="django.contrib.staticfiles.storage.StaticFilesStorage",
)
class CsrfProtectionTests(TestCase):
    """Regression tests for the removal of @csrf_exempt (CWE-352).

    These routes used to opt out of Django's CSRF protection. They must now
    reject state changing requests that carry no token, while still working for
    a normal browser session that submits the token rendered by the
    ``{% csrf_token %}`` template tag.
    """

    PASSWORD = "Str0ng-Passw0rd!"

    # One entry per view that carried @csrf_exempt.
    PROTECTED_VIEWS = (
        views.xxe_see, views.xxe_parse, views.ba, views.ba_lab,
        views.cmd_lab, views.cmd_lab2, views.Otp, views.a9_lab,
        views.a9_lab2, views.a1_broken_access, views.a1_broken_access_lab_1,
        views.a1_broken_access_lab_2, views.injection, views.injection_sql_lab,
        views.auth_failure_lab3,
        apis.ssrf_code_checker, apis.log_function_checker,
        apis.A7_disscussion_api, apis.A6_disscussion_api,
        apis.A6_disscussion_api_2,
        mitre.csrf_transfer_monei, mitre.mitre_lab_25_api,
        mitre.mitre_lab_17_api,
        log_function_target,
    )

    # Routes whose unsafe requests must now be rejected without a token.
    UNSAFE_ROUTES = (
        "/ba_lab",
        "/cmd_lab",
        "/cmd_lab2",
        "/otp",
        "/a9_lab",
        "/a9_lab2",
        "/broken_access_lab_1",
        "/broken_access_lab_2",
        "/injection_sql_lab",
        "/xxe_parse",
        "/mitre/17/lab/api",
        "/mitre/25/lab/api",
        "/2021/discussion/A6/api",
        "/2021/discussion/A6/api2",
        "/2021/discussion/A7/api",
        "/2021/discussion/A9/target",
    )

    def setUp(self):
        self.user = User.objects.create_user(username="csrfuser",
                                            password=self.PASSWORD)

    def enforcing_client(self):
        client = Client(enforce_csrf_checks=True)
        client.force_login(self.user)
        return client

    def test_no_view_is_csrf_exempt(self):
        for view in self.PROTECTED_VIEWS:
            self.assertFalse(getattr(view, "csrf_exempt", False),
                             msg=getattr(view, "__name__", repr(view)))

    def test_post_without_token_is_rejected(self):
        client = self.enforcing_client()
        for url in self.UNSAFE_ROUTES:
            self.assertEqual(client.post(url, {}).status_code, 403, msg=url)

    def test_form_page_renders_token_and_post_with_token_succeeds(self):
        """A normal browser session still completes the lab flow."""
        client = self.enforcing_client()
        page = client.get("/cmd_lab")
        self.assertEqual(page.status_code, 200)
        self.assertContains(page, "csrfmiddlewaretoken")
        token = page.cookies["csrftoken"].value
        response = client.post("/cmd_lab", {"domain": "example.com; id",
                                            "os": "nix",
                                            "csrfmiddlewaretoken": token})
        self.assertEqual(response.status_code, 200)
        self.assertContains(response, "Invalid domain name")

    def test_api_accepts_token_in_header(self):
        """The fetch/XHR callers send the token in the X-CSRFToken header."""
        client = self.enforcing_client()
        page = client.get("/mitre/25/lab")
        self.assertEqual(page.status_code, 200)
        token = page.cookies["csrftoken"].value
        response = client.post("/mitre/25/lab/api", {"expression": "7*7"},
                               HTTP_X_CSRFTOKEN=token)
        self.assertEqual(response.status_code, 200)
        self.assertEqual(response.json()["result"], 49)


class TemplateCsrfTokenTests(SimpleTestCase):
    """Every hand written POST form must carry ``{% csrf_token %}`` (CWE-352).

    Django only injects the hidden ``csrfmiddlewaretoken`` input where the tag
    is present, so a POST form without it is rejected by
    ``CsrfViewMiddleware``. Writing the tag with HTML entities
    (``{&#37; csrf_token &#37;}``) looks right in a browser but leaves no tag in
    the template, which is how these forms regressed before; this scan compares
    the template source, so that spelling fails again.
    """

    TEMPLATE_ROOT = Path(__file__).resolve().parent / "templates"
    FORM_RE = re.compile(r"<form\b[^>]*>.*?</form>", re.DOTALL | re.IGNORECASE)
    POST_METHOD_RE = re.compile(r"""method\s*=\s*["']?post""", re.IGNORECASE)
    CSRF_TAG_RE = re.compile(r"{%\s*csrf_token\s*%}")

    def test_every_post_form_declares_a_csrf_token(self):
        missing = []
        for template in sorted(self.TEMPLATE_ROOT.rglob("*.html")):
            source = template.read_text(encoding="utf-8")
            for form in self.FORM_RE.finditer(source):
                block = form.group(0)
                if not self.POST_METHOD_RE.search(block):
                    continue
                if self.CSRF_TAG_RE.search(block):
                    continue
                line = source.count("\n", 0, form.start()) + 1
                missing.append(
                    f"{template.relative_to(self.TEMPLATE_ROOT)}:{line}")
        self.assertEqual(
            missing, [],
            msg="POST forms without a csrf_token tag: " + ", ".join(missing))


# DEBUG=False + django-heroku's manifest static storage makes {% static %} fail
# without collectstatic, so mirror tests_platform.py and force plain storage.
@override_settings(
    DEBUG=True,
    STATICFILES_STORAGE="django.contrib.staticfiles.storage.StaticFilesStorage",
)
class SsrfDiscussionSampleCodeTests(TestCase):
    """The SSRF discussion page teaches the fixed ``ssrf_lab.html`` markup.

    Its four sample forms hold ``{% csrf_token %}`` inside ``{% verbatim %}``
    blocks, so the tag reaches the student as literal lesson text instead of
    being rendered into the textarea. These assertions pin both halves of that:
    the text is shown verbatim, and no real token is expanded inside the sample.
    """

    PASSWORD = "Str0ng-Passw0rd!"

    def setUp(self):
        self.user = User.objects.create_user(username="ssrfuser",
                                            password=self.PASSWORD)
        self.client.force_login(self.user)

    def test_sample_forms_show_the_csrf_tag_as_text(self):
        response = self.client.get("/ssrf_discussion")
        self.assertEqual(response.status_code, 200)
        body = response.content.decode()
        # One literal tag per sample form, printed rather than rendered.
        self.assertEqual(body.count("{% csrf_token %}"), 4)
        self.assertNotIn("{&#37; csrf_token &#37;}", body)

    def test_sample_textarea_holds_no_expanded_token(self):
        response = self.client.get("/ssrf_discussion")
        body = response.content.decode()
        textarea = body.split('<textarea id="html">')[1].split("</textarea>")[0]
        self.assertIn("{% csrf_token %}", textarea)
        self.assertNotIn("csrfmiddlewaretoken", textarea)


# DEBUG=False + django-heroku's manifest static storage makes {% static %} fail
# without collectstatic, so mirror tests_platform.py and force plain storage.
@override_settings(
    DEBUG=True,
    STATICFILES_STORAGE="django.contrib.staticfiles.storage.StaticFilesStorage",
)
class AuthLabResponseEscapingTests(TestCase):
    """Regression tests for the broken auth lab responses (CWE-79).

    Signup, login and logout used to build the page with ``render_to_string``
    and hand the finished markup to ``HttpResponse``, bypassing Django's XSS
    defences. They now return the autoescaping template response itself, so an
    attacker controlled name/username is echoed as inert text and template
    syntax is never evaluated server side.
    """

    SCRIPT_PAYLOAD = "<script>alert(1)</script>"
    ESCAPED_SCRIPT = "&lt;script&gt;alert(1)&lt;/script&gt;"
    TEMPLATE_PAYLOAD = "{{7*7}}"
    PASSWORD = "L4b-P@ssw0rd!"

    def assertPayloadIsInert(self, response):
        self.assertEqual(response.status_code, 200)
        body = response.content.decode()
        # Escaped, so the browser never sees an executable script element.
        self.assertNotIn(self.SCRIPT_PAYLOAD, body)
        self.assertIn(self.ESCAPED_SCRIPT, body)
        # Rendered as data, not as template source: no server side evaluation.
        self.assertIn(self.TEMPLATE_PAYLOAD, body)
        self.assertNotIn("49", body)

    def signup(self):
        return self.client.post(reverse("auth_lab_signup"),
                                {"name": self.SCRIPT_PAYLOAD,
                                 "username": self.TEMPLATE_PAYLOAD,
                                 "pass": self.PASSWORD})

    def test_signup_escapes_attacker_controlled_fields(self):
        response = self.signup()
        self.assertPayloadIsInert(response)
        self.assertIn("userid", response.cookies)

    def test_login_by_cookie_escapes_stored_fields(self):
        self.signup()
        obj = authLogin.objects.get(username=self.TEMPLATE_PAYLOAD)
        self.client.cookies["userid"] = obj.userid
        self.assertPayloadIsInert(self.client.get(reverse("auth_lab_login")))

    def test_login_by_credentials_escapes_stored_fields(self):
        self.signup()
        response = self.client.post(reverse("auth_lab_login"),
                                    {"username": self.TEMPLATE_PAYLOAD,
                                     "pass": self.PASSWORD})
        self.assertPayloadIsInert(response)

    def test_logout_renders_template_and_clears_cookie(self):
        self.signup()
        response = self.client.get(reverse("auth_lab_logout"))
        self.assertEqual(response.status_code, 200)
        self.assertContains(response, "Logout successful")
        self.assertEqual(response.cookies["userid"].value, "")


class LabFileWriteGuardTests(SimpleTestCase):
    """Unit tests for the guards around lab file writes (CWE-93).

    Several labs store text a student posted in a file. The submission is size
    capped so a caller cannot fill the disk or roll a large file over, the
    destination is resolved inside a fixed directory, and the content is written
    in one step instead of being appended to an existing file.
    """

    def test_accepts_text_within_the_limit(self):
        self.assertEqual(validate_submitted_text("print(1)", 32), "print(1)")
        self.assertEqual(validate_submitted_text("", 32), "")

    def test_rejects_oversize_text(self):
        with self.assertRaises(SubmittedContentTooLargeError):
            validate_submitted_text("a" * 33, 32)
        # The cap is on encoded bytes, so multi byte characters count fully.
        with self.assertRaises(SubmittedContentTooLargeError):
            validate_submitted_text("é" * 17, 32)

    def test_rejects_missing_or_non_text_content(self):
        for value in (None, 42, b"bytes", ["code"]):
            with self.assertRaises(SubmittedContentTooLargeError, msg=repr(value)):
                validate_submitted_text(value, 32)

    def test_resolves_a_bare_name_inside_the_directory(self):
        with TemporaryDirectory() as tmp:
            target = resolve_inside_directory(tmp, "utility.py")
            self.assertEqual(os.path.dirname(target), os.path.realpath(tmp))
            self.assertEqual(os.path.basename(target), "utility.py")

    def test_rejects_names_that_leave_the_directory(self):
        with TemporaryDirectory() as tmp:
            for name in ("../settings.py", "../../etc/passwd", "sub/utility.py",
                         "/etc/passwd", "..", ".", "", "   ", None, 7):
                with self.assertRaises(UnsafeWritePathError, msg=repr(name)):
                    resolve_inside_directory(tmp, name)

    def test_rejects_a_symlink_pointing_outside_the_directory(self):
        with TemporaryDirectory() as tmp, TemporaryDirectory() as outside:
            secret = os.path.join(outside, "secret.txt")
            with open(secret, "w", encoding="utf-8") as handle:
                handle.write("secret")
            try:
                os.symlink(secret, os.path.join(tmp, "utility.py"))
            except (OSError, NotImplementedError):
                self.skipTest("symlinks are not supported on this platform")
            with self.assertRaises(UnsafeWritePathError):
                resolve_inside_directory(tmp, "utility.py")

    def test_atomic_write_replaces_content_and_leaves_no_partial_file(self):
        with TemporaryDirectory() as tmp:
            target = os.path.join(tmp, "main.py")
            write_text_atomically(target, "first")
            write_text_atomically(target, "second")
            with open(target, encoding="utf-8") as handle:
                # Replaced, never appended to the file that was already there.
                self.assertEqual(handle.read(), "second")
            self.assertEqual(os.listdir(tmp), ["main.py"])

    def test_exclusive_write_never_touches_an_existing_file(self):
        with TemporaryDirectory() as tmp:
            target = os.path.join(tmp, "blog.txt")
            write_text_exclusively(target, "body")
            with self.assertRaises(FileExistsError):
                write_text_exclusively(target, "overwritten")
            with open(target, encoding="utf-8") as handle:
                self.assertEqual(handle.read(), "body")


class FilterBlogTests(SimpleTestCase):
    """``filter_blog`` used to return its input unchanged.

    It is the sanitiser the SSTI lab runs a blog body through, so it must now
    actually neutralise Django template syntax (CWE-1336).
    """

    DELIMITERS = ("{%", "%}", "{{", "}}", "{#", "#}")

    def test_strips_template_constructs(self):
        cleaned = filter_blog("hi {{7*7}} {% load log %}{# note #} there")
        for delimiter in self.DELIMITERS:
            self.assertNotIn(delimiter, cleaned)
        self.assertIn("hi", cleaned)
        self.assertIn("there", cleaned)

    def test_strips_unbalanced_delimiters(self):
        for payload in ("{% load log", "7*7}}", "{{ 7*7", "{#", "#}"):
            cleaned = filter_blog(payload)
            for delimiter in self.DELIMITERS:
                self.assertNotIn(delimiter, cleaned, msg=payload)

    def test_keeps_plain_text_and_fails_closed_on_non_text(self):
        self.assertEqual(filter_blog("a normal blog post"), "a normal blog post")
        self.assertEqual(filter_blog(None), "")


# DEBUG=False + django-heroku's manifest static storage makes {% static %} fail
# without collectstatic, so mirror tests_platform.py and force plain storage.
@override_settings(
    DEBUG=True,
    STATICFILES_STORAGE="django.contrib.staticfiles.storage.StaticFilesStorage",
)
class PlaygroundCodeWriteTests(TestCase):
    """Regression tests for the playground code editors (CWE-93).

    ``/2021/discussion/A9/api`` and ``/2021/discussion/A6/api2`` store the code
    a student submits in the playground package the labs import. They used to
    pass the posted body straight to ``open(...).write()``, so an unauthenticated
    caller could write an unbounded amount of data into those files. They now
    require a session, cap the submission and write to a destination pinned to
    the playground directory.
    """

    PASSWORD = "Str0ng-Passw0rd!"
    APP_DIR = os.path.dirname(os.path.abspath(views.__file__))

    def setUp(self):
        self.user = User.objects.create_user(username="playgrounduser",
                                             password=self.PASSWORD)

    def logged_in_client(self, enforce_csrf_checks=False):
        client = Client(enforce_csrf_checks=enforce_csrf_checks)
        client.force_login(self.user)
        return client

    def read(self, path):
        with open(path, encoding="utf-8") as handle:
            return handle.read()

    def test_destinations_are_pinned_inside_the_playground_directory(self):
        playground = os.path.realpath(os.path.join(self.APP_DIR, "playground"))
        targets = {
            resolve_inside_directory(apis.A9_PLAYGROUND_DIR, "main.py"),
            resolve_inside_directory(apis.A9_PLAYGROUND_DIR, "api.py"),
            resolve_inside_directory(apis.A6_PLAYGROUND_DIR, "utility.py"),
        }
        self.assertEqual(len(targets), 3)
        for target in targets:
            self.assertTrue(target.startswith(playground + os.sep), msg=target)
            self.assertTrue(os.path.exists(target), msg=target)

    def test_a9_api_requires_a_session(self):
        target = os.path.join(apis.A9_PLAYGROUND_DIR, "main.py")
        before = self.read(target)
        response = Client().post("/2021/discussion/A9/api",
                                 {"log_code": "print(1)", "api_code": "print(2)"})
        self.assertEqual(response.status_code, 401)
        self.assertEqual(self.read(target), before)

    def test_a9_api_rejects_oversize_code(self):
        target = os.path.join(apis.A9_PLAYGROUND_DIR, "main.py")
        before = self.read(target)
        response = self.logged_in_client().post(
            "/2021/discussion/A9/api",
            {"log_code": "a" * (MAX_LAB_CODE_BYTES + 1), "api_code": "print(2)"})
        self.assertEqual(response.status_code, 400)
        self.assertEqual(self.read(target), before)

    def test_a9_api_rejects_a_missing_field(self):
        target = os.path.join(apis.A9_PLAYGROUND_DIR, "api.py")
        before = self.read(target)
        response = self.logged_in_client().post("/2021/discussion/A9/api",
                                                {"log_code": "print(1)"})
        self.assertEqual(response.status_code, 400)
        self.assertEqual(self.read(target), before)

    def test_a6_api2_requires_a_session(self):
        target = os.path.join(apis.A6_PLAYGROUND_DIR, "utility.py")
        before = self.read(target)
        response = Client().post("/2021/discussion/A6/api2", {"code": "print(1)"})
        self.assertEqual(response.status_code, 401)
        self.assertEqual(self.read(target), before)

    def test_a6_api2_stores_submitted_code(self):
        code = "def check_vuln(modules):\n    return []\n"
        with TemporaryDirectory() as tmp:
            target = os.path.join(tmp, "utility.py")
            write_text_atomically(target, "# original\n")
            with patch.object(apis, "A6_PLAYGROUND_DIR", tmp):
                response = self.logged_in_client().post("/2021/discussion/A6/api2",
                                                        {"code": code})
            self.assertEqual(response.status_code, 200)
            self.assertEqual(response.json()["message"], "success")
            self.assertEqual(self.read(target), code)
            # Replaced in place: no leftover temporary file, nothing else written.
            self.assertEqual(os.listdir(tmp), ["utility.py"])

    def test_a6_api2_rejects_oversize_code(self):
        with TemporaryDirectory() as tmp:
            target = os.path.join(tmp, "utility.py")
            write_text_atomically(target, "# original\n")
            with patch.object(apis, "A6_PLAYGROUND_DIR", tmp):
                response = self.logged_in_client().post(
                    "/2021/discussion/A6/api2",
                    {"code": "a" * (MAX_LAB_CODE_BYTES + 1)})
            self.assertEqual(response.status_code, 400)
            self.assertEqual(self.read(target), "# original\n")
            self.assertEqual(os.listdir(tmp), ["utility.py"])

    def test_a6_api2_still_accepts_the_fetch_callers_csrf_token(self):
        """The a6.js flow (session cookie + X-CSRFToken header) keeps working."""
        client = self.logged_in_client(enforce_csrf_checks=True)
        page = client.get("/2021/discussion/A6")
        self.assertEqual(page.status_code, 200)
        self.assertContains(page, "csrfmiddlewaretoken")
        token = page.cookies["csrftoken"].value
        with TemporaryDirectory() as tmp:
            write_text_atomically(os.path.join(tmp, "utility.py"), "# original\n")
            with patch.object(apis, "A6_PLAYGROUND_DIR", tmp):
                response = client.post("/2021/discussion/A6/api2",
                                       {"code": "print(1)\n"},
                                       HTTP_X_CSRFTOKEN=token)
            self.assertEqual(response.status_code, 200)
            self.assertEqual(self.read(os.path.join(tmp, "utility.py")), "print(1)\n")


# DEBUG=False + django-heroku's manifest static storage makes {% static %} fail
# without collectstatic, so mirror tests_platform.py and force plain storage.
@override_settings(
    DEBUG=True,
    STATICFILES_STORAGE="django.contrib.staticfiles.storage.StaticFilesStorage",
)
class SstiBlogWriteTests(TestCase):
    """Regression tests for the SSTI lab blog writer (CWE-93/CWE-1336).

    A blog body used to be pasted into a generated Django template file that was
    then rendered, so posted template syntax executed on the server. The body is
    now size capped, stripped of template syntax, stored as data in a dedicated
    directory outside the template search path, and printed through an
    autoescaped context variable.
    """

    PASSWORD = "Str0ng-Passw0rd!"
    PAYLOAD = ("{{7*7}}{% load log %}{% get_admin_log 5 as log %}"
               "<script>alert(1)</script>")
    # Captured before the per test patch below replaces it with a temp dir.
    REAL_BLOG_DIR = views.SSTI_BLOG_DIR

    def setUp(self):
        self.user = User.objects.create_user(username="sstiuser",
                                            password=self.PASSWORD)
        self.client.force_login(self.user)
        blog_dir = TemporaryDirectory()
        self.addCleanup(blog_dir.cleanup)
        self.blog_dir = blog_dir.name
        patcher = patch.object(views, "SSTI_BLOG_DIR", self.blog_dir)
        patcher.start()
        self.addCleanup(patcher.stop)

    def post_blog(self, body):
        return self.client.post("/ssti/lab", {"blog": body})

    def shown_body(self, response):
        """The text inside the blog element, so page chrome is not matched."""
        block = response.content.decode().split('class="ssti-blog-body"')[1]
        return block.split(">", 1)[1].split("</pre>")[0]

    def test_blog_directory_is_outside_the_template_search_path(self):
        app_dir = os.path.realpath(os.path.dirname(os.path.abspath(views.__file__)))
        templates = os.path.join(app_dir, "templates")
        blog_dir = os.path.realpath(self.REAL_BLOG_DIR)
        # A stored body must never be reachable by the template loader.
        self.assertTrue(blog_dir.startswith(app_dir + os.sep), msg=blog_dir)
        self.assertFalse(blog_dir.startswith(templates + os.sep), msg=blog_dir)

    def test_template_payload_is_stored_as_data_and_not_evaluated(self):
        response = self.post_blog(self.PAYLOAD)
        self.assertEqual(response.status_code, 302)
        blog_id = response["Location"].rsplit("/", 1)[-1]
        self.assertEqual(Blogs.objects.filter(blog_id=blog_id).count(), 1)

        stored = os.listdir(self.blog_dir)
        self.assertEqual(stored, ["%s.txt" % blog_id])
        body = Path(self.blog_dir, stored[0]).read_text(encoding="utf-8")
        for delimiter in ("{%", "%}", "{{", "}}"):
            self.assertNotIn(delimiter, body)

        page = self.client.get("/ssti/blog/%s" % blog_id)
        self.assertEqual(page.status_code, 200)
        shown = self.shown_body(page)
        # Displayed as data: the expression was never evaluated ...
        self.assertNotIn("49", shown)
        self.assertNotIn("{{7*7}}", shown)
        # ... and the markup is escaped rather than executed in the browser.
        self.assertNotIn("<script>alert(1)</script>", page.content.decode())
        self.assertIn("&lt;script&gt;alert(1)&lt;/script&gt;", shown)

    def test_normal_blog_round_trips(self):
        response = self.post_blog("a normal blog post")
        self.assertEqual(response.status_code, 302)
        blog_id = response["Location"].rsplit("/", 1)[-1]
        stored = os.path.join(self.blog_dir, "%s.txt" % blog_id)
        self.assertEqual(os.listdir(self.blog_dir), ["%s.txt" % blog_id])
        self.assertTrue(os.path.realpath(stored).startswith(
            os.path.realpath(self.blog_dir) + os.sep))
        page = self.client.get("/ssti/blog/%s" % blog_id)
        self.assertEqual(page.status_code, 200)
        self.assertIn("a normal blog post", self.shown_body(page))

    def test_oversize_blog_is_rejected(self):
        response = self.post_blog("a" * (MAX_BLOG_BODY_BYTES + 1))
        self.assertEqual(response.status_code, 400)
        self.assertEqual(os.listdir(self.blog_dir), [])
        self.assertEqual(Blogs.objects.count(), 0)

    def test_missing_blog_field_is_rejected(self):
        response = self.client.post("/ssti/lab", {})
        self.assertEqual(response.status_code, 400)
        self.assertEqual(os.listdir(self.blog_dir), [])
        self.assertEqual(Blogs.objects.count(), 0)

    def test_anonymous_caller_cannot_write_a_blog(self):
        response = Client().post("/ssti/lab", {"blog": "x"})
        self.assertEqual(response.status_code, 302)
        self.assertEqual(os.listdir(self.blog_dir), [])
        self.assertEqual(Blogs.objects.count(), 0)

    def test_ids_that_are_not_generated_blog_ids_are_refused(self):
        for blog_id in ("main", "utility", "0db9c0e7093z", "0DB9C0E7093D",
                        "0db9c0e7093", "0db9c0e7093dd", "settings"):
            response = self.client.get("/ssti/blog/%s" % blog_id)
            self.assertEqual(response.status_code, 404, msg=blog_id)
