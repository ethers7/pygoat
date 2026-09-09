import importlib
import json
import os
import re
import uuid
from unittest import mock

from django.contrib.auth.models import User
from django.test import SimpleTestCase, TestCase

from .models import authLogin, comments
from .utility import (MAX_OUTBOUND_RESPONSE_BYTES, read_bounded_body,
                      read_lab_file, safe_eval_arithmetic, safe_lab_path,
                      safe_lab_source, safe_lab_text, safe_outbound_url,
                      safe_parse_comment_xml, write_lab_file)

# A publicly routable literal used as an allowlisted destination so the tests
# never depend on DNS resolution.
PUBLIC_TEST_HOST = "1.1.1.1"


def streamed_response(is_redirect=False, headers=None, chunks=()):
    """A requests response double usable as the context manager the views open.

    Bodies are only exposed through iter_content(), like a real stream=True
    response, so a test cannot accidentally assert on an unbounded .content read.
    """
    response = mock.MagicMock()
    response.__enter__.return_value = response
    response.is_redirect = is_redirect
    response.headers = headers or {}
    response.iter_content.return_value = list(chunks)
    return response


class SafeOutboundUrlTests(SimpleTestCase):
    """Regression tests for the SSRF destination guard (CWE-918)."""

    @mock.patch.dict(os.environ, {"PYGOAT_ALLOWED_FETCH_HOSTS": PUBLIC_TEST_HOST})
    def test_allows_allowlisted_public_host(self):
        self.assertEqual(
            safe_outbound_url("http://%s/blog?id=2#frag" % PUBLIC_TEST_HOST),
            "http://%s/blog?id=2" % PUBLIC_TEST_HOST)

    @mock.patch.dict(
        os.environ,
        {"PYGOAT_ALLOWED_FETCH_HOSTS": "127.0.0.1,169.254.169.254,10.0.0.5,192.168.1.1,::1"})
    def test_rejects_internal_addresses_even_when_allowlisted(self):
        for url in (
                "http://127.0.0.1/",
                "http://169.254.169.254/latest/meta-data/",
                "http://10.0.0.5/admin",
                "http://192.168.1.1/",
                "http://[::1]/"):
            with self.subTest(url=url):
                self.assertIsNone(safe_outbound_url(url))

    @mock.patch.dict(os.environ, {"PYGOAT_ALLOWED_FETCH_HOSTS": PUBLIC_TEST_HOST})
    def test_rejects_host_outside_allowlist(self):
        self.assertIsNone(safe_outbound_url("http://not-allowlisted.example.org/"))

    @mock.patch.dict(os.environ, {"PYGOAT_ALLOWED_FETCH_HOSTS": PUBLIC_TEST_HOST})
    def test_rejects_non_http_schemes(self):
        for url in (
                "file:///etc/passwd",
                "gopher://%s/" % PUBLIC_TEST_HOST,
                "ftp://%s/" % PUBLIC_TEST_HOST,
                "HTTP+unix://%s/" % PUBLIC_TEST_HOST):
            with self.subTest(url=url):
                self.assertIsNone(safe_outbound_url(url))

    @mock.patch.dict(os.environ, {"PYGOAT_ALLOWED_FETCH_HOSTS": PUBLIC_TEST_HOST})
    def test_rejects_embedded_credentials_and_odd_ports(self):
        self.assertIsNone(safe_outbound_url("http://%s@127.0.0.1/" % PUBLIC_TEST_HOST))
        self.assertIsNone(safe_outbound_url("http://%s:2375/containers/json" % PUBLIC_TEST_HOST))

    @mock.patch.dict(os.environ, {"PYGOAT_ALLOWED_FETCH_HOSTS": PUBLIC_TEST_HOST})
    def test_rejects_empty_and_non_string_values(self):
        for value in (None, "", "   ", 42):
            with self.subTest(value=value):
                self.assertIsNone(safe_outbound_url(value))


class SsrfLab2ViewTests(TestCase):
    """The lab view must fail closed instead of fetching internal targets."""

    def setUp(self):
        self.user = User.objects.create_user(username="ssrf_lab_tester")
        self.client.force_login(self.user)

    @mock.patch("introduction.views.requests.get")
    def test_metadata_url_is_rejected_without_any_request(self, mocked_get):
        response = self.client.post("/ssrf_lab2", {"url": "http://169.254.169.254/latest/meta-data/"})

        self.assertEqual(response.status_code, 200)
        self.assertContains(response, "URL rejected")
        mocked_get.assert_not_called()

    @mock.patch("introduction.views.requests.get")
    def test_loopback_url_is_rejected_without_any_request(self, mocked_get):
        response = self.client.post("/ssrf_lab2", {"url": "http://127.0.0.1:80/ssrf_target"})

        self.assertEqual(response.status_code, 200)
        self.assertContains(response, "URL rejected")
        mocked_get.assert_not_called()

    @mock.patch.dict(os.environ, {"PYGOAT_ALLOWED_FETCH_HOSTS": PUBLIC_TEST_HOST})
    @mock.patch("introduction.views.requests.get")
    def test_redirect_to_internal_address_is_not_followed(self, mocked_get):
        mocked_get.return_value = streamed_response(
            is_redirect=True,
            headers={"location": "http://169.254.169.254/latest/meta-data/"})

        response = self.client.post("/ssrf_lab2", {"url": "http://%s/blog" % PUBLIC_TEST_HOST})

        self.assertEqual(response.status_code, 200)
        self.assertContains(response, "URL rejected")
        self.assertEqual(mocked_get.call_count, 1)

    @mock.patch.dict(os.environ, {"PYGOAT_ALLOWED_FETCH_HOSTS": PUBLIC_TEST_HOST})
    @mock.patch("introduction.views.requests.get")
    def test_allowlisted_target_is_fetched_with_timeout(self, mocked_get):
        mocked_get.return_value = streamed_response(chunks=[b"blog ", b"body"])

        response = self.client.post("/ssrf_lab2", {"url": "http://%s/blog" % PUBLIC_TEST_HOST})

        self.assertEqual(response.status_code, 200)
        self.assertContains(response, "blog body")
        args, kwargs = mocked_get.call_args
        self.assertEqual(args[0], "http://%s/blog" % PUBLIC_TEST_HOST)
        self.assertFalse(kwargs["allow_redirects"])
        # An explicit (connect, read) timeout and a streamed body keep a slow or
        # endless target from exhausting the worker (CWE-400).
        self.assertEqual(len(kwargs["timeout"]), 2)
        self.assertTrue(all(kwargs["timeout"]))
        self.assertTrue(kwargs["stream"])

    @mock.patch.dict(os.environ, {"PYGOAT_ALLOWED_FETCH_HOSTS": PUBLIC_TEST_HOST})
    @mock.patch("introduction.views.requests.get")
    def test_oversized_response_body_is_rejected_instead_of_buffered(self, mocked_get):
        chunk = b"x" * (64 * 1024)
        oversized = [chunk] * (MAX_OUTBOUND_RESPONSE_BYTES // len(chunk) + 1)
        mocked_get.return_value = streamed_response(chunks=oversized)

        response = self.client.post("/ssrf_lab2", {"url": "http://%s/blog" % PUBLIC_TEST_HOST})

        self.assertEqual(response.status_code, 200)
        self.assertContains(response, "Response rejected")
        self.assertNotContains(response, "xxxx")


class ReadBoundedBodyTests(SimpleTestCase):
    """Regression tests for the bounded response reader (CWE-400)."""

    def test_returns_the_whole_body_when_it_fits(self):
        self.assertEqual(
            read_bounded_body(streamed_response(chunks=[b"ab", b"", b"cd"])), b"abcd")

    def test_returns_none_once_the_limit_is_exceeded(self):
        self.assertIsNone(
            read_bounded_body(streamed_response(chunks=[b"abc", b"de"]), max_bytes=4))

    def test_stops_reading_instead_of_draining_an_endless_stream(self):
        def endless():
            while True:
                yield b"x" * 1024

        response = mock.MagicMock()
        response.iter_content.return_value = endless()

        self.assertIsNone(read_bounded_body(response, max_bytes=4096))


EXTERNAL_ENTITY_XML = (
    "<?xml version='1.0'?>"
    "<!DOCTYPE comm [<!ELEMENT comm (#PCDATA)>"
    " <!ENTITY xxe SYSTEM 'file:///etc/passwd'>]>"
    "<comm><text>&xxe;</text></comm>")

BILLION_LAUGHS_XML = (
    "<?xml version='1.0'?>"
    "<!DOCTYPE comm ["
    "<!ENTITY a 'aaaaaaaaaa'>"
    "<!ENTITY b '&a;&a;&a;&a;&a;&a;&a;&a;&a;&a;'>"
    "<!ENTITY c '&b;&b;&b;&b;&b;&b;&b;&b;&b;&b;'>]>"
    "<comm><text>&c;</text></comm>")


class SafeParseCommentXmlTests(SimpleTestCase):
    """Regression tests for the defused XML comment parser (CWE-611)."""

    def test_parses_well_formed_document(self):
        self.assertEqual(
            safe_parse_comment_xml("<comm><text>hello world</text></comm>"),
            "hello world")

    def test_parses_well_formed_bytes_body(self):
        self.assertEqual(
            safe_parse_comment_xml(b"<comm><text>hello bytes</text></comm>"),
            "hello bytes")

    def test_rejects_external_entity_document(self):
        with self.assertRaises(ValueError):
            safe_parse_comment_xml(EXTERNAL_ENTITY_XML)

    def test_rejects_entity_expansion_document(self):
        with self.assertRaises(ValueError):
            safe_parse_comment_xml(BILLION_LAUGHS_XML)

    def test_rejects_malformed_oversized_and_non_text_documents(self):
        for value in (
                "<comm><text>unclosed</comm>",
                "<comm><other>no text element</other></comm>",
                "<comm><text>%s</text></comm>" % ("a" * (64 * 1024)),
                b"\xff\xfe not utf-8",
                None,
                42):
            with self.subTest(value=type(value)):
                with self.assertRaises(ValueError):
                    safe_parse_comment_xml(value)


class XxeParseViewTests(TestCase):
    """The lab still stores well formed comments but refuses XXE payloads."""

    def setUp(self):
        self.comment = comments.objects.create(name="System", comment="original comment")

    def _stored_comment(self):
        return comments.objects.get(pk=self.comment.pk).comment

    def test_external_entity_payload_is_rejected(self):
        response = self.client.post(
            "/xxe_parse", data=EXTERNAL_ENTITY_XML, content_type="text/xml")

        self.assertEqual(response.status_code, 400)
        self.assertContains(response, "Comment rejected", status_code=400)
        self.assertNotContains(response, "root:", status_code=400)
        self.assertEqual(self._stored_comment(), "original comment")

    def test_entity_expansion_payload_is_rejected(self):
        response = self.client.post(
            "/xxe_parse", data=BILLION_LAUGHS_XML, content_type="text/xml")

        self.assertEqual(response.status_code, 400)
        self.assertContains(response, "Comment rejected", status_code=400)
        self.assertEqual(self._stored_comment(), "original comment")

    def test_well_formed_comment_is_accepted(self):
        response = self.client.post(
            "/xxe_parse",
            data="<comm><text>a harmless comment</text></comm>",
            content_type="text/xml")

        self.assertEqual(response.status_code, 200)
        self.assertNotContains(response, "Comment rejected")


# Payloads that reach arbitrary code execution when an expression is handed to
# eval()/exec() (CWE-95).
CODE_INJECTION_PAYLOADS = (
    "__import__('os').popen('id').read()",
    "__import__('subprocess').check_output(['id'])",
    "().__class__.__bases__[0].__subclasses__()",
    "open('/etc/passwd').read()",
    "eval('1+1')",
    "globals()",
    "[x for x in range(3)]",
    "'a'*10",
    "f'{7*7}'",
    "1 if print('side effect') else 2",
    "lambda: 1",
    "7*7 ; 8*8",
)


class SafeEvalArithmeticTests(SimpleTestCase):
    """Regression tests for the restricted expression evaluator (CWE-95)."""

    def test_evaluates_allowed_arithmetic(self):
        for expression, expected in (
                ("7*7", 49),
                (" 1 + 2 * 3 ", 7),
                ("(4 + 6) / 4", 2.5),
                ("7 // 2", 3),
                ("7 % 4", 3),
                ("2 ** 10", 1024),
                ("-5 + +3", -2),
                ("1.5 * 2", 3.0)):
            with self.subTest(expression=expression):
                self.assertEqual(safe_eval_arithmetic(expression), expected)

    def test_rejects_code_execution_payloads(self):
        for expression in CODE_INJECTION_PAYLOADS:
            with self.subTest(expression=expression):
                with self.assertRaises(ValueError):
                    safe_eval_arithmetic(expression)

    def test_rejects_names_attributes_calls_and_subscripts(self):
        for expression in (
                "settings",
                "(1).__class__",
                "abs(-1)",
                "[1, 2][0]",
                "{'a': 1}",
                "True and False",
                "1 < 2"):
            with self.subTest(expression=expression):
                with self.assertRaises(ValueError):
                    safe_eval_arithmetic(expression)

    def test_bounds_input_size_and_resource_exhaustion(self):
        for expression in (
                "1+" * 200 + "1",
                "9" * 200,
                "2 ** 99999999",
                "10 ** 18 * 10 ** 18",
                "1 / 0",
                "1 % 0"):
            with self.subTest(expression=expression):
                with self.assertRaises(ValueError):
                    safe_eval_arithmetic(expression)

    def test_rejects_empty_and_non_string_values(self):
        for value in (None, "", "   ", 42, b"7*7"):
            with self.subTest(value=value):
                with self.assertRaises(ValueError):
                    safe_eval_arithmetic(value)


class CmdLab2ViewTests(TestCase):
    """The eval lab still calculates, but refuses non arithmetic expressions."""

    def setUp(self):
        self.user = User.objects.create_user(username="cmd_lab2_tester")
        self.client.force_login(self.user)

    def test_arithmetic_expression_is_evaluated(self):
        response = self.client.post("/cmd_lab2", {"val": "7*7"})

        self.assertEqual(response.status_code, 200)
        self.assertContains(response, "49")

    def test_code_execution_payloads_are_rejected(self):
        for payload in CODE_INJECTION_PAYLOADS:
            with self.subTest(payload=payload):
                response = self.client.post("/cmd_lab2", {"val": payload})

                self.assertEqual(response.status_code, 200)
                self.assertContains(response, "Expression rejected")
                self.assertNotContains(response, "uid=")


XSS_SCRIPT_PAYLOAD = "<script>alert('xss')</script>"
ESCAPED_SCRIPT_PREFIX = "&lt;script&gt;"
# Not a credential: the broken-auth lab model stores an opaque value, and the
# tests only need a non-empty one.
LAB_FIXTURE_SECRETLESS_VALUE = "lab-fixture-value"


class AuthLabXssTests(TestCase):
    """The broken-auth lab must reflect names/usernames HTML escaped (CWE-79).

    The views used to hand a pre-rendered string to a bare ``HttpResponse``;
    they now return ``render(...)`` so Django's autoescaping applies to every
    reflected, attacker controlled value.
    """

    def _assert_payload_is_escaped(self, response):
        self.assertEqual(response.status_code, 200)
        self.assertNotContains(response, XSS_SCRIPT_PAYLOAD)
        self.assertContains(response, ESCAPED_SCRIPT_PREFIX)

    def test_signup_escapes_reflected_name(self):
        response = self.client.post(
            "/auth_lab/signup",
            {
                "name": XSS_SCRIPT_PAYLOAD,
                "username": "auth_xss_signup",
                "pass": LAB_FIXTURE_SECRETLESS_VALUE,
            })

        self._assert_payload_is_escaped(response)

    def test_cookie_login_escapes_stored_name(self):
        stored = authLogin.objects.create(
            name=XSS_SCRIPT_PAYLOAD,
            username="auth_xss_cookie",
            password=LAB_FIXTURE_SECRETLESS_VALUE)
        self.client.cookies["userid"] = str(stored.userid)

        response = self.client.get("/auth_lab/login")

        self._assert_payload_is_escaped(response)

    def test_post_login_escapes_stored_name(self):
        authLogin.objects.create(
            name=XSS_SCRIPT_PAYLOAD,
            username="auth_xss_post",
            password=LAB_FIXTURE_SECRETLESS_VALUE)

        response = self.client.post(
            "/auth_lab/login",
            {"username": "auth_xss_post", "pass": LAB_FIXTURE_SECRETLESS_VALUE})

        self._assert_payload_is_escaped(response)

    def test_logout_still_renders_confirmation(self):
        response = self.client.get("/auth_lab/logout")

        self.assertEqual(response.status_code, 200)
        self.assertContains(response, "Logout successful")


class MitreLab25ApiViewTests(TestCase):
    """The calculator API fails closed instead of evaluating Python code."""

    def test_arithmetic_expression_is_evaluated(self):
        response = self.client.post("/mitre/25/lab/api", {"expression": "6*7"})

        self.assertEqual(response.status_code, 200)
        self.assertEqual(response.json()["result"], 42)

    def test_code_execution_payloads_are_rejected(self):
        for payload in CODE_INJECTION_PAYLOADS:
            with self.subTest(payload=payload):
                response = self.client.post(
                    "/mitre/25/lab/api", {"expression": payload})

                self.assertEqual(response.status_code, 400)
                body = response.json()
                self.assertIn("Expression rejected", body["error"])
                self.assertIn("Expression rejected", body["result"])

    def test_missing_expression_is_rejected(self):
        response = self.client.post("/mitre/25/lab/api", {})

        self.assertEqual(response.status_code, 400)
        self.assertIn("Expression rejected", response.json()["error"])


FORM_TAG_RE = re.compile(r"<form\b[^>]*>", re.IGNORECASE)
POST_METHOD_RE = re.compile(r"""method\s*=\s*["']?post""", re.IGNORECASE)
# Either the template tag or the field name it renders (scripts that POST read
# the field back and resend it as an X-CSRFToken header, see js/csrf.js).
CSRF_TOKEN_RE = re.compile(r"{%\s*csrf_token\s*%}|csrfmiddlewaretoken")

_INTRODUCTION_DIR = os.path.dirname(os.path.abspath(__file__))
_PROJECT_DIR = os.path.dirname(_INTRODUCTION_DIR)
# Template roots of this Django project. The Flask labs under dockerized_labs/
# are separate applications with their own CSRF handling and are not rendered by
# the Django engine, so they are out of this suite's scope.
DJANGO_TEMPLATE_ROOTS = (
    os.path.join(_INTRODUCTION_DIR, "templates"),
    os.path.join(_PROJECT_DIR, "challenge", "templates"),
)


def post_forms_without_csrf_token(source):
    """Return the 1-based line of every POST <form> that renders no CSRF token."""
    offending_lines = []
    for match in FORM_TAG_RE.finditer(source):
        if not POST_METHOD_RE.search(match.group(0)):
            continue
        closing = source.lower().find("</form>", match.end())
        body = source[match.end():closing if closing != -1 else len(source)]
        if not CSRF_TOKEN_RE.search(body):
            offending_lines.append(source[:match.start()].count("\n") + 1)
    return offending_lines


class TemplateCsrfTokenTests(SimpleTestCase):
    """Every manually written POST form must carry a csrf_token (CWE-352).

    Django's CsrfViewMiddleware rejects a POST without the token, so a form that
    omits it is both broken and the pattern that made the labs exploitable
    while the views were decorated with @csrf_exempt.
    """

    def _django_templates(self):
        for root in DJANGO_TEMPLATE_ROOTS:
            self.assertTrue(os.path.isdir(root), "missing template root %s" % root)
            for dirpath, _dirnames, filenames in os.walk(root):
                for filename in sorted(filenames):
                    if filename.endswith(".html"):
                        yield os.path.join(dirpath, filename)

    def test_every_post_form_renders_a_csrf_token(self):
        checked_forms = 0
        offenders = {}
        for template in self._django_templates():
            with open(template, encoding="utf-8") as handle:
                source = handle.read()
            checked_forms += len(
                [tag for tag in FORM_TAG_RE.findall(source) if POST_METHOD_RE.search(tag)])
            missing = post_forms_without_csrf_token(source)
            if missing:
                offenders[os.path.relpath(template, _PROJECT_DIR)] = missing

        self.assertEqual(offenders, {})
        # Guards against a walk that silently stops finding templates.
        self.assertGreaterEqual(checked_forms, 30)

    def test_detector_reports_a_form_that_omits_the_token(self):
        self.assertEqual(
            post_forms_without_csrf_token('<form method="post">\n<input>\n</form>'), [1])
        self.assertEqual(
            post_forms_without_csrf_token(
                '<form method="post">{% csrf_token %}<input></form>'), [])
        # A GET form needs no token.
        self.assertEqual(post_forms_without_csrf_token('<form method="get"></form>'), [])


BLOGS_RELATIVE_DIR = "templates/Lab_2021/A3_Injection/Blogs"


class SafeLabFileWriteTests(SimpleTestCase):
    """Regression tests for the lab file write guards (CWE-93 / CWE-73).

    Request data used to be written to disk verbatim, so a value could carry CR
    line endings (forging records in the file it lands in) or NUL/escape
    sequences. Every lab write now goes through these helpers.
    """

    def test_folds_cr_and_crlf_line_endings(self):
        self.assertEqual(
            safe_lab_text("first\r\nsecond\rthird\n"), "first\nsecond\nthird\n")

    def test_drops_other_control_characters(self):
        self.assertEqual(safe_lab_text("audit\x00log\x07entry\x1b"), "auditlogentry")

    def test_keeps_tabs_newlines_and_non_ascii_text(self):
        self.assertEqual(safe_lab_text("\tprint('héllo')\n"),
                         "\tprint('héllo')\n")

    def test_rejects_missing_non_text_and_oversized_content(self):
        for value in (None, b"bytes are not text", 42):
            with self.subTest(value=repr(value)):
                with self.assertRaises(ValueError):
                    safe_lab_text(value)
        with self.assertRaises(ValueError):
            safe_lab_text("x" * 10, max_bytes=9)

    def test_source_guard_accepts_python_and_rejects_everything_else(self):
        self.assertEqual(
            safe_lab_source("def f():\r\n    return 1\r\n"), "def f():\n    return 1\n")
        for payload in ("def broken(: ???", "}{", "class:", "return 1\r\n  return 2"):
            with self.subTest(payload=repr(payload)):
                with self.assertRaises(ValueError):
                    safe_lab_source(payload)

    def test_write_rejects_destinations_outside_the_allowlisted_directories(self):
        for destination in (
                "",
                "manage.py",
                "../../evil.py",
                "playground/A9/../../../evil.py",
                "playground/A9/nested/evil.py",
                "/tmp/evil.py"):
            with self.subTest(destination=destination):
                with self.assertRaises(ValueError):
                    write_lab_file(destination, "x = 1\n")

    def test_write_neutralises_content_inside_an_allowlisted_directory(self):
        relative = "%s/regression-%s.html" % (BLOGS_RELATIVE_DIR, uuid.uuid4().hex)

        written = write_lab_file(relative, "line\r\nnext\x00\r")

        self.addCleanup(os.remove, written)
        with open(written, encoding="utf-8", newline="") as handle:
            self.assertEqual(handle.read(), "line\nnext\n")


class LabFileWriteViewTests(TestCase):
    """The lab writers must neutralise request data instead of writing it raw."""

    def setUp(self):
        self.user = User.objects.create_user(username="lab_write_tester")
        self.client.force_login(self.user)

    def test_ssti_blog_is_written_without_control_characters(self):
        response = self.client.post("/ssti/lab", {"blog": "hello\r\nworld\x00!"})

        self.assertEqual(response.status_code, 302)
        blog_id = response["Location"].rsplit("/", 1)[-1]
        written = os.path.join(
            _INTRODUCTION_DIR, *BLOGS_RELATIVE_DIR.split("/"), "%s.txt" % blog_id)
        self.addCleanup(os.remove, written)
        with open(written, encoding="utf-8", newline="") as handle:
            body = handle.read()

        self.assertNotIn("\r", body)
        self.assertNotIn("\x00", body)
        self.assertEqual(body, "hello\nworld!")

    def test_oversized_blog_is_rejected_without_writing_a_file(self):
        blogs_dir = os.path.join(_INTRODUCTION_DIR, *BLOGS_RELATIVE_DIR.split("/"))
        before = set(os.listdir(blogs_dir))

        response = self.client.post("/ssti/lab", {"blog": "A" * (64 * 1024 + 1)})

        self.assertEqual(response.status_code, 200)
        self.assertContains(response, "Blog rejected")
        self.assertEqual(set(os.listdir(blogs_dir)), before)

    def test_a9_log_checker_rejects_unparseable_code_and_keeps_the_module(self):
        module = os.path.join(_INTRODUCTION_DIR, "playground", "A9", "main.py")
        with open(module, encoding="utf-8") as handle:
            before = handle.read()

        response = self.client.post(
            "/2021/discussion/A9/api",
            {"log_code": "def broken(: ???", "api_code": "def f():\n    pass\n"})

        self.assertEqual(response.status_code, 400)
        self.assertIn("invalid code", response.json()["message"])
        with open(module, encoding="utf-8") as handle:
            self.assertEqual(handle.read(), before)

    def test_a6_api_rejects_unparseable_code_and_keeps_the_module(self):
        module = os.path.join(_INTRODUCTION_DIR, "playground", "A6", "utility.py")
        with open(module, encoding="utf-8") as handle:
            before = handle.read()

        response = self.client.post("/2021/discussion/A6/api2", {"code": "import ???"})

        self.assertEqual(response.status_code, 400)
        self.assertIn("invalid code", response.json()["message"])
        with open(module, encoding="utf-8") as handle:
            self.assertEqual(handle.read(), before)

    def test_a6_api_still_saves_valid_code_neutralised_at_the_fixed_lab_path(self):
        submitted = "def check_vuln(packages):\r\n    return []\r\n"

        with mock.patch("introduction.apis.write_lab_file") as mocked_write:
            response = self.client.post("/2021/discussion/A6/api2", {"code": submitted})

        self.assertEqual(response.status_code, 200)
        self.assertEqual(response.json()["message"], "success")
        mocked_write.assert_called_once_with(
            "playground/A6/utility.py", "def check_vuln(packages):\n    return []\n")


class SstiBlogRenderingTests(TestCase):
    """The stored blog must come back escaped, as data (CWE-79).

    The submitted body used to be concatenated into Django template source
    ("{% extends ... %}" + blog) that was written to disk and then rendered as a
    template, so submitted markup was served as live HTML and template tags were
    executed. The body is now stored as plain text and printed by
    ``ssti_blog.html`` through the template engine.
    """

    def setUp(self):
        self.user = User.objects.create_user(username="ssti_blog_tester")
        self.client.force_login(self.user)

    def _post_blog(self, body):
        """Store a blog and return its id, removing the stored file afterwards."""
        response = self.client.post("/ssti/lab", {"blog": body})

        self.assertEqual(response.status_code, 302)
        blog_id = response["Location"].rsplit("/", 1)[-1]
        self.addCleanup(os.remove, self._stored_path(blog_id))
        return blog_id

    @staticmethod
    def _stored_path(blog_id):
        return os.path.join(
            _INTRODUCTION_DIR, *BLOGS_RELATIVE_DIR.split("/"), "%s.txt" % blog_id)

    def test_script_payload_comes_back_escaped(self):
        blog_id = self._post_blog(XSS_SCRIPT_PAYLOAD)

        response = self.client.get("/ssti/blog/%s" % blog_id)

        self.assertEqual(response.status_code, 200)
        self.assertNotContains(response, XSS_SCRIPT_PAYLOAD)
        self.assertNotContains(response, "<script>alert")
        self.assertContains(response, ESCAPED_SCRIPT_PREFIX)

    def test_stored_blog_is_plain_text_not_template_source(self):
        blog_id = self._post_blog(XSS_SCRIPT_PAYLOAD)

        with open(self._stored_path(blog_id), encoding="utf-8") as handle:
            stored = handle.read()

        self.assertEqual(stored, XSS_SCRIPT_PAYLOAD)
        self.assertNotIn("{% extends", stored)
        self.assertNotIn("{% block", stored)

    def test_template_syntax_in_a_blog_is_not_evaluated(self):
        blog_id = self._post_blog("{{ 7 * 191 }} and {{ settings.SECRET_KEY }}")

        response = self.client.get("/ssti/blog/%s" % blog_id)

        self.assertEqual(response.status_code, 200)
        self.assertNotContains(response, "1337")
        self.assertContains(response, "{{ 7 * 191 }}")

    def test_blog_body_is_still_served_to_its_author(self):
        blog_id = self._post_blog("a harmless blog body")

        response = self.client.get("/ssti/blog/%s" % blog_id)

        self.assertContains(response, "a harmless blog body")

    def test_unknown_blog_is_refused_instead_of_loading_a_template(self):
        response = self.client.get("/ssti/blog/does-not-exist")

        self.assertContains(response, "No blog found", status_code=404)

    def test_blog_reader_stays_inside_the_lab_blog_directory(self):
        from .views import (SSTI_BLOG_DIR, SSTI_BLOG_EXTENSION,
                            ssti_blog_relative_path)

        for payload in ("../../../../manage.py",
                        "../../../../../../etc/passwd",
                        "/etc/passwd",
                        "../ssti_lab"):
            with self.subTest(payload=payload):
                self.assertIsNone(
                    read_lab_file(
                        ssti_blog_relative_path(payload),
                        allowed_dirs=(SSTI_BLOG_DIR,),
                        allowed_extensions=(SSTI_BLOG_EXTENSION,)))


class A6DependencyCheckerTests(SimpleTestCase):
    """The A6 lab's PyPI lookups must be bounded (CWE-400).

    Both the importable lab module and the reference solution it ships with are
    checked, since the lab replaces the former with the learner's submission.
    """

    MODULE_NAMES = (
        "introduction.playground.A6.utility",
        "introduction.playground.A6.soln",
    )

    def test_every_lookup_carries_a_timeout_and_streams_the_body(self):
        body = json.dumps({"vulnerabilities": [{"id": "PYSEC-0000-1"}]}).encode("utf-8")
        for name in self.MODULE_NAMES:
            module = importlib.import_module(name)
            with self.subTest(module=name):
                with mock.patch.object(module.requests, "get") as mocked_get:
                    mocked_get.return_value = streamed_response(chunks=[body])
                    result = module.check_vuln(["requests==2.28.0"])

                self.assertEqual(result, [[{"id": "PYSEC-0000-1"}]])
                args, kwargs = mocked_get.call_args
                self.assertEqual(args[0], "https://pypi.org/pypi/requests/2.28.0/json")
                self.assertEqual(len(kwargs["timeout"]), 2)
                self.assertTrue(all(kwargs["timeout"]))
                self.assertTrue(kwargs["stream"])

    def test_oversized_pypi_response_is_refused_instead_of_buffered(self):
        chunk = b"x" * 1024
        for name in self.MODULE_NAMES:
            module = importlib.import_module(name)
            with self.subTest(module=name):
                oversized = [chunk] * (module.MAX_PYPI_RESPONSE_BYTES // len(chunk) + 1)
                with mock.patch.object(module.requests, "get") as mocked_get:
                    mocked_get.return_value = streamed_response(chunks=oversized)
                    with self.assertRaises(ValueError):
                        module.check_vuln(["requests==2.28.0"])


BLOGS_READ_RELATIVE_DIR = "templates/Lab/ssrf/blogs"
_BLOGS_READ_DIR = os.path.join(
    _INTRODUCTION_DIR, *BLOGS_READ_RELATIVE_DIR.split("/"))

# Destinations the blog reader must never open: parent directory traversal, an
# absolute path (os.path.join() replaces the base directory with it outright),
# percent encoded variants of both - the request body is decoded once by Django,
# so a further decode inside the guard would re-create the traversal - and files
# that do exist in this project but outside the allowlisted blog directory.
BLOG_TRAVERSAL_PAYLOADS = (
    "../../etc/passwd",
    "../../../../../../etc/passwd",
    "templates/Lab/ssrf/blogs/../../../../../../etc/passwd",
    "/etc/passwd",
    "//etc/passwd",
    "..%2f..%2fetc%2fpasswd",
    "%2e%2e/%2e%2e/etc/passwd",
    "templates/Lab/ssrf/blogs/%2e%2e/secret.txt",
    "templates/Lab/ssrf/secret.txt",
    "playground/ssrf/secret.txt",
    "../manage.py",
    "../pygoat/settings.py",
    "../.env",
    "templates/Lab/ssrf/blogs",
    "",
    "   ",
)


class SafeLabFileReadTests(SimpleTestCase):
    """Regression tests for the lab file read guard (CWE-22).

    The blog reader used to join the request supplied name onto this package's
    directory and open the result, so "../../etc/passwd" - or any absolute path,
    which os.path.join() substitutes for the base outright - was read back to the
    caller. Reads now resolve through safe_lab_path()/read_lab_file(), which
    confine the result to the allowlisted blog directory.
    """

    def test_reads_a_blog_from_the_allowlisted_directory(self):
        blog = os.path.join(_BLOGS_READ_DIR, "blog1.txt")
        with open(blog, encoding="utf-8") as handle:
            expected = handle.read()
        relative = "%s/blog1.txt" % BLOGS_READ_RELATIVE_DIR

        self.assertEqual(safe_lab_path(relative), os.path.realpath(blog))
        self.assertEqual(read_lab_file(relative), expected)

    def test_rejects_traversal_absolute_and_encoded_destinations(self):
        for payload in BLOG_TRAVERSAL_PAYLOADS:
            with self.subTest(payload=payload):
                self.assertIsNone(safe_lab_path(payload))
                self.assertIsNone(read_lab_file(payload))

    def test_rejects_non_text_null_byte_and_absent_destinations(self):
        for payload in (None, 42, b"blog1.txt", ["blog1.txt"],
                        "%s/blog1.txt\x00" % BLOGS_READ_RELATIVE_DIR,
                        "%s/does-not-exist.txt" % BLOGS_READ_RELATIVE_DIR):
            with self.subTest(payload=repr(payload)):
                self.assertIsNone(safe_lab_path(payload))
                self.assertIsNone(read_lab_file(payload))

    def test_rejects_an_extension_outside_the_allowlist(self):
        name = "regression-%s.py" % uuid.uuid4().hex
        created = os.path.join(_BLOGS_READ_DIR, name)
        with open(created, "w", encoding="utf-8") as handle:
            handle.write("SECRET = 1\n")
        self.addCleanup(os.remove, created)
        relative = "%s/%s" % (BLOGS_READ_RELATIVE_DIR, name)

        self.assertIsNone(safe_lab_path(relative))
        self.assertIsNone(read_lab_file(relative))

    def test_rejects_a_symlink_that_escapes_the_blog_directory(self):
        outside = os.path.join(_PROJECT_DIR, "manage.py")
        name = "regression-%s.txt" % uuid.uuid4().hex
        link = os.path.join(_BLOGS_READ_DIR, name)
        try:
            os.symlink(outside, link)
        except (AttributeError, NotImplementedError, OSError) as error:
            self.skipTest("symlinks are unavailable here: %s" % error)
        self.addCleanup(os.remove, link)
        relative = "%s/%s" % (BLOGS_READ_RELATIVE_DIR, name)

        self.assertIsNone(safe_lab_path(relative))
        self.assertIsNone(read_lab_file(relative))

    def test_read_is_size_bounded(self):
        relative = "%s/blog1.txt" % BLOGS_READ_RELATIVE_DIR

        self.assertEqual(len(read_lab_file(relative, max_bytes=8)), 8)


class SsrfLabBlogReadViewTests(TestCase):
    """The blog reader lab must serve allowlisted blogs and nothing else."""

    def setUp(self):
        self.user = User.objects.create_user(username="blog_read_tester")
        self.client.force_login(self.user)

    def test_allowlisted_blog_is_still_served(self):
        with open(os.path.join(_BLOGS_READ_DIR, "blog1.txt"),
                  encoding="utf-8") as handle:
            first_line = handle.read().splitlines()[0]

        response = self.client.post(
            "/ssrf_lab", {"blog": "%s/blog1.txt" % BLOGS_READ_RELATIVE_DIR})

        self.assertEqual(response.status_code, 200)
        self.assertContains(response, first_line)

    def test_traversal_payloads_are_refused_without_leaking_file_contents(self):
        for payload in BLOG_TRAVERSAL_PAYLOADS:
            with self.subTest(payload=payload):
                response = self.client.post("/ssrf_lab", {"blog": payload})

                self.assertContains(response, "No blog found", status_code=404)
                self.assertNotContains(response, "root:", status_code=404)
                self.assertNotContains(
                    response, "DJANGO_SETTINGS_MODULE", status_code=404)

    def test_missing_blog_parameter_is_refused_instead_of_erroring(self):
        response = self.client.post("/ssrf_lab", {})

        self.assertContains(response, "No blog found", status_code=404)

    def test_get_still_renders_the_lab(self):
        response = self.client.get("/ssrf_lab")

        self.assertEqual(response.status_code, 200)
