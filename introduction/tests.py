import os
from unittest import mock

from django.contrib.auth.models import User
from django.test import SimpleTestCase, TestCase

from .models import authLogin, comments
from .utility import (safe_eval_arithmetic, safe_outbound_url,
                      safe_parse_comment_xml)

# A publicly routable literal used as an allowlisted destination so the tests
# never depend on DNS resolution.
PUBLIC_TEST_HOST = "1.1.1.1"


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
        redirect_response = mock.Mock()
        redirect_response.is_redirect = True
        redirect_response.headers = {"location": "http://169.254.169.254/latest/meta-data/"}
        mocked_get.return_value = redirect_response

        response = self.client.post("/ssrf_lab2", {"url": "http://%s/blog" % PUBLIC_TEST_HOST})

        self.assertEqual(response.status_code, 200)
        self.assertContains(response, "URL rejected")
        self.assertEqual(mocked_get.call_count, 1)

    @mock.patch.dict(os.environ, {"PYGOAT_ALLOWED_FETCH_HOSTS": PUBLIC_TEST_HOST})
    @mock.patch("introduction.views.requests.get")
    def test_allowlisted_target_is_fetched_with_timeout(self, mocked_get):
        fetched = mock.Mock()
        fetched.is_redirect = False
        fetched.content = b"blog body"
        mocked_get.return_value = fetched

        response = self.client.post("/ssrf_lab2", {"url": "http://%s/blog" % PUBLIC_TEST_HOST})

        self.assertEqual(response.status_code, 200)
        self.assertContains(response, "blog body")
        args, kwargs = mocked_get.call_args
        self.assertEqual(args[0], "http://%s/blog" % PUBLIC_TEST_HOST)
        self.assertFalse(kwargs["allow_redirects"])
        self.assertTrue(kwargs["timeout"])


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
