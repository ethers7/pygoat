from django.test import SimpleTestCase, TestCase, override_settings
from django.urls import reverse

from .models import comments
from .utility import (UnsafeExpressionError, UnsafeUrlError,
                      safe_arithmetic_eval, validate_public_url)

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
