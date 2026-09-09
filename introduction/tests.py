from django.contrib.auth.hashers import is_password_usable
from django.contrib.auth.models import User
from django.test import SimpleTestCase, TestCase, override_settings
from django.urls import reverse

from .models import CF_user, CSRF_user_tbl, comments
from .utility import (UnsafeExpressionError, UnsafeUrlError,
                      hash_lab_password, safe_arithmetic_eval,
                      validate_public_url, verify_lab_password)

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
