import hashlib
import os
from unittest import mock

from django.test import SimpleTestCase, TestCase
from django.urls import reverse

from .models import comments
from .utility import (UnsafeExpression, customHash, ensure_password_hash,
                      hash_password, is_password_hash, safe_arithmetic_eval,
                      validate_fetch_url, verify_password)


class SafeArithmeticEvalTests(SimpleTestCase):
    """The calculator labs must compute arithmetic and never execute code."""

    def test_calculates_arithmetic_expressions(self):
        self.assertEqual(safe_arithmetic_eval("1 + 1"), 2)
        self.assertEqual(safe_arithmetic_eval("7*7"), 49)
        self.assertEqual(safe_arithmetic_eval(" (2 + 3) * -4 "), -20)
        self.assertEqual(safe_arithmetic_eval("7 % 4"), 3)
        self.assertEqual(safe_arithmetic_eval("7 // 2"), 3)
        self.assertEqual(safe_arithmetic_eval("2 ** 8"), 256)
        self.assertAlmostEqual(safe_arithmetic_eval("1.5 / 0.5"), 3.0)

    def test_rejects_code_execution_payloads(self):
        for payload in ("os.system('id')",
                        "__import__('os').system('id')",
                        "__import__('os').popen('id').read()",
                        "eval('1+1')",
                        "open('/etc/passwd').read()",
                        "().__class__.__bases__[0].__subclasses__()",
                        "[x for x in (1, 2)]",
                        "{'a': 1}",
                        "'abc' * 3",
                        "print(1)",
                        "1 if True else 2",
                        "FLAG",
                        "1 == 1",
                        "1 & 2",
                        "import os"):
            with self.assertRaises(UnsafeExpression, msg=payload):
                safe_arithmetic_eval(payload)

    def test_rejects_resource_exhaustion_and_bad_input(self):
        for payload in ("9 ** 9 ** 9", "10 ** 100000", "99999 ** 99999",
                        "1 / 0", "", "   ", "1 +", "1" * 200):
            with self.assertRaises(UnsafeExpression, msg=payload):
                safe_arithmetic_eval(payload)
        self.assertRaises(UnsafeExpression, safe_arithmetic_eval, None)


class ValidateFetchUrlTests(SimpleTestCase):
    """The SSRF lab2 fetch must only accept allowlisted public http(s) URLs."""

    def test_rejects_non_http_schemes(self):
        for url in ("file:///etc/passwd", "gopher://example.com/", "ftp://example.com/x"):
            self.assertIsNone(validate_fetch_url(url))

    def test_rejects_hosts_outside_the_allowlist(self):
        self.assertIsNone(validate_fetch_url("http://attacker.example.net/"))

    def test_rejects_internal_and_metadata_addresses(self):
        for url in ("http://127.0.0.1:8000/ssrf_target",
                    "http://169.254.169.254/latest/meta-data/",
                    "http://10.0.0.1/",
                    "http://[::1]/"):
            self.assertIsNone(validate_fetch_url(url))

    def test_rejects_allowlisted_host_resolving_to_a_private_address(self):
        with mock.patch.dict(os.environ, {"SSRF_ALLOWED_HOSTS": "localhost"}):
            self.assertIsNone(validate_fetch_url("http://localhost:80/ssrf_target"))

    def test_rejects_non_standard_ports_and_bad_input(self):
        self.assertIsNone(validate_fetch_url("http://example.com:8000/"))
        self.assertIsNone(validate_fetch_url("http://example.com:notaport/"))
        self.assertIsNone(validate_fetch_url(None))
        self.assertIsNone(validate_fetch_url(""))

    def test_accepts_allowlisted_host_and_drops_credentials_and_fragment(self):
        with mock.patch("introduction.utility._is_public_host", return_value=True):
            self.assertEqual(
                validate_fetch_url(" https://user:pass@example.com/page?q=1#frag "),
                "https://example.com/page?q=1")

    def test_credential_trick_pointing_at_metadata_is_rejected(self):
        self.assertIsNone(validate_fetch_url("http://example.com@169.254.169.254/"))


class LabPasswordHashingTests(SimpleTestCase):
    """Lab credentials must be stored with a salted KDF, never a fast digest."""

    PASSWORD = "P@$$w0rd"

    def test_hash_password_is_salted_and_not_a_bare_digest(self):
        first = hash_password(self.PASSWORD)
        second = hash_password(self.PASSWORD)
        self.assertNotEqual(first, self.PASSWORD)
        self.assertNotEqual(first, second)          # random per-password salt
        self.assertTrue(first.startswith("pbkdf2_sha256$"))
        self.assertNotIn(hashlib.md5(self.PASSWORD.encode()).hexdigest(), first)
        self.assertNotIn(hashlib.sha256(self.PASSWORD.encode()).hexdigest(), first)

    def test_verify_password_accepts_the_right_password_only(self):
        stored = hash_password(self.PASSWORD)
        self.assertTrue(verify_password(self.PASSWORD, stored))
        self.assertFalse(verify_password("wrong", stored))
        self.assertFalse(verify_password("", stored))
        self.assertFalse(verify_password(None, stored))

    def test_verify_password_rejects_legacy_and_cracked_digests(self):
        """A dumped MD5/SHA256 digest is not a credential and never verifies."""
        md5_digest = hashlib.md5(self.PASSWORD.encode()).hexdigest()
        sha1_digest = hashlib.sha1(self.PASSWORD.encode()).hexdigest()
        for stored in (md5_digest,
                       sha1_digest,
                       "md5$$" + md5_digest,
                       "sha1$$" + sha1_digest,
                       customHash(self.PASSWORD),
                       self.PASSWORD,
                       "",
                       None):
            self.assertFalse(is_password_hash(stored), msg=repr(stored))
            self.assertFalse(verify_password(self.PASSWORD, stored), msg=repr(stored))
            self.assertFalse(verify_password(md5_digest, stored), msg=repr(stored))

    def test_ensure_password_hash_hashes_plaintext_once(self):
        hashed = ensure_password_hash(self.PASSWORD)
        self.assertTrue(is_password_hash(hashed))
        self.assertTrue(verify_password(self.PASSWORD, hashed))
        self.assertEqual(ensure_password_hash(hashed), hashed)   # never double hashed
        self.assertEqual(ensure_password_hash(""), "")
        self.assertIsNone(ensure_password_hash(None))


class XxeParseTests(TestCase):
    """The XXE lab must still parse benign XML but refuse DTDs/external entities."""

    XXE_PAYLOAD = ("<?xml version='1.0'?>"
                   "<!DOCTYPE comm [<!ELEMENT comm (#PCDATA)>"
                   "<!ENTITY xxe SYSTEM 'file:///etc/passwd'>]>"
                   "<comm><text>&xxe;</text></comm>")

    def setUp(self):
        self.comment = comments.objects.create(id=1, name="System", comment="untouched")

    def _post(self, body):
        return self.client.post(reverse("xxe_parse"), data=body, content_type="text/xml")

    def test_benign_comment_is_parsed_and_stored(self):
        response = self._post("<?xml version='1.0'?><comm><text>hello world</text></comm>")
        self.assertEqual(response.status_code, 200)
        self.assertEqual(comments.objects.get(id=1).comment, "hello world")

    def test_external_entity_payload_is_rejected(self):
        response = self._post(self.XXE_PAYLOAD)
        self.assertEqual(response.status_code, 400)
        self.assertEqual(comments.objects.get(id=1).comment, "untouched")

    def test_document_without_text_element_is_rejected(self):
        response = self._post("<?xml version='1.0'?><comm></comm>")
        self.assertEqual(response.status_code, 400)
        self.assertEqual(comments.objects.get(id=1).comment, "untouched")
