import hashlib
import os
import shutil
import tempfile
from unittest import mock

from django.test import SimpleTestCase, TestCase
from django.urls import reverse

from .models import comments
from .utility import (LAB_CODE_MAX_BYTES, LabCodeRejected, UnsafeExpression,
                      customHash, ensure_password_hash, hash_password,
                      is_password_hash, lab_code_path, safe_arithmetic_eval,
                      validate_fetch_url, validate_lab_code, verify_password,
                      write_lab_code)


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

    def test_rejects_results_that_are_not_a_calculator_answer(self):
        """The operand bounds must not let an unusable value out.

        Such a value used to escape as an unhandled TypeError/ValueError when
        the view serialised or rendered it (a 500, and a debug page), instead
        of being reported as an invalid expression.
        """
        # A negative base with a fractional exponent yields a complex number.
        for payload in ("(-1) ** 0.5", "(-8) ** (1 / 3)", "(-2) ** 0.5 * 2"):
            with self.assertRaises(UnsafeExpression, msg=payload):
                safe_arithmetic_eval(payload)
        # Non-finite floats (inf / nan) are not serialisable as valid JSON.
        for payload in ("1e1000", "1e1000 * 0", "1e308 * 10", "-1e1000"):
            with self.assertRaises(UnsafeExpression, msg=payload):
                safe_arithmetic_eval(payload)
        # A product of individually allowed powers is still bounded: this is
        # 4455 digits, which str()/json.dumps() refuse to convert.
        with self.assertRaises(UnsafeExpression):
            safe_arithmetic_eval("*".join(["999**99"] * 15))
        # Big-but-usable answers keep working, and stay printable.
        self.assertEqual(len(str(safe_arithmetic_eval("999 ** 99"))), 297)


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


class LabCodeWriteTests(SimpleTestCase):
    """Submitted coding-ground code is bounded, parseable and written safely.

    These helpers do not sandbox the submitted code (running it is the
    exercise); they make sure the *write* cannot be steered by the request and
    cannot leave a broken shared module behind.
    """

    VALID = "def check_vuln(mods):\n    return []\n"

    def setUp(self):
        self.root = tempfile.mkdtemp()
        self.addCleanup(shutil.rmtree, self.root, True)
        for package in ("A6", "A9"):
            os.mkdir(os.path.join(self.root, package))
        patcher = mock.patch("introduction.utility._LAB_CODE_ROOT", self.root)
        patcher.start()
        self.addCleanup(patcher.stop)

    def test_only_allowlisted_targets_resolve(self):
        self.assertEqual(lab_code_path("A6_utility"),
                         os.path.join(self.root, "A6", "utility.py"))
        for target in ("../../settings.py", "playground/A6/utility.py", "", None, 1):
            with self.assertRaises(LabCodeRejected, msg=repr(target)):
                lab_code_path(target)

    def test_rejects_missing_oversized_and_unparseable_code(self):
        for code in (None, "", "   ", 42):
            with self.assertRaises(LabCodeRejected, msg=repr(code)):
                validate_lab_code(code)
        with self.assertRaises(LabCodeRejected):
            validate_lab_code("x = 1\n" + "# pad\n" * LAB_CODE_MAX_BYTES)
        for code in ("def broken(:\n", "class A\n", "x = \x00"):
            with self.assertRaises(LabCodeRejected, msg=repr(code)):
                validate_lab_code(code)

    def test_accepts_a_normal_submission_and_installs_it_atomically(self):
        path = write_lab_code("A6_utility", self.VALID)
        self.assertEqual(path, os.path.join(self.root, "A6", "utility.py"))
        with open(path, encoding="utf-8") as handle:
            self.assertEqual(handle.read(), self.VALID)
        # No temporary leftovers next to the module a running app imports.
        self.assertEqual(os.listdir(os.path.join(self.root, "A6")), ["utility.py"])

    def test_a_rejected_submission_leaves_the_previous_module_untouched(self):
        path = write_lab_code("A9_log", self.VALID)
        with self.assertRaises(LabCodeRejected):
            write_lab_code("A9_log", "def broken(:\n")
        with open(path, encoding="utf-8") as handle:
            self.assertEqual(handle.read(), self.VALID)


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
