import hashlib
import os
import shutil
import tempfile
from unittest import mock

from django.test import SimpleTestCase, TestCase, override_settings
from django.urls import reverse

from .models import comments
from .utility import (LAB_CODE_MAX_BYTES, BlogNotAllowed, LabCodeRejected,
                      UnsafeExpression, blog_path, customHash,
                      ensure_password_hash, hash_password, is_password_hash,
                      lab_code_path, safe_arithmetic_eval,
                      secure_cookies_enabled, validate_fetch_url,
                      validate_lab_code, verify_password, write_lab_code)


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


class SecureCookiesEnabledTests(SimpleTestCase):
    """Lab cookies are Secure by default; opting out has to be explicit."""

    def _with_env(self, value):
        with mock.patch.dict(os.environ, {"PYGOAT_INSECURE_COOKIES": value}):
            return secure_cookies_enabled()

    def test_secure_by_default(self):
        environ = dict(os.environ)
        environ.pop("PYGOAT_INSECURE_COOKIES", None)
        with mock.patch.dict(os.environ, environ, clear=True):
            self.assertTrue(secure_cookies_enabled())

    def test_documented_values_opt_out(self):
        for value in ("1", "true", "TRUE", "Yes", "on", " on "):
            self.assertFalse(self._with_env(value), msg=value)

    def test_anything_else_keeps_the_secure_default(self):
        for value in ("", "   ", "0", "false", "no", "off", "maybe", "secure"):
            self.assertTrue(self._with_env(value), msg=value)

    @override_settings(SESSION_COOKIE_SECURE=True)
    def test_https_only_settings_cannot_be_downgraded_by_the_opt_out(self):
        self.assertTrue(self._with_env("1"))

    @override_settings(SECURE_SSL_REDIRECT=True)
    def test_ssl_redirect_settings_cannot_be_downgraded_by_the_opt_out(self):
        self.assertTrue(self._with_env("1"))


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


class LabBlogPathTests(SimpleTestCase):
    """The SSRF/LFI lab may only ever open a blog file of that lab (CWE-22).

    The blog name comes from a request. Joining it onto a server directory and
    opening the result read any file the app user could: "../.env" walked out
    of the blogs directory and os.path.join() dropped the base entirely for an
    absolute name. Reading the lab's own blogs must keep working.
    """

    BLOGS = ("blog1.txt", "blog2.txt", "blog3.txt", "blog4.txt")
    SUFFIX = os.path.join("templates", "Lab", "ssrf", "blogs")

    def test_the_blogs_of_the_lab_still_resolve(self):
        for name in self.BLOGS:
            path = blog_path(name)
            self.assertTrue(os.path.isfile(path), path)
            self.assertEqual(os.path.dirname(path)[-len(self.SUFFIX):], self.SUFFIX)
            self.assertEqual(os.path.basename(path), name)

    def test_rejects_traversal_absolute_and_malformed_names(self):
        for name in ("../.env", "../../.env", "../../pygoat/settings.py",
                     "/etc/passwd", "/etc/shadow", "..\\.env", "C:\\secret.txt",
                     "....//....//.env", "..%2f.env", "%2e%2e/.env",
                     "blogs/blog1.txt", "./blog1.txt", "blog1.txt\x00.env",
                     "blog1.txt ", " blog1.txt", "blog1.py", ".env", "-blog1.txt",
                     "", "   ", None, 1, b"blog1.txt"):
            with self.assertRaises(BlogNotAllowed, msg=repr(name)):
                blog_path(name)

    def test_rejects_a_well_formed_name_that_is_not_a_blog(self):
        # secret.txt of this lab sits one directory above the blogs directory.
        for name in ("secret.txt", "blog99.txt"):
            with self.assertRaises(BlogNotAllowed, msg=name):
                blog_path(name)

    def test_rejects_a_symlink_that_leaves_the_blogs_directory(self):
        root = tempfile.mkdtemp()
        self.addCleanup(shutil.rmtree, root, True)
        blogs = os.path.join(root, "blogs")
        os.mkdir(blogs)
        outside = os.path.join(root, "credentials.txt")
        with open(outside, "w", encoding="utf-8") as handle:
            handle.write("SECRET_KEY=not-a-real-key")
        with open(os.path.join(blogs, "blog1.txt"), "w", encoding="utf-8") as handle:
            handle.write("a blog")
        os.symlink(outside, os.path.join(blogs, "blog9.txt"))
        os.symlink(root, os.path.join(blogs, "up.txt"))
        with mock.patch("introduction.utility._BLOG_ROOT", os.path.realpath(blogs)):
            self.assertEqual(os.path.basename(blog_path("blog1.txt")), "blog1.txt")
            # realpath() resolves the link before the containment check, so a
            # link planted inside the blogs directory cannot point outside it.
            for name in ("blog9.txt", "up.txt"):
                with self.assertRaises(BlogNotAllowed, msg=name):
                    blog_path(name)

    def test_rejects_a_directory_and_only_returns_regular_files(self):
        root = tempfile.mkdtemp()
        self.addCleanup(shutil.rmtree, root, True)
        os.mkdir(os.path.join(root, "notes.txt"))
        with mock.patch("introduction.utility._BLOG_ROOT", os.path.realpath(root)):
            with self.assertRaises(BlogNotAllowed):
                blog_path("notes.txt")


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

    def test_entity_payload_declaring_an_encoding_is_rejected_without_a_server_error(self):
        # Parsing a decoded str would raise ValueError on the encoding declaration
        # before the entity checks ran, leaking a traceback; this must be a 400.
        response = self._post('<?xml version="1.0" encoding="UTF-8"?>'
                              '<!DOCTYPE comm [<!ELEMENT comm (#PCDATA)>'
                              '<!ENTITY xxe SYSTEM "file:///etc/passwd">]>'
                              '<comm><text>&xxe;</text></comm>')
        self.assertEqual(response.status_code, 400)
        self.assertEqual(comments.objects.get(id=1).comment, "untouched")

    def test_benign_document_declaring_an_encoding_is_still_parsed(self):
        response = self._post('<?xml version="1.0" encoding="UTF-8"?>'
                              '<comm><text>hello world</text></comm>')
        self.assertEqual(response.status_code, 200)
        self.assertEqual(comments.objects.get(id=1).comment, "hello world")

    def test_oversized_comment_is_bounded_to_the_column_width(self):
        max_length = comments._meta.get_field("comment").max_length
        payload = "A" * (max_length + 50)
        response = self._post("<?xml version='1.0'?><comm><text>%s</text></comm>" % payload)
        self.assertEqual(response.status_code, 200)
        self.assertEqual(comments.objects.get(id=1).comment, "A" * max_length)
