from django.test import SimpleTestCase, TestCase, override_settings
from django.urls import reverse

from .models import comments
from .utility import UnsafeUrlError, validate_public_url

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
