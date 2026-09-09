import os
from unittest import mock

from django.contrib.auth.models import User
from django.test import SimpleTestCase, TestCase

from .utility import safe_outbound_url

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
