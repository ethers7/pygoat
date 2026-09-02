"""Regression tests for the challenge container controls.

Focus: CWE-78. The docker calls made on behalf of a user must never be built
as a shell string, and the stored container reference must be validated before
it is handed to ``docker``.
"""
from unittest.mock import patch

from django.contrib.auth.models import User
from django.test import TestCase, override_settings

from .models import Challenge, UserChallenge
from .utility import safe_container_ref


class SafeContainerRefTests(TestCase):
    def test_accepts_plain_container_references(self):
        self.assertEqual(safe_container_ref("a1b2c3d4e5f6"), "a1b2c3d4e5f6")
        self.assertEqual(safe_container_ref(" " + "f" * 64 + " "), "f" * 64)
        self.assertEqual(safe_container_ref("pygoat_lab-1.0"), "pygoat_lab-1.0")

    def test_rejects_injection_and_option_payloads(self):
        for payload in (
            None,
            123,
            "",
            "   ",
            "abc123; id",
            "abc123 && whoami",
            "abc123 | cat /etc/passwd",
            "$(id)",
            "`id`",
            "abc123\nid",
            "abc123 --time 0",
            "-f",
            "../../etc/passwd",
        ):
            self.assertIsNone(safe_container_ref(payload), msg=repr(payload))


@override_settings(
    DEBUG=True,
    STATICFILES_STORAGE="django.contrib.staticfiles.storage.StaticFilesStorage",
)
class StopContainerTests(TestCase):
    PASSWORD = "Str0ng-Passw0rd!"

    def setUp(self):
        self.user = User.objects.create_user(
            username="chaluser",
            email="chaluser@example.com",
            password=self.PASSWORD,
        )
        self.challenge = Challenge.objects.create(
            name="lab1",
            description="demo",
            docker_image="pygoat/lab1",
            docker_port=8000,
            start_port=8000,
            end_port=8100,
            flag="flag{demo}",
            point=10,
        )
        self.client.force_login(self.user)

    def _user_challenge(self, container_id):
        return UserChallenge.objects.create(
            user=self.user,
            challenge=self.challenge,
            container_id=container_id,
            port=8001,
            is_live=True,
        )

    @patch("challenge.views.subprocess.Popen")
    def test_stop_uses_argv_without_shell(self, popen):
        popen.return_value.communicate.return_value = (b"", b"")
        user_chal = self._user_challenge("a1b2c3d4e5f6")

        response = self.client.delete("/challenge/lab1")

        self.assertEqual(response.status_code, 200)
        args, kwargs = popen.call_args
        self.assertEqual(args[0], ["docker", "stop", "a1b2c3d4e5f6"])
        self.assertFalse(kwargs.get("shell", False))
        user_chal.refresh_from_db()
        self.assertFalse(user_chal.is_live)

    @patch("challenge.views.subprocess.Popen")
    def test_stop_refuses_injected_container_reference(self, popen):
        popen.return_value.communicate.return_value = (b"", b"")
        self._user_challenge("a1b2c3d4e5f6; id")

        response = self.client.delete("/challenge/lab1")

        self.assertEqual(response.status_code, 200)
        self.assertEqual(response.json()["status"], "500")
        popen.assert_not_called()

    def test_stop_requires_authentication(self):
        self.client.logout()
        response = self.client.delete("/challenge/lab1")
        self.assertEqual(response.status_code, 302)
        self.assertIn("/login", response["Location"])
