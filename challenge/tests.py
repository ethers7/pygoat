from unittest.mock import patch

from django.contrib.auth.models import User
from django.test import SimpleTestCase, TestCase, override_settings

from .models import Challenge, UserChallenge
from .utility import validate_container_ref


class ContainerRefValidationTests(SimpleTestCase):
    """Guards challenge.utility.validate_container_ref (CWE-78 allowlist)."""

    def test_accepts_container_ids_and_names(self):
        for value, expected in (
            ("a" * 64, "a" * 64),
            ("  9f2c1b3d4e5f ", "9f2c1b3d4e5f"),
            ("pygoat_chal-1.0", "pygoat_chal-1.0"),
        ):
            self.assertEqual(validate_container_ref(value), expected)

    def test_rejects_metacharacters_option_flags_and_blanks(self):
        for value in (
            "abc123; id",
            "abc123 && id",
            "abc123 | cat /etc/passwd",
            "$(id)",
            "`id`",
            "abc123\nid",
            "abc123 --time=0",
            "-f",
            "../abc123",
            "",
            "   ",
            None,
        ):
            with self.assertRaises(ValueError, msg=repr(value)):
                validate_container_ref(value)


@override_settings(
    DEBUG=True,
    STATICFILES_STORAGE="django.contrib.staticfiles.storage.StaticFilesStorage",
)
class ChallengeStopArgvTests(TestCase):
    """Stopping a challenge must still run docker, but never via a split string.

    Guards challenge.views.DoItFast.delete against a regression back to a
    command string built from the stored container reference and split on
    spaces (CWE-78).
    """

    PASSWORD = "Str0ng-Passw0rd!"

    def setUp(self):
        self.user = User.objects.create_user(
            username="chaluser",
            email="chaluser@example.com",
            password=self.PASSWORD,
        )
        self.client.force_login(self.user)
        self.chal = Challenge.objects.create(
            name="lab1",
            description="demo",
            docker_image="pygoat/lab1",
            docker_port=8000,
            start_port=8000,
            end_port=8100,
            flag="flag{demo}",
            point=10,
        )

    def _user_challenge(self, container_id):
        return UserChallenge.objects.create(
            user=self.user,
            challenge=self.chal,
            container_id=container_id,
            port=8001,
            is_live=True,
        )

    def test_delete_still_stops_container_as_argv(self):
        self._user_challenge("9f2c1b3d4e5f")
        with patch("challenge.views.subprocess.Popen") as popen:
            popen.return_value.communicate.return_value = (b"9f2c1b3d4e5f\n", b"")
            r = self.client.delete("/challenge/lab1")
        self.assertEqual(r.status_code, 200)
        self.assertEqual(r.json()["message"], "success")
        args, kwargs = popen.call_args
        self.assertEqual(args[0], ["docker", "stop", "9f2c1b3d4e5f"])
        self.assertFalse(kwargs.get("shell", False))

    def test_delete_rejects_injected_container_reference(self):
        self._user_challenge("9f2c1b3d4e5f; touch /tmp/pwned")
        with patch("challenge.views.subprocess.Popen") as popen:
            r = self.client.delete("/challenge/lab1")
        popen.assert_not_called()
        self.assertEqual(r.json()["message"], "failed")
