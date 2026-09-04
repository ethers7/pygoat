from django.test import SimpleTestCase

from .utility import validate_container_id

# Create your tests here.


class ValidateContainerIdTests(SimpleTestCase):
    def test_accepts_docker_ids(self):
        self.assertEqual(validate_container_id('a1b2c3d4e5f6'), 'a1b2c3d4e5f6')
        self.assertEqual(validate_container_id('0' * 64), '0' * 64)
        self.assertEqual(validate_container_id('  a1b2c3d4e5f6  '), 'a1b2c3d4e5f6')

    def test_rejects_command_injection_payloads(self):
        for payload in (
            'a1b2c3d4e5f6; rm -rf /',
            'a1b2c3d4e5f6 && cat /etc/passwd',
            'a1b2c3d4e5f6 $(id)',
            'a1b2c3d4e5f6|whoami',
            '--help',
            '-f a1b2c3d4e5f6',
            'a1b2c3d4e5f6 extra',
            'notahexid1234',
            'short',
            '',
            None,
        ):
            self.assertIsNone(validate_container_id(payload), payload)
