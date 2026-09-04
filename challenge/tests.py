from django.test import SimpleTestCase

from .utility import validate_container_id, validate_docker_image, validate_port

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


class ValidateDockerImageTests(SimpleTestCase):
    def test_accepts_image_references(self):
        self.assertEqual(validate_docker_image('pygoat'), 'pygoat')
        self.assertEqual(validate_docker_image('  library/nginx:1.25-alpine  '),
                         'library/nginx:1.25-alpine')
        self.assertEqual(validate_docker_image('registry.example.com/team/app:v1.2.3'),
                         'registry.example.com/team/app:v1.2.3')
        self.assertEqual(validate_docker_image('alpine@sha256:' + 'a' * 64),
                         'alpine@sha256:' + 'a' * 64)

    def test_rejects_command_injection_and_option_payloads(self):
        for payload in (
            'alpine; rm -rf /',
            'alpine && cat /etc/passwd',
            'alpine $(id)',
            'alpine|whoami',
            'alpine\nrm -rf /',
            '--privileged',
            '-v /:/host alpine',
            'alpine -v /:/host',
            '--entrypoint=/bin/sh alpine',
            'alpine@sha256:notadigest',
            'a' * 256,
            '',
            None,
            123,
        ):
            self.assertIsNone(validate_docker_image(payload), payload)


class ValidatePortTests(SimpleTestCase):
    def test_accepts_ports_in_range(self):
        self.assertEqual(validate_port(8080), 8080)
        self.assertEqual(validate_port('  8080  '), 8080)
        self.assertEqual(validate_port(1), 1)
        self.assertEqual(validate_port(65535), 65535)

    def test_rejects_out_of_range_and_injection_payloads(self):
        for payload in (0, -1, 65536, '8080; id', '8080 -v /:/host', '', None, True):
            self.assertIsNone(validate_port(payload), payload)
