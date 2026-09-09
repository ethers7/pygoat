from unittest import mock

from django.contrib.auth.models import User
from django.test import SimpleTestCase, TestCase

from .models import Challenge
from .utility import safe_container_id, safe_docker_image

# Create your tests here.


class SafeContainerIdTests(SimpleTestCase):
    def test_accepts_container_id_and_name(self):
        self.assertEqual(safe_container_id('3f2b1c4d5e6a'), '3f2b1c4d5e6a')
        self.assertEqual(safe_container_id('  pygoat_lab-1.0  '), 'pygoat_lab-1.0')

    def test_rejects_shell_metacharacters_and_option_injection(self):
        for value in ['abc; rm -rf /', 'abc && whoami', 'abc | id', 'abc $(id)', 'a b', '-rm', '', None]:
            self.assertIsNone(safe_container_id(value))


class SafeDockerImageTests(SimpleTestCase):
    """CWE-78: only a validated image reference may reach `docker run`."""

    def test_accepts_image_references(self):
        for value in [
            'pygoat',
            'pygoat:1.2.0',
            'library/pygoat:latest',
            'registry.example.com:5000/team/pygoat:1.0',
            'pygoat@sha256:' + '0' * 64,
        ]:
            self.assertEqual(safe_docker_image(value), value)
        self.assertEqual(safe_docker_image('  pygoat:latest  '), 'pygoat:latest')

    def test_rejects_shell_metacharacters_option_and_argument_injection(self):
        for value in [
            'pygoat; id',
            'pygoat && whoami',
            'pygoat | id',
            'pygoat $(id)',
            'pygoat `id`',
            'pygoat\nid',
            'pygoat -v /:/host',
            '--privileged',
            '-v/:/host',
            '',
            '   ',
            None,
            1234,
        ]:
            self.assertIsNone(safe_docker_image(value), msg=repr(value))


class DoItFastCommandTests(TestCase):
    """CWE-78: the challenge container commands run as argv, never via a shell."""

    def setUp(self):
        self.user = User.objects.create_user(username='challenge_tester')
        self.client.force_login(self.user)
        self.chal = Challenge.objects.create(
            name='lab1',
            description='lab',
            docker_image='pygoat/lab1:latest',
            docker_port=8080,
            start_port=8000,
            end_port=8100,
            flag='flag',
            point=10,
        )

    @mock.patch('challenge.views.get_free_port', return_value=8005)
    @mock.patch('challenge.views.subprocess.Popen')
    def test_docker_run_uses_argv_list_without_shell(self, mocked_popen, mocked_port):
        mocked_popen.return_value.communicate.return_value = (b'containerid123\n', b'')

        response = self.client.post('/challenge/lab1')

        self.assertEqual(response.status_code, 200)
        args, kwargs = mocked_popen.call_args
        self.assertEqual(
            args[0],
            ['docker', 'run', '-d', '-p', '8005:8080', 'pygoat/lab1:latest'])
        self.assertFalse(kwargs['shell'])

    @mock.patch('challenge.views.get_free_port', return_value=8005)
    @mock.patch('challenge.views.subprocess.Popen')
    def test_hostile_image_reference_runs_no_command(self, mocked_popen, mocked_port):
        Challenge.objects.filter(pk=self.chal.pk).update(
            docker_image='pygoat/lab1:latest -v /:/host')

        response = self.client.post('/challenge/lab1')

        self.assertEqual(response.status_code, 200)
        self.assertEqual(response.json()['status'], '500')
        mocked_popen.assert_not_called()

    @mock.patch('challenge.views.subprocess.Popen')
    def test_docker_stop_uses_argv_list_without_shell(self, mocked_popen):
        mocked_popen.return_value.communicate.return_value = (b'', b'')
        self.chal.userchallenge_set.create(
            user=self.user, container_id='containerid123', port=8005, is_live=True)

        response = self.client.delete('/challenge/lab1')

        self.assertEqual(response.status_code, 200)
        args, kwargs = mocked_popen.call_args
        self.assertEqual(args[0], ['docker', 'stop', 'containerid123'])
        self.assertFalse(kwargs['shell'])

    @mock.patch('challenge.views.subprocess.Popen')
    def test_hostile_container_id_runs_no_command(self, mocked_popen):
        self.chal.userchallenge_set.create(
            user=self.user, container_id='containerid123; id', port=8005, is_live=True)

        response = self.client.delete('/challenge/lab1')

        self.assertEqual(response.json()['status'], '500')
        mocked_popen.assert_not_called()
