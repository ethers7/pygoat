from django.test import SimpleTestCase

from .utility import safe_container_id

# Create your tests here.


class SafeContainerIdTests(SimpleTestCase):
    def test_accepts_container_id_and_name(self):
        self.assertEqual(safe_container_id('3f2b1c4d5e6a'), '3f2b1c4d5e6a')
        self.assertEqual(safe_container_id('  pygoat_lab-1.0  '), 'pygoat_lab-1.0')

    def test_rejects_shell_metacharacters_and_option_injection(self):
        for value in ['abc; rm -rf /', 'abc && whoami', 'abc | id', 'abc $(id)', 'a b', '-rm', '', None]:
            self.assertIsNone(safe_container_id(value))
