"""Provision lab account passwords from the environment, at run time.

The cryptographic-failure lab (CF_user) and the CSRF lab (CSRF_user_tbl) used to
authenticate by matching an unsalted MD5 digest of the submitted password
(CWE-327). Both labs now verify passwords with Django's password hashers, so the
stored value has to be a salted hash.

No credential is committed to the repository: the password for each account is
read from the environment when this command runs, and accounts without a
configured password are left with an unusable password (fail closed).

Environment variables::

    PYGOAT_CF_LAB_PASSWORD[_<USERNAME>]      crypto failure lab (alex/admin/rupak)
    PYGOAT_CSRF_LAB_PASSWORD[_<USERNAME>]    CSRF lab (susUser2878/Alfresko)

Usage::

    python manage.py seed_lab_users
"""
import os

from django.core.management.base import BaseCommand

from introduction.models import CF_user, CSRF_user_tbl
from introduction.utility import hash_lab_password

CF_LAB_USERNAMES = ('alex', 'admin', 'rupak')
CSRF_LAB_USERS = (('susUser2878', 1000), ('Alfresko', 0))


def configured_password(prefix, username):
    """Return the env supplied password for username, or None when unset."""
    return (os.environ.get('{}_{}'.format(prefix, username.upper()))
            or os.environ.get(prefix)
            or None)


class Command(BaseCommand):
    help = (
        "Sets the lab account passwords from the PYGOAT_CF_LAB_PASSWORD / "
        "PYGOAT_CSRF_LAB_PASSWORD environment variables, storing them as salted "
        "Django password hashes. Accounts with no configured password keep an "
        "unusable password so the lab fails closed."
    )

    def _report(self, username, raw_password):
        if raw_password:
            self.stdout.write(self.style.SUCCESS(
                "'{}': salted password hash installed from the environment.".format(username)))
        else:
            self.stdout.write(
                "'{}': no password configured, left with an unusable password.".format(username))

    def handle(self, *args, **options):
        for username in CF_LAB_USERNAMES:
            raw_password = configured_password('PYGOAT_CF_LAB_PASSWORD', username)
            # hash_lab_password(None) yields an unusable password hash.
            updated = CF_user.objects.filter(username=username).update(
                password=hash_lab_password(raw_password))
            if not updated:
                self.stderr.write(self.style.WARNING(
                    "'{}': no CF_user row found, run migrate first.".format(username)))
                continue
            self._report(username, raw_password)

        for username, balance in CSRF_LAB_USERS:
            raw_password = configured_password('PYGOAT_CSRF_LAB_PASSWORD', username)
            user, created = CSRF_user_tbl.objects.get_or_create(
                username=username,
                defaults={'password': hash_lab_password(raw_password), 'balance': balance})
            if not created:
                user.password = hash_lab_password(raw_password)
                user.save(update_fields=['password'])
            self._report(username, raw_password)

        self.stdout.write(self.style.SUCCESS("Lab account passwords processed."))
