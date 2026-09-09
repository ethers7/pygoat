"""Store the cryptographic-failure lab (lab 1) passwords as salted hashes.

The lab used to keep unsalted MD5 digests in the ``password`` column and log
users in by matching that digest inside the query (CWE-327). Passwords are now
verified with Django's password hashers, so any legacy digest still present in
an existing database is replaced here.

Credentials are supplied at run time, never committed:

* ``PYGOAT_CF_LAB_PASSWORD_<USERNAME>`` - password for a single lab account
* ``PYGOAT_CF_LAB_PASSWORD`` - password used for every lab account

When nothing is configured the row keeps an unusable password, so the lab fails
closed rather than shipping a crackable credential. The ``seed_lab_users``
management command applies the same environment variables later on.
"""
import os

from django.contrib.auth.hashers import make_password
from django.db import migrations

LAB_USERNAMES = ('alex', 'admin', 'rupak')


def configured_password(username):
    """Return the env supplied password for username, or None when unset."""
    return (os.environ.get('PYGOAT_CF_LAB_PASSWORD_{}'.format(username.upper()))
            or os.environ.get('PYGOAT_CF_LAB_PASSWORD')
            or None)


def seed_salted_passwords(apps, schema_editor):
    CF_user = apps.get_model('introduction', 'CF_user')
    for username in LAB_USERNAMES:
        # make_password(None) stores an unusable password, which check_password()
        # always rejects, so an unconfigured lab cannot be logged into.
        encoded = make_password(configured_password(username))
        CF_user.objects.filter(username=username).update(password=encoded)


class Migration(migrations.Migration):

    dependencies = [
        ('introduction', '0021_csrf_user_tbl'),
    ]

    operations = [
        migrations.RunPython(seed_salted_passwords, migrations.RunPython.noop),
    ]
