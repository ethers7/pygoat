from django.conf import settings
from django.contrib.auth import hashers
from django.core.validators import MaxValueValidator
from django.db import models


def hash_lab_password(raw_password):
    """Normalise a lab credential to a hash from a configured password hasher.

    Lab users are seeded through the Django admin / shell, so the value handed
    to ``save()`` may be a plaintext password (hashed here with PBKDF2, the
    default configured by ``pygoat/settings.py``) or a string that is already a
    valid Django hash, which is returned untouched so repeated ``save()`` calls
    stay idempotent.
    """
    if not raw_password:
        return raw_password
    try:
        hashers.identify_hasher(raw_password)
    except ValueError:
        return hashers.make_password(raw_password)
    return raw_password


def verify_lab_password(raw_password, stored_password):
    """Verify a submitted lab password against its stored hash (CWE-327).

    Uses the configured password hashers, which compare in constant time. Rows
    that still hold a digest from an unsupported algorithm (for example a bare
    unsalted MD5 hex digest seeded before this app hashed properly) make
    ``check_password`` raise, so authentication fails closed until the row is
    re-seeded rather than 500-ing.
    """
    if not raw_password or not stored_password:
        return False
    try:
        return hashers.check_password(raw_password, stored_password)
    except ValueError:
        return False

# Create your models here.

class FAANG (models.Model):
    id = models.AutoField(primary_key=True)
    company=models.CharField(max_length=200);
    def __str__(self):
        return self.company;

class info(models.Model):
    id = models.AutoField(primary_key=True)
    faang=models.ForeignKey(to=FAANG,on_delete=models.CASCADE)

    ceo=models.CharField(max_length=200)
    about=models.CharField(max_length=200)

class login(models.Model):
    id = models.AutoField(primary_key=True)
    user=models.CharField(max_length=200)
    password=models.CharField(max_length=300)

class comments(models.Model):
    id = models.AutoField(primary_key=True)
    name=models.CharField(max_length=200)
    comment=models.CharField(max_length=600)

class authLogin(models.Model):
    username=models.CharField(max_length=200, unique = True)
    name=models.CharField(max_length=200)
    password=models.CharField(max_length=200)
    userid = models.AutoField(primary_key=True)

class otp(models.Model):
    id = models.AutoField(primary_key=True)
    email=models.CharField(max_length=200)
    otp=models.IntegerField(validators=[MaxValueValidator(300)])

class tickits(models.Model):
    id = models.AutoField(primary_key=True)
    user=models.ForeignKey(settings.AUTH_USER_MODEL,on_delete=models.CASCADE)
    tickit=models.CharField(max_length=40, unique = True)

    def __str__(self):
        return self.tickit+ " " + self.user.username; 

class sql_lab_table(models.Model):
    id = models.CharField(primary_key = True, max_length=200)
    password = models.CharField(max_length=200)

class Blogs(models.Model):
    id = models.AutoField(primary_key=True)
    author = models.ForeignKey(settings.AUTH_USER_MODEL,on_delete=models.CASCADE)
    blog_id = models.CharField(max_length=15, unique=True)
    def __str__(self):
        return self.blog_id

class CF_user(models.Model):
    id = models.AutoField(primary_key=True)
    username = models.CharField(max_length=200)
    password = models.CharField(max_length=200)
    password2 = models.CharField(max_length=64)

    def save(self, *args, **kwargs):
        # CWE-327: never persist a plaintext or MD5 credential for this lab.
        self.password = hash_lab_password(self.password)
        super().save(*args, **kwargs)

    def __str__(self):
        return self.username

class AF_admin(models.Model):
    id = models.AutoField(primary_key=True)
    username = models.CharField(max_length=200)
    password = models.CharField(max_length=200)
    session_id = models.CharField(max_length=200)
    last_login = models.DateTimeField(blank= True, null = True)
    logged_in = models.BooleanField(default=False)
    is_locked = models.BooleanField(default=False)
    failattempt = models.IntegerField(default=0)
    lockout_cooldown = models.DateTimeField(blank= True, null = True)

    def __str__(self):
        return self.username

class AF_session_id(models.Model):
    id = models.AutoField(primary_key=True)
    session_id = models.CharField(max_length=200)
    user = models.CharField(max_length=200)
    def __str__(self):
        return self.user

class CSRF_user_tbl(models.Model):
    id = models.AutoField(primary_key=True)
    username = models.CharField(max_length=200)
    password = models.CharField(max_length=200)
    balance = models.IntegerField(default=0)
    is_loggedin = models.BooleanField(default=False)

    def save(self, *args, **kwargs):
        # CWE-327: never persist a plaintext or MD5 credential for this lab.
        self.password = hash_lab_password(self.password)
        super().save(*args, **kwargs)

    def __str__(self):
        return self.username