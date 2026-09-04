from django.contrib import admin

from .models import (FAANG, AF_admin, AF_session_id, CF_user, CSRF_user_tbl,
                     comments, info, login, otp, tickits)
from .utility import ensure_password_hash


class LabUserAdmin(admin.ModelAdmin):
    """Admin for the lab account tables; stores passwords hashed.

    The admin site is the only write path for these demo accounts, and the
    crypto-failure and CSRF labs now verify credentials with Django's password
    hashers. A password typed into this form is therefore hashed (salted
    PBKDF2) before it is written, while a value that already is such a hash is
    kept as-is. Demo accounts are seeded with the documented plaintext
    password and never stored in the clear (nor as an unsalted MD5 digest).
    """

    def save_model(self, request, obj, form, change):
        obj.password = ensure_password_hash(obj.password)
        super().save_model(request, obj, form, change)


# Register your models here.
admin.site.register(FAANG)
admin.site.register(info)
admin.site.register(login)
admin.site.register(comments)
admin.site.register(otp)
admin.site.register(tickits)
admin.site.register(CF_user, LabUserAdmin)
admin.site.register(AF_admin)
admin.site.register(AF_session_id)
admin.site.register(CSRF_user_tbl, LabUserAdmin)
