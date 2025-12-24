from django.apps import AppConfig
from django.db import OperationalError, ProgrammingError


class UserConfig(AppConfig):
    default_auto_field = "django.db.models.BigAutoField"
    name = "user"

    def ready(self):
        from django.conf import settings
        if not getattr(settings, 'BOOTSTRAP_SUPERADMIN', False):
            return

        try:
            from user.models import Role, User

            # Try to access the database - if tables don't exist, this will fail gracefully
            role, _ = Role.objects.get_or_create(
                name="super-admin",
                defaults={"status": True}
            )

            User.objects.get_or_create(
                phoneNo="0700000000",
                defaults={
                    "firstName": "System",
                    "lastName": "Admin",
                    "phoneNo": "0700000000",
                    "dob": "2000-01-01",
                    "isAgreeTermsConditions": True,
                    "role": role,
                    "status": True,
                    "is_staff": True,
                    "is_superuser": True,
                }
            )
        except (OperationalError, ProgrammingError):
            # Tables don't exist yet (migrations not run), skip bootstrap
            # This is expected during initial setup
            pass
        except Exception:
            # Any other error, skip bootstrap to prevent startup failures
            pass
