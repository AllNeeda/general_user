import uuid
from django.contrib.auth.models import AbstractUser, BaseUserManager
from django.db import models
from django.utils import timezone
from datetime import timedelta


class Role(models.Model):
    id = models.UUIDField(primary_key=True, default=uuid.uuid4, editable=False)
    name = models.CharField(max_length=64)
    status = models.BooleanField(default=False)
    created_at = models.DateTimeField(auto_now_add=True)
    updated_at = models.DateTimeField(auto_now=True)

    def __str__(self):
        return self.name



class UserManager(BaseUserManager):
    use_in_migrations = True

    def create_user(self, phoneNo, password=None, **extra_fields):
        if not phoneNo:
            raise ValueError("Phone number must be set")
        # Set username to phoneNo to avoid unique constraint issues
        extra_fields.setdefault('username', phoneNo)
        user = self.model(phoneNo=phoneNo, **extra_fields)
        user.set_password(password)
        user.save(using=self._db)
        return user

    def create_superuser(self, phoneNo, password=None, **extra_fields):
        extra_fields.setdefault("is_staff", True)
        extra_fields.setdefault("is_superuser", True)
        if extra_fields.get("is_staff") is not True:
            raise ValueError("Superuser must have is_staff=True.")
        if extra_fields.get("is_superuser") is not True:
            raise ValueError("Superuser must have is_superuser=True.")
        return self.create_user(phoneNo, password, **extra_fields)


class User(AbstractUser):
    id = models.UUIDField(primary_key=True, default=uuid.uuid4, editable=False)
    firstName = models.CharField(max_length=150)
    lastName = models.CharField(max_length=150)
    phoneNo = models.CharField(max_length=15, unique=True)
    dob = models.DateField()
    isAgreeTermsConditions = models.BooleanField(default=False)
    role = models.ForeignKey('Role', on_delete=models.PROTECT, db_column="role_id")
    status = models.BooleanField(default=False)
    
    # Override username field to make it nullable and non-unique since we use phoneNo
    username = models.CharField(
        max_length=150,
        null=True,
        blank=True,
        unique=False,
        help_text="Optional. Not used for authentication."
    )

    USERNAME_FIELD = "phoneNo"
    REQUIRED_FIELDS = ["firstName", "lastName", "dob"]

    objects = UserManager()

    class Meta:
        abstract = False
        # Remove unique constraint from username if it exists
        constraints = []

    def __str__(self):
        return self.firstName + " " + self.lastName



class OTP(models.Model):
    phoneNo = models.CharField(max_length=15)
    otp = models.CharField(max_length=4)
    created_at = models.DateTimeField(auto_now_add=True)
    is_verified = models.BooleanField(default=False)

    def is_expired(self):
        return timezone.now() > self.created_at + timedelta(minutes=5)

    def __str__(self):
        return f"OTP for {self.phone_no}"



