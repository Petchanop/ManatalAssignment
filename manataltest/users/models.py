import uuid
from django.db import models
from django.utils.timezone import now

# Create your models here.


class Users(models.Model):
    id = models.UUIDField(
        name="id", primary_key=True, editable=False, default=uuid.uuid4
    )
    username = models.CharField(name="username", max_length=8, null=False)
    email = models.EmailField(name="email", unique=True)
    password = models.CharField(name="password", max_length=255, null=False)

    ROLES = [
        ("ADMIN", "admin"),
        ("USER", "user")
    ]
    roles = models.CharField(name="role", choices=ROLES, null=True)
    created_at = models.DateTimeField(default=now)
    updated_at = models.DateTimeField(default=now)
