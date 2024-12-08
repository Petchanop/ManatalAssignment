# Generated by Django 5.1.3 on 2024-11-16 11:27

import datetime
from django.db import migrations, models


class Migration(migrations.Migration):

    dependencies = [
        ("users", "0001_initial"),
    ]

    operations = [
        migrations.RenameField(
            model_name="users",
            old_name="email address",
            new_name="email",
        ),
        migrations.AddField(
            model_name="users",
            name="created_at",
            field=models.DateTimeField(
                default=datetime.datetime(
                    2024, 11, 16, 11, 27, 17, 765860, tzinfo=datetime.timezone.utc
                )
            ),
        ),
        migrations.AddField(
            model_name="users",
            name="updated_at",
            field=models.DateTimeField(
                default=datetime.datetime(
                    2024, 11, 16, 11, 27, 17, 765897, tzinfo=datetime.timezone.utc
                )
            ),
        ),
    ]