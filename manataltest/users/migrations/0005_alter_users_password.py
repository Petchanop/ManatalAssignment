# Generated by Django 5.1.3 on 2024-11-17 14:42

from django.db import migrations, models


class Migration(migrations.Migration):

    dependencies = [
        ("users", "0004_rename_uuid_users_id"),
    ]

    operations = [
        migrations.AlterField(
            model_name="users",
            name="password",
            field=models.CharField(max_length=255),
        ),
    ]
