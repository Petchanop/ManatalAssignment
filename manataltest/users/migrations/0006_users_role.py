# Generated by Django 5.1.3 on 2024-11-18 10:10

from django.db import migrations, models


class Migration(migrations.Migration):

    dependencies = [
        ("users", "0005_alter_users_password"),
    ]

    operations = [
        migrations.AddField(
            model_name="users",
            name="role",
            field=models.CharField(
                choices=[("ADMIN", "admin"), ("USER", "user")], null=True
            ),
        ),
    ]