# Generated by Django 4.1.5 on 2023-04-07 07:01

from django.conf import settings
from django.db import migrations, models
import django.db.models.deletion


class Migration(migrations.Migration):

    dependencies = [
        ('AppApi', '0014_alter_messages_receiver_alter_messages_sender'),
    ]

    operations = [
        migrations.AddField(
            model_name='messages',
            name='is_deleted',
            field=models.BooleanField(default=False),
        ),
        migrations.RemoveField(
            model_name='messages',
            name='deleted_by',
        ),
        migrations.AddField(
            model_name='messages',
            name='deleted_by',
            field=models.ForeignKey(blank=True, null=True, on_delete=django.db.models.deletion.CASCADE, related_name='deleted_messages', to=settings.AUTH_USER_MODEL),
        ),
    ]