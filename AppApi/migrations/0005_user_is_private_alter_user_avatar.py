# Generated by Django 4.1.5 on 2023-02-21 06:30

import AppApi.models
from django.db import migrations, models
import imagekit.models.fields


class Migration(migrations.Migration):

    dependencies = [
        ('AppApi', '0004_alter_user_full_name'),
    ]

    operations = [
        migrations.AddField(
            model_name='user',
            name='is_private',
            field=models.BooleanField(default=False),
        ),
        migrations.AlterField(
            model_name='user',
            name='avatar',
            field=imagekit.models.fields.ProcessedImageField(default='avatar/default.jpg', help_text='Profile Picture', upload_to=AppApi.models.avatar_path, verbose_name='Profile Picture'),
        ),
    ]
