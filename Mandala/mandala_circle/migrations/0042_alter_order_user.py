# Generated by Django 3.2.6 on 2021-09-20 17:17

import django.contrib.auth.models
from django.db import migrations, models


class Migration(migrations.Migration):

    dependencies = [
        ('mandala_circle', '0041_auto_20210920_2259'),
    ]

    operations = [
        migrations.AlterField(
            model_name='order',
            name='user',
            field=models.CharField(blank=True, max_length=2000, null=True, verbose_name=django.contrib.auth.models.User),
        ),
    ]
