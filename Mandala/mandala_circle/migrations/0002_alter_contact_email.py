# Generated by Django 3.2.6 on 2021-09-05 15:58

import django.core.validators
from django.db import migrations, models


class Migration(migrations.Migration):

    dependencies = [
        ('mandala_circle', '0001_initial'),
    ]

    operations = [
        migrations.AlterField(
            model_name='contact',
            name='email',
            field=models.EmailField(max_length=254, validators=[django.core.validators.EmailValidator()]),
        ),
    ]
