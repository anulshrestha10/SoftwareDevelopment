# Generated by Django 3.2.6 on 2021-09-09 08:45

import django.core.validators
from django.db import migrations, models


class Migration(migrations.Migration):

    dependencies = [
        ('mandala_circle', '0002_alter_contact_email'),
    ]

    operations = [
        migrations.CreateModel(
            name='Commission',
            fields=[
                ('id', models.BigAutoField(auto_created=True, primary_key=True, serialize=False, verbose_name='ID')),
                ('name', models.CharField(max_length=100, validators=[django.core.validators.MinLengthValidator(5)])),
                ('email', models.EmailField(max_length=254)),
                ('subject', models.CharField(max_length=100)),
                ('message', models.CharField(max_length=200)),
            ],
        ),
        migrations.DeleteModel(
            name='Contact',
        ),
    ]
