# Generated by Django 3.2.6 on 2021-09-28 08:45

import django.core.validators
from django.db import migrations, models


class Migration(migrations.Migration):

    dependencies = [
        ('mandala_circle', '0061_remove_shippingaddress_product'),
    ]

    operations = [
        migrations.CreateModel(
            name='Gallery',
            fields=[
                ('id', models.BigAutoField(auto_created=True, primary_key=True, serialize=False, verbose_name='ID')),
                ('name', models.CharField(max_length=500, null=True, validators=[django.core.validators.MinLengthValidator(2)])),
                ('image', models.ImageField(upload_to='static/gallery')),
            ],
        ),
    ]