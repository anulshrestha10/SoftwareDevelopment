# Generated by Django 3.2.6 on 2021-09-20 17:24

from django.db import migrations


class Migration(migrations.Migration):

    dependencies = [
        ('mandala_circle', '0042_alter_order_user'),
    ]

    operations = [
        migrations.RemoveField(
            model_name='order',
            name='payment',
        ),
    ]
