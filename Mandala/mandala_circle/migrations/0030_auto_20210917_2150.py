# Generated by Django 3.2.6 on 2021-09-17 16:05

from django.db import migrations


class Migration(migrations.Migration):

    dependencies = [
        ('mandala_circle', '0029_orderitem_status'),
    ]

    operations = [
        migrations.RemoveField(
            model_name='orderitem',
            name='status',
        ),
        migrations.DeleteModel(
            name='Cart',
        ),
    ]
