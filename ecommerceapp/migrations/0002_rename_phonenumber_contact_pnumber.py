# Generated by Django 5.0.7 on 2024-09-04 04:27

from django.db import migrations


class Migration(migrations.Migration):

    dependencies = [
        ('ecommerceapp', '0001_initial'),
    ]

    operations = [
        migrations.RenameField(
            model_name='contact',
            old_name='phonenumber',
            new_name='pnumber',
        ),
    ]
