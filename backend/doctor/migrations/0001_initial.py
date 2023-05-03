# Generated by Django 4.2 on 2023-05-03 06:48

from django.db import migrations, models


class Migration(migrations.Migration):

    initial = True

    dependencies = [
    ]

    operations = [
        migrations.CreateModel(
            name='doctor',
            fields=[
                ('id', models.BigAutoField(auto_created=True, primary_key=True, serialize=False, verbose_name='ID')),
                ('department', models.CharField(choices=[('CL', 'Cardiologist'), ('DL', 'Dermatologists'), ('OB', 'Obstetrician'), ('EMC', 'Emergency Medicine Specialists'), ('IL', 'Immunologists'), ('AL', 'Anesthesiologists'), ('CRS', 'Colon and Rectal Surgeons')], default='OB', max_length=3)),
                ('phone', models.CharField(max_length=10)),
                ('qualification', models.CharField(choices=[('PHD', 'PHD'), ('Doctor', 'Dr'), ('Masters', 'Ms'), ('A0', 'A0'), ('A1', 'A1'), ('A2', 'A2')], default='A2', max_length=10)),
                ('birth_date', models.DateField()),
            ],
        ),
    ]
