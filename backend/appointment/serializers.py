from rest_framework import serializers
from .models import SemesterAppointment, Checkup, Vaccination


class ReadOnlyAppointmentSerializer(serializers.ModelSerializer):
    class Meta:
        model = SemesterAppointment
        fields = ['semester','test_date','utelas_height','children_situation','appointment_date','status','description']

