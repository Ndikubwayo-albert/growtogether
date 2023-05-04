from django.db import models
from django.contrib.auth.models import AbstractUser



USER_CHOICES = [
    ('D', 'Doctor'),
    ('W', 'Woman'),
    ('R', 'Receptionist'),
    ('HR', 'HR'),
    ('C', 'Consultator')
]
class User(AbstractUser):
    user_type = models.CharField(max_length=3, choices=USER_CHOICES, default='W')
    birthdate = models.DateField(null= True)
    phone = models.CharField(max_length=13, null= True) 
    is_email_verified = models.BooleanField(default=False, blank=True)
            
    def is_doctor(self):
        if self.user_type == 'D':
            return True
        else:
            return False

    def is_woman(self):
        if self.user_type == 'W':
            return True
        else:
            return False

    def is_receptionist(self):
        if self.user_type == 'R':
            return True
        else:
            return False
    def is_consultator(self):
        if self.user_type == 'C':
            return True
        else:
            return False

    def is_HR(self):
        if self.user_type == 'HR':
            return True
        else:
            return False
        
    def __str__(self):
        return self.username

class Woman_profile(models.Model):
    PREGNANCY_STATUS_CHOICE=[
        ('Pregnant','yes'),
        ('Not Pregnant','no')
    ]
    user_id= models.ForeignKey(User, on_delete= models.CASCADE)    
    pregnant_times= models.IntegerField()
    children= models.IntegerField()
    pregnant_date= models.DateField()
    expected_birth= models.DateField()
    pregnancy_status= models.CharField(max_length= 64, choices= PREGNANCY_STATUS_CHOICE)

    def __str__(self):
        return self.user_id.first_name
    
class Address(models.Model):
    user_id= models.ForeignKey(User, on_delete= models.CASCADE)
    district= models.CharField(max_length= 128)
    sector= models.CharField(max_length= 128)
    cell= models.CharField(max_length= 128)
    village= models.CharField(max_length= 128)

    def __str__(self):
        return self.user_id.first_name     

