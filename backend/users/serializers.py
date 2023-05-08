from rest_framework import serializers, exceptions, viewsets
from rest_framework.response import Response
from django.contrib.auth import get_user_model
from users.models import User
from django.contrib.auth.hashers import make_password

from django.utils.encoding import force_str
from django.utils.http import urlsafe_base64_decode
from django.contrib.auth.tokens import PasswordResetTokenGenerator
from .utils import Util

from rest_framework import serializers
from django.contrib.auth import get_user_model
from rest_framework.authtoken.models import Token
from django.contrib.auth.hashers import make_password
from .models import Woman

UserModel = get_user_model()
class UserSerializer(serializers.ModelSerializer):
	class Meta:
		model = UserModel
		fields = ['username']


class UserRegisterSerializer(serializers.ModelSerializer):
	class Meta:
		model = UserModel
		fields = ['email','password', 'first_name','last_name','username','is_active']

  
	def create(self, clean_data):
     
		user_obj = UserModel.objects.create(email=clean_data['email'],
                                      password= make_password(clean_data['password']),
                                      username = clean_data['username'],
                                      birthdate= clean_data['birthdate'], 
                                      first_name = clean_data['first_name'],
                                      last_name = clean_data['last_name'],
                                      is_active = False
				      )		  
		return user_obj

class ReadUserSerializer(serializers.ModelSerializer):
	class Meta:
		model = UserModel
		fields =['email', 'first_name','last_name']
		

# serializers for dealing with account passwords 

class ChangePasswordSerializer(serializers.Serializer):
    class Meta:
        extra_kwargs= {
            'confirm_newpassword': {'write_only': True,} 
		}                
    model= UserModel
    
    old_password= serializers.CharField(required= True)
    new_password= serializers.CharField(required= True)
    confirm_newpassword= serializers.CharField(required= True, write_only=True)
    
class RequestResetPasswordSerializer(serializers.Serializer):
    email= serializers.EmailField(min_length= 2)
    class Meta:
        fields= ['email']        

      
class SetNewPasswordSerializer(serializers.Serializer):
    newpassword= serializers.CharField(min_length=6, max_length= 64, write_only= True)
    uidb64= serializers.CharField(min_length= 1, write_only= True )
    token= serializers.CharField(min_length= 1, write_only= True )
    
    class Meta:
        fields= '__all__'
        
    def validate(self, attrs):
        try:
            newpassword= attrs.get('newpassword')
            token= attrs.get('token')
            uidb64= attrs.get('uidb64') 
            
            print(f"token: {token}")
            print(f"uidb64: {uidb64}")           
            
            id= force_str(urlsafe_base64_decode(uidb64))
            user= User.objects.get(id=id)
            
            print(f"User: {user}")
            
            if not PasswordResetTokenGenerator().check_token(user, token):
                raise exceptions.AuthenticationFailed({'Error':'The Reset link is invalid, Expired link!'}, 401)
            
            user.set_password(newpassword)
            user.save()
            
            data= {
                'email_body': 'The password for your growtogether account was reset successfully.',
                'to_email': user.email,
                'email_subject': 'Security alert for '+user.email+' -- Growtogether System.'}
            Util.send_email(data)
            
            return Response({'user': user})                                      
        except Exception as e: 
            
            print(f"error: {e} ") 
            
            raise exceptions.AuthenticationFailed({'Error':'The Reset link is invalid !' }, 401)
        
       
# woman info serializer
# class WomanProfileSerializer(serializers.ModelSerializer):
#     class Meta:
#         model= Woman_profile
#         fields= '__all__'
              
class WomanProfileSerializer(serializers.Serializer):
	birth_date = serializers.DateField(label="Birth Date")
	phone = serializers.CharField(label='Phone', max_length=13)

	def validate_phone(self, phone):
		if phone.isdigit()==False:
			raise serializers.ValidationError('Please Enter a valid Phone number!')
		return phone
	
	def create(self, validated_data):
		
		new_woman = Woman.objects.create(birth_date=validated_data['birth_date'],
				   phone=validated_data['phone'])
		return new_woman
	
	def update(self, instance, validated_data):
		instance.birth_date=validated_data.get('phone', instance.birth_date)
		instance.phone = validated_data.get('phone', instance.phone)
		instance.save()
		return instance
	
class WriteProfileSerializer(serializers.ModelSerializer):
    user =  serializers.HiddenField(default=serializers.CurrentUserDefault())
    class Meta:
        model = Woman
        fields = ['birth_date', 'phone', 'user']
		