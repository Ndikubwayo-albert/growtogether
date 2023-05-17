from .serializers import (UserRegisterSerializer, 
                          ChangePasswordSerializer, 
                          RequestResetPasswordSerializer,
                          SetNewPasswordSerializer,

                          ReadUserSerializer
)

from django.contrib.auth import get_user_model, authenticate
from .utils import Util
from rest_framework.permissions import IsAuthenticated, AllowAny, IsAdminUser
from rest_framework.authentication import TokenAuthentication
from rest_framework_simplejwt.tokens import RefreshToken
from django.conf import settings
from django.urls import reverse
from django.contrib.sites.shortcuts import get_current_site
import jwt
from datetime import date
from rest_framework.response import Response
from rest_framework import permissions, status, generics, viewsets
from rest_framework.views import APIView
from auto_tasks.auto_generate import auto_username_password_generator

from rest_framework.authtoken.models import Token


#for phone messages
from lib.pindo import send_sms
from drf_yasg.utils import swagger_auto_schema


User= get_user_model()

# Create your views here.


class UserRegister(viewsets.ViewSet):
    permission_classes = []
    @swagger_auto_schema(
        tags=['user action'],
        operation_description='List of all user in system',

    )
    def list(self, request):
        all_users= User.objects.filter(user_type='W')
        serializer= ReadUserSerializer(all_users, many= True) 
        return Response(serializer.data)
    
    @swagger_auto_schema(
        request_body=UserRegisterSerializer,
        tags=['user action'],
        operation_description='This help to register Women',

    )
  
    def post(self, request):
        if User.is_doctor:
                        
            clean_data = auto_username_password_generator(request.data)
            serializer = UserRegisterSerializer(data=clean_data)
            if serializer.is_valid(raise_exception=True):
                # user = serializer.create(clean_data)
                user = serializer.save()
                # Token.objects.get_or_create(user)
                
                if user:
                    token= RefreshToken.for_user(user).access_token 
                    current_site= get_current_site(request).domain 
                    rela_link= reverse('email-verify')        
                    abs_url= 'http://'+current_site +rela_link+'?token='+str(token)
                    email_body= 'Hello '+ user.first_name+'.\n\nYour Account has been Created Successfully!\n\nUse the link provided below to activate your account.\n'+ abs_url
                    data= {
                        'email_body': email_body,
                        'to_email': user.email,
                        'email_subject': 'Activate Your Account -- Growtogether system.'}
                    Util.send_email(data)
                return Response(serializer.data, status=status.HTTP_201_CREATED) 
        else:
            return Response({'Error':'You are not Staff user'})
        return Response(status=status.HTTP_400_BAD_REQUEST)
    
    
class VerifyAccount(APIView):

    def get(self, request):
        token= request.GET.get('token') 
        
        try:
            payload= jwt.decode(token, settings.SECRET_KEY, algorithms=['HS256'])
            user= User.objects.get(id=payload['user_id'])
            encryptedpassword=request.GET.get('password')
            
            if not user.is_active:
                user.is_active= True                             
                user.save()
                
                current_site= get_current_site(request).domain 
                rela_link= reverse('login')        
                abs_url= 'http://'+current_site +rela_link
                
                email_body= 'Hello '+ user.first_name+'.\n\nYour Account is successfully activated!\n\n Use Credentials provided below to login into your account.\n\n'+'Username: '+user.username+'\nPassword: '+ user.first_name+'@'+str(date.today().year) +'\n\nLogin Link:\n'+ abs_url
                data= {
                    'email_body': email_body,
                    'to_email': user.email,
                    'email_subject': 'Login into your Growtogether account.'}
                Util.send_email(data)                
            return Response({'Email is Verified': 'Your Account is successfully activated! -- Growtogether system'}, status= status.HTTP_200_OK)
        
        except jwt.ExpiredSignatureError as identifier:
            return Response({'It\'s an Error':'Activation link expired!'}, status= status.HTTP_400_BAD_REQUEST)
        except jwt.exceptions.DecodeError as identifier:
            return Response({'It\'s an Error':'Invalid token!'}, status= status.HTTP_400_BAD_REQUEST)
    

class LoginApi(generics.GenericAPIView):
    serializer_class= UserRegisterSerializer
    permission_classes= [AllowAny, ]

    permission_classes = []
    @swagger_auto_schema(
        tags=['user action'],
        operation_description='user Login in system',

    )
            
    def post(self, request):
        username= request.data.get('username')
        passwd= request.data.get('password')
        user= authenticate(username= username, password= passwd)
        
        if user:
            if user.is_active:
                if user.user_type == "W":
                    token, created= Token.objects.get_or_create(user= user)
                    response= {
                    'Message':'Logged in successfully',
                    'Token': token.key
                }
                    return Response(data= response)
                return Response(data= {'Message':'You are not allowed to Login as Woman'},status= status.HTTP_401_UNAUTHORIZED)
            else:
                return Response(data= {'Message':'Account is not allowed'}, status= status.HTTP_401_UNAUTHORIZED)
        else:
            return Response(data= {'Message':'Invalid credentials'},status= status.HTTP_401_UNAUTHORIZED)
    permission_classes = []

    @swagger_auto_schema(
        tags=['user action'],

    )   
    def get(self, request):
        content= {'user': str(request.user), 'auth':str(request.auth)}
        return Response(data= content, status= status.HTTP_200_OK)
    
class LogoutApi(APIView):
    permission_classes = [IsAuthenticated]
    authentication_classes= [TokenAuthentication]

    permission_classes = []
    @swagger_auto_schema(
        tags=['user action'],

    )
    
    def get(self, request):
        content= {'user': str(request.user), 'auth':str(request.auth)}
        return Response(data= content, status= status.HTTP_200_OK)
    

    @swagger_auto_schema(
        tags=['user action'],

    )
        
    def post(self, request, format=None):
        request.auth.delete()
        return Response(data= {'Message':'User Logged out'})
    
        
class ChangePasswordApi(generics.UpdateAPIView):
    model= User
    serializer_class= ChangePasswordSerializer
    permission_classes= [IsAuthenticated, ]    
        
    def get_object(self, queryset= None):
        obj= self.request.user
        return obj
    
    def update(self, request, *args, **kwargs):
        self.object= self.get_object()
        serializer= self.get_serializer(data= request.data)
        
        if serializer.is_valid():
            if not self.object.check_password(serializer.data.get('old_password')):
                return Response({'old_password': ['Old Password is Wrong!'] }, status= status.HTTP_400_BAD_REQUEST)           
           
            if self.object.check_password(serializer.data.get('newpassword')):
                return Response({'Confirm_pas sword': ['Failed to confirm new password!'] }, status= status.HTTP_400_BAD_REQUEST)           
            
            self.object.set_password(serializer.data.get('new_password'))   
            self.object.save() 
            return Response(serializer.data, status= status.HTTP_200_OK)
        return Response(serializer.errors, status= status.HTTP_400_BAD_REQUEST)
         
        
class RequestResetPasswordEmail(generics.GenericAPIView):
    serializer_class= RequestResetPasswordSerializer
    
    def post(self, request):
        serializer= self.serializer_class(data= request.data)        
        email= request.data['email']
        
        if UserModel.objects.filter(email=email).exists():
            user= User.objects.get(email=email)
            
            uidb64= urlsafe_base64_encode(force_bytes(user.pk) )
            token= PasswordResetTokenGenerator().make_token(user)
            
            current_site= get_current_site(request= request).domain 
            rela_link= reverse('password-reset-confirm', kwargs={'uidb64': uidb64, 'token': token} )        
            abs_url= 'http://'+current_site + rela_link
            
            email_body= 'Hello '+ user.first_name+'.\n\nUse the link below to reset your password.\n'+ abs_url
            data= {
                'email_body': email_body,
                'to_email': user.email,
                'email_subject': 'Reset Your Password -- Growtogether System.'}
            Util.send_email(data)
            return Response({'Email sent': 'We sent you an email with reset password link.' })                
        return Response({'Error': 'Account with this email not found!' })
    
class PasswordCheckTokenApi(APIView):
    
    def get(self, request, uidb64, token):
        try:
            id= smart_str(urlsafe_base64_decode(uidb64))
            user= User.objects.get(id=id)
            if not PasswordResetTokenGenerator().check_token(user, token):
                return Response({'Error': 'Token is invalid, Request new one.' })
            return Response({'Success': True, 'Message':'Credentials are valid', 'uidb64': uidb64, 'token': token })
 
        except DjangoUnicodeDecodeError as identifier:
                return Response({'Error': 'Token is invalid, Request new one.' })
           
class SetNewPasswordApi(generics.GenericAPIView):
    serializer_class= SetNewPasswordSerializer
    permission_classes= [AllowAny, ]
       
    def patch(self, request):
        serializer= self.serializer_class(data= request.data)
        serializer.is_valid(raise_exception= True)        
        return Response({'Success': True, 'Message':'Password reset successfully'}, status= status.HTTP_200_OK)  
                        

class CreateWomenProfileView(APIView):
    pass
 

