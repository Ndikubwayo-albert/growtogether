from django.urls import path, include
from .views import (UserRegister, VerifyAccount, RequestResetPasswordEmail, PasswordCheckTokenApi, SetNewPasswordApi, 
                     ChangePasswordApi, 
                     LoginApi, LogoutApi,
                    
)

from rest_framework.routers import DefaultRouter



router= DefaultRouter()
router.register('users', UserRegister, basename='users')

urlpatterns = [ 
                
    path('', include(router.urls)),    
    path('activateaccount/', VerifyAccount.as_view(), name='email-verify'),
    path('login/', LoginApi.as_view(), name='login'),
    path('logout/', LogoutApi.as_view(), name='logout'),   
    
    #changing password not working on confirming passwd field      
    path('users/changepassword/', ChangePasswordApi.as_view(), name='changepassword'),
    path('requestresetemail/', RequestResetPasswordEmail.as_view(), name='request-reset-email'),
    path('resetpassword/<uidb64>/<token>/', PasswordCheckTokenApi.as_view(), name='password-reset-confirm'),
    path('resetpassword/', SetNewPasswordApi.as_view(), name='password-reset-done'),
    
   
    
]