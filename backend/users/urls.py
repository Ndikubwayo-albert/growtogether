from django.urls import path, include
from .views import (UserRegister, VerifyAccount, ChangePasswordApi, LoginApi, LogoutApi, RequestResetPasswordEmail,
                    PasswordCheckTokenApi, SetNewPasswordApi,)

from rest_framework.routers import DefaultRouter


router= DefaultRouter()
router.register('accounts', UserRegister, basename='accounts')

urlpatterns = [ 
               
    path('', include(router.urls)),    
    path('accounts/activateaccount/', VerifyAccount.as_view(), name='email-verify'),
    path('accounts/login/', LoginApi.as_view(), name='login'),
    path('accounts/logout/', LogoutApi.as_view(), name='logout'),    
    
    #changing password not working on confirming passwd field      
    path('accounts/changepassword/', ChangePasswordApi.as_view(), name='changepassword'),
    path('accounts/requestresetemail/', RequestResetPasswordEmail.as_view(), name='request-reset-email'),
    path('accounts/resetpassword/<uidb64>/<token>/', PasswordCheckTokenApi.as_view(), name='password-reset-confirm'),
    path('accounts/resetpassword/', SetNewPasswordApi.as_view(), name='password-reset-done'),
    
    # for woman_info
    path('accounts/womaninfo/', SetNewPasswordApi.as_view(), name='password-reset-done'),

    
]