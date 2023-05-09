from django.urls import path, include
from .views import (UserRegister, VerifyAccount,
RequestResetPasswordEmail, PasswordCheckTokenApi, SetNewPasswordApi, 
                     ChangePasswordApi, 
                     LoginApi, LogoutApi,
                    WomanProfileAPIView,
                    CreateWomenProfileView,
                      )

from rest_framework.routers import DefaultRouter



router= DefaultRouter()
router.register('registeruser', UserRegister, basename='accounts')

urlpatterns = [ 
               
    path('accounts/', include(router.urls)),
    path('accounts/activateaccount/', VerifyAccount.as_view(), name='email-verify'),
    path('accounts/login/', LoginApi.as_view(), name='login'),
    path('accounts/logout/', LogoutApi.as_view(), name='logout'),    
    
    #changing password not working on confirming passwd field      
    path('accounts/changepassword/', ChangePasswordApi.as_view(), name='changepassword'),
    path('accounts/requestresetemail/', RequestResetPasswordEmail.as_view(), name='request-reset-email'),
    path('accounts/resetpassword/<uidb64>/<token>/', PasswordCheckTokenApi.as_view(), name='password-reset-confirm'),
    path('accounts/resetpassword/', SetNewPasswordApi.as_view(), name='password-reset-done'),
    
    # for woman_info
    path('profile/', WomanProfileAPIView.as_view(), name='api_woman_profile'), 
    path('create_profile/',CreateWomenProfileView.as_view(), name='create_profile'),
 
   

    
]