from django.urls import path, include
from user.views import SignupView, LoginView, PasswordResetView, VerifyResetCodeView, ResetPasswordView, UserActivationView

urlpatterns = [
    path('signup/', SignupView.as_view(), name='signup'),
    path('login/', LoginView.as_view(), name='login'),
    path('forgot-password/', PasswordResetView.as_view(), name='forgot-password'),
    path('verify-reset-code/', VerifyResetCodeView.as_view(), name='verify-reset-code'),
    path('reset-password/', ResetPasswordView.as_view(), name='reset-password'),
    path('activate-user/', UserActivationView.as_view(), name='activate-user'),  
]