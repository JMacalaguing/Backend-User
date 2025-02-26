from django.urls import path, include
from user.views import SignupView, LoginView, PasswordResetView, VerifyResetCodeView, ResetPasswordView, UserActivationView

urlpatterns = [
    path('api/signup/', SignupView.as_view(), name='signup'),
    path('api/login/', LoginView.as_view(), name='login'),
    path('api/forgot-password/', PasswordResetView.as_view(), name='forgot-password'),
    path('api/verify-reset-code/', VerifyResetCodeView.as_view(), name='verify-reset-code'),
    path('api/reset-password/', ResetPasswordView.as_view(), name='reset-password'),
    path('api/activate-user/', UserActivationView.as_view(), name='activate-user'),  
]