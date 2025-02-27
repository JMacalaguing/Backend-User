from rest_framework import generics, status, permissions
from rest_framework.response import Response
from rest_framework.authtoken.models import Token
from django.contrib.auth import authenticate
from django.core.mail import send_mail
from django.conf import settings
from django.utils.timezone import now
from .models import CustomUser, PasswordResetCode
from .serializers import UserSerializer, LoginSerializer, PasswordResetSerializer, VerifyResetCodeSerializer, ResetPasswordSerializer
import random

class SignupView(generics.CreateAPIView):
    serializer_class = UserSerializer
    permission_classes = [permissions.AllowAny]  # Allow anyone to register

    def post(self, request, *args, **kwargs):
        print(request.data)  # Debug: Check incoming data
        serializer = self.get_serializer(data=request.data)
        
        if serializer.is_valid():
            is_staff = serializer.validated_data.get('is_staff', False)

            # Restrict staff user creation
            if is_staff and not request.user.is_authenticated:
                return Response({'error': 'Only authenticated staff or superusers can create admin accounts'}, status=status.HTTP_403_FORBIDDEN)

            user = serializer.save()
            token, _ = Token.objects.get_or_create(user=user)

            return Response({
                'message': 'User registered successfully!',
                'token': token.key,
                'is_staff': user.is_staff,
                'status': user.status,
            }, status=status.HTTP_201_CREATED)

        return Response(serializer.errors, status=status.HTTP_400_BAD_REQUEST)


class LoginView(generics.GenericAPIView):
    serializer_class = LoginSerializer
    permission_classes = [permissions.AllowAny]  # Allow anyone to register

    def post(self, request, *args, **kwargs):
        serializer = self.get_serializer(data=request.data)
        serializer.is_valid(raise_exception=True)

        email = serializer.validated_data['email']
        password = serializer.validated_data['password']
        
        user = authenticate(email=email, password=password)
        
        if user:
            token, _ = Token.objects.get_or_create(user=user)
            return Response({
                'message': 'Login successful!',
                'token': token.key,
                'user': {
                    'first_name': user.first_name,
                    'last_name': user.last_name,
                    'email': user.email,
                    'phone_number': user.phone_number,
                    'is_staff': user.is_staff,
                    'status': user.status
                }
            }, status=status.HTTP_200_OK)
        
        return Response({'error': 'Invalid email or password'}, status=status.HTTP_401_UNAUTHORIZED)

class PasswordResetView(generics.GenericAPIView):
    serializer_class = PasswordResetSerializer

    def post(self, request, *args, **kwargs):
        serializer = self.get_serializer(data=request.data)
        if serializer.is_valid():
            email = serializer.validated_data['email']
            try:
                user = CustomUser.objects.get(email=email, is_active=True)
                # Generate a 6-digit random code
                reset_code = ''.join([str(random.randint(0, 9)) for _ in range(6)])
                PasswordResetCode.objects.create(user=user, code=reset_code)

                # Send reset code via email
                subject = 'Password Reset Code'
                message = f'Your password reset code is: {reset_code}. It expires in 15 minutes.'
                send_mail(
                    subject=subject,
                    message=message,
                    from_email=settings.EMAIL_HOST_USER,
                    recipient_list=[email],
                    fail_silently=True,
                )
                return Response({
                    'message': 'Password reset code sent to your email.',
                }, status=status.HTTP_200_OK)
            except CustomUser.DoesNotExist:
                return Response({'error': 'User not found or account is deactivated'}, status=status.HTTP_404_NOT_FOUND)
        return Response(serializer.errors, status=status.HTTP_400_BAD_REQUEST)

class VerifyResetCodeView(generics.GenericAPIView):
    serializer_class = VerifyResetCodeSerializer

    def post(self, request, *args, **kwargs):
        serializer = self.get_serializer(data=request.data)
        if serializer.is_valid():
            code = serializer.validated_data['code']
            try:
                reset_code = PasswordResetCode.objects.get(code=code)
                if reset_code.is_valid():
                    return Response({'message': 'Code is valid.'}, status=status.HTTP_200_OK)
                return Response({'error': 'Code has expired.'}, status=status.HTTP_400_BAD_REQUEST)
            except PasswordResetCode.DoesNotExist:
                return Response({'error': 'Invalid code.'}, status=status.HTTP_400_BAD_REQUEST)
        return Response(serializer.errors, status=status.HTTP_400_BAD_REQUEST)

class ResetPasswordView(generics.GenericAPIView):
    serializer_class = ResetPasswordSerializer

    def post(self, request, *args, **kwargs):
        serializer = self.get_serializer(data=request.data)
        if serializer.is_valid():
            code = serializer.validated_data['code']
            password = serializer.validated_data['password']
            try:
                reset_code = PasswordResetCode.objects.get(code=code)
                if reset_code.is_valid():
                    user = reset_code.user
                    user.set_password(password)
                    user.save()
                    reset_code.delete()  # Clean up the used code
                    return Response({
                        'message': 'Password reset successfully!',
                    }, status=status.HTTP_200_OK)
                return Response({'error': 'Code has expired.'}, status=status.HTTP_400_BAD_REQUEST)
            except PasswordResetCode.DoesNotExist:
                return Response({'error': 'Invalid code.'}, status=status.HTTP_400_BAD_REQUEST)
        return Response(serializer.errors, status=status.HTTP_400_BAD_REQUEST)

class UserActivationView(generics.UpdateAPIView):
    """
    View to activate or deactivate a user by their email.
    Restricted to authenticated staff or superusers.
    """
    permission_classes = [permissions.IsAuthenticated, permissions.IsAdminUser]  # Only admins can activate/deactivate

    def put(self, request, *args, **kwargs):
        email = request.data.get('email')
        if not email:
            return Response({'error': 'Email is required'}, status=status.HTTP_400_BAD_REQUEST)

        try:
            user = CustomUser.objects.get(email=email)
            # Toggle is_active and status
            user.is_active = not user.is_active  # Flip the boolean
            user.status = 'active' if user.is_active else 'deactivate'
            user.save()

            return Response({
                'message': f'User {email} is now {"active" if user.is_active else "deactivated"}.',
                'is_active': user.is_active,
                'status': user.status,
            }, status=status.HTTP_200_OK)
        except CustomUser.DoesNotExist:
            return Response({'error': 'User not found'}, status=status.HTTP_404_NOT_FOUND)

class UserListView(generics.ListAPIView):
    """
    View to list all users.
    Restricted to authenticated staff or superusers.
    """
    serializer_class = UserSerializer
    permission_classes = [permissions.IsAuthenticated, permissions.IsAdminUser]

    def get_queryset(self):
        return CustomUser.objects.all()