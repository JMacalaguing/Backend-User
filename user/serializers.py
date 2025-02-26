from rest_framework import serializers
from .models import CustomUser, PasswordResetCode

class UserSerializer(serializers.ModelSerializer):
    """
    Serializer for creating and updating CustomUser instances.
    Handles signup with first_name, last_name, email, phone_number, password, is_staff, and status.
    """
    class Meta:
        model = CustomUser
        fields = ['first_name', 'last_name', 'email', 'phone_number', 'password', 'is_staff', 'status', 'is_active']
        extra_kwargs = {
            'password': {'write_only': True},  # Password is not returned in responses
            'is_staff': {'default': False},    # Default to regular user
            'status': {'default': 'active'},   # Default to 'active' status
            'is_active': {'read_only': True}   # Typically managed by admin, not user-editable
        }

    def create(self, validated_data):
        """
        Create a new user instance with the validated data.
        Hashes the password before saving.
        """
        user = CustomUser(
            first_name=validated_data['first_name'],
            last_name=validated_data['last_name'],
            email=validated_data['email'],
            phone_number=validated_data['phone_number'],
            is_staff=validated_data.get('is_staff', False),
            status=validated_data.get('status', 'active'),
            is_active=True  # Default to active on creation
        )
        user.set_password(validated_data['password'])  # Hash the password
        user.save()
        return user

    def update(self, instance, validated_data):
        """
        Update an existing user instance, handling password updates if provided.
        """
        instance.first_name = validated_data.get('first_name', instance.first_name)
        instance.last_name = validated_data.get('last_name', instance.last_name)
        instance.email = validated_data.get('email', instance.email)
        instance.phone_number = validated_data.get('phone_number', instance.phone_number)
        instance.is_staff = validated_data.get('is_staff', instance.is_staff)
        instance.status = validated_data.get('status', instance.status)
        
        password = validated_data.get('password')
        if password:
            instance.set_password(password)
        instance.save()
        return instance

class LoginSerializer(serializers.Serializer):
    """
    Serializer for handling login with email and password.
    """
    email = serializers.EmailField()
    password = serializers.CharField()

class PasswordResetSerializer(serializers.Serializer):
    """
    Serializer for initiating a password reset with an email.
    """
    email = serializers.EmailField()

class VerifyResetCodeSerializer(serializers.Serializer):
    """
    Serializer for verifying a password reset code.
    """
    code = serializers.CharField(max_length=6)

class ResetPasswordSerializer(serializers.Serializer):
    """
    Serializer for resetting a password using a reset code.
    """
    code = serializers.CharField(max_length=6)
    password = serializers.CharField()