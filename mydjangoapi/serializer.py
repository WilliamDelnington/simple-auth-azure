from rest_framework import serializers
from rest_framework_simplejwt.tokens import RefreshToken
from rest_framework.permissions import AllowAny
from django.contrib.auth import authenticate
from django.contrib.auth.tokens import PasswordResetTokenGenerator
from django.utils.http import urlsafe_base64_encode, urlsafe_base64_decode
from django.utils.encoding import force_str
from django.conf import settings
from .models import User

class UserSerializer(serializers.ModelSerializer):
    class Meta:
        model = User
        fields = (
            'email',
            'first_name',
            'last_name',
            'phone_number',
            'address',
            'location'
        )

class SignUpSerializer(serializers.ModelSerializer):
    permission_classes = [AllowAny] 

    password = serializers.CharField(write_only=True, required=True, style={'input_type': 'password'})
    class Meta:
        model = User
        fields = (
            'email', 
            'first_name', 
            'last_name', 
            'password', 
            'phone_number', 
            'address',
            'location'
        )
        extra_kwargs = {'password': {'write_only': True}}

    def create(self, validated_data):
        user = User.objects.create_user(
            email=validated_data['email'],
            first_name=validated_data.get('first_name', ''),
            last_name=validated_data.get('last_name', ''),
            password=validated_data['password'],
            phone_number=validated_data.get('phone_number', ''),
            address = validated_data.get("address", ""),
            location = validated_data.get("location", "")
        )
        return user
    
    def get_tokens(self, user):
        refresh = RefreshToken.for_user(user)
        return {
            'refresh': str(refresh),
            'access': str(refresh.access_token),
        }
    
    def validate(self, data):
        phone_number = data.get('phone_number')
        if phone_number and not phone_number.replace('+', '').isdigit():
            raise serializers.ValidationError({'phone_number': 'Phone number must contain only digits and optional leading +.'})

        return data
    
class SignInSerializer(serializers.Serializer):
    emailPhoneNumber = serializers.CharField(required=True)
    password = serializers.CharField(
        style={'input_type': 'password'}, 
        required=True, write_only=True
    )

    def validate(self, data):
        emailPhoneNumber = data.get("emailPhoneNumber")
        password = data.get("password")

        if emailPhoneNumber and password:
            user = authenticate(request=self.context.get("request"), email=emailPhoneNumber, password=password)
            if not user:
                user = authenticate(request=self.context.get("request"), phone_number=emailPhoneNumber, password=password)
                if not user:
                    raise serializers.ValidationError('Invalid email/phone number or password.')
        else:
            raise serializers.ValidationError('Email and password are required.')

        data["user"] = user
        return data

    def get_tokens(self, user):
        refresh = RefreshToken.for_user(user)
        return {
            'refresh': str(refresh),
            'access': str(refresh.access_token),
        }
    
class UpdateProfileSerializer(serializers.ModelSerializer):
    class Meta:
        model = User
        fields = ['email', 'first_name', 'last_name', 'phone_number', 'address', 'location']
        extra_kwargs = {
            'email': {'required': False},
            'first_name': {'required': False},
            'last_name': {'required': False},
            'phone_number': {'required': False},
            'address': {'required': False},
            'location': {'required': False},
        }

    def validate(self, data):
        phone_number = data.get('phone_number')
        if phone_number and not phone_number.replace('+', '').isdigit():
            raise serializers.ValidationError({'phone_number': 'Phone number must contain only digits and optional leading +.'})
        return data
    
    def update(self, instance, validated_data):
        for field, value in validated_data.items():
            # Skip if blank or None
            if value in [None, ""]:
                continue
            # Skip if same as current value
            if getattr(instance, field) == value:
                continue
            # Otherwise update
            setattr(instance, field, value)

        instance.save()
        return instance
    
class UpdatePasswordSerializer(serializers.Serializer):
    current_password = serializers.CharField(write_only=True)
    new_password = serializers.CharField(write_only=True, min_length=8)

    def validate(self, data):
        user = self.context['request'].user
        current_password = data.get('current_password')
        new_password = data.get('new_password')

        # Verify current password
        if not user.check_password(current_password):
            raise serializers.ValidationError({'message': 'Current password is incorrect.'})

        # Optional: Add additional password validation (e.g., complexity)
        if new_password == current_password:
            raise serializers.ValidationError({'message': 'New password must be different from the current password.'})

        return data

    def save(self):
        user = self.context['request'].user
        user.set_password(self.validated_data['new_password'])
        user.save()
        # Create a new token after password change
        refresh = RefreshToken.for_user(user)
        return {
            'refresh': str(refresh),
            'access': str(refresh.access_token),
        }
    
class ForgotPasswordSerializer(serializers.Serializer):
    email = serializers.EmailField()

    def validate_email(self, value):
        # Don't reveal if the user exists
        self.user = User.objects.filter(email=value).first()
        return value

    def save(self):
        if not self.user:
            return
        token_generator = PasswordResetTokenGenerator()
        token = token_generator.make_token(self.user)
        uid = urlsafe_base64_encode(str(self.user.id).encode())
        FRONTEND_URI = f"{settings.CURRENT_FRONTEND_URL}/reset-password"
        reset_url = f"{FRONTEND_URI}?uid={uid}&token={token}"
        
        # Send email
        from django.core.mail import send_mail
        subject = 'Password Reset Request'
        message = f'Click the link to reset your password: {reset_url}\n. This link is valid for 30 minutes.'
        send_mail(
            subject,
            message,
            from_email=None,  # Uses EMAIL_HOST_USER from settings
            recipient_list=[self.user.email],
            fail_silently=False,
        )
        return self.user

class ResetPasswordSerializer(serializers.Serializer):
    uid = serializers.CharField()
    token = serializers.CharField()
    new_password = serializers.CharField(write_only=True, min_length=8)

    def validate(self, data):
        try:
            uid = force_str(urlsafe_base64_decode(data['uid']))
            self.user = User.objects.get(id=uid)
        except (TypeError, ValueError, OverflowError, User.DoesNotExist):
            raise serializers.ValidationError({'uid': 'Invalid user ID.'})

        token_generator = PasswordResetTokenGenerator()
        if not token_generator.check_token(self.user, data['token']):
            raise serializers.ValidationError({'token': 'Invalid or expired token.'})

        return data

    def save(self):
        self.user.set_password(self.validated_data['new_password'])
        self.user.save()
        # Generate new tokens
        refresh = RefreshToken.for_user(self.user)
        return {
            'refresh': str(refresh),
            'access': str(refresh.access_token),
        }