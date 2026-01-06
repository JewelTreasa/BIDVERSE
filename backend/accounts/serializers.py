from rest_framework import serializers
from django.contrib.auth import authenticate
from .models import User
import requests
from django.conf import settings

class UserRegistrationSerializer(serializers.ModelSerializer):
    password = serializers.CharField(write_only=True)

    class Meta:
        model = User
        fields = ('id', 'first_name', 'last_name', 'email', 'phone', 'user_type', 'password')

    def create(self, validated_data):
        user = User.objects.create_user(
            username=validated_data['email'], # Use email as username
            email=validated_data['email'],
            first_name=validated_data.get('first_name', ''),
            last_name=validated_data.get('last_name', ''),
            phone=validated_data.get('phone', ''),
            user_type=validated_data.get('user_type', 'BUYER'),
        )
        user.set_password(validated_data['password'])
        user.save()
        return user

class LoginSerializer(serializers.Serializer):
    email = serializers.EmailField()
    password = serializers.CharField()

    def validate(self, data):
        user = authenticate(username=data['email'], password=data['password'])
        if user and user.is_active:
            return user
        raise serializers.ValidationError("Incorrect Credentials")

class GoogleLoginSerializer(serializers.Serializer):
    access_token = serializers.CharField(required=True)
    user_type = serializers.CharField(required=False, default='BUYER') # Default role if new user

    def validate(self, data):
        access_token = data.get('access_token')
        # Validate token with Google
        google_url = "https://www.googleapis.com/oauth2/v3/userinfo"
        response = requests.get(google_url, params={'access_token': access_token})
        
        if not response.ok:
            raise serializers.ValidationError("Invalid Google Token")
        
        user_data = response.json()
        email = user_data.get('email')
        
        if not email:
            raise serializers.ValidationError("Google account has no email")

        # Check if user exists, else create
        try:
            user = User.objects.get(email=email)
        except User.DoesNotExist:
            user = User.objects.create_user(
                username=email,
                email=email,
                first_name=user_data.get('given_name', ''),
                last_name=user_data.get('family_name', ''),
                user_type=data.get('user_type', 'BUYER')
            )
            user.set_unusable_password() # No password for google accounts
            user.save()
            
        return user
