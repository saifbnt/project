from rest_framework import serializers
from .models import AppUser
from django.contrib.auth import authenticate

class UserRegisterSerializer(serializers.ModelSerializer):
    class Meta:
        model = AppUser
        fields = ('email', 'username', 'password', 'role')
        extra_kwargs = {'password': {'write_only': True}, 'role': {'default': 'viewer'}}

    def create(self, validated_data):
        user = AppUser.objects.create_user(
            email=validated_data['email'],
            username=validated_data['username'],
            password=validated_data['password'],
            role='viewer'  # Role par défaut
        )
        return user

class UserLoginSerializer(serializers.Serializer):
    email = serializers.EmailField()
    password = serializers.CharField(write_only=True)

    def check_user(self, data):
        user = authenticate(email=data['email'], password=data['password'])
        if not user:
            raise serializers.ValidationError("Invalid login credentials")
        return user

class UserSerializer(serializers.ModelSerializer):
    class Meta:
        model = AppUser
        fields = ('user_id', 'email', 'username', 'role')
