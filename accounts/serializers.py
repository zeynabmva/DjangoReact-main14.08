from rest_framework import serializers
from django.contrib.auth import get_user_model, authenticate
from rest_framework_simplejwt.tokens import RefreshToken
from django.core.mail import send_mail
from django.contrib.auth.tokens import PasswordResetTokenGenerator
from django.utils.encoding import smart_str, smart_bytes
from django.utils.http import urlsafe_base64_encode, urlsafe_base64_decode
from django.conf import settings


User = get_user_model()


class LoginSerializer(serializers.ModelSerializer):
    email = serializers.EmailField()

    class Meta:
        model = User
        fields = ("email", "password")
        extra_kwargs = {
            "password": {
                "write_only": True
            }
        }

    def validate(self, attrs):
        email = attrs.get("email")
        password = attrs.get("password")

        user = authenticate(email=email, password=password)

        if not user:
            raise serializers.ValidationError({"error": "This user does not exist"})

        if not user.is_active:
            raise serializers.ValidationError({"error": "This user is not activated"})

        return super().validate(attrs)


    def create(self, validated_data):
        email = validated_data.get("email")
        password = validated_data.get("password")
        user = authenticate(email=email, password=password)
        return user


    def to_representation(self, instance):
        repr_ = super().to_representation(instance)
        token = RefreshToken.for_user(instance)
        repr_["token"] = {"refresh": str(token), "access": str(token.access_token)}
        return repr_




class RegisterSerializer(serializers.ModelSerializer):
    passwordConfirm = serializers.CharField(write_only=True)

    class Meta:
        model = User
        fields = ("email", "password", "passwordConfirm")
        extra_kwargs = {
            "password": {
                "write_only": True
            },
            "passwordConfirm": {
                "write_only": True
            },
        }


    def validate(self, attrs):
        email = attrs.get("email")
        password = attrs.get("password")
        passwordConfirm = attrs.get("passwordConfirm")

        user = authenticate(email=email, password=password)

        if user:
            raise serializers.ValidationError({"error": "This user already exists"})

        if password != passwordConfirm:
            raise serializers.ValidationError({"error": "The passwords should match each other"})

        return super().validate(attrs)


    def create(self, validated_data):
        validated_data.pop("passwordConfirm")
        print(validated_data)
        user = User.objects.create(
            **validated_data, is_active=False
        )

        # send mail
        token = PasswordResetTokenGenerator().make_token(user)
        uuid64 = urlsafe_base64_encode(smart_bytes(user.id))
        link = f"http://localhost:8000/api/accounts/activation/{uuid64}/{token}/"
        send_mail(
            "Activation email",  # --> subject
            f"Please click the link below\n{link}",  # --> message,
            settings.EMAIL_HOST_USER,
            [user.email],
            fail_silently=False
        )
        return user