from django.shortcuts import HttpResponseRedirect, HttpResponse
from rest_framework import generics
from .serializers import LoginSerializer
from .serializers import RegisterSerializer
from django.contrib.auth import get_user_model
from django.utils.encoding import smart_str, smart_bytes
from django.contrib.auth.tokens import PasswordResetTokenGenerator
from django.utils.http import urlsafe_base64_encode, urlsafe_base64_decode
from django.utils.http import urlsafe_base64_encode, urlsafe_base64_decode

User = get_user_model()

class LoginView(generics.CreateAPIView):
    queryset = User.objects.all()
    serializer_class = LoginSerializer

class RegisterView(generics.CreateAPIView):
    queryset = User.objects.all()
    serializer_class = RegisterSerializer

def activation_view(request, uuid64, token):
    id = smart_str(urlsafe_base64_decode(uuid64))
    user = User.objects.get(id=id)

    if not PasswordResetTokenGenerator().check_token(user, token):
        message = "Link Duzgun Deyil"
        return HttpResponse(f"<h1>{message}</h1>")

    user.is_active = True
    user.save()

    return HttpResponseRedirect("http://127.0.0.1:8000/access-activation") #login sehifesi