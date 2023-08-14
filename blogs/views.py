from django.shortcuts import render
from rest_framework.decorators import api_view
from rest_framework.response import Response
from .models import Blogs
from .serializers import BlogSerializer
from datetime import datetime
import requests
import json
from django.http import JsonResponse
from django.views.decorators.csrf import csrf_exempt
from django.core.exceptions import ValidationError
from django.conf import settings
 # Create your views here.

@api_view(["GET"])
def blog_list_view(request):
    blogs=Blogs.objects.all()
    serializer=BlogSerializer(blogs,many=True)
    return Response(serializer.data)

 
        
@api_view(["POST"])
@csrf_exempt
def blog_create_view(request):
    serializer = BlogSerializer(data=request.data)
    serializer.is_valid(raise_exception=True)
    serializer.save()
    return Response(serializer.data, status=201)
    
@api_view(["GET"])
def blog_detail_view(request,id):
    blog=Blogs.objects.get(id=id)
    serializer=BlogSerializer(blog)
    return Response(serializer.data)


 