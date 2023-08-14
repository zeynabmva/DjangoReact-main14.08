from django.shortcuts import render
from rest_framework.decorators import api_view
from rest_framework.response import Response
from .models import Recipes
from .serializers import RecipeSerializer
# Create your views here.

@api_view(["GET"])
def recipe_list_view(request):
    recipes=Recipes.objects.all()
    serializer=RecipeSerializer(recipes,many=True)
    return Response(serializer.data)

@api_view(["POST"])
def recipe_create_view(request):
    serializer=RecipeSerializer(data=request.data)
    serializer.is_valid(raise_exception=True)
    serializer.save()
    return Response(serializer.data)
        
@api_view(["GET"])
def recipe_detail_view(request,id):
    recipe=Recipes.objects.get(id=id)
    serializer=RecipeSerializer(recipe)
    return Response(serializer.data)



 