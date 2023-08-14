from rest_framework import serializers
from .models import Recipes
class RecipeSerializer(serializers.ModelSerializer):
    class Meta:
        model=Recipes
        fields="__all__"