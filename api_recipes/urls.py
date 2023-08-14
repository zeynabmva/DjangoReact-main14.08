from django.urls import path
from . import views
from api_recipes.views import recipe_list_view,recipe_detail_view, recipe_create_view

app_name="recipes"

urlpatterns = [
    path("list/",recipe_list_view, name="recipe_list"),
    path("detail/<id>/",recipe_detail_view, name="recipe_detail"),
    path("create/",recipe_create_view, name="recipe_create"),
]
