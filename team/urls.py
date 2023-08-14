from django.urls import path
from . import views

app_name="team"

urlpatterns = [
    path("list/", views.team_list_view ,name="team_list"),
]
