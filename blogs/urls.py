from django.urls import path
from . import views

app_name='blogs'

urlpatterns = [
    path("list/",views.blog_list_view, name="blog_list"),
    path("detail/<id>/",views.blog_detail_view, name="blog_detail"),
    path("create/",views.blog_create_view, name="blog_create"),
]
