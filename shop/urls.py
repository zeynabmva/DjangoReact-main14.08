from django.urls import path
from . import views
from shop.views import shopProduct_list_view, shopProduct_detail_view, shopProduct_create_view

app_name="shop_product"

urlpatterns = [
    path("list/",shopProduct_list_view, name="shopProduct_list"),
    path("detail/<id>/",shopProduct_detail_view, name="shopProduct_detail"),
    path("create/",shopProduct_create_view, name="shopProduct_create"),
]
