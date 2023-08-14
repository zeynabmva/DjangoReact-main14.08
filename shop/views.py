from django.shortcuts import render



from rest_framework.decorators import api_view
from rest_framework.response import Response
from .models import ShopProduct
from .serializers import ShopProductSerializer

from django.core.paginator import Paginator
# Create your views here.

@api_view(["GET"])
def shopProduct_list_view(request):
    products=ShopProduct.objects.all()
    serializer=ShopProductSerializer(products,many=True)

    paginator = Paginator(products , 4)
    page = request.GET.get('page' ,1)
    product_list = paginator.get_page(page)

    context = {
        "products": product_list
    }


    # return render (request, "products/list.html" , context)
    return Response(serializer.data)

@api_view(["POST"])
def shopProduct_create_view(request):
    serializer=ShopProductSerializer(data=request.data)
    serializer.is_valid(raise_exception=True)
    serializer.save()
    return Response(serializer.data)
        
@api_view(["GET"])
def shopProduct_detail_view(request,id):
    products=ShopProduct.objects.get(id=id)
    serializer=ShopProductSerializer(products)
    return Response(serializer.data)