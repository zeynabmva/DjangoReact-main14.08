from django.db import models

# Create your models here.

class Recipes(models.Model):
    name=models.CharField(max_length=350)
    summary=models.TextField(blank=True,null=True)
    image=models.ImageField(blank=True,null=True)
    type=models.CharField(max_length=250)
    addition_pic=models.ImageField(blank=True,null=True)
    preparation=models.CharField(max_length=250)
    cooking=models.CharField(max_length=250)
    services=models.CharField(max_length=250)
    ingredients=models.TextField(blank=True,null=True)
    instructions=models.TextField(blank=True,null=True)
    products=models.ManyToManyField('shop.ShopProduct',blank=True)
    created_at=models.DateTimeField(auto_now_add=True)
    updated_at=models.DateTimeField(auto_now=True)
    
    def __str__(self):
        return self.name
    