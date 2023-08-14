from django.db import models

# Create your models here.
class ShopProduct(models.Model):
    name=models.CharField(max_length=350)
    category=models.CharField(max_length=350 , default='')
    image=models.ImageField(blank=True,null=True)
    oldprice=models.FloatField(max_length=250)
    newprice=models.FloatField(max_length=250)
    calories=models.FloatField(max_length=250)
    text=models.TextField(max_length=550 , default='')
    description_text=models.TextField(max_length=550)
    additional_text=models.TextField(blank=True,null=True)
 
    created_at=models.DateTimeField(auto_now_add=True)
    updated_at=models.DateTimeField(auto_now=True)
    
    def __str__(self):
        return self.name