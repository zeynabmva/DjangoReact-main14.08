from django.db import models

# Create your models here.
class Team(models.Model):
    name=models.CharField(max_length=200)
    profession=models.CharField(max_length=250)
    image=models.ImageField(blank=True,null=True)
    facebook=models.URLField(blank=True,null=True)
    twitter=models.URLField(blank=True,null=True)
    instagram=models.URLField(blank=True,null=True)
    
    def __str__(self):
        return self.name