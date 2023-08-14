from rest_framework import serializers
from .models import Blogs
class  BlogSerializer(serializers.ModelSerializer):
    class Meta:
        model=Blogs
        
        fields="__all__"
        
        
    def to_representation(self, instance):
        repr_ = super().to_representation(instance)
        repr_["created_at_display"] = instance.created_at.strftime("%d %b")
        return repr_